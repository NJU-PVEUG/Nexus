package singleton

import (
	"cmp"
	"context"
	"crypto/tls"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/goccy/go-json"
	"github.com/robfig/cron/v3"
	"golang.org/x/sync/errgroup"

	"github.com/nezhahq/nezha/model"
)

const federationSyntheticIDMask uint64 = 1 << 63

type FederatedServerRef struct {
	SourceName string
	RemoteID   uint64
}

type FederationManager struct {
	conf model.FederationConfig

	syncMu sync.Mutex
	mu     sync.RWMutex

	sources []*federationSourceRuntime
	index   map[uint64]FederatedServerRef
	servers map[uint64]*model.Server

	jobID cron.EntryID
}

type federationSourceRuntime struct {
	config model.FederationSource
	client *http.Client

	token          string
	tokenExpiresAt time.Time
	lastSync       time.Time

	servers   map[uint64]*model.Server
	remoteIDs map[uint64]uint64
	ordered   []*model.Server
}

func NewFederationManager(conf *model.FederationConfig) (*FederationManager, error) {
	manager := &FederationManager{
		index:   make(map[uint64]FederatedServerRef),
		servers: make(map[uint64]*model.Server),
	}
	if conf == nil {
		return manager, nil
	}

	normalized := *conf
	if err := normalized.Normalize(); err != nil {
		return nil, err
	}

	manager.conf = normalized

	for _, source := range normalized.Sources {
		if !source.Enabled {
			continue
		}

		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: source.InsecureTLS}

		manager.sources = append(manager.sources, &federationSourceRuntime{
			config: source,
			client: &http.Client{
				Timeout:   normalized.RequestTimeout,
				Transport: transport,
			},
			servers:   make(map[uint64]*model.Server),
			remoteIDs: make(map[uint64]uint64),
		})
	}

	if len(manager.sources) == 0 {
		return manager, nil
	}

	if CronShared != nil {
		jobID, err := CronShared.AddFunc(fmt.Sprintf("@every %s", manager.conf.SyncInterval), func() {
			if err := manager.Sync(context.Background()); err != nil {
				log.Printf("NEZHA>> Federation sync finished with errors: %v", err)
			}
		})
		if err != nil {
			return nil, err
		}
		manager.jobID = jobID
		go func() {
			if err := manager.Sync(context.Background()); err != nil {
				log.Printf("NEZHA>> Federation initial sync finished with errors: %v", err)
			}
		}()
	}

	return manager, nil
}

func (m *FederationManager) Enabled() bool {
	return m != nil && len(m.sources) > 0
}

func (m *FederationManager) Sync(ctx context.Context) error {
	if !m.Enabled() {
		return nil
	}

	m.syncMu.Lock()
	defer m.syncMu.Unlock()

	group, groupCtx := errgroup.WithContext(ctx)
	for _, source := range m.sources {
		source := source
		group.Go(func() error {
			return m.syncSource(groupCtx, source)
		})
	}

	return group.Wait()
}

func (m *FederationManager) syncSource(ctx context.Context, source *federationSourceRuntime) error {
	servers, err := m.fetchRemoteServers(ctx, source)
	if err != nil {
		return err
	}

	now := time.Now()
	serverMap := make(map[uint64]*model.Server, len(servers))
	remoteIDs := make(map[uint64]uint64, len(servers))
	ordered := make([]*model.Server, 0, len(servers))

	for i := range servers {
		server := servers[i]
		remoteID := server.ID
		syntheticID := synthesizeFederatedID(source.config, remoteID)

		if existingID, ok := remoteIDs[syntheticID]; ok && existingID != remoteID {
			log.Printf("NEZHA>> Federation synthetic ID collision inside source %s: remote %d conflicts with %d", source.config.Name, remoteID, existingID)
			continue
		}

		server.ID = syntheticID
		server.TaskStream = nil
		server.ConfigCache = nil
		server.PrevTransferInSnapshot = 0
		server.PrevTransferOutSnapshot = 0
		ensureServerRuntimeFields(server)

		serverMap[syntheticID] = server
		remoteIDs[syntheticID] = remoteID
		ordered = append(ordered, server)
	}

	m.mu.Lock()
	source.servers = serverMap
	source.remoteIDs = remoteIDs
	source.ordered = ordered
	source.lastSync = now
	m.rebuildIndexLocked()
	m.mu.Unlock()

	return nil
}

func (m *FederationManager) fetchRemoteServers(ctx context.Context, source *federationSourceRuntime) ([]*model.Server, error) {
	if err := m.ensureAuthenticated(ctx, source); err != nil {
		return nil, err
	}

	servers, unauthorized, err := m.requestServerList(ctx, source)
	if unauthorized {
		source.token = ""
		source.tokenExpiresAt = time.Time{}
		if err := m.ensureAuthenticated(ctx, source); err != nil {
			return nil, err
		}
		servers, unauthorized, err = m.requestServerList(ctx, source)
	}
	if unauthorized {
		return nil, fmt.Errorf("federation source %q rejected authenticated server list request", source.config.Name)
	}
	if err != nil {
		return nil, err
	}

	return servers, nil
}

func (m *FederationManager) ensureAuthenticated(ctx context.Context, source *federationSourceRuntime) error {
	if source.token != "" && (source.tokenExpiresAt.IsZero() || time.Now().Before(source.tokenExpiresAt.Add(-30*time.Second))) {
		return nil
	}

	loginBody, err := json.Marshal(model.LoginRequest{
		Username: source.config.Username,
		Password: source.config.Password,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, source.endpoint("api/v1/login"), strings.NewReader(string(loginBody)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := source.client.Do(req)
	if err != nil {
		return fmt.Errorf("federation source %q login failed: %w", source.config.Name, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("federation source %q login read failed: %w", source.config.Name, err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("federation source %q login returned status %d", source.config.Name, resp.StatusCode)
	}

	var result model.CommonResponse[model.LoginResponse]
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("federation source %q login decode failed: %w", source.config.Name, err)
	}
	if !result.Success || result.Data.Token == "" {
		return fmt.Errorf("federation source %q login rejected: %s", source.config.Name, strings.TrimSpace(result.Error))
	}

	source.token = result.Data.Token
	if result.Data.Expire != "" {
		expiresAt, err := time.Parse(time.RFC3339, result.Data.Expire)
		if err == nil {
			source.tokenExpiresAt = expiresAt
		} else {
			source.tokenExpiresAt = time.Time{}
		}
	} else {
		source.tokenExpiresAt = time.Time{}
	}

	return nil
}

func (m *FederationManager) requestServerList(ctx context.Context, source *federationSourceRuntime) ([]*model.Server, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source.endpoint("api/v1/server"), nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Authorization", "Bearer "+source.token)

	resp, err := source.client.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("federation source %q server list failed: %w", source.config.Name, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, fmt.Errorf("federation source %q server list read failed: %w", source.config.Name, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("federation source %q server list returned status %d", source.config.Name, resp.StatusCode)
	}

	var result model.CommonResponse[[]model.Server]
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, false, fmt.Errorf("federation source %q server list decode failed: %w", source.config.Name, err)
	}
	if !result.Success {
		return nil, result.Error == "ApiErrorUnauthorized", fmt.Errorf("federation source %q server list rejected: %s", source.config.Name, strings.TrimSpace(result.Error))
	}

	servers := make([]*model.Server, 0, len(result.Data))
	for i := range result.Data {
		server := result.Data[i]
		ensureServerRuntimeFields(&server)
		servers = append(servers, &server)
	}

	return servers, false, nil
}

func (m *FederationManager) GetServer(id uint64) (*model.Server, bool) {
	if !m.Enabled() {
		return nil, false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	server, ok := m.servers[id]
	return server, ok
}

func (m *FederationManager) Lookup(id uint64) (FederatedServerRef, bool) {
	if !m.Enabled() {
		return FederatedServerRef{}, false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	ref, ok := m.index[id]
	return ref, ok
}

func (m *FederationManager) GetActiveServers(authorized bool) []*model.Server {
	if !m.Enabled() {
		return nil
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	now := time.Now()
	servers := make([]*model.Server, 0)
	for _, source := range m.sources {
		if source.lastSync.IsZero() || now.Sub(source.lastSync) > m.conf.StaleAfter {
			continue
		}
		for _, server := range source.ordered {
			if !authorized && server.HideForGuest {
				continue
			}
			servers = append(servers, server)
		}
	}

	sortServersForRealtime(servers)
	return servers
}

func (m *FederationManager) rebuildIndexLocked() {
	index := make(map[uint64]FederatedServerRef)
	servers := make(map[uint64]*model.Server)

	for _, source := range m.sources {
		for syntheticID, server := range source.servers {
			ref := FederatedServerRef{
				SourceName: source.config.Name,
				RemoteID:   source.remoteIDs[syntheticID],
			}
			if existing, ok := index[syntheticID]; ok && existing != ref {
				log.Printf("NEZHA>> Federation synthetic ID collision across sources: %s/%d conflicts with %s/%d", ref.SourceName, ref.RemoteID, existing.SourceName, existing.RemoteID)
				continue
			}
			index[syntheticID] = ref
			servers[syntheticID] = server
		}
	}

	m.index = index
	m.servers = servers
}

func (s *federationSourceRuntime) endpoint(path string) string {
	return strings.TrimRight(s.config.BaseURL, "/") + "/" + strings.TrimLeft(path, "/")
}

func ensureServerRuntimeFields(server *model.Server) {
	if server.Host == nil {
		server.Host = &model.Host{}
	}
	if server.State == nil {
		server.State = &model.HostState{}
	}
	if server.GeoIP == nil {
		server.GeoIP = &model.GeoIP{}
	}
	if server.ConfigCache == nil {
		server.ConfigCache = make(chan any, 1)
	}
}

func synthesizeFederatedID(source model.FederationSource, remoteID uint64) uint64 {
	hasher := fnv.New64a()
	hasher.Write([]byte(source.Name))
	hasher.Write([]byte{0})
	hasher.Write([]byte(source.BaseURL))
	hasher.Write([]byte{0})
	hasher.Write([]byte(strconv.FormatUint(remoteID, 10)))
	return federationSyntheticIDMask | (hasher.Sum64() &^ federationSyntheticIDMask)
}

func IsFederatedServerID(id uint64) bool {
	return id&federationSyntheticIDMask != 0
}

func GetRealtimeServerList(authorized bool) []*model.Server {
	var servers []*model.Server
	if authorized {
		servers = ServerShared.GetSortedList()
	} else {
		servers = ServerShared.GetSortedListForGuest()
	}

	if FederationShared == nil || !FederationShared.Enabled() {
		return servers
	}

	merged := append(servers, FederationShared.GetActiveServers(authorized)...)
	sortServersForRealtime(merged)
	return merged
}

func sortServersForRealtime(servers []*model.Server) {
	slices.SortStableFunc(servers, func(a, b *model.Server) int {
		if a.DisplayIndex == b.DisplayIndex {
			return cmp.Compare(a.ID, b.ID)
		}
		return cmp.Compare(b.DisplayIndex, a.DisplayIndex)
	})
}
