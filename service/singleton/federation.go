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
	SourceID    uint64
	OwnerUserID uint64
	RemoteID    uint64
}

type FederationManager struct {
	conf model.FederationConfig

	syncMu sync.Mutex
	mu     sync.RWMutex

	sources map[uint64]*federationSourceRuntime
	index   map[uint64]FederatedServerRef
	servers map[uint64]*model.Server

	jobID cron.EntryID
}

type federationSourceRuntime struct {
	source model.FederationSource
	client *http.Client

	servers   map[uint64]*model.Server
	remoteIDs map[uint64]uint64
	ordered   []*model.Server
}

func NewFederationManager(conf *model.FederationConfig) (*FederationManager, error) {
	manager := &FederationManager{
		sources: make(map[uint64]*federationSourceRuntime),
		index:   make(map[uint64]FederatedServerRef),
		servers: make(map[uint64]*model.Server),
	}

	if conf != nil {
		normalized := *conf
		if err := normalized.Normalize(); err != nil {
			return nil, err
		}
		manager.conf = normalized
	} else if err := manager.conf.Normalize(); err != nil {
		return nil, err
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
	return m != nil
}

func (m *FederationManager) Sync(ctx context.Context) error {
	if m == nil {
		return nil
	}

	m.syncMu.Lock()
	defer m.syncMu.Unlock()

	dbSources, err := m.loadEnabledSources()
	if err != nil {
		return err
	}

	m.mu.Lock()
	runtimes := m.reconcileSourcesLocked(dbSources)
	m.mu.Unlock()

	group, groupCtx := errgroup.WithContext(ctx)
	for _, source := range runtimes {
		source := source
		group.Go(func() error {
			return m.syncSource(groupCtx, source)
		})
	}

	return group.Wait()
}

func (m *FederationManager) Reload() error {
	if m == nil {
		return nil
	}

	dbSources, err := m.loadEnabledSources()
	if err != nil {
		return err
	}

	m.mu.Lock()
	m.reconcileSourcesLocked(dbSources)
	m.mu.Unlock()
	return nil
}

func (m *FederationManager) loadEnabledSources() ([]model.FederationSource, error) {
	if DB == nil {
		return nil, nil
	}

	var sources []model.FederationSource
	if err := DB.Where("enabled = ?", true).Order("id ASC").Find(&sources).Error; err != nil {
		return nil, err
	}
	return sources, nil
}

func (m *FederationManager) reconcileSourcesLocked(dbSources []model.FederationSource) []*federationSourceRuntime {
	next := make(map[uint64]*federationSourceRuntime, len(dbSources))
	runtimes := make([]*federationSourceRuntime, 0, len(dbSources))

	for _, source := range dbSources {
		runtime, ok := m.sources[source.ID]
		if !ok || federationClientNeedsReset(runtime.source, source) {
			runtime = &federationSourceRuntime{
				source:    source,
				client:    newFederationHTTPClient(source.InsecureTLS, m.conf.RequestTimeout),
				servers:   make(map[uint64]*model.Server),
				remoteIDs: make(map[uint64]uint64),
			}
		} else {
			runtime.source = source
		}

		next[source.ID] = runtime
		runtimes = append(runtimes, runtime)
	}

	m.sources = next
	m.rebuildIndexLocked()
	return runtimes
}

func federationClientNeedsReset(current, next model.FederationSource) bool {
	return current.BaseURL != next.BaseURL || current.InsecureTLS != next.InsecureTLS
}

func newFederationHTTPClient(insecureTLS bool, timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: insecureTLS}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}

func (m *FederationManager) syncSource(ctx context.Context, source *federationSourceRuntime) error {
	if source.source.ReauthRequired || source.source.Token == "" {
		m.clearSource(source.source.ID)
		return nil
	}

	if err := m.refreshTokenIfNeeded(ctx, source); err != nil {
		return err
	}

	servers, unauthorized, err := m.requestServerList(ctx, source)
	if unauthorized {
		return m.markSourceReauth(source.source.ID, "remote authorization expired")
	}
	if err != nil {
		return m.recordSourceError(source.source.ID, err.Error())
	}

	now := time.Now()
	serverMap := make(map[uint64]*model.Server, len(servers))
	remoteIDs := make(map[uint64]uint64, len(servers))
	ordered := make([]*model.Server, 0, len(servers))

	for i := range servers {
		server := servers[i]
		remoteID := server.ID
		syntheticID := synthesizeFederatedID(source.source.ID, remoteID)

		if existingID, ok := remoteIDs[syntheticID]; ok && existingID != remoteID {
			log.Printf("NEZHA>> Federation synthetic ID collision inside source %d: remote %d conflicts with %d", source.source.ID, remoteID, existingID)
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

	if err := m.persistSourceSuccess(source.source.ID, source.source.Token, source.source.TokenExpiresAt, now); err != nil {
		return err
	}

	m.mu.Lock()
	if runtime, ok := m.sources[source.source.ID]; ok {
		runtime.servers = serverMap
		runtime.remoteIDs = remoteIDs
		runtime.ordered = ordered
		runtime.source.Token = source.source.Token
		runtime.source.TokenExpiresAt = source.source.TokenExpiresAt
		runtime.source.LastSyncAt = now
		runtime.source.LastError = ""
		runtime.source.ReauthRequired = false
	}
	m.rebuildIndexLocked()
	m.mu.Unlock()

	return nil
}

func (m *FederationManager) refreshTokenIfNeeded(ctx context.Context, source *federationSourceRuntime) error {
	if source.source.Token == "" || source.source.ReauthRequired {
		return m.markSourceReauth(source.source.ID, "remote authorization expired")
	}
	if source.source.TokenExpiresAt.IsZero() || time.Now().Before(source.source.TokenExpiresAt.Add(-30*time.Second)) {
		return nil
	}

	token, expiresAt, unauthorized, err := m.requestRefreshToken(ctx, source)
	if unauthorized {
		return m.markSourceReauth(source.source.ID, "remote authorization expired")
	}
	if err != nil {
		return m.recordSourceError(source.source.ID, err.Error())
	}

	source.source.Token = token
	source.source.TokenExpiresAt = expiresAt
	if err := m.persistSourceToken(source.source.ID, token, expiresAt); err != nil {
		return err
	}

	m.mu.Lock()
	if runtime, ok := m.sources[source.source.ID]; ok {
		runtime.source.Token = token
		runtime.source.TokenExpiresAt = expiresAt
	}
	m.mu.Unlock()

	return nil
}

func (m *FederationManager) requestRefreshToken(ctx context.Context, source *federationSourceRuntime) (string, time.Time, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source.endpoint("api/v1/refresh-token"), nil)
	if err != nil {
		return "", time.Time{}, false, err
	}
	req.Header.Set("Authorization", "Bearer "+source.source.Token)

	resp, err := source.client.Do(req)
	if err != nil {
		return "", time.Time{}, false, fmt.Errorf("federation source %q refresh failed: %w", source.source.BaseURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", time.Time{}, false, fmt.Errorf("federation source %q refresh read failed: %w", source.source.BaseURL, err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, false, fmt.Errorf("federation source %q refresh returned status %d", source.source.BaseURL, resp.StatusCode)
	}

	var result model.CommonResponse[model.LoginResponse]
	if err := json.Unmarshal(body, &result); err != nil {
		return "", time.Time{}, false, fmt.Errorf("federation source %q refresh decode failed: %w", source.source.BaseURL, err)
	}
	if !result.Success {
		return "", time.Time{}, result.Error == "ApiErrorUnauthorized", fmt.Errorf("federation source %q refresh rejected: %s", source.source.BaseURL, strings.TrimSpace(result.Error))
	}

	expiresAt := time.Time{}
	if result.Data.Expire != "" {
		if parsed, err := time.Parse(time.RFC3339, result.Data.Expire); err == nil {
			expiresAt = parsed
		}
	}
	return result.Data.Token, expiresAt, false, nil
}

func (m *FederationManager) requestServerList(ctx context.Context, source *federationSourceRuntime) ([]*model.Server, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source.endpoint("api/v1/server"), nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Authorization", "Bearer "+source.source.Token)

	resp, err := source.client.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("federation source %q server list failed: %w", source.source.BaseURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, fmt.Errorf("federation source %q server list read failed: %w", source.source.BaseURL, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("federation source %q server list returned status %d", source.source.BaseURL, resp.StatusCode)
	}

	var result model.CommonResponse[[]model.Server]
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, false, fmt.Errorf("federation source %q server list decode failed: %w", source.source.BaseURL, err)
	}
	if !result.Success {
		return nil, result.Error == "ApiErrorUnauthorized", fmt.Errorf("federation source %q server list rejected: %s", source.source.BaseURL, strings.TrimSpace(result.Error))
	}

	servers := make([]*model.Server, 0, len(result.Data))
	for i := range result.Data {
		server := result.Data[i]
		ensureServerRuntimeFields(&server)
		servers = append(servers, &server)
	}

	return servers, false, nil
}

func (m *FederationManager) persistSourceSuccess(sourceID uint64, token string, expiresAt time.Time, lastSyncAt time.Time) error {
	updates := map[string]any{
		"token":            token,
		"token_expires_at": expiresAt,
		"reauth_required":  false,
		"last_error":       "",
		"last_sync_at":     lastSyncAt,
	}
	if err := DB.Model(&model.FederationSource{}).Where("id = ?", sourceID).Updates(updates).Error; err != nil {
		return err
	}
	return nil
}

func (m *FederationManager) persistSourceToken(sourceID uint64, token string, expiresAt time.Time) error {
	updates := map[string]any{
		"token":            token,
		"token_expires_at": expiresAt,
		"reauth_required":  false,
	}
	return DB.Model(&model.FederationSource{}).Where("id = ?", sourceID).Updates(updates).Error
}

func (m *FederationManager) recordSourceError(sourceID uint64, lastError string) error {
	if err := DB.Model(&model.FederationSource{}).Where("id = ?", sourceID).Updates(map[string]any{
		"last_error": strings.TrimSpace(lastError),
	}).Error; err != nil {
		return err
	}

	m.mu.Lock()
	if runtime, ok := m.sources[sourceID]; ok {
		runtime.source.LastError = strings.TrimSpace(lastError)
	}
	m.mu.Unlock()

	return fmt.Errorf("%s", strings.TrimSpace(lastError))
}

func (m *FederationManager) markSourceReauth(sourceID uint64, lastError string) error {
	updates := map[string]any{
		"token":            "",
		"token_expires_at": time.Time{},
		"reauth_required":  true,
		"last_error":       strings.TrimSpace(lastError),
	}
	if err := DB.Model(&model.FederationSource{}).Where("id = ?", sourceID).Updates(updates).Error; err != nil {
		return err
	}

	m.mu.Lock()
	if runtime, ok := m.sources[sourceID]; ok {
		runtime.source.Token = ""
		runtime.source.TokenExpiresAt = time.Time{}
		runtime.source.ReauthRequired = true
		runtime.source.LastError = strings.TrimSpace(lastError)
		runtime.servers = make(map[uint64]*model.Server)
		runtime.remoteIDs = make(map[uint64]uint64)
		runtime.ordered = nil
	}
	m.rebuildIndexLocked()
	m.mu.Unlock()

	return fmt.Errorf("%s", strings.TrimSpace(lastError))
}

func (m *FederationManager) clearSource(sourceID uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if runtime, ok := m.sources[sourceID]; ok {
		runtime.servers = make(map[uint64]*model.Server)
		runtime.remoteIDs = make(map[uint64]uint64)
		runtime.ordered = nil
	}
	m.rebuildIndexLocked()
}

func (m *FederationManager) GetServer(id uint64) (*model.Server, bool) {
	if m == nil {
		return nil, false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	server, ok := m.servers[id]
	return server, ok
}

func (m *FederationManager) GetVisibleServer(id uint64, viewer *model.User) (*model.Server, bool) {
	if m == nil {
		return nil, false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	ref, ok := m.index[id]
	if !ok {
		return nil, false
	}

	runtime, ok := m.sources[ref.SourceID]
	if !ok || !m.sourceActiveLocked(runtime) || !m.canViewerSeeSourceLocked(runtime.source, viewer) {
		return nil, false
	}

	server, ok := runtime.servers[id]
	if !ok {
		return nil, false
	}

	return server, true
}

func (m *FederationManager) Lookup(id uint64) (FederatedServerRef, bool) {
	if m == nil {
		return FederatedServerRef{}, false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	ref, ok := m.index[id]
	return ref, ok
}

func (m *FederationManager) GetActiveServers(viewer *model.User) []*model.Server {
	if m == nil {
		return nil
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	servers := make([]*model.Server, 0)
	for _, source := range m.sources {
		if !m.sourceActiveLocked(source) || !m.canViewerSeeSourceLocked(source.source, viewer) {
			continue
		}

		for _, server := range source.ordered {
			servers = append(servers, server)
		}
	}

	sortServersForRealtime(servers)
	return servers
}

func (m *FederationManager) sourceActiveLocked(source *federationSourceRuntime) bool {
	if !source.source.Enabled || source.source.ReauthRequired || source.source.Token == "" {
		return false
	}
	if source.source.LastSyncAt.IsZero() {
		return false
	}
	return time.Since(source.source.LastSyncAt) <= m.conf.StaleAfter
}

func (m *FederationManager) canViewerSeeSourceLocked(source model.FederationSource, viewer *model.User) bool {
	if viewer == nil {
		return source.IsPublic
	}
	return source.IsPublic || source.OwnerUserID == viewer.ID
}

func (m *FederationManager) rebuildIndexLocked() {
	index := make(map[uint64]FederatedServerRef)
	servers := make(map[uint64]*model.Server)

	for _, source := range m.sources {
		for syntheticID, server := range source.servers {
			ref := FederatedServerRef{
				SourceID:    source.source.ID,
				OwnerUserID: source.source.OwnerUserID,
				RemoteID:    source.remoteIDs[syntheticID],
			}
			if existing, ok := index[syntheticID]; ok && existing != ref {
				log.Printf("NEZHA>> Federation synthetic ID collision across sources: %d/%d conflicts with %d/%d", ref.SourceID, ref.RemoteID, existing.SourceID, existing.RemoteID)
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
	return strings.TrimRight(s.source.BaseURL, "/") + "/" + strings.TrimLeft(path, "/")
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

func synthesizeFederatedID(sourceID, remoteID uint64) uint64 {
	hasher := fnv.New64a()
	hasher.Write([]byte(strconv.FormatUint(sourceID, 10)))
	hasher.Write([]byte{0})
	hasher.Write([]byte(strconv.FormatUint(remoteID, 10)))
	return federationSyntheticIDMask | (hasher.Sum64() &^ federationSyntheticIDMask)
}

func IsFederatedServerID(id uint64) bool {
	return id&federationSyntheticIDMask != 0
}

func GetRealtimeServerList(viewer *model.User) []*model.Server {
	var servers []*model.Server
	if viewer != nil {
		servers = ServerShared.GetSortedList()
	} else {
		servers = ServerShared.GetSortedListForGuest()
	}

	if FederationShared == nil {
		return servers
	}

	merged := append(servers, FederationShared.GetActiveServers(viewer)...)
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
