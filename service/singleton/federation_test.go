package singleton

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/nezhahq/nezha/model"
)

func TestFederationManagerVisibilityAndReload(t *testing.T) {
	db, cleanup := setupFederationDB(t)
	defer cleanup()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/public/api/v1/server":
			writeFederationJSON(t, w, model.CommonResponse[[]model.Server]{
				Success: true,
				Data: []model.Server{
					{
						Common:       model.Common{ID: 7},
						Name:         "public-visible",
						DisplayIndex: 3,
						Host:         &model.Host{Platform: "linux"},
						State:        &model.HostState{CPU: 12},
						GeoIP:        &model.GeoIP{CountryCode: "US"},
					},
					{
						Common:       model.Common{ID: 8},
						Name:         "public-hidden",
						DisplayIndex: 2,
						HideForGuest: true,
						Host:         &model.Host{Platform: "linux"},
						State:        &model.HostState{CPU: 24},
						GeoIP:        &model.GeoIP{CountryCode: "JP"},
					},
				},
			})
		case "/private/api/v1/server":
			writeFederationJSON(t, w, model.CommonResponse[[]model.Server]{
				Success: true,
				Data: []model.Server{{
					Common:       model.Common{ID: 9},
					Name:         "private-only",
					DisplayIndex: 4,
					Host:         &model.Host{Platform: "linux"},
					State:        &model.HostState{CPU: 36},
					GeoIP:        &model.GeoIP{CountryCode: "DE"},
				}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	publicSource := model.FederationSource{
		OwnerUserID:    1,
		BaseURL:        upstream.URL + "/public",
		SiteName:       "Public Child",
		Provider:       "GitHub",
		RemoteUserID:   "viewer-public",
		RemoteUsername: "alice",
		Token:          "token-public",
		TokenExpiresAt: time.Now().Add(time.Hour),
		Enabled:        true,
		IsPublic:       true,
	}
	privateSource := model.FederationSource{
		OwnerUserID:    1,
		BaseURL:        upstream.URL + "/private",
		SiteName:       "Private Child",
		Provider:       "GitHub",
		RemoteUserID:   "viewer-private",
		RemoteUsername: "alice",
		Token:          "token-private",
		TokenExpiresAt: time.Now().Add(time.Hour),
		Enabled:        true,
		IsPublic:       false,
	}
	if err := db.Create(&publicSource).Error; err != nil {
		t.Fatalf("create public federation source failed: %v", err)
	}
	if err := db.Create(&privateSource).Error; err != nil {
		t.Fatalf("create private federation source failed: %v", err)
	}

	manager, err := NewFederationManager(&model.FederationConfig{
		RequestTimeout: time.Second,
		StaleAfter:     50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("create federation manager failed: %v", err)
	}
	if err := manager.Sync(context.Background()); err != nil {
		t.Fatalf("sync federation manager failed: %v", err)
	}

	owner := &model.User{Common: model.Common{ID: 1}}
	other := &model.User{Common: model.Common{ID: 2}}

	if names := serverNames(manager.GetActiveServers(nil)); !equalStringSlices(names, []string{"public-visible", "public-hidden"}) {
		t.Fatalf("unexpected guest-visible servers: %#v", names)
	}
	if names := serverNames(manager.GetActiveServers(owner)); !equalStringSlices(names, []string{"private-only", "public-visible", "public-hidden"}) {
		t.Fatalf("unexpected owner-visible servers: %#v", names)
	}
	if names := serverNames(manager.GetActiveServers(other)); !equalStringSlices(names, []string{"public-visible", "public-hidden"}) {
		t.Fatalf("unexpected other-user-visible servers: %#v", names)
	}

	var privateID uint64
	for _, server := range manager.GetActiveServers(owner) {
		if server.Name == "private-only" {
			privateID = server.ID
			break
		}
	}
	if privateID == 0 {
		t.Fatal("expected synthetic ID for private server")
	}
	if _, ok := manager.GetVisibleServer(privateID, owner); !ok {
		t.Fatal("expected owner to resolve private server")
	}
	if _, ok := manager.GetVisibleServer(privateID, other); ok {
		t.Fatal("did not expect other user to resolve private server")
	}

	if err := db.Model(&model.FederationSource{}).Where("id = ?", publicSource.ID).Update("enabled", false).Error; err != nil {
		t.Fatalf("disable public source failed: %v", err)
	}
	if err := manager.Reload(); err != nil {
		t.Fatalf("reload federation manager failed: %v", err)
	}
	if names := serverNames(manager.GetActiveServers(nil)); len(names) != 0 {
		t.Fatalf("expected no guest-visible servers after disabling public source, got %#v", names)
	}
	if names := serverNames(manager.GetActiveServers(owner)); !equalStringSlices(names, []string{"private-only"}) {
		t.Fatalf("unexpected owner-visible servers after reload: %#v", names)
	}

	manager.mu.Lock()
	if runtime, ok := manager.sources[privateSource.ID]; ok {
		runtime.source.LastSyncAt = time.Now().Add(-time.Second)
	}
	manager.mu.Unlock()
	if names := serverNames(manager.GetActiveServers(owner)); len(names) != 0 {
		t.Fatalf("expected stale private source to disappear, got %#v", names)
	}
}

func TestFederationManagerRefreshUnauthorizedMarksReauth(t *testing.T) {
	db, cleanup := setupFederationDB(t)
	defer cleanup()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/reauth/api/v1/refresh-token":
			writeFederationJSON(t, w, model.CommonResponse[model.LoginResponse]{
				Success: false,
				Error:   "ApiErrorUnauthorized",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	source := model.FederationSource{
		OwnerUserID:    1,
		BaseURL:        upstream.URL + "/reauth",
		SiteName:       "Expiring Child",
		Provider:       "GitHub",
		RemoteUserID:   "viewer-expiring",
		RemoteUsername: "alice",
		Token:          "token-expiring",
		TokenExpiresAt: time.Now().Add(5 * time.Second),
		Enabled:        true,
		IsPublic:       true,
	}
	if err := db.Create(&source).Error; err != nil {
		t.Fatalf("create federation source failed: %v", err)
	}

	manager, err := NewFederationManager(&model.FederationConfig{
		RequestTimeout: time.Second,
		StaleAfter:     time.Second,
	})
	if err != nil {
		t.Fatalf("create federation manager failed: %v", err)
	}

	if err := manager.Sync(context.Background()); err == nil {
		t.Fatal("expected sync to fail when refresh is unauthorized")
	}

	var refreshed model.FederationSource
	if err := db.First(&refreshed, source.ID).Error; err != nil {
		t.Fatalf("reload federation source failed: %v", err)
	}
	if !refreshed.ReauthRequired {
		t.Fatal("expected reauth_required to be set after unauthorized refresh")
	}
	if refreshed.Token != "" {
		t.Fatalf("expected token to be cleared, got %q", refreshed.Token)
	}
	if len(manager.GetActiveServers(nil)) != 0 {
		t.Fatal("expected reauth source to be hidden from realtime list")
	}
}

func setupFederationDB(t *testing.T) (*gorm.DB, func()) {
	t.Helper()

	tempDB, err := os.CreateTemp(t.TempDir(), "nezha-federation-*.db")
	if err != nil {
		t.Fatalf("create temp db failed: %v", err)
	}
	tempDB.Close()

	db, err := gorm.Open(sqlite.Open(tempDB.Name()), &gorm.Config{})
	if err != nil {
		t.Fatalf("open temp db failed: %v", err)
	}
	if err := db.AutoMigrate(&model.FederationSource{}); err != nil {
		t.Fatalf("migrate federation source failed: %v", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("unwrap sql db failed: %v", err)
	}

	prevDB := DB
	prevCron := CronShared
	DB = db
	CronShared = nil

	return db, func() {
		DB = prevDB
		CronShared = prevCron
		_ = sqlDB.Close()
	}
}

func serverNames(servers []*model.Server) []string {
	names := make([]string, 0, len(servers))
	for _, server := range servers {
		names = append(names, server.Name)
	}
	return names
}

func equalStringSlices(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func writeFederationJSON(t *testing.T, w http.ResponseWriter, payload any) {
	t.Helper()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Fatalf("encode response failed: %v", err)
	}
}
