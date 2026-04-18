package controller

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/goccy/go-json"
	"github.com/patrickmn/go-cache"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/nezhahq/nezha/model"
	pkgI18n "github.com/nezhahq/nezha/pkg/i18n"
	"github.com/nezhahq/nezha/service/singleton"
)

func TestFederatedVisibilityAndFallbacks(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, cleanup := setupControllerDB(t, &model.Server{}, &model.FederationSource{})
	defer cleanup()

	if err := db.Create(&model.Server{
		Common:       model.Common{ID: 1},
		Name:         "local-node",
		DisplayIndex: 1,
	}).Error; err != nil {
		t.Fatalf("create local server failed: %v", err)
	}

	singleton.ServerShared = singleton.NewServerClass()
	localServer, ok := singleton.ServerShared.Get(1)
	if !ok {
		t.Fatal("expected local server in shared cache")
	}
	localServer.Host = &model.Host{Platform: "linux"}
	localServer.State = &model.HostState{CPU: 11}
	localServer.GeoIP = &model.GeoIP{CountryCode: "CN"}
	localServer.LastActive = time.Now()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/public/api/v1/server":
			writeControllerJSON(t, w, model.CommonResponse[[]model.Server]{
				Success: true,
				Data: []model.Server{
					{
						Common:       model.Common{ID: 9},
						Name:         "public-visible",
						DisplayIndex: 3,
						Host:         &model.Host{Platform: "linux"},
						State:        &model.HostState{CPU: 22},
						GeoIP:        &model.GeoIP{CountryCode: "US"},
					},
					{
						Common:       model.Common{ID: 10},
						Name:         "public-hidden",
						DisplayIndex: 2,
						HideForGuest: true,
						Host:         &model.Host{Platform: "linux"},
						State:        &model.HostState{CPU: 33},
						GeoIP:        &model.GeoIP{CountryCode: "JP"},
					},
				},
			})
		case "/private/api/v1/server":
			writeControllerJSON(t, w, model.CommonResponse[[]model.Server]{
				Success: true,
				Data: []model.Server{{
					Common:       model.Common{ID: 11},
					Name:         "private-only",
					DisplayIndex: 4,
					Host:         &model.Host{Platform: "linux"},
					State:        &model.HostState{CPU: 44},
					GeoIP:        &model.GeoIP{CountryCode: "DE"},
				}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	publicSource := model.FederationSource{
		OwnerUserID:    42,
		BaseURL:        upstream.URL + "/public",
		SiteName:       "Public Child",
		Provider:       "GitHub",
		RemoteUserID:   "remote-public",
		RemoteUsername: "owner",
		Token:          "token-public",
		TokenExpiresAt: time.Now().Add(time.Hour),
		Enabled:        true,
		IsPublic:       true,
	}
	privateSource := model.FederationSource{
		OwnerUserID:    42,
		BaseURL:        upstream.URL + "/private",
		SiteName:       "Private Child",
		Provider:       "GitHub",
		RemoteUserID:   "remote-private",
		RemoteUsername: "owner",
		Token:          "token-private",
		TokenExpiresAt: time.Now().Add(time.Hour),
		Enabled:        true,
		IsPublic:       false,
	}
	if err := db.Create(&publicSource).Error; err != nil {
		t.Fatalf("create public source failed: %v", err)
	}
	if err := db.Create(&privateSource).Error; err != nil {
		t.Fatalf("create private source failed: %v", err)
	}

	manager, err := singleton.NewFederationManager(&model.FederationConfig{
		RequestTimeout: time.Second,
		StaleAfter:     time.Second,
	})
	if err != nil {
		t.Fatalf("create federation manager failed: %v", err)
	}
	if err := manager.Sync(context.Background()); err != nil {
		t.Fatalf("sync federation manager failed: %v", err)
	}
	singleton.FederationShared = manager

	owner := &model.User{Common: model.Common{ID: 42}}
	other := &model.User{Common: model.Common{ID: 100}}

	t.Run("realtime stream respects visibility", func(t *testing.T) {
		guestPayload, err := getServerStat(true, nil)
		if err != nil {
			t.Fatalf("getServerStat guest failed: %v", err)
		}
		ownerPayload, err := getServerStat(true, owner)
		if err != nil {
			t.Fatalf("getServerStat owner failed: %v", err)
		}
		otherPayload, err := getServerStat(true, other)
		if err != nil {
			t.Fatalf("getServerStat other user failed: %v", err)
		}

		var guestStream, ownerStream, otherStream model.StreamServerData
		if err := json.Unmarshal(guestPayload, &guestStream); err != nil {
			t.Fatalf("decode guest stream failed: %v", err)
		}
		if err := json.Unmarshal(ownerPayload, &ownerStream); err != nil {
			t.Fatalf("decode owner stream failed: %v", err)
		}
		if err := json.Unmarshal(otherPayload, &otherStream); err != nil {
			t.Fatalf("decode other-user stream failed: %v", err)
		}

		if names := streamNames(guestStream.Servers); !equalControllerSlices(names, []string{"public-visible", "public-hidden", "local-node"}) {
			t.Fatalf("unexpected guest stream order: %#v", names)
		}
		if names := streamNames(ownerStream.Servers); !equalControllerSlices(names, []string{"private-only", "public-visible", "public-hidden", "local-node"}) {
			t.Fatalf("unexpected owner stream order: %#v", names)
		}
		if names := streamNames(otherStream.Servers); !equalControllerSlices(names, []string{"public-visible", "public-hidden", "local-node"}) {
			t.Fatalf("unexpected other-user stream order: %#v", names)
		}
	})

	var privateID uint64
	for _, server := range manager.GetActiveServers(owner) {
		if server.Name == "private-only" {
			privateID = server.ID
			break
		}
	}
	if privateID == 0 {
		t.Fatal("expected synthetic private server ID")
	}

	t.Run("private server fallback is owner-only", func(t *testing.T) {
		ownerCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
		ownerCtx.Request = httptest.NewRequest(http.MethodGet, "/api/v1/server/"+strconv.FormatUint(privateID, 10)+"/metrics?metric=cpu", nil)
		ownerCtx.Params = gin.Params{{Key: "id", Value: strconv.FormatUint(privateID, 10)}}
		ownerCtx.Set(model.CtxKeyAuthorizedUser, owner)

		metrics, err := getServerMetrics(ownerCtx)
		if err != nil {
			t.Fatalf("getServerMetrics owner failed: %v", err)
		}
		if metrics.ServerName != "private-only" {
			t.Fatalf("unexpected owner-visible server name: %s", metrics.ServerName)
		}
		if len(metrics.DataPoints) != 0 {
			t.Fatalf("expected empty remote metrics, got %d points", len(metrics.DataPoints))
		}

		otherCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
		otherCtx.Request = httptest.NewRequest(http.MethodGet, "/api/v1/server/"+strconv.FormatUint(privateID, 10)+"/service", nil)
		otherCtx.Params = gin.Params{{Key: "id", Value: strconv.FormatUint(privateID, 10)}}
		otherCtx.Set(model.CtxKeyAuthorizedUser, other)

		if _, err := listServerServices(otherCtx); err == nil {
			t.Fatal("expected other user to be blocked from private source")
		}
	})
}

func TestOauth2CallbackCreatesFederationGrant(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, cleanup := setupControllerDB(t, &model.User{}, &model.Oauth2Bind{})
	defer cleanup()

	user := model.User{Username: "owner"}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user failed: %v", err)
	}
	if err := db.Create(&model.Oauth2Bind{
		UserID:   user.ID,
		Provider: "github",
		OpenID:   "180728341",
	}).Error; err != nil {
		t.Fatalf("create oauth2 bind failed: %v", err)
	}

	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"provider-token","token_type":"bearer"}`))
		case "/user":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"180728341"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()

	singleton.Conf = &singleton.ConfigClass{
		Config: &model.Config{
			Oauth2: map[string]*model.Oauth2Config{
				"GitHub": {
					ClientID:     "cid",
					ClientSecret: "secret",
					Endpoint: model.Oauth2Endpoint{
						AuthURL:  provider.URL + "/auth",
						TokenURL: provider.URL + "/token",
					},
					UserInfoURL: provider.URL + "/user",
					UserIDPath:  "id",
				},
			},
		},
		Oauth2Providers: []string{"GitHub"},
	}

	stateKey := "state-key"
	state := "oauth-state"
	singleton.Cache.Set(model.CacheKeyOauth2State+stateKey, &model.Oauth2State{
		Action:                model.RTypeFederationGrant,
		Provider:              "GitHub",
		State:                 state,
		RedirectURL:           "https://child.example.com/api/v1/oauth2/callback",
		FederationCallbackURL: "https://main.example.com/api/v1/federation/callback",
		FederationState:       "pending-state",
	}, cache.DefaultExpiration)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/oauth2/callback?state="+state+"&code=oauth-code", nil)
	req.AddCookie(&http.Cookie{Name: "nz-o2s", Value: stateKey})
	ctx.Request = req
	ctx.Set(model.CtxKeyRealIPStr, "127.0.0.1")

	_, err := oauth2callback(nil)(ctx)
	if !errors.Is(err, errNoop) {
		t.Fatalf("expected redirect sentinel error, got %v", err)
	}

	location := recorder.Header().Get("Location")
	if location == "" {
		t.Fatal("expected callback redirect location")
	}

	redirectURL, err := neturl.Parse(location)
	if err != nil {
		t.Fatalf("parse redirect location failed: %v", err)
	}
	if got := redirectURL.Query().Get("state"); got != "pending-state" {
		t.Fatalf("unexpected federation state %q", got)
	}
	grantCode := redirectURL.Query().Get("code")
	if grantCode == "" {
		t.Fatal("expected federation grant code in redirect")
	}

	rawGrant, ok := singleton.Cache.Get(model.CacheKeyFederationGrant + grantCode)
	if !ok {
		t.Fatal("expected federation grant to be cached")
	}
	grant, ok := rawGrant.(*model.FederationGrant)
	if !ok {
		t.Fatalf("unexpected federation grant type %T", rawGrant)
	}
	if grant.UserID != user.ID || grant.Provider != "github" || grant.RemoteUserID != "180728341" {
		t.Fatalf("unexpected federation grant: %+v", grant)
	}
}

func setupControllerDB(t *testing.T, models ...any) (*gorm.DB, func()) {
	t.Helper()

	tempDB, err := os.CreateTemp(t.TempDir(), "nezha-controller-*.db")
	if err != nil {
		t.Fatalf("create temp db failed: %v", err)
	}
	tempDB.Close()

	db, err := gorm.Open(sqlite.Open(tempDB.Name()), &gorm.Config{})
	if err != nil {
		t.Fatalf("open test db failed: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("unwrap test db failed: %v", err)
	}
	if len(models) > 0 {
		if err := db.AutoMigrate(models...); err != nil {
			t.Fatalf("migrate test db failed: %v", err)
		}
	}

	prevDB := singleton.DB
	prevServerShared := singleton.ServerShared
	prevFederationShared := singleton.FederationShared
	prevLocalizer := singleton.Localizer
	prevCache := singleton.Cache
	prevConf := singleton.Conf
	prevCron := singleton.CronShared

	singleton.DB = db
	singleton.ServerShared = nil
	singleton.FederationShared = nil
	singleton.Localizer = pkgI18n.NewLocalizer("en_US", "nezha", "translations", pkgI18n.Translations)
	singleton.Cache = cache.New(5*time.Minute, 10*time.Minute)
	singleton.CronShared = nil
	if singleton.Conf == nil {
		singleton.Conf = &singleton.ConfigClass{Config: &model.Config{}}
	}

	return db, func() {
		singleton.DB = prevDB
		singleton.ServerShared = prevServerShared
		singleton.FederationShared = prevFederationShared
		singleton.Localizer = prevLocalizer
		singleton.Cache = prevCache
		singleton.Conf = prevConf
		singleton.CronShared = prevCron
		_ = sqlDB.Close()
	}
}

func streamNames(servers []model.StreamServer) []string {
	names := make([]string, 0, len(servers))
	for _, server := range servers {
		names = append(names, server.Name)
	}
	return names
}

func equalControllerSlices(got, want []string) bool {
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

func writeControllerJSON(t *testing.T, w http.ResponseWriter, payload any) {
	t.Helper()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Fatalf("encode response failed: %v", err)
	}
}
