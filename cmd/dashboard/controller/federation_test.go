package controller

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/goccy/go-json"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/service/singleton"
)

func TestFederatedServerFallbacksAndRealtimeStream(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tempDB, err := os.CreateTemp(t.TempDir(), "nezha-controller-test-*.db")
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
	if err := db.AutoMigrate(&model.Server{}); err != nil {
		t.Fatalf("migrate test db failed: %v", err)
	}
	if err := db.Create(&model.Server{
		Common:       model.Common{ID: 1},
		Name:         "local-node",
		DisplayIndex: 1,
	}).Error; err != nil {
		t.Fatalf("create local server failed: %v", err)
	}

	prevDB := singleton.DB
	prevServerShared := singleton.ServerShared
	prevFederationShared := singleton.FederationShared
	t.Cleanup(func() {
		singleton.DB = prevDB
		singleton.ServerShared = prevServerShared
		singleton.FederationShared = prevFederationShared
		sqlDB.Close()
	})

	singleton.DB = db
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
		case "/api/v1/login":
			writeControllerJSON(t, w, model.CommonResponse[model.LoginResponse]{
				Success: true,
				Data: model.LoginResponse{
					Token:  "token-1",
					Expire: time.Now().Add(time.Hour).Format(time.RFC3339),
				},
			})
		case "/api/v1/server":
			writeControllerJSON(t, w, model.CommonResponse[[]model.Server]{
				Success: true,
				Data: []model.Server{{
					Common:       model.Common{ID: 9},
					Name:         "remote-node",
					DisplayIndex: 3,
					Host:         &model.Host{Platform: "linux"},
					State:        &model.HostState{CPU: 22},
					GeoIP:        &model.GeoIP{CountryCode: "US"},
				}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	manager, err := singleton.NewFederationManager(&model.FederationConfig{
		RequestTimeout: time.Second,
		StaleAfter:     time.Second,
		Sources: []model.FederationSource{{
			Name:     "alice",
			BaseURL:  upstream.URL,
			Username: "exporter",
			Password: "secret",
			Enabled:  true,
		}},
	})
	if err != nil {
		t.Fatalf("create federation manager failed: %v", err)
	}
	if err := manager.Sync(t.Context()); err != nil {
		t.Fatalf("sync federation manager failed: %v", err)
	}
	singleton.FederationShared = manager

	remoteServers := manager.GetActiveServers(true)
	if len(remoteServers) != 1 {
		t.Fatalf("expected 1 remote server, got %d", len(remoteServers))
	}
	remoteID := remoteServers[0].ID

	t.Run("server metrics fallback", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodGet, "/api/v1/server/"+strconv.FormatUint(remoteID, 10)+"/metrics?metric=cpu", nil)
		ctx.Params = gin.Params{{Key: "id", Value: strconv.FormatUint(remoteID, 10)}}

		resp, err := getServerMetrics(ctx)
		if err != nil {
			t.Fatalf("getServerMetrics failed: %v", err)
		}
		if resp.ServerName != "remote-node" {
			t.Fatalf("unexpected remote server name: %s", resp.ServerName)
		}
		if len(resp.DataPoints) != 0 {
			t.Fatalf("expected empty remote metrics, got %d points", len(resp.DataPoints))
		}
	})

	t.Run("server services fallback", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodGet, "/api/v1/server/"+strconv.FormatUint(remoteID, 10)+"/service", nil)
		ctx.Params = gin.Params{{Key: "id", Value: strconv.FormatUint(remoteID, 10)}}

		resp, err := listServerServices(ctx)
		if err != nil {
			t.Fatalf("listServerServices failed: %v", err)
		}
		if len(resp) != 0 {
			t.Fatalf("expected empty remote service list, got %d items", len(resp))
		}
	})

	t.Run("realtime stream merges local and remote", func(t *testing.T) {
		payload, err := getServerStat(true, true)
		if err != nil {
			t.Fatalf("getServerStat failed: %v", err)
		}

		var stream model.StreamServerData
		if err := json.Unmarshal(payload, &stream); err != nil {
			t.Fatalf("decode websocket payload failed: %v", err)
		}
		if len(stream.Servers) != 2 {
			t.Fatalf("expected 2 merged servers, got %d", len(stream.Servers))
		}
		if stream.Servers[0].Name != "remote-node" || stream.Servers[1].Name != "local-node" {
			t.Fatalf("unexpected merged order: %+v", stream.Servers)
		}
	})
}

func writeControllerJSON(t *testing.T, w http.ResponseWriter, payload any) {
	t.Helper()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Fatalf("encode response failed: %v", err)
	}
}
