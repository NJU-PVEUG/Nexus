package singleton

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goccy/go-json"

	"github.com/nezhahq/nezha/model"
)

func TestFederationManagerSyncAndGuestFiltering(t *testing.T) {
	token := "token-1"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/login":
			writeJSON(t, w, model.CommonResponse[model.LoginResponse]{
				Success: true,
				Data: model.LoginResponse{
					Token:  token,
					Expire: time.Now().Add(time.Hour).Format(time.RFC3339),
				},
			})
		case "/api/v1/server":
			if r.Header.Get("Authorization") != "Bearer "+token {
				writeJSON(t, w, model.CommonResponse[any]{Success: false, Error: "ApiErrorUnauthorized"})
				return
			}
			writeJSON(t, w, model.CommonResponse[[]model.Server]{
				Success: true,
				Data: []model.Server{
					{
						Common:       model.Common{ID: 7},
						Name:         "guest-visible",
						DisplayIndex: 3,
						Host:         &model.Host{Platform: "linux"},
						State:        &model.HostState{CPU: 12},
						GeoIP:        &model.GeoIP{CountryCode: "US"},
					},
					{
						Common:       model.Common{ID: 8},
						Name:         "guest-hidden",
						DisplayIndex: 1,
						HideForGuest: true,
						Host:         &model.Host{Platform: "linux"},
						State:        &model.HostState{CPU: 24},
						GeoIP:        &model.GeoIP{CountryCode: "JP"},
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	conf := model.FederationConfig{
		RequestTimeout: 2 * time.Second,
		StaleAfter:     40 * time.Millisecond,
		Sources: []model.FederationSource{{
			Name:     "alice",
			BaseURL:  upstream.URL,
			Username: "exporter",
			Password: "secret",
			Enabled:  true,
		}},
	}

	manager, err := NewFederationManager(&conf)
	if err != nil {
		t.Fatalf("create manager failed: %v", err)
	}
	if err := manager.Sync(context.Background()); err != nil {
		t.Fatalf("sync manager failed: %v", err)
	}

	authorized := manager.GetActiveServers(true)
	if len(authorized) != 2 {
		t.Fatalf("expected 2 authorized servers, got %d", len(authorized))
	}
	if !IsFederatedServerID(authorized[0].ID) || !IsFederatedServerID(authorized[1].ID) {
		t.Fatal("expected federated synthetic IDs")
	}
	if _, ok := manager.Lookup(authorized[0].ID); !ok {
		t.Fatal("expected lookup entry for federated server")
	}

	guest := manager.GetActiveServers(false)
	if len(guest) != 1 {
		t.Fatalf("expected 1 guest-visible server, got %d", len(guest))
	}
	if guest[0].Name != "guest-visible" {
		t.Fatalf("unexpected guest-visible server: %s", guest[0].Name)
	}

	manager.mu.Lock()
	manager.sources[0].lastSync = time.Now().Add(-time.Second)
	manager.mu.Unlock()
	if stale := manager.GetActiveServers(true); len(stale) != 0 {
		t.Fatalf("expected stale source to be hidden, got %d servers", len(stale))
	}
}

func TestFederationManagerReauthOnUnauthorized(t *testing.T) {
	var loginCount atomic.Int32

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/login":
			n := loginCount.Add(1)
			writeJSON(t, w, model.CommonResponse[model.LoginResponse]{
				Success: true,
				Data: model.LoginResponse{
					Token:  fmt.Sprintf("token-%d", n),
					Expire: time.Now().Add(time.Hour).Format(time.RFC3339),
				},
			})
		case "/api/v1/server":
			if r.Header.Get("Authorization") != "Bearer token-2" {
				writeJSON(t, w, model.CommonResponse[any]{Success: false, Error: "ApiErrorUnauthorized"})
				return
			}
			writeJSON(t, w, model.CommonResponse[[]model.Server]{
				Success: true,
				Data: []model.Server{{
					Common: model.Common{ID: 9},
					Name:   "reauth-ok",
					Host:   &model.Host{},
					State:  &model.HostState{},
					GeoIP:  &model.GeoIP{},
				}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	conf := model.FederationConfig{
		RequestTimeout: time.Second,
		StaleAfter:     time.Second,
		Sources: []model.FederationSource{{
			Name:     "reauth",
			BaseURL:  upstream.URL,
			Username: "exporter",
			Password: "secret",
			Enabled:  true,
		}},
	}

	manager, err := NewFederationManager(&conf)
	if err != nil {
		t.Fatalf("create manager failed: %v", err)
	}
	if err := manager.Sync(context.Background()); err != nil {
		t.Fatalf("expected reauth sync to succeed: %v", err)
	}
	if loginCount.Load() != 2 {
		t.Fatalf("expected 2 logins, got %d", loginCount.Load())
	}
	if len(manager.GetActiveServers(true)) != 1 {
		t.Fatal("expected synced server after reauth")
	}
}

func TestFederationManagerErrorCases(t *testing.T) {
	t.Run("bad JSON", func(t *testing.T) {
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/v1/login":
				writeJSON(t, w, model.CommonResponse[model.LoginResponse]{
					Success: true,
					Data: model.LoginResponse{
						Token:  "token-1",
						Expire: time.Now().Add(time.Hour).Format(time.RFC3339),
					},
				})
			case "/api/v1/server":
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("{"))
			default:
				http.NotFound(w, r)
			}
		}))
		defer upstream.Close()

		manager, err := NewFederationManager(&model.FederationConfig{
			RequestTimeout: time.Second,
			StaleAfter:     time.Second,
			Sources: []model.FederationSource{{
				Name:     "bad-json",
				BaseURL:  upstream.URL,
				Username: "exporter",
				Password: "secret",
				Enabled:  true,
			}},
		})
		if err != nil {
			t.Fatalf("create manager failed: %v", err)
		}
		if err := manager.Sync(context.Background()); err == nil {
			t.Fatal("expected bad JSON sync to fail")
		}
	})

	t.Run("timeout", func(t *testing.T) {
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(150 * time.Millisecond)
			writeJSON(t, w, model.CommonResponse[model.LoginResponse]{
				Success: true,
				Data: model.LoginResponse{
					Token:  "token-1",
					Expire: time.Now().Add(time.Hour).Format(time.RFC3339),
				},
			})
		}))
		defer upstream.Close()

		manager, err := NewFederationManager(&model.FederationConfig{
			RequestTimeout: 50 * time.Millisecond,
			StaleAfter:     time.Second,
			Sources: []model.FederationSource{{
				Name:     "timeout",
				BaseURL:  upstream.URL,
				Username: "exporter",
				Password: "secret",
				Enabled:  true,
			}},
		})
		if err != nil {
			t.Fatalf("create manager failed: %v", err)
		}
		if err := manager.Sync(context.Background()); err == nil {
			t.Fatal("expected timeout sync to fail")
		}
	})

	t.Run("self signed tls", func(t *testing.T) {
		upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/v1/login":
				writeJSON(t, w, model.CommonResponse[model.LoginResponse]{
					Success: true,
					Data: model.LoginResponse{
						Token:  "token-1",
						Expire: time.Now().Add(time.Hour).Format(time.RFC3339),
					},
				})
			case "/api/v1/server":
				writeJSON(t, w, model.CommonResponse[[]model.Server]{
					Success: true,
					Data: []model.Server{{
						Common: model.Common{ID: 10},
						Name:   "tls-ok",
						Host:   &model.Host{},
						State:  &model.HostState{},
						GeoIP:  &model.GeoIP{},
					}},
				})
			default:
				http.NotFound(w, r)
			}
		}))
		defer upstream.Close()

		manager, err := NewFederationManager(&model.FederationConfig{
			RequestTimeout: time.Second,
			StaleAfter:     time.Second,
			Sources: []model.FederationSource{{
				Name:        "tls",
				BaseURL:     upstream.URL,
				Username:    "exporter",
				Password:    "secret",
				Enabled:     true,
				InsecureTLS: true,
			}},
		})
		if err != nil {
			t.Fatalf("create manager failed: %v", err)
		}
		if err := manager.Sync(context.Background()); err != nil {
			t.Fatalf("expected self-signed tls sync to succeed: %v", err)
		}
	})
}

func writeJSON(t *testing.T, w http.ResponseWriter, payload any) {
	t.Helper()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Fatalf("encode response failed: %v", err)
	}
}
