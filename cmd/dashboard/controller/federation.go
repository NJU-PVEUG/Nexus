package controller

import (
	"context"
	"crypto/tls"
	"fmt"
	"html/template"
	"io"
	"net/http"
	neturl "net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	"github.com/goccy/go-json"
	"github.com/patrickmn/go-cache"
	"golang.org/x/oauth2"
	"gorm.io/gorm"

	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/pkg/utils"
	"github.com/nezhahq/nezha/service/singleton"
)

func currentViewer(c *gin.Context) *model.User {
	u, ok := c.Get(model.CtxKeyAuthorizedUser)
	if !ok {
		return nil
	}
	return u.(*model.User)
}

func listFederationProviders(c *gin.Context) (*model.FederationProvidersResponse, error) {
	return &model.FederationProvidersResponse{
		SiteName:  singleton.Conf.SiteName,
		Providers: federationGithubProviders(),
	}, nil
}

func listFederationSource(c *gin.Context) ([]model.FederationSource, error) {
	viewer := currentViewer(c)
	if viewer == nil {
		return nil, singleton.Localizer.ErrorT("unauthorized")
	}

	var sources []model.FederationSource
	if err := singleton.DB.Where("owner_user_id = ?", viewer.ID).Order("updated_at DESC").Find(&sources).Error; err != nil {
		return nil, newGormError("%v", err)
	}
	return sources, nil
}

func discoverFederationSource(c *gin.Context) (*model.FederationProvidersResponse, error) {
	if currentViewer(c) == nil {
		return nil, singleton.Localizer.ErrorT("unauthorized")
	}

	var form model.FederationDiscoverForm
	if err := c.ShouldBindJSON(&form); err != nil {
		return nil, err
	}

	baseURL, err := model.NormalizeFederationBaseURL(form.BaseURL)
	if err != nil {
		return nil, err
	}

	return discoverRemoteFederation(baseURL, form.InsecureTLS, singleton.Conf.Federation.RequestTimeout)
}

func startFederationSource(c *gin.Context) (*model.Oauth2LoginResponse, error) {
	viewer := currentViewer(c)
	if viewer == nil {
		return nil, singleton.Localizer.ErrorT("unauthorized")
	}

	var form model.FederationStartForm
	if err := c.ShouldBindJSON(&form); err != nil {
		return nil, err
	}

	baseURL, err := model.NormalizeFederationBaseURL(form.BaseURL)
	if err != nil {
		return nil, err
	}

	provider := strings.TrimSpace(form.Provider)
	if provider == "" {
		return nil, singleton.Localizer.ErrorT("provider is required")
	}

	info, err := discoverRemoteFederation(baseURL, form.InsecureTLS, singleton.Conf.Federation.RequestTimeout)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(info.Providers, provider) {
		return nil, singleton.Localizer.ErrorT("provider not found")
	}

	randomString, err := utils.GenerateRandomString(32)
	if err != nil {
		return nil, err
	}
	state, stateKey := randomString[:16], randomString[16:]
	singleton.Cache.Set(fmt.Sprintf("%s%s", model.CacheKeyFederationState, stateKey), &model.FederationPendingState{
		UserID:      viewer.ID,
		State:       state,
		BaseURL:     baseURL,
		Provider:    provider,
		InsecureTLS: form.InsecureTLS,
	}, cache.DefaultExpiration)

	callbackURL := getFederationCallbackURL(c)
	secureCookie := strings.HasPrefix(callbackURL, "https://")
	c.SetCookie("nz-fed-s", stateKey, 60*5, "/", "", secureCookie, false)

	redirectURL := fmt.Sprintf("%s/api/v1/federation/oauth2/%s?callback=%s&state=%s",
		baseURL,
		neturl.PathEscape(provider),
		neturl.QueryEscape(callbackURL),
		neturl.QueryEscape(state),
	)

	return &model.Oauth2LoginResponse{Redirect: redirectURL}, nil
}

func federationOauth2Redirect(c *gin.Context) (any, error) {
	provider := c.Param("provider")
	if provider == "" {
		return nil, singleton.Localizer.ErrorT("provider is required")
	}

	callbackURL := strings.TrimSpace(c.Query("callback"))
	if callbackURL == "" {
		return nil, singleton.Localizer.ErrorT("callback is required")
	}
	callbackState := strings.TrimSpace(c.Query("state"))
	if callbackState == "" {
		return nil, singleton.Localizer.ErrorT("state is required")
	}

	parsedCallback, err := neturl.Parse(callbackURL)
	if err != nil || (parsedCallback.Scheme != "http" && parsedCallback.Scheme != "https") || parsedCallback.Host == "" {
		return nil, singleton.Localizer.ErrorT("invalid callback")
	}
	if parsedCallback.Path != "/api/v1/federation/callback" {
		return nil, singleton.Localizer.ErrorT("invalid callback")
	}

	o2confRaw, has := singleton.Conf.Oauth2[provider]
	if !has {
		return nil, singleton.Localizer.ErrorT("provider not found")
	}

	redirectURL := getRedirectURL(c)
	o2conf := o2confRaw.Setup(redirectURL)

	randomString, err := utils.GenerateRandomString(32)
	if err != nil {
		return nil, err
	}
	state, stateKey := randomString[:16], randomString[16:]
	singleton.Cache.Set(fmt.Sprintf("%s%s", model.CacheKeyOauth2State, stateKey), &model.Oauth2State{
		Action:                model.RTypeFederationGrant,
		Provider:              provider,
		State:                 state,
		RedirectURL:           redirectURL,
		FederationCallbackURL: parsedCallback.String(),
		FederationState:       callbackState,
	}, cache.DefaultExpiration)

	c.SetCookie("nz-o2s", stateKey, 60*5, "/", "", strings.HasPrefix(redirectURL, "https://"), false)
	c.Redirect(http.StatusFound, o2conf.AuthCodeURL(state, oauth2.AccessTypeOnline))
	return nil, errNoop
}

func federationExchange(jwtConfig *jwt.GinJWTMiddleware) func(c *gin.Context) (*model.FederationExchangeResponse, error) {
	return func(c *gin.Context) (*model.FederationExchangeResponse, error) {
		var form model.FederationExchangeForm
		if err := c.ShouldBindJSON(&form); err != nil {
			return nil, err
		}
		if strings.TrimSpace(form.Code) == "" {
			return nil, singleton.Localizer.ErrorT("code is required")
		}

		cacheKey := fmt.Sprintf("%s%s", model.CacheKeyFederationGrant, strings.TrimSpace(form.Code))
		rawGrant, ok := singleton.Cache.Get(cacheKey)
		if !ok {
			return nil, singleton.Localizer.ErrorT("invalid code")
		}
		singleton.Cache.Delete(cacheKey)

		grant, ok := rawGrant.(*model.FederationGrant)
		if !ok {
			return nil, singleton.Localizer.ErrorT("invalid code")
		}

		var user model.User
		if err := singleton.DB.Select("id", "username").First(&user, grant.UserID).Error; err != nil {
			return nil, singleton.Localizer.ErrorT("unauthorized")
		}

		tokenString, expireAt, err := jwtConfig.TokenGenerator(map[string]interface{}{
			"user_id": fmt.Sprintf("%d", grant.UserID),
			"ip":      c.GetString(model.CtxKeyRealIPStr),
		})
		if err != nil {
			return nil, err
		}

		return &model.FederationExchangeResponse{
			LoginResponse: model.LoginResponse{
				Token:  tokenString,
				Expire: expireAt.Format(time.RFC3339),
			},
			SiteName:       singleton.Conf.SiteName,
			Provider:       grant.Provider,
			RemoteUserID:   grant.RemoteUserID,
			RemoteUsername: user.Username,
		}, nil
	}
}

func federationCallback(c *gin.Context) (any, error) {
	viewer := currentViewer(c)
	if viewer == nil {
		redirectFederationPage(c, "error", "Please log in to the main panel first.")
		return nil, errNoop
	}

	pending, err := verifyFederationPendingState(c, c.Query("state"))
	if err != nil {
		redirectFederationPage(c, "error", err.Error())
		return nil, errNoop
	}
	if pending.UserID != viewer.ID {
		redirectFederationPage(c, "error", "The current user does not match the user that started this authorization.")
		return nil, errNoop
	}

	code := strings.TrimSpace(c.Query("code"))
	if code == "" {
		redirectFederationPage(c, "error", "Missing federation grant code.")
		return nil, errNoop
	}

	exchangeResp, err := exchangeFederationGrant(c, pending, code)
	if err != nil {
		redirectFederationPage(c, "error", err.Error())
		return nil, errNoop
	}

	expireAt := time.Time{}
	if exchangeResp.Expire != "" {
		if parsed, parseErr := time.Parse(time.RFC3339, exchangeResp.Expire); parseErr == nil {
			expireAt = parsed
		}
	}

	var source model.FederationSource
	err = singleton.DB.Where("owner_user_id = ? AND base_url = ? AND provider = ? AND remote_user_id = ?",
		viewer.ID, pending.BaseURL, pending.Provider, exchangeResp.RemoteUserID).
		First(&source).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, newGormError("%v", err)
	}

	if err == gorm.ErrRecordNotFound {
		source = model.FederationSource{
			OwnerUserID:  viewer.ID,
			BaseURL:      pending.BaseURL,
			Provider:     pending.Provider,
			RemoteUserID: exchangeResp.RemoteUserID,
			Enabled:      true,
			IsPublic:     true,
		}
	}

	source.SiteName = exchangeResp.SiteName
	source.RemoteUsername = exchangeResp.RemoteUsername
	source.InsecureTLS = pending.InsecureTLS
	source.Enabled = true
	source.Token = exchangeResp.Token
	source.TokenExpiresAt = expireAt
	source.ReauthRequired = false
	source.LastError = ""

	if source.ID == 0 {
		if err := singleton.DB.Create(&source).Error; err != nil {
			return nil, newGormError("%v", err)
		}
	} else {
		if err := singleton.DB.Save(&source).Error; err != nil {
			return nil, newGormError("%v", err)
		}
	}

	if singleton.FederationShared != nil {
		go singleton.FederationShared.Sync(context.Background())
	}

	redirectFederationPage(c, "connected", "")
	return nil, errNoop
}

func updateFederationSource(c *gin.Context) (any, error) {
	viewer := currentViewer(c)
	if viewer == nil {
		return nil, singleton.Localizer.ErrorT("unauthorized")
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		return nil, err
	}

	var source model.FederationSource
	if err := singleton.DB.Where("id = ? AND owner_user_id = ?", id, viewer.ID).First(&source).Error; err != nil {
		return nil, singleton.Localizer.ErrorT("federation source not found")
	}

	var form model.FederationUpdateForm
	if err := c.ShouldBindJSON(&form); err != nil {
		return nil, err
	}
	if form.Enabled == nil && form.IsPublic == nil {
		return nil, singleton.Localizer.ErrorT("nothing to update")
	}

	if form.Enabled != nil {
		source.Enabled = *form.Enabled
	}
	if form.IsPublic != nil {
		source.IsPublic = *form.IsPublic
	}

	if err := singleton.DB.Save(&source).Error; err != nil {
		return nil, newGormError("%v", err)
	}

	if singleton.FederationShared != nil {
		if err := singleton.FederationShared.Reload(); err != nil {
			return nil, err
		}
		if form.Enabled != nil && *form.Enabled {
			go singleton.FederationShared.Sync(context.Background())
		}
	}

	return nil, nil
}

func deleteFederationSource(c *gin.Context) (any, error) {
	viewer := currentViewer(c)
	if viewer == nil {
		return nil, singleton.Localizer.ErrorT("unauthorized")
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		return nil, err
	}

	if err := singleton.DB.Where("id = ? AND owner_user_id = ?", id, viewer.ID).Delete(&model.FederationSource{}).Error; err != nil {
		return nil, newGormError("%v", err)
	}

	if singleton.FederationShared != nil {
		if err := singleton.FederationShared.Reload(); err != nil {
			return nil, err
		}
	}

	return nil, nil
}

func federationPage(c *gin.Context) {
	if currentViewer(c) == nil {
		c.Redirect(http.StatusFound, "/dashboard/login")
		return
	}

	page := template.Must(template.New("federation-page").Parse(federationPageHTML))
	c.Header("Content-Type", "text/html; charset=utf-8")
	_ = page.Execute(c.Writer, map[string]any{
		"SiteName": singleton.Conf.SiteName,
	})
}

func discoverRemoteFederation(baseURL string, insecureTLS bool, timeout time.Duration) (*model.FederationProvidersResponse, error) {
	client := newFederationDiscoveryClient(insecureTLS, timeout)
	req, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/federation/providers", nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("federation provider discovery returned status %d", resp.StatusCode)
	}

	var result model.CommonResponse[model.FederationProvidersResponse]
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	if !result.Success {
		return nil, fmt.Errorf("%s", strings.TrimSpace(result.Error))
	}
	if len(result.Data.Providers) == 0 {
		return nil, fmt.Errorf("target panel has no OAuth providers available")
	}
	return &result.Data, nil
}

func exchangeFederationGrant(c *gin.Context, pending *model.FederationPendingState, code string) (*model.FederationExchangeResponse, error) {
	client := newFederationDiscoveryClient(pending.InsecureTLS, singleton.Conf.Federation.RequestTimeout)
	payload, err := json.Marshal(model.FederationExchangeForm{Code: code})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodPost, pending.BaseURL+"/api/v1/federation/exchange", strings.NewReader(string(payload)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("federation exchange returned status %d", resp.StatusCode)
	}

	var result model.CommonResponse[model.FederationExchangeResponse]
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	if !result.Success || result.Data.Token == "" {
		return nil, fmt.Errorf("%s", strings.TrimSpace(result.Error))
	}

	return &result.Data, nil
}

func verifyFederationPendingState(c *gin.Context, state string) (*model.FederationPendingState, error) {
	stateKey, err := c.Cookie("nz-fed-s")
	if err != nil {
		return nil, singleton.Localizer.ErrorT("invalid state key")
	}

	cacheKey := fmt.Sprintf("%s%s", model.CacheKeyFederationState, stateKey)
	rawState, ok := singleton.Cache.Get(cacheKey)
	if !ok {
		return nil, singleton.Localizer.ErrorT("invalid state key")
	}
	singleton.Cache.Delete(cacheKey)

	pendingState, ok := rawState.(*model.FederationPendingState)
	if !ok || pendingState.State != state {
		return nil, singleton.Localizer.ErrorT("invalid state key")
	}

	return pendingState, nil
}

func getFederationCallbackURL(c *gin.Context) string {
	scheme := "http://"
	referer := c.Request.Referer()
	if forwardedProto := c.Request.Header.Get("X-Forwarded-Proto"); forwardedProto == "https" || strings.HasPrefix(referer, "https://") {
		scheme = "https://"
	}
	return scheme + c.Request.Host + "/api/v1/federation/callback"
}

func redirectFederationPage(c *gin.Context, status, message string) {
	params := neturl.Values{}
	if status != "" {
		params.Set("status", status)
	}
	if message != "" {
		params.Set("message", message)
	}

	location := "/dashboard/profile/federation"
	if encoded := params.Encode(); encoded != "" {
		location += "?" + encoded
	}
	c.Redirect(http.StatusFound, location)
}

func newFederationDiscoveryClient(insecureTLS bool, timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: insecureTLS}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}

func federationGithubProviders() []string {
	if singleton.Conf == nil {
		return nil
	}

	providers := make([]string, 0, len(singleton.Conf.Oauth2))
	for name, conf := range singleton.Conf.Oauth2 {
		authURL, err := neturl.Parse(conf.Endpoint.AuthURL)
		if err != nil {
			continue
		}
		host := strings.ToLower(authURL.Host)
		if strings.Contains(host, "github") || strings.Contains(strings.ToLower(name), "github") {
			providers = append(providers, name)
		}
	}
	slices.Sort(providers)
	return providers
}

const federationPageHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ .SiteName }} - Federation</title>
  <style>
    :root { color-scheme: dark; --bg:#111; --panel:#1d1d1d; --muted:#a7a7a7; --line:#323232; --text:#f7f7f7; --accent:#2f6cf6; --danger:#d53b3b; }
    * { box-sizing:border-box; }
    body { margin:0; font-family: "Segoe UI", sans-serif; background:linear-gradient(180deg,#121212 0,#0f0f0f 100%); color:var(--text); }
    .wrap { max-width:1100px; margin:0 auto; padding:32px 20px 48px; }
    .top { display:flex; justify-content:space-between; align-items:center; gap:16px; margin-bottom:24px; }
    .title { font-size:32px; font-weight:700; margin:0; }
    .sub { color:var(--muted); margin-top:6px; }
    .back { color:var(--text); text-decoration:none; border:1px solid var(--line); padding:10px 14px; border-radius:12px; }
    .grid { display:grid; gap:20px; grid-template-columns:repeat(auto-fit,minmax(320px,1fr)); }
    .card { background:rgba(255,255,255,.04); border:1px solid var(--line); border-radius:20px; padding:20px; box-shadow:0 24px 60px rgba(0,0,0,.22); }
    .card h2 { margin:0 0 14px; font-size:22px; }
    label { display:block; font-size:14px; color:var(--muted); margin-bottom:8px; }
    input, select { width:100%; background:#141414; color:var(--text); border:1px solid var(--line); border-radius:12px; padding:12px 14px; margin-bottom:14px; }
    button { cursor:pointer; border:none; border-radius:12px; padding:12px 16px; background:var(--accent); color:white; font-weight:700; }
    button.secondary { background:#242424; border:1px solid var(--line); }
    button.danger { background:var(--danger); }
    .actions { display:flex; gap:10px; flex-wrap:wrap; }
    .row { display:flex; align-items:center; gap:10px; margin:6px 0 14px; color:var(--muted); }
    .status { margin-bottom:16px; min-height:22px; color:#ffd36a; }
    .status.ok { color:#84f2a8; }
    .sources { display:grid; gap:14px; }
    .source { border:1px solid var(--line); border-radius:16px; padding:16px; background:#141414; }
    .source-top { display:flex; justify-content:space-between; gap:14px; flex-wrap:wrap; }
    .source-name { font-size:20px; font-weight:700; }
    .meta { color:var(--muted); font-size:13px; margin-top:6px; line-height:1.6; }
    .toggles { display:flex; gap:16px; flex-wrap:wrap; margin:14px 0; }
    .toggles label { display:flex; gap:8px; align-items:center; margin:0; color:var(--text); }
    .inline-msg { font-size:13px; color:var(--muted); margin-top:8px; }
    code { color:#cde3ff; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="top">
      <div>
        <h1 class="title">Federation</h1>
        <div class="sub">Connect your own child panel with GitHub OAuth and control whether that entire source is public to guests.</div>
      </div>
      <a class="back" href="/dashboard/profile">Back to profile</a>
    </div>
    <div id="pageStatus" class="status"></div>
    <div class="grid">
      <section class="card">
        <h2>Add Child Panel</h2>
        <div class="inline-msg" style="margin-bottom:14px;">The child panel must also run this fork and have GitHub OAuth configured before you connect it here.</div>
        <label for="baseUrl">Base URL</label>
        <input id="baseUrl" placeholder="https://child.example.com">
        <div class="row">
          <input id="insecureTls" type="checkbox" style="width:auto;margin:0;">
          <label for="insecureTls" style="margin:0;">Use insecure TLS for self-signed certificates</label>
        </div>
        <div class="actions" style="margin-bottom:14px;">
          <button id="discoverBtn" class="secondary" type="button">Discover</button>
        </div>
        <label for="providerSelect">OAuth Provider</label>
        <select id="providerSelect" disabled>
          <option value="">Discover first</option>
        </select>
        <div id="discoverResult" class="inline-msg">Authorization will be completed by the child panel using its own GitHub OAuth settings.</div>
        <div class="actions" style="margin-top:14px;">
          <button id="connectBtn" type="button" disabled>Authorize and Connect</button>
        </div>
      </section>
      <section class="card">
        <h2>My Child Panels</h2>
        <div class="inline-msg">Guests see all public child-panel nodes. Logged-in users also see their own private child-panel nodes.</div>
        <div id="sources" class="sources" style="margin-top:14px;"></div>
      </section>
    </div>
  </div>
  <script>
    const pageStatus = document.getElementById('pageStatus');
    const sourcesEl = document.getElementById('sources');
    const discoverResult = document.getElementById('discoverResult');
    const providerSelect = document.getElementById('providerSelect');
    const connectBtn = document.getElementById('connectBtn');
    const discoverBtn = document.getElementById('discoverBtn');
    const baseUrlInput = document.getElementById('baseUrl');
    const insecureTlsInput = document.getElementById('insecureTls');

    function showStatus(message, ok = false) {
      pageStatus.textContent = message || '';
      pageStatus.className = 'status' + (ok ? ' ok' : '');
    }

    function getPayload() {
      return {
        base_url: baseUrlInput.value.trim(),
        insecure_tls: insecureTlsInput.checked,
      };
    }

    async function api(path, options = {}) {
      const response = await fetch(path, {
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
        ...options,
      });
      const data = await response.json();
      if (!data.success) {
        throw new Error(data.error || 'Request failed');
      }
      return data.data;
    }

    function readPageMessage() {
      const params = new URLSearchParams(window.location.search);
      const status = params.get('status');
      const message = params.get('message');
      if (status === 'connected') {
        showStatus('Child panel connected. Federation sync is running.', true);
      } else if (status === 'error' && message) {
        showStatus(message, false);
      }
      if (status || message) {
        history.replaceState({}, '', '/dashboard/profile/federation');
      }
    }

    async function loadSources() {
      const sources = await api('/api/v1/federation/source');
      if (!sources.length) {
        sourcesEl.innerHTML = '<div class="inline-msg">No child panels connected yet.</div>';
        return;
      }
      sourcesEl.innerHTML = '';
      for (const source of sources) {
        const card = document.createElement('div');
        card.className = 'source';
        card.innerHTML = [
          '<div class="source-top">',
          '  <div>',
          '    <div class="source-name">' + (source.site_name || source.base_url) + '</div>',
          '    <div class="meta">',
          '      <div>URL: <code>' + source.base_url + '</code></div>',
          '      <div>Provider: ' + source.provider + '</div>',
          '      <div>Remote user: ' + (source.remote_username || source.remote_user_id || '-') + '</div>',
          '      <div>Last sync: ' + (source.last_sync_at ? new Date(source.last_sync_at).toLocaleString() : 'Never') + '</div>',
          '      <div>Status: ' + (source.last_error || (source.reauth_required ? 'Re-authorization required' : 'OK')) + '</div>',
          '    </div>',
          '  </div>',
          '  <div class="actions">',
          '    <button class="secondary reconnect-btn" type="button">Reconnect</button>',
          '    <button class="danger delete-btn" type="button">Delete</button>',
          '  </div>',
          '</div>',
          '<div class="toggles">',
          '  <label><input class="enabled-toggle" type="checkbox" ' + (source.enabled ? 'checked' : '') + '> Enabled</label>',
          '  <label><input class="public-toggle" type="checkbox" ' + (source.is_public ? 'checked' : '') + '> Public to guests</label>',
          '</div>',
        ].join('');
        card.querySelector('.enabled-toggle').addEventListener('change', async (event) => {
          try {
            await api('/api/v1/federation/source/' + source.id, {
              method: 'PATCH',
              body: JSON.stringify({ enabled: event.target.checked }),
            });
            showStatus('Enabled state updated.', true);
            await loadSources();
          } catch (error) {
            event.target.checked = !event.target.checked;
            showStatus(error.message, false);
          }
        });
        card.querySelector('.public-toggle').addEventListener('change', async (event) => {
          try {
            await api('/api/v1/federation/source/' + source.id, {
              method: 'PATCH',
              body: JSON.stringify({ is_public: event.target.checked }),
            });
            showStatus('Public visibility updated.', true);
            await loadSources();
          } catch (error) {
            event.target.checked = !event.target.checked;
            showStatus(error.message, false);
          }
        });
        card.querySelector('.delete-btn').addEventListener('click', async () => {
          if (!confirm('Delete this child-panel connection?')) return;
          try {
            await api('/api/v1/federation/source/' + source.id, { method: 'DELETE' });
            showStatus('Child-panel connection deleted.', true);
            await loadSources();
          } catch (error) {
            showStatus(error.message, false);
          }
        });
        card.querySelector('.reconnect-btn').addEventListener('click', async () => {
          try {
            const data = await api('/api/v1/federation/source/start', {
              method: 'POST',
              body: JSON.stringify({
                base_url: source.base_url,
                provider: source.provider,
                insecure_tls: source.insecure_tls,
              }),
            });
            window.location.href = data.redirect;
          } catch (error) {
            showStatus(error.message, false);
          }
        });
        sourcesEl.appendChild(card);
      }
    }

    discoverBtn.addEventListener('click', async () => {
      try {
        const data = await api('/api/v1/federation/source/discover', {
          method: 'POST',
          body: JSON.stringify(getPayload()),
        });
        providerSelect.innerHTML = '';
        for (const provider of data.providers) {
          const option = document.createElement('option');
          option.value = provider;
          option.textContent = provider;
          providerSelect.appendChild(option);
        }
        providerSelect.disabled = false;
        connectBtn.disabled = !data.providers.length;
        discoverResult.textContent = 'Discovered panel: ' + (data.site_name || 'Unnamed') + '. Providers: ' + data.providers.join(', ');
        showStatus('Child panel discovered.', true);
      } catch (error) {
        providerSelect.innerHTML = '<option value="">Discover first</option>';
        providerSelect.disabled = true;
        connectBtn.disabled = true;
        discoverResult.textContent = 'Discovery failed. Check the URL and network path.';
        showStatus(error.message, false);
      }
    });

    connectBtn.addEventListener('click', async () => {
      try {
        const data = await api('/api/v1/federation/source/start', {
          method: 'POST',
          body: JSON.stringify({
            ...getPayload(),
            provider: providerSelect.value,
          }),
        });
        window.location.href = data.redirect;
      } catch (error) {
        showStatus(error.message, false);
      }
    });

    readPageMessage();
    loadSources().catch((error) => showStatus(error.message, false));
  </script>
</body>
</html>`
