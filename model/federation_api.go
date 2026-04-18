package model

type FederationProvidersResponse struct {
	SiteName  string   `json:"site_name,omitempty"`
	Providers []string `json:"providers,omitempty"`
}

type FederationDiscoverForm struct {
	BaseURL     string `json:"base_url,omitempty"`
	InsecureTLS bool   `json:"insecure_tls,omitempty"`
}

type FederationStartForm struct {
	BaseURL     string `json:"base_url,omitempty"`
	Provider    string `json:"provider,omitempty"`
	InsecureTLS bool   `json:"insecure_tls,omitempty"`
}

type FederationUpdateForm struct {
	Enabled  *bool `json:"enabled,omitempty"`
	IsPublic *bool `json:"is_public,omitempty"`
}

type FederationExchangeForm struct {
	Code string `json:"code,omitempty"`
}

type FederationExchangeResponse struct {
	LoginResponse
	SiteName       string `json:"site_name,omitempty"`
	Provider       string `json:"provider,omitempty"`
	RemoteUserID   string `json:"remote_user_id,omitempty"`
	RemoteUsername string `json:"remote_username,omitempty"`
}

type FederationPendingState struct {
	UserID      uint64
	State       string
	BaseURL     string
	Provider    string
	InsecureTLS bool
}

type FederationGrant struct {
	UserID       uint64
	Provider     string
	OpenID       string
	RemoteUserID string
}
