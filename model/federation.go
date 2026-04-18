package model

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type FederationSource struct {
	ID        uint64    `gorm:"primaryKey" json:"id,omitempty"`
	CreatedAt time.Time `gorm:"index;<-:create" json:"created_at,omitempty"`
	UpdatedAt time.Time `gorm:"autoUpdateTime" json:"updated_at,omitempty"`

	OwnerUserID    uint64    `gorm:"column:owner_user_id;index;uniqueIndex:idx_federation_owner_remote" json:"owner_user_id,omitempty"`
	BaseURL        string    `gorm:"size:255;uniqueIndex:idx_federation_owner_remote" json:"base_url,omitempty"`
	SiteName       string    `gorm:"size:255" json:"site_name,omitempty"`
	Provider       string    `gorm:"size:128;uniqueIndex:idx_federation_owner_remote" json:"provider,omitempty"`
	RemoteUserID   string    `gorm:"size:255;uniqueIndex:idx_federation_owner_remote" json:"remote_user_id,omitempty"`
	RemoteUsername string    `gorm:"size:255" json:"remote_username,omitempty"`
	Token          string    `gorm:"type:text" json:"-"`
	TokenExpiresAt time.Time `json:"token_expires_at,omitempty"`
	Enabled        bool      `gorm:"default:true" json:"enabled"`
	IsPublic       bool      `gorm:"default:true" json:"is_public"`
	InsecureTLS    bool      `json:"insecure_tls,omitempty"`
	ReauthRequired bool      `gorm:"default:false" json:"reauth_required,omitempty"`
	LastSyncAt     time.Time `json:"last_sync_at,omitempty"`
	LastError      string    `gorm:"type:text" json:"last_error,omitempty"`
}

func (s *FederationSource) GetID() uint64 {
	return s.ID
}

func (s *FederationSource) GetUserID() uint64 {
	return s.OwnerUserID
}

func (s *FederationSource) HasPermission(ctx *gin.Context) bool {
	auth, ok := ctx.Get(CtxKeyAuthorizedUser)
	if !ok {
		return false
	}

	user := auth.(*User)
	return user.Role.IsAdmin() || user.ID == s.OwnerUserID
}

func NormalizeFederationBaseURL(raw string) (string, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(raw), "/")
	if baseURL == "" {
		return "", fmt.Errorf("base_url is required")
	}

	parsed, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid base_url: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("base_url must use http or https")
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("base_url host is required")
	}

	normalizedPath := strings.TrimRight(parsed.Path, "/")
	return parsed.Scheme + "://" + parsed.Host + normalizedPath, nil
}
