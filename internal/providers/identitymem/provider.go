package identitymem

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/warjiang/portal/internal/identity"
)

type Provider struct {
	mu      sync.RWMutex
	members map[string][]identity.Principal
}

func NewProvider() *Provider {
	return &Provider{
		members: map[string][]identity.Principal{
			"tenant-acme": {
				{TenantID: "tenant-acme", UserID: "u-admin", Email: "admin@acme.ai", Role: "tenant_admin"},
				{TenantID: "tenant-acme", UserID: "u-viewer", Email: "viewer@acme.ai", Role: "viewer"},
			},
		},
	}
}

func (p *Provider) StartLogin(_ context.Context, tenantID, redirectURI string) (string, string, error) {
	if tenantID == "" || redirectURI == "" {
		return "", "", errors.New("tenant_id and redirect_uri are required")
	}
	state := "state-demo"
	authURL := fmt.Sprintf("%s?code=demo-code&state=%s&tenant_id=%s", redirectURI, state, tenantID)
	return authURL, state, nil
}

func (p *Provider) HandleCallback(_ context.Context, code, state string) (string, error) {
	if code == "" || state == "" {
		return "", errors.New("code and state are required")
	}
	// Development-only token format: dev:<tenant_id>:<user_id>
	return "dev:tenant-acme:u-admin", nil
}

func (p *Provider) GetPrincipalByToken(_ context.Context, token string) (identity.Principal, error) {
	parts := strings.Split(token, ":")
	if len(parts) != 3 || parts[0] != "dev" {
		return identity.Principal{}, errors.New("invalid bearer token")
	}
	tenantID, userID := parts[1], parts[2]
	for _, member := range p.members[tenantID] {
		if member.UserID == userID {
			return member, nil
		}
	}
	return identity.Principal{}, errors.New("principal not found")
}

func (p *Provider) ListTenantMembers(_ context.Context, tenantID string) ([]identity.Principal, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	members := p.members[tenantID]
	cloned := make([]identity.Principal, len(members))
	copy(cloned, members)
	return cloned, nil
}
