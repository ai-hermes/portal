package identity

import "context"

type Provider interface {
	StartLogin(ctx context.Context, tenantID, redirectURI string) (authURL, state string, err error)
	HandleCallback(ctx context.Context, code, state string) (token string, err error)
	GetPrincipalByToken(ctx context.Context, token string) (Principal, error)
	ListTenantMembers(ctx context.Context, tenantID string) ([]Principal, error)
}

type Principal struct {
	TenantID string `json:"tenant_id"`
	UserID   string `json:"user_id"`
	Email    string `json:"email,omitempty"`
	Role     string `json:"role,omitempty"`
}
