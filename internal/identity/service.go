package identity

import "context"

type Service struct {
	provider Provider
}

func NewService(provider Provider) *Service {
	return &Service{provider: provider}
}

func (s *Service) ListTenantMembers(ctx context.Context, tenantID string) ([]Principal, error) {
	return s.provider.ListTenantMembers(ctx, tenantID)
}

func (s *Service) ResolvePrincipal(ctx context.Context, token string) (Principal, error) {
	return s.provider.GetPrincipalByToken(ctx, token)
}
