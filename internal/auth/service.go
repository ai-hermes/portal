package auth

import (
	"context"

	"github.com/warjiang/portal/internal/identity"
)

type Service struct {
	provider identity.Provider
}

func NewService(provider identity.Provider) *Service {
	return &Service{provider: provider}
}

func (s *Service) StartLogin(ctx context.Context, tenantID, redirectURI string) (authURL, state string, err error) {
	return s.provider.StartLogin(ctx, tenantID, redirectURI)
}

func (s *Service) HandleCallback(ctx context.Context, code, state string) (string, error) {
	return s.provider.HandleCallback(ctx, code, state)
}
