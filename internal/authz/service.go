package authz

import (
	"context"

	"github.com/warjiang/portal/internal/models"
)

type Service struct {
	provider Provider
}

func NewService(provider Provider) *Service {
	return &Service{provider: provider}
}

func (s *Service) Check(ctx context.Context, tuple models.PolicyTuple) (bool, error) {
	return s.provider.Check(ctx, tuple)
}

func (s *Service) WriteRelationships(ctx context.Context, tuples []models.PolicyTuple) error {
	return s.provider.WriteRelationships(ctx, tuples)
}
