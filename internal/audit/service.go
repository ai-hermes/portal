package audit

import (
	"context"
	"time"

	"github.com/warjiang/portal/internal/models"
)

type Service struct {
	store Store
}

func NewService(store Store) *Service {
	return &Service{store: store}
}

func (s *Service) Record(ctx context.Context, event models.AuditEvent) (models.AuditEvent, error) {
	if event.At.IsZero() {
		event.At = time.Now().UTC()
	}
	return s.store.Append(ctx, event)
}

func (s *Service) Query(ctx context.Context, filter QueryFilter) ([]models.AuditEvent, error) {
	return s.store.Query(ctx, filter)
}
