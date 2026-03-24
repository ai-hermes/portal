package auditmem

import (
	"context"
	"sync"

	"github.com/warjiang/portal/internal/audit"
	"github.com/warjiang/portal/internal/models"
)

type Store struct {
	mu     sync.RWMutex
	nextID int64
	events []models.AuditEvent
}

func NewStore() *Store {
	return &Store{nextID: 1}
}

func (s *Store) Append(_ context.Context, event models.AuditEvent) (models.AuditEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	event.ID = s.nextID
	s.nextID++
	s.events = append(s.events, event)
	return event, nil
}

func (s *Store) Query(_ context.Context, filter audit.QueryFilter) ([]models.AuditEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]models.AuditEvent, 0, len(s.events))
	for _, e := range s.events {
		if filter.TenantID != "" && e.TenantID != filter.TenantID {
			continue
		}
		if filter.Actor != "" && e.Actor != filter.Actor {
			continue
		}
		if filter.Action != "" && e.Action != filter.Action {
			continue
		}
		if filter.Resource != "" && e.Resource != filter.Resource {
			continue
		}
		result = append(result, e)
	}
	return result, nil
}
