package audit

import (
	"context"

	"github.com/warjiang/portal/internal/models"
)

type Store interface {
	Append(ctx context.Context, event models.AuditEvent) (models.AuditEvent, error)
	Query(ctx context.Context, filter QueryFilter) ([]models.AuditEvent, error)
}

type QueryFilter struct {
	TenantID string
	Actor    string
	Action   string
	Resource string
}
