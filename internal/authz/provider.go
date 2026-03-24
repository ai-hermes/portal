package authz

import (
	"context"

	"github.com/warjiang/portal/internal/models"
)

type Provider interface {
	Check(ctx context.Context, tuple models.PolicyTuple) (bool, error)
	WriteRelationships(ctx context.Context, tuples []models.PolicyTuple) error
}
