package authzmem

import (
	"context"
	"sync"

	"github.com/warjiang/portal/internal/models"
)

type Provider struct {
	mu    sync.RWMutex
	tuple map[models.PolicyTuple]struct{}
}

func NewProvider() *Provider {
	return &Provider{tuple: make(map[models.PolicyTuple]struct{})}
}

func (p *Provider) Check(_ context.Context, tuple models.PolicyTuple) (bool, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, ok := p.tuple[tuple]
	return ok, nil
}

func (p *Provider) WriteRelationships(_ context.Context, tuples []models.PolicyTuple) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, t := range tuples {
		p.tuple[t] = struct{}{}
	}
	return nil
}
