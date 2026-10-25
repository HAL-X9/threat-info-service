package memory

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/HAL-X9/threat-info-service/internal/domain"
)

type Repository struct {
	mu      sync.RWMutex
	threats map[domain.MD5]domain.Threat
}

func New() *Repository {
	return &Repository{threats: make(map[domain.MD5]domain.Threat)}
}

func (r *Repository) Create(_ context.Context, threat domain.Threat) (domain.Threat, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.threats[threat.MD5]; exists {
		return domain.Threat{}, domain.ErrConflict
	}

	r.threats[threat.MD5] = clone(threat)

	return clone(threat), nil
}

func (r *Repository) Get(_ context.Context, md5 domain.MD5) (domain.Threat, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	threat, exists := r.threats[md5]
	if !exists {
		return domain.Threat{}, domain.ErrNotFound
	}

	return clone(threat), nil
}

func (r *Repository) Update(_ context.Context, md5 domain.MD5, details domain.Details, now time.Time) (domain.Threat, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	threat, exists := r.threats[md5]
	if !exists {
		return domain.Threat{}, domain.ErrNotFound
	}

	threat.Details = details
	threat.UpdatedAt = now
	r.threats[md5] = clone(threat)

	return clone(threat), nil
}

func clone(threat domain.Threat) domain.Threat {
	threat.Tags = slices.Clone(threat.Tags)

	return threat
}
