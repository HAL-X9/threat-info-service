package service

import (
	"context"
	"time"

	"github.com/HAL-X9/threat-info-service/internal/domain"
)

type Repository interface {
	Create(ctx context.Context, threat domain.Threat) (domain.Threat, error)
	Get(ctx context.Context, md5 domain.MD5) (domain.Threat, error)
	Update(ctx context.Context, md5 domain.MD5, details domain.Details, now time.Time) (domain.Threat, error)
}

type Service struct {
	repo Repository
	now  func() time.Time
}

func New(repo Repository, now func() time.Time) *Service {
	return &Service{repo: repo, now: now}
}

func (s *Service) Create(ctx context.Context, md5 domain.MD5, details domain.Details) (domain.Threat, error) {
	threat, err := domain.NewThreat(md5, details, s.now())
	if err != nil {
		return domain.Threat{}, err
	}

	return s.repo.Create(ctx, threat)
}

func (s *Service) Get(ctx context.Context, md5 domain.MD5) (domain.Threat, error) {
	return s.repo.Get(ctx, md5)
}

func (s *Service) Update(ctx context.Context, md5 domain.MD5, details domain.Details) (domain.Threat, error) {
	details, err := details.Normalized()
	if err != nil {
		return domain.Threat{}, err
	}

	return s.repo.Update(ctx, md5, details, s.now().UTC())
}
