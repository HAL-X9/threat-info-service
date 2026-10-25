package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/HAL-X9/threat-info-service/internal/domain"
)

const uniqueViolation = "23505"

const columns = "md5, name, severity, category, description, tags, created_at, updated_at"

const (
	insertThreat = "INSERT INTO threats (" + columns + ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING " + columns

	selectThreat = "SELECT " + columns + " FROM threats WHERE md5 = $1"

	updateThreat = "UPDATE threats SET name = $2, severity = $3, category = $4, description = $5, tags = $6, updated_at = $7 " +
		"WHERE md5 = $1 RETURNING " + columns
)

type Threats struct {
	pool    *pgxpool.Pool
	timeout time.Duration
}

func NewThreats(pool *pgxpool.Pool, timeout time.Duration) *Threats {
	return &Threats{pool: pool, timeout: timeout}
}

func (r *Threats) Create(ctx context.Context, threat domain.Threat) (domain.Threat, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	row := r.pool.QueryRow(ctx, insertThreat,
		string(threat.MD5), threat.Name, string(threat.Severity), string(threat.Category),
		threat.Description, tagsOrEmpty(threat.Tags), threat.CreatedAt, threat.UpdatedAt,
	)

	return scan(row)
}

func (r *Threats) Get(ctx context.Context, md5 domain.MD5) (domain.Threat, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	return scan(r.pool.QueryRow(ctx, selectThreat, string(md5)))
}

func (r *Threats) Update(ctx context.Context, md5 domain.MD5, details domain.Details, now time.Time) (domain.Threat, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	row := r.pool.QueryRow(ctx, updateThreat,
		string(md5), details.Name, string(details.Severity), string(details.Category),
		details.Description, tagsOrEmpty(details.Tags), now,
	)

	return scan(row)
}

func scan(row pgx.Row) (domain.Threat, error) {
	var (
		threat                  domain.Threat
		md5, severity, category string
	)

	err := row.Scan(
		&md5, &threat.Name, &severity, &category, &threat.Description,
		&threat.Tags, &threat.CreatedAt, &threat.UpdatedAt,
	)
	if err != nil {
		return domain.Threat{}, translate(err)
	}

	threat.MD5 = domain.MD5(md5)
	threat.Severity = domain.Severity(severity)
	threat.Category = domain.Category(category)
	threat.CreatedAt = threat.CreatedAt.UTC()
	threat.UpdatedAt = threat.UpdatedAt.UTC()

	return threat, nil
}

func translate(err error) error {
	var pgErr *pgconn.PgError

	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return domain.ErrNotFound
	case errors.As(err, &pgErr) && pgErr.Code == uniqueViolation:
		return domain.ErrConflict
	default:
		return fmt.Errorf("query threats: %w", err)
	}
}

func tagsOrEmpty(tags []string) []string {
	if tags == nil {
		return []string{}
	}

	return tags
}
