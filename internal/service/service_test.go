package service_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/HAL-X9/threat-info-service/internal/domain"
	"github.com/HAL-X9/threat-info-service/internal/service"
)

const md5 = domain.MD5("d41d8cd98f00b204e9800998ecf8427e")

var start = time.Date(2026, 10, 24, 12, 0, 0, 0, time.FixedZone("MSK", 3*60*60))

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

func newService() (*service.Service, *clock) {
	c := &clock{now: start}

	return service.New(newFakeRepo(), c.Now), c
}

func details() domain.Details {
	return domain.Details{
		Name:        "Trojan.Win32.Generic",
		Severity:    domain.SeverityHigh,
		Category:    domain.CategoryTrojan,
		Description: "Drops additional modules",
		Tags:        []string{"dropper"},
	}
}

func TestCreate(t *testing.T) {
	svc, _ := newService()
	in := details()
	in.Name = "  Trojan.Win32.Generic  "
	in.Tags = []string{"Dropper", "dropper"}

	got, err := svc.Create(context.Background(), md5, in)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	want := domain.Threat{MD5: md5, Details: details(), CreatedAt: start.UTC(), UpdatedAt: start.UTC()}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Create = %+v, want %+v", got, want)
	}

	stored, err := svc.Get(context.Background(), md5)
	if err != nil || !reflect.DeepEqual(stored, want) {
		t.Errorf("Get = %+v, %v, want %+v", stored, err, want)
	}
}

func TestCreateRejectsAnExistingMD5(t *testing.T) {
	svc, _ := newService()

	if _, err := svc.Create(context.Background(), md5, details()); err != nil {
		t.Fatalf("Create: %v", err)
	}

	other := details()
	other.Name = "Other"

	if _, err := svc.Create(context.Background(), md5, other); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("second Create error = %v, want ErrConflict", err)
	}

	stored, _ := svc.Get(context.Background(), md5)
	if stored.Name != details().Name {
		t.Errorf("Name = %q, want the original to be kept", stored.Name)
	}
}

func TestCreateRejectsInvalidInputAndStoresNothing(t *testing.T) {
	bad := details()
	bad.Severity = "urgent"

	tests := map[string]struct {
		md5     domain.MD5
		details domain.Details
	}{
		"invalid details": {md5, bad},
		"invalid md5":     {"not-a-hash", details()},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			svc, _ := newService()

			if _, err := svc.Create(context.Background(), tc.md5, tc.details); !errors.Is(err, domain.ErrValidation) {
				t.Fatalf("Create error = %v, want ErrValidation", err)
			}

			if _, err := svc.Get(context.Background(), md5); !errors.Is(err, domain.ErrNotFound) {
				t.Errorf("Get error = %v, want nothing to have been stored", err)
			}
		})
	}
}

func TestGetMissing(t *testing.T) {
	svc, _ := newService()

	if _, err := svc.Get(context.Background(), md5); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Get error = %v, want ErrNotFound", err)
	}
}

func TestUpdateReplacesTheDetails(t *testing.T) {
	svc, clk := newService()

	if _, err := svc.Create(context.Background(), md5, details()); err != nil {
		t.Fatalf("Create: %v", err)
	}

	clk.now = start.Add(time.Hour)

	got, err := svc.Update(context.Background(), md5, domain.Details{
		Name:     "  Renamed  ",
		Severity: domain.SeverityLow,
		Category: domain.CategoryWorm,
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}

	want := domain.Threat{
		MD5:       md5,
		Details:   domain.Details{Name: "Renamed", Severity: domain.SeverityLow, Category: domain.CategoryWorm, Tags: []string{}},
		CreatedAt: start.UTC(),
		UpdatedAt: clk.now.UTC(),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Update = %+v, want %+v: omitted optional fields must be cleared", got, want)
	}

	stored, _ := svc.Get(context.Background(), md5)
	if !reflect.DeepEqual(stored, want) {
		t.Errorf("Get = %+v, want %+v", stored, want)
	}
}

func TestUpdateMissing(t *testing.T) {
	svc, _ := newService()

	if _, err := svc.Update(context.Background(), md5, details()); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Update error = %v, want ErrNotFound", err)
	}
}

func TestUpdateRejectsInvalidDetailsAndKeepsTheRecord(t *testing.T) {
	svc, clk := newService()

	if _, err := svc.Create(context.Background(), md5, details()); err != nil {
		t.Fatalf("Create: %v", err)
	}

	clk.now = start.Add(time.Hour)

	bad := details()
	bad.Name = strings.Repeat("x", 256)

	if _, err := svc.Update(context.Background(), md5, bad); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("Update error = %v, want ErrValidation", err)
	}

	stored, _ := svc.Get(context.Background(), md5)
	if stored.Name != details().Name || !stored.UpdatedAt.Equal(start) {
		t.Errorf("record = %+v, want it untouched", stored)
	}
}

type failingRepo struct{ err error }

func (r failingRepo) Create(context.Context, domain.Threat) (domain.Threat, error) {
	return domain.Threat{}, r.err
}

func (r failingRepo) Get(context.Context, domain.MD5) (domain.Threat, error) {
	return domain.Threat{}, r.err
}

func (r failingRepo) Update(context.Context, domain.MD5, domain.Details, time.Time) (domain.Threat, error) {
	return domain.Threat{}, r.err
}

func TestRepositoryFailuresArePassedThrough(t *testing.T) {
	boom := errors.New("database is down")
	svc := service.New(failingRepo{err: boom}, func() time.Time { return start })

	if _, err := svc.Create(context.Background(), md5, details()); !errors.Is(err, boom) {
		t.Errorf("Create error = %v, want %v", err, boom)
	}

	if _, err := svc.Get(context.Background(), md5); !errors.Is(err, boom) {
		t.Errorf("Get error = %v, want %v", err, boom)
	}

	if _, err := svc.Update(context.Background(), md5, details()); !errors.Is(err, boom) {
		t.Errorf("Update error = %v, want %v", err, boom)
	}
}

type fakeRepo struct{ threats map[domain.MD5]domain.Threat }

func newFakeRepo() *fakeRepo {
	return &fakeRepo{threats: make(map[domain.MD5]domain.Threat)}
}

func (r *fakeRepo) Create(_ context.Context, threat domain.Threat) (domain.Threat, error) {
	if _, exists := r.threats[threat.MD5]; exists {
		return domain.Threat{}, domain.ErrConflict
	}

	r.threats[threat.MD5] = threat

	return threat, nil
}

func (r *fakeRepo) Get(_ context.Context, md5 domain.MD5) (domain.Threat, error) {
	threat, exists := r.threats[md5]
	if !exists {
		return domain.Threat{}, domain.ErrNotFound
	}

	return threat, nil
}

func (r *fakeRepo) Update(_ context.Context, md5 domain.MD5, details domain.Details, now time.Time) (domain.Threat, error) {
	threat, exists := r.threats[md5]
	if !exists {
		return domain.Threat{}, domain.ErrNotFound
	}

	threat.Details = details
	threat.UpdatedAt = now
	r.threats[md5] = threat

	return threat, nil
}
