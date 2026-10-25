package memory

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HAL-X9/threat-info-service/internal/domain"
)

const md5 = domain.MD5("d41d8cd98f00b204e9800998ecf8427e")

var created = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

func newThreat(t *testing.T) domain.Threat {
	t.Helper()

	threat, err := domain.NewThreat(md5, domain.Details{
		Name:     "Trojan.Win32.Generic",
		Severity: domain.SeverityHigh,
		Category: domain.CategoryTrojan,
		Tags:     []string{"dropper"},
	}, created)
	if err != nil {
		t.Fatalf("NewThreat: %v", err)
	}

	return threat
}

func TestCreateAndGet(t *testing.T) {
	repo := New()
	want := newThreat(t)

	got, err := repo.Create(context.Background(), want)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("Create = %+v, want %+v", got, want)
	}

	stored, err := repo.Get(context.Background(), md5)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if !reflect.DeepEqual(stored, want) {
		t.Errorf("Get = %+v, want %+v", stored, want)
	}
}

func TestCreateRejectsADuplicate(t *testing.T) {
	repo := New()
	original := newThreat(t)

	if _, err := repo.Create(context.Background(), original); err != nil {
		t.Fatalf("Create: %v", err)
	}

	other := original
	other.Name = "Other"

	if _, err := repo.Create(context.Background(), other); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("second Create error = %v, want ErrConflict", err)
	}

	stored, _ := repo.Get(context.Background(), md5)
	if stored.Name != original.Name {
		t.Errorf("Name = %q, want the original %q to be kept", stored.Name, original.Name)
	}
}

func TestMissingThreat(t *testing.T) {
	repo := New()

	if _, err := repo.Get(context.Background(), md5); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("Get error = %v, want ErrNotFound", err)
	}

	if _, err := repo.Update(context.Background(), md5, domain.Details{}, created); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("Update error = %v, want ErrNotFound", err)
	}
}

func TestUpdateReplacesDetailsAndKeepsIdentity(t *testing.T) {
	repo := New()

	if _, err := repo.Create(context.Background(), newThreat(t)); err != nil {
		t.Fatalf("Create: %v", err)
	}

	details := domain.Details{
		Name:     "Renamed",
		Severity: domain.SeverityLow,
		Category: domain.CategoryWorm,
		Tags:     []string{},
	}
	later := created.Add(time.Hour)

	got, err := repo.Update(context.Background(), md5, details, later)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}

	want := domain.Threat{MD5: md5, Details: details, CreatedAt: created, UpdatedAt: later}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Update = %+v, want %+v", got, want)
	}

	stored, _ := repo.Get(context.Background(), md5)
	if !reflect.DeepEqual(stored, want) {
		t.Errorf("Get = %+v, want %+v", stored, want)
	}
}

func TestStoredDataIsIsolatedFromCallers(t *testing.T) {
	repo := New()
	threat := newThreat(t)

	returned, err := repo.Create(context.Background(), threat)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	threat.Tags[0] = "changed through the input"
	returned.Tags[0] = "changed through the result"

	stored, _ := repo.Get(context.Background(), md5)
	stored.Tags[0] = "changed through Get"

	again, _ := repo.Get(context.Background(), md5)
	if again.Tags[0] != "dropper" {
		t.Errorf("Tags[0] = %q, want the stored value to stay intact", again.Tags[0])
	}
}

func TestConcurrentCreatesOfOneMD5HaveOneWinner(t *testing.T) {
	const workers = 50

	repo := New()
	threat := newThreat(t)

	var (
		wg        sync.WaitGroup
		created   atomic.Int32
		conflicts atomic.Int32
	)

	for range workers {
		wg.Add(1)

		go func() {
			defer wg.Done()

			switch _, err := repo.Create(context.Background(), threat); {
			case err == nil:
				created.Add(1)
			case errors.Is(err, domain.ErrConflict):
				conflicts.Add(1)
			}
		}()
	}

	wg.Wait()

	if created.Load() != 1 || conflicts.Load() != workers-1 {
		t.Errorf("created = %d, conflicts = %d, want 1 and %d", created.Load(), conflicts.Load(), workers-1)
	}
}
