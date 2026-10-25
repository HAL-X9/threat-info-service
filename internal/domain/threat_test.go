package domain

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func validDetails() Details {
	return Details{
		Name:        "Trojan.Win32.Generic",
		Severity:    SeverityHigh,
		Category:    CategoryTrojan,
		Description: "Drops and runs additional modules",
		Tags:        []string{"dropper", "persistence"},
	}
}

func TestNormalizedAcceptsAndNormalizes(t *testing.T) {
	tests := map[string]struct {
		mutate func(*Details)
		want   func(*Details)
	}{
		"already normal": {
			mutate: func(*Details) {},
			want:   func(*Details) {},
		},
		"trims name and description": {
			mutate: func(d *Details) { d.Name = "  Trojan  "; d.Description = "\tdescription\n" },
			want:   func(d *Details) { d.Name = "Trojan"; d.Description = "description" },
		},
		"lowercases and trims tags": {
			mutate: func(d *Details) { d.Tags = []string{" Dropper ", "PERSISTENCE"} },
			want:   func(*Details) {},
		},
		"drops duplicate tags, keeping the first": {
			mutate: func(d *Details) { d.Tags = []string{"b", "A", "a", "B", "c"} },
			want:   func(d *Details) { d.Tags = []string{"b", "a", "c"} },
		},
		"missing tags become an empty list": {
			mutate: func(d *Details) { d.Tags = nil },
			want:   func(d *Details) { d.Tags = []string{} },
		},
		"missing description": {
			mutate: func(d *Details) { d.Description = "" },
			want:   func(d *Details) { d.Description = "" },
		},
		"name of 255 characters": {
			mutate: func(d *Details) { d.Name = strings.Repeat("я", 255) },
			want:   func(d *Details) { d.Name = strings.Repeat("я", 255) },
		},
		"description of 2000 characters": {
			mutate: func(d *Details) { d.Description = strings.Repeat("я", 2000) },
			want:   func(d *Details) { d.Description = strings.Repeat("я", 2000) },
		},
		"20 tags": {
			mutate: func(d *Details) { d.Tags = tags(20) },
			want:   func(d *Details) { d.Tags = tags(20) },
		},
		"tag of 50 characters": {
			mutate: func(d *Details) { d.Tags = []string{strings.Repeat("я", 50)} },
			want:   func(d *Details) { d.Tags = []string{strings.Repeat("я", 50)} },
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			in, want := validDetails(), validDetails()
			tc.mutate(&in)
			tc.want(&want)

			got, err := in.Normalized()
			if err != nil {
				t.Fatalf("Normalized: %v", err)
			}

			if !reflect.DeepEqual(got, want) {
				t.Errorf("Normalized = %+v, want %+v", got, want)
			}

			again, err := got.Normalized()
			if err != nil || !reflect.DeepEqual(again, got) {
				t.Errorf("Normalized is not idempotent: %+v -> %+v (%v)", got, again, err)
			}
		})
	}
}

func TestNormalizedRejectsInvalidDetails(t *testing.T) {
	tests := map[string]struct {
		mutate  func(*Details)
		wantMsg string
	}{
		"empty name":             {func(d *Details) { d.Name = "" }, "name"},
		"blank name":             {func(d *Details) { d.Name = " \t " }, "name"},
		"name of 256 characters": {func(d *Details) { d.Name = strings.Repeat("я", 256) }, "name"},
		"unknown severity":       {func(d *Details) { d.Severity = "urgent" }, "severity"},
		"empty severity":         {func(d *Details) { d.Severity = "" }, "severity"},
		"severity in wrong case": {func(d *Details) { d.Severity = "HIGH" }, "severity"},
		"unknown category":       {func(d *Details) { d.Category = "virus" }, "category"},
		"empty category":         {func(d *Details) { d.Category = "" }, "category"},
		"description too long":   {func(d *Details) { d.Description = strings.Repeat("я", 2001) }, "description"},
		"21 tags":                {func(d *Details) { d.Tags = tags(21) }, "tags"},
		"empty tag":              {func(d *Details) { d.Tags = []string{"ok", ""} }, "tag"},
		"blank tag":              {func(d *Details) { d.Tags = []string{"  "} }, "tag"},
		"tag of 51 characters":   {func(d *Details) { d.Tags = []string{strings.Repeat("я", 51)} }, "tag"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			d := validDetails()
			tc.mutate(&d)

			_, err := d.Normalized()
			if !errors.Is(err, ErrValidation) {
				t.Fatalf("Normalized error = %v, want ErrValidation", err)
			}

			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error = %q, want it to mention %q", err, tc.wantMsg)
			}
		})
	}
}

func TestNormalizedDoesNotShareTagsWithTheInput(t *testing.T) {
	in := validDetails()

	got, err := in.Normalized()
	if err != nil {
		t.Fatalf("Normalized: %v", err)
	}

	got.Tags[0] = "changed"

	if in.Tags[0] != "dropper" {
		t.Errorf("the input tags were modified through the result: %v", in.Tags)
	}
}

func TestNewThreat(t *testing.T) {
	const md5 = MD5("d41d8cd98f00b204e9800998ecf8427e")

	local := time.Date(2026, 10, 24, 17, 30, 0, 0, time.FixedZone("MSK", 3*60*60))

	got, err := NewThreat(md5, validDetails(), local)
	if err != nil {
		t.Fatalf("NewThreat: %v", err)
	}

	if got.MD5 != md5 {
		t.Errorf("MD5 = %q, want %q", got.MD5, md5)
	}

	if !got.CreatedAt.Equal(local) || got.CreatedAt.Location() != time.UTC {
		t.Errorf("CreatedAt = %v, want %v in UTC", got.CreatedAt, local.UTC())
	}

	if !got.UpdatedAt.Equal(got.CreatedAt) {
		t.Errorf("UpdatedAt = %v, want it equal to CreatedAt %v", got.UpdatedAt, got.CreatedAt)
	}

	if !reflect.DeepEqual(got.Details, validDetails()) {
		t.Errorf("Details = %+v, want %+v", got.Details, validDetails())
	}
}

func TestNewThreatNormalizesItsInput(t *testing.T) {
	d := validDetails()
	d.Name = "  Trojan  "
	d.Tags = []string{"A", "a"}

	got, err := NewThreat("D41D8CD98F00B204E9800998ECF8427E", d, time.Now())
	if err != nil {
		t.Fatalf("NewThreat: %v", err)
	}

	if got.MD5 != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Errorf("MD5 = %q, want it lowercased", got.MD5)
	}

	if got.Name != "Trojan" || !reflect.DeepEqual(got.Tags, []string{"a"}) {
		t.Errorf("Details = %+v, want them normalized", got.Details)
	}
}

func TestNewThreatRejectsInvalidInput(t *testing.T) {
	bad := validDetails()
	bad.Name = ""

	tests := map[string]struct {
		md5     MD5
		details Details
	}{
		"invalid md5":     {"not-a-hash", validDetails()},
		"empty md5":       {"", validDetails()},
		"invalid details": {"d41d8cd98f00b204e9800998ecf8427e", bad},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := NewThreat(tc.md5, tc.details, time.Now())
			if !errors.Is(err, ErrValidation) {
				t.Fatalf("NewThreat error = %v, want ErrValidation", err)
			}

			if !reflect.DeepEqual(got, Threat{}) {
				t.Errorf("NewThreat returned %+v together with an error, want the zero value", got)
			}
		})
	}
}

func TestEnumsValid(t *testing.T) {
	for _, s := range []Severity{SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical} {
		if !s.Valid() {
			t.Errorf("Severity %q is not valid", s)
		}
	}

	for _, c := range []Category{CategoryTrojan, CategoryRansomware, CategoryWorm, CategorySpyware, CategoryAdware, CategoryOther} {
		if !c.Valid() {
			t.Errorf("Category %q is not valid", c)
		}
	}

	if Severity("").Valid() || Category("").Valid() {
		t.Error("an empty value must not be valid")
	}
}

func FuzzDetailsNormalized(f *testing.F) {
	f.Add("Trojan", "high", "trojan", "description", "a", "B")
	f.Add("  ", "", "", "", "", "")
	f.Add(strings.Repeat("я", 300), "low", "worm", "", "Tag", "tag")

	f.Fuzz(func(t *testing.T, name, severity, category, description, tag1, tag2 string) {
		in := Details{
			Name:        name,
			Severity:    Severity(severity),
			Category:    Category(category),
			Description: description,
			Tags:        []string{tag1, tag2},
		}

		got, err := in.Normalized()
		if err != nil {
			if !errors.Is(err, ErrValidation) {
				t.Fatalf("error = %v, want ErrValidation", err)
			}

			return
		}

		again, err := got.Normalized()
		if err != nil || !reflect.DeepEqual(again, got) {
			t.Fatalf("Normalized is not idempotent: %+v -> %+v (%v)", got, again, err)
		}

		if got.Tags == nil || len(got.Tags) > 2 {
			t.Fatalf("Tags = %#v, want a non-nil list without extra entries", got.Tags)
		}
	})
}

// tags returns n distinct tags.
func tags(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "tag" + string(rune('a'+i))
	}

	return out
}
