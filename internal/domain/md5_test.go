package domain

import (
	"errors"
	"strings"
	"testing"
)

func TestParseMD5(t *testing.T) {
	const lower = "d41d8cd98f00b204e9800998ecf8427e"

	tests := map[string]struct {
		in      string
		want    MD5
		wantErr bool
	}{
		"lowercase":        {in: lower, want: lower},
		"uppercase":        {in: strings.ToUpper(lower), want: lower},
		"mixed case":       {in: "D41d8cd98f00B204e9800998ecF8427e", want: lower},
		"empty":            {in: "", wantErr: true},
		"too short":        {in: lower[:31], wantErr: true},
		"too long":         {in: lower + "0", wantErr: true},
		"not hexadecimal":  {in: "g41d8cd98f00b204e9800998ecf8427e", wantErr: true},
		"surrounding text": {in: " " + lower[:30] + " ", wantErr: true},
		"multibyte":        {in: "é" + lower[:30], wantErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := ParseMD5(tc.in)

			if tc.wantErr {
				if !errors.Is(err, ErrValidation) {
					t.Fatalf("ParseMD5(%q) error = %v, want ErrValidation", tc.in, err)
				}

				return
			}

			if err != nil {
				t.Fatalf("ParseMD5(%q): %v", tc.in, err)
			}

			if got != tc.want {
				t.Errorf("ParseMD5(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func FuzzParseMD5(f *testing.F) {
	for _, seed := range []string{
		"d41d8cd98f00b204e9800998ecf8427e",
		"D41D8CD98F00B204E9800998ECF8427E",
		"",
		"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
		"é41d8cd98f00b204e9800998ecf8427",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, in string) {
		got, err := ParseMD5(in)
		if err != nil {
			if !errors.Is(err, ErrValidation) {
				t.Fatalf("ParseMD5(%q) error = %v, want ErrValidation", in, err)
			}

			return
		}

		if len(got) != md5Length || got != MD5(strings.ToLower(string(got))) {
			t.Fatalf("ParseMD5(%q) = %q, want 32 lowercase characters", in, got)
		}

		if !strings.EqualFold(in, string(got)) {
			t.Fatalf("ParseMD5(%q) = %q changed more than the case", in, got)
		}

		if again, err := ParseMD5(string(got)); err != nil || again != got {
			t.Fatalf("ParseMD5 is not idempotent: %q -> %q -> %q (%v)", in, got, again, err)
		}
	})
}
