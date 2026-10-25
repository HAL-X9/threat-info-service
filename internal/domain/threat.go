package domain

import (
	"strings"
	"time"
	"unicode/utf8"
)

// Limits of the threat fields, counted in characters, not bytes.
const (
	maxNameLength        = 255
	maxDescriptionLength = 2000
	maxTags              = 20
	maxTagLength         = 50
)

// Details is the part of a threat that clients supply and may replace.
type Details struct {
	Name        string
	Severity    Severity
	Category    Category
	Description string
	Tags        []string
}

// Threat is a known malicious file. Its MD5 and creation time never change.
type Threat struct {
	MD5 MD5
	Details
	CreatedAt time.Time
	UpdatedAt time.Time
}

// NewThreat validates and normalizes d and returns a threat created at now.
func NewThreat(md5 MD5, d Details, now time.Time) (Threat, error) {
	md5, err := ParseMD5(string(md5))
	if err != nil {
		return Threat{}, err
	}

	d, err = d.Normalized()
	if err != nil {
		return Threat{}, err
	}

	now = now.UTC()

	return Threat{MD5: md5, Details: d, CreatedAt: now, UpdatedAt: now}, nil
}

// Normalized returns d with the whitespace trimmed and the tags lowercased and
// deduplicated, or an ErrValidation if a field breaks its limits. The result
// never shares its tags with d, and normalizing it again changes nothing.
func (d Details) Normalized() (Details, error) {
	d.Name = strings.TrimSpace(d.Name)
	d.Description = strings.TrimSpace(d.Description)

	if n := utf8.RuneCountInString(d.Name); n == 0 || n > maxNameLength {
		return Details{}, invalid("name must be 1 to %d characters", maxNameLength)
	}

	if !d.Severity.Valid() {
		return Details{}, invalid("severity must be one of %v", severities)
	}

	if !d.Category.Valid() {
		return Details{}, invalid("category must be one of %v", categories)
	}

	if utf8.RuneCountInString(d.Description) > maxDescriptionLength {
		return Details{}, invalid("description must be at most %d characters", maxDescriptionLength)
	}

	tags, err := normalizeTags(d.Tags)
	if err != nil {
		return Details{}, err
	}

	d.Tags = tags

	return d, nil
}

func normalizeTags(tags []string) ([]string, error) {
	out := make([]string, 0, len(tags))
	seen := make(map[string]struct{}, len(tags))

	for _, tag := range tags {
		tag = strings.ToLower(strings.TrimSpace(tag))

		if n := utf8.RuneCountInString(tag); n == 0 || n > maxTagLength {
			return nil, invalid("each tag must be 1 to %d characters", maxTagLength)
		}

		if _, dup := seen[tag]; dup {
			continue
		}

		seen[tag] = struct{}{}
		out = append(out, tag)
	}

	if len(out) > maxTags {
		return nil, invalid("at most %d tags are allowed", maxTags)
	}

	return out, nil
}
