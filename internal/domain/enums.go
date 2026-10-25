package domain

import "slices"

// Severity is how dangerous a threat is.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

var severities = []Severity{SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}

func (s Severity) Valid() bool { return slices.Contains(severities, s) }

// Category is the kind of a threat.
type Category string

const (
	CategoryTrojan     Category = "trojan"
	CategoryRansomware Category = "ransomware"
	CategoryWorm       Category = "worm"
	CategorySpyware    Category = "spyware"
	CategoryAdware     Category = "adware"
	CategoryOther      Category = "other"
)

var categories = []Category{
	CategoryTrojan, CategoryRansomware, CategoryWorm,
	CategorySpyware, CategoryAdware, CategoryOther,
}

func (c Category) Valid() bool { return slices.Contains(categories, c) }
