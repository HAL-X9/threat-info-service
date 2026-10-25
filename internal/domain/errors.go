package domain

import (
	"errors"
	"fmt"
)

var (
	ErrNotFound   = errors.New("threat not found")
	ErrConflict   = errors.New("threat already exists")
	ErrValidation = errors.New("validation failed")
)

// invalid returns an ErrValidation that carries a human-readable reason.
func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrValidation, fmt.Sprintf(format, args...))
}
