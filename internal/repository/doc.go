// Package repository is the PostgreSQL implementation of the storage interface
// declared by the service. Each operation is a single statement; uniqueness is
// decided by the primary key, and database errors are translated into the errors
// of the domain.
package repository
