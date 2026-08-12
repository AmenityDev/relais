// Package store is the only place that reads or writes relais' own tables.
//
// It sits on top of the sqlc-generated queries and adds the invariants that
// cannot live in SQL: sealing and opening backend passwords, minting credential
// secrets, normalizing domains, and validating sender patterns before they are
// persisted. Callers (the CLI, the admin API, the ingest pipeline) never see a
// sealed envelope or an unvalidated pattern.
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/amenitydev/relais/internal/crypto"
	dbgen "github.com/amenitydev/relais/internal/db/gen"
	"github.com/amenitydev/relais/internal/frompattern"
)

// Sentinel errors let callers map failures onto HTTP statuses and SMTP replies
// without inspecting driver-specific error types.
var (
	// ErrNotFound reports a row that does not exist.
	ErrNotFound = errors.New("not found")
	// ErrConflict reports a uniqueness violation, such as a duplicate credential
	// name or an SMTP username already in use.
	ErrConflict = errors.New("conflict")
	// ErrReference reports a foreign-key violation, which Postgres raises in both
	// directions: deleting a row something else points at (a backend still
	// carrying domains), and inserting a row pointing at something absent (a
	// pattern for a credential that does not exist). Which one it is depends on
	// the operation, so callers phrase the message themselves.
	ErrReference = errors.New("foreign key violation")
	// ErrConstraint reports a CHECK violation, which means a bug: the Go side
	// should have rejected the value before it reached the database.
	ErrConstraint = errors.New("violates a database constraint")
	// ErrValidation reports a value the store itself refused, before any query ran.
	//
	// It exists so a caller can tell "the request was wrong" from "the database
	// failed" without inspecting error text. An earlier version of the admin API
	// guessed by substring and classified "refusing SMTP AUTH over a plaintext
	// backend connection" as a database problem, because the message happens to
	// contain the word "connection" — answering 503 to a request that was simply
	// invalid.
	ErrValidation = errors.New("invalid value")
)

// invalid builds a validation error carrying ErrValidation.
func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrValidation}, args...)...)
}

// Store holds the database handles and the key material.
type Store struct {
	pool    *pgxpool.Pool
	q       *dbgen.Queries
	keyring *crypto.Keyring
	hasher  *crypto.Hasher
}

// New builds a Store. The keyring and hasher are required: every write path
// either seals a password or fingerprints a secret.
func New(pool *pgxpool.Pool, keyring *crypto.Keyring, hasher *crypto.Hasher) (*Store, error) {
	switch {
	case pool == nil:
		return nil, errors.New("store: a database pool is required")
	case keyring == nil:
		return nil, errors.New("store: an encryption keyring is required")
	case hasher == nil:
		return nil, errors.New("store: a credential hasher is required")
	}
	return &Store{pool: pool, q: dbgen.New(pool), keyring: keyring, hasher: hasher}, nil
}

// Pool exposes the underlying pool for the components that need their own
// handle, such as the river client.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Queries exposes the generated queries for read paths that need no extra
// invariant. Write paths should go through a Store method so the invariants stay
// in one place.
func (s *Store) Queries() *dbgen.Queries { return s.q }

// withTx runs fn inside a transaction, rolling back on error.
func (s *Store) withTx(ctx context.Context, fn func(*dbgen.Queries) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	// Rollback after a successful commit is a no-op, so this needs no flag.
	defer func() { _ = tx.Rollback(ctx) }()

	if err := fn(s.q.WithTx(tx)); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}

// ConstraintError names the database constraint that rejected a write.
//
// It matches the sentinels through errors.Is, so ordinary callers write
// errors.Is(err, ErrConflict), while the few that need to react to a specific
// constraint (retrying a colliding generated lookup, for instance) can pull the
// name out with errors.As.
type ConstraintError struct {
	Sentinel   error
	Constraint string
	err        error
}

func (e *ConstraintError) Error() string {
	if e.Constraint == "" {
		return e.Sentinel.Error()
	}
	return e.Sentinel.Error() + " (" + e.Constraint + ")"
}

// Is reports a match against the sentinel this error stands for.
func (e *ConstraintError) Is(target error) bool { return target == e.Sentinel }

// Unwrap keeps the driver error reachable for debugging.
func (e *ConstraintError) Unwrap() error { return e.err }

// ConstraintName returns the violated constraint, or "" when the error is not a
// constraint violation.
func ConstraintName(err error) string {
	var ce *ConstraintError
	if errors.As(err, &ce) {
		return ce.Constraint
	}
	return ""
}

// classify turns a driver error into one of the package's sentinel errors.
//
// Doing this once, here, is what keeps pgx error codes out of the HTTP and SMTP
// layers.
func classify(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		var sentinel error
		switch pgErr.Code {
		case "23505": // unique_violation
			sentinel = ErrConflict
		// 23503 is a plain foreign-key violation; 23001 is what a RESTRICT
		// (rather than NO ACTION) referential action raises, which is how
		// domain.smtp_backend_id is declared. Both mean "a reference stands in
		// the way".
		case "23503", "23001":
			sentinel = ErrReference
		case "23514": // check_violation
			sentinel = ErrConstraint
		}
		if sentinel != nil {
			return &ConstraintError{Sentinel: sentinel, Constraint: pgErr.ConstraintName, err: err}
		}
	}
	return err
}

// wrap annotates an error with the operation that produced it, after classifying
// it, so callers can both match a sentinel and read what failed.
func wrap(op string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", op, classify(err))
}

// normalizePatterns parses and de-duplicates a raw pattern list.
//
// It is called on every write path that touches patterns, so an invalid pattern
// can never reach the database, and the database CHECK never has to be the thing
// that catches an operator's typo.
func normalizePatterns(raw []string) ([]string, error) {
	set, err := frompattern.NewSet(raw)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, set.Len())
	for _, p := range set.Patterns() {
		out = append(out, p.String())
	}
	return out, nil
}
