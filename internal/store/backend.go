package store

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/amenitydev/relais/internal/crypto"
	dbgen "github.com/amenitydev/relais/internal/db/gen"
)

// TLS modes accepted by smtp_backend.tls_mode.
const (
	// TLSModeSTARTTLS connects in the clear then upgrades. This is what OCI
	// Email Delivery expects on port 587.
	TLSModeSTARTTLS = "starttls"
	// TLSModeImplicit connects with TLS from the first byte (port 465).
	TLSModeImplicit = "tls"
	// TLSModeNone is plaintext, only usable for a local sink such as mailpit.
	// The schema refuses to store credentials alongside it.
	TLSModeNone = "none"
)

var validTLSModes = []string{TLSModeSTARTTLS, TLSModeImplicit, TLSModeNone}

// NewBackendParams describes a backend to create.
type NewBackendParams struct {
	Name string
	Host string
	Port int32
	// TLSMode is one of the TLSMode* constants.
	TLSMode string
	// AuthUser and AuthPassword may both be empty, meaning "do not attempt
	// SMTP AUTH". Supplying one without the other is refused.
	AuthUser     string
	AuthPassword crypto.Secret
	// HeloName overrides the EHLO name presented to this backend.
	HeloName       string
	MaxConcurrency int32
	Enabled        bool
}

func (p *NewBackendParams) normalize() error {
	p.Name = strings.TrimSpace(p.Name)
	p.Host = strings.TrimSpace(p.Host)
	p.TLSMode = strings.ToLower(strings.TrimSpace(p.TLSMode))
	p.AuthUser = strings.TrimSpace(p.AuthUser)
	p.HeloName = strings.TrimSpace(p.HeloName)

	if p.MaxConcurrency == 0 {
		p.MaxConcurrency = 2
	}

	switch {
	case p.Name == "":
		return invalid("backend name is required")
	case p.Host == "":
		return invalid("backend host is required")
	case p.Port < 1 || p.Port > 65535:
		return invalid("backend port %d is out of range", p.Port)
	case !slices.Contains(validTLSModes, p.TLSMode):
		return invalid("backend tls mode %q: want one of %s", p.TLSMode, strings.Join(validTLSModes, ", "))
	case p.MaxConcurrency < 1 || p.MaxConcurrency > 64:
		return invalid("backend max concurrency %d: want 1-64", p.MaxConcurrency)
	// A half-configured AUTH is a silent delivery failure waiting to happen, so
	// both halves are required together.
	case p.AuthUser != "" && p.AuthPassword.IsEmpty():
		return invalid("backend auth user was given without a password")
	case p.AuthUser == "" && !p.AuthPassword.IsEmpty():
		return invalid("backend auth password was given without a user")
	// Mirrors smtp_backend_no_plaintext_auth: never hand a password to a
	// plaintext connection.
	case p.TLSMode == TLSModeNone && p.AuthUser != "":
		return invalid("refusing SMTP AUTH over a plaintext backend connection: use starttls or tls")
	}
	return nil
}

// CreateBackend seals the password and inserts the backend.
func (s *Store) CreateBackend(ctx context.Context, p NewBackendParams) (dbgen.SmtpBackend, error) {
	if err := p.normalize(); err != nil {
		return dbgen.SmtpBackend{}, err
	}

	sealed, err := s.sealBackendPassword(p.AuthPassword)
	if err != nil {
		return dbgen.SmtpBackend{}, err
	}

	row, err := s.q.CreateSMTPBackend(ctx, dbgen.CreateSMTPBackendParams{
		Name:               p.Name,
		Host:               p.Host,
		Port:               p.Port,
		TlsMode:            p.TLSMode,
		AuthUser:           p.AuthUser,
		AuthPasswordSealed: sealed,
		HeloName:           p.HeloName,
		MaxConcurrency:     p.MaxConcurrency,
		Enabled:            p.Enabled,
	})
	if err != nil {
		return dbgen.SmtpBackend{}, wrap("create smtp backend", err)
	}
	return row, nil
}

// GetBackend fetches a backend by id.
func (s *Store) GetBackend(ctx context.Context, id uuid.UUID) (dbgen.SmtpBackend, error) {
	row, err := s.q.GetSMTPBackend(ctx, id)
	if err != nil {
		return dbgen.SmtpBackend{}, wrap("get smtp backend", err)
	}
	return row, nil
}

// GetBackendByName fetches a backend by name, case-insensitively.
func (s *Store) GetBackendByName(ctx context.Context, name string) (dbgen.SmtpBackend, error) {
	row, err := s.q.GetSMTPBackendByName(ctx, strings.TrimSpace(name))
	if err != nil {
		return dbgen.SmtpBackend{}, wrap("get smtp backend by name", err)
	}
	return row, nil
}

// ListBackends returns every backend, ordered by name.
func (s *Store) ListBackends(ctx context.Context) ([]dbgen.SmtpBackend, error) {
	rows, err := s.q.ListSMTPBackends(ctx)
	if err != nil {
		return nil, wrap("list smtp backends", err)
	}
	return rows, nil
}

// DeleteBackend removes a backend. It fails with ErrReference while any domain still
// points at it, which is the schema refusing to orphan a domain.
func (s *Store) DeleteBackend(ctx context.Context, id uuid.UUID) error {
	affected, err := s.q.DeleteSMTPBackend(ctx, id)
	if err != nil {
		return wrap("delete smtp backend", err)
	}
	if affected == 0 {
		return fmt.Errorf("delete smtp backend: %w", ErrNotFound)
	}
	return nil
}

// OpenBackendPassword decrypts a backend's stored password.
//
// The result is a crypto.Secret, so logging or serialising it yields a
// placeholder rather than the password.
func (s *Store) OpenBackendPassword(sealed string) (crypto.Secret, error) {
	if sealed == "" {
		return "", nil
	}
	plaintext, err := s.keyring.OpenString(sealed)
	if err != nil {
		return "", fmt.Errorf("open backend password: %w", err)
	}
	return crypto.Secret(plaintext), nil
}

func (s *Store) sealBackendPassword(password crypto.Secret) (string, error) {
	if password.IsEmpty() {
		return "", nil
	}
	sealed, err := s.keyring.SealString(password.Reveal())
	if err != nil {
		return "", fmt.Errorf("seal backend password: %w", err)
	}
	return sealed, nil
}

// RewrapBackendPasswords re-seals every backend password under the active key.
//
// This is the second half of a key rotation: add the new key and point the
// active id at it, then run this to retire the old key so it can be removed
// from the environment.
func (s *Store) RewrapBackendPasswords(ctx context.Context) (rewrapped int, err error) {
	rows, err := s.q.ListSMTPBackendsNeedingRewrap(ctx)
	if err != nil {
		return 0, wrap("list backends for rewrap", err)
	}

	for _, row := range rows {
		if !s.keyring.NeedsRewrap(row.AuthPasswordSealed) {
			continue
		}
		plaintext, err := s.keyring.OpenString(row.AuthPasswordSealed)
		if err != nil {
			// A key that is no longer configured cannot be opened. Report which
			// backend is stranded instead of failing anonymously.
			return rewrapped, fmt.Errorf("rewrap backend %q (%s): %w", row.Name, row.ID, err)
		}
		sealed, err := s.keyring.SealString(plaintext)
		if err != nil {
			return rewrapped, fmt.Errorf("rewrap backend %q (%s): %w", row.Name, row.ID, err)
		}
		if err := s.q.UpdateSMTPBackendSealedPassword(ctx, dbgen.UpdateSMTPBackendSealedPasswordParams{
			ID:                 row.ID,
			AuthPasswordSealed: sealed,
		}); err != nil {
			return rewrapped, wrap("store rewrapped backend password", err)
		}
		rewrapped++
	}
	return rewrapped, nil
}
