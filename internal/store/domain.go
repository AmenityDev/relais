package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/amenitydev/relais/internal/crypto"
	dbgen "github.com/amenitydev/relais/internal/db/gen"
	"github.com/amenitydev/relais/internal/frompattern"
)

// NewDomainParams describes a sending domain to register.
type NewDomainParams struct {
	// Name is normalized to lowercase punycode before insert.
	Name      string
	BackendID uuid.UUID
	// IncludeSubdomains lets senders in strict subdomains resolve through this
	// row. It must be set for a "*@*.example.com" sender pattern to be usable,
	// otherwise validation would pass and routing would then fail.
	IncludeSubdomains bool
	Enabled           bool
}

// CreateDomain registers a sending domain against a backend.
func (s *Store) CreateDomain(ctx context.Context, p NewDomainParams) (dbgen.Domain, error) {
	name, err := frompattern.NormalizeDomain(p.Name)
	if err != nil {
		return dbgen.Domain{}, err
	}
	if p.BackendID == uuid.Nil {
		return dbgen.Domain{}, invalid("domain %q: a backend is required", name)
	}

	row, err := s.q.CreateDomain(ctx, dbgen.CreateDomainParams{
		Name:              name,
		SmtpBackendID:     p.BackendID,
		IncludeSubdomains: p.IncludeSubdomains,
		Enabled:           p.Enabled,
	})
	if err != nil {
		return dbgen.Domain{}, wrap("create domain", err)
	}
	return row, nil
}

// GetDomainByID looks a domain up by id.
func (s *Store) GetDomainByID(ctx context.Context, id uuid.UUID) (dbgen.Domain, error) {
	row, err := s.q.GetDomain(ctx, id)
	if err != nil {
		return dbgen.Domain{}, wrap("get domain", err)
	}
	return row, nil
}

// GetDomainByName looks a domain up by its normalized name.
func (s *Store) GetDomainByName(ctx context.Context, name string) (dbgen.Domain, error) {
	normalized, err := frompattern.NormalizeDomain(name)
	if err != nil {
		return dbgen.Domain{}, err
	}
	row, err := s.q.GetDomainByName(ctx, normalized)
	if err != nil {
		return dbgen.Domain{}, wrap("get domain by name", err)
	}
	return row, nil
}

// ListDomains returns every domain with its backend's name.
func (s *Store) ListDomains(ctx context.Context) ([]dbgen.ListDomainsRow, error) {
	rows, err := s.q.ListDomains(ctx)
	if err != nil {
		return nil, wrap("list domains", err)
	}
	return rows, nil
}

// DeleteDomain removes a domain.
func (s *Store) DeleteDomain(ctx context.Context, id uuid.UUID) error {
	affected, err := s.q.DeleteDomain(ctx, id)
	if err != nil {
		return wrap("delete domain", err)
	}
	if affected == 0 {
		return fmt.Errorf("delete domain: %w", ErrNotFound)
	}
	return nil
}

// SenderRoute is everything needed to deliver a message for a given sender
// domain: which backend, how to reach it, and how to authenticate.
//
// AuthPassword is already decrypted, and is a crypto.Secret so that an
// accidental log line or JSON encode prints a placeholder.
type SenderRoute struct {
	DomainID   uuid.UUID
	DomainName string

	BackendID      uuid.UUID
	BackendName    string
	Host           string
	Port           int32
	TLSMode        string
	AuthUser       string
	AuthPassword   crypto.Secret
	HeloName       string
	MaxConcurrency int32
}

// UsesAuth reports whether this route should attempt SMTP AUTH.
func (r SenderRoute) UsesAuth() bool { return r.AuthUser != "" && !r.AuthPassword.IsEmpty() }

// Address returns the host:port to dial.
func (r SenderRoute) Address() string { return fmt.Sprintf("%s:%d", r.Host, r.Port) }

// ResolveSender finds the route governing a sender domain.
//
// Resolution happens at ingestion time, not at delivery time: a message whose
// domain is unknown is refused synchronously with a clear reason, and an
// accepted message pins the backend it was routed to so the audit trail survives
// a later re-assignment.
//
// An exact domain match wins; otherwise the closest ancestor that opted into
// include_subdomains is used. ErrNotFound means "this domain is not configured
// for sending", which is a rejection, not a server error.
func (s *Store) ResolveSender(ctx context.Context, senderDomain string) (SenderRoute, error) {
	normalized, err := frompattern.NormalizeDomain(senderDomain)
	if err != nil {
		return SenderRoute{}, err
	}

	row, err := s.q.ResolveSenderDomain(ctx, normalized)
	if err != nil {
		return SenderRoute{}, wrap("resolve sender domain", err)
	}

	password, err := s.OpenBackendPassword(row.AuthPasswordSealed)
	if err != nil {
		// The row exists but its password cannot be opened, which means the key
		// that sealed it is gone from the environment. This is an operator error
		// worth shouting about, not a rejection of the sender.
		return SenderRoute{}, invalid("backend %q for domain %q: %w", row.BackendName, row.DomainName, err)
	}

	return SenderRoute{
		DomainID:       row.DomainID,
		DomainName:     row.DomainName,
		BackendID:      row.BackendID,
		BackendName:    row.BackendName,
		Host:           row.Host,
		Port:           row.Port,
		TLSMode:        row.TlsMode,
		AuthUser:       row.AuthUser,
		AuthPassword:   password,
		HeloName:       row.HeloName,
		MaxConcurrency: row.MaxConcurrency,
	}, nil
}
