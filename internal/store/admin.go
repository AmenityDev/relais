package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/amenitydev/relais/internal/crypto"
	dbgen "github.com/amenitydev/relais/internal/db/gen"
	"github.com/amenitydev/relais/internal/frompattern"
)

// This file holds the write paths the admin API needs and the CLI does not. They
// live here for the same reason every other query does: the store is the only
// place that touches the tables, so an invariant cannot be enforced in one caller
// and forgotten in another.

// UpdateBackendParams describes a backend edit.
//
// RotatePassword decides whether AuthPassword is written at all. Without it, an
// admin editing a hostname would have to re-enter a password relais cannot show
// them — and the obvious workaround, sending an empty string, would silently wipe
// the credential.
type UpdateBackendParams struct {
	ID   uuid.UUID
	Name string
	Host string
	Port int32

	TLSMode  string
	AuthUser string

	RotatePassword bool
	AuthPassword   crypto.Secret

	HeloName       string
	MaxConcurrency int32
	Enabled        bool
}

// UpdateBackend edits a backend, optionally rotating its password.
func (s *Store) UpdateBackend(ctx context.Context, p UpdateBackendParams) (dbgen.SmtpBackend, error) {
	// The same validation as creation: an edit must not be able to reach a state
	// creation refuses.
	check := NewBackendParams{
		Name: p.Name, Host: p.Host, Port: p.Port, TLSMode: p.TLSMode,
		AuthUser: p.AuthUser, AuthPassword: p.AuthPassword,
		HeloName: p.HeloName, MaxConcurrency: p.MaxConcurrency, Enabled: p.Enabled,
	}
	if !p.RotatePassword {
		// The stored password is being kept, so the "user without password" rule
		// cannot be judged from this request alone. Read the existing row.
		existing, err := s.GetBackend(ctx, p.ID)
		if err != nil {
			return dbgen.SmtpBackend{}, err
		}
		if existing.AuthPasswordSealed != "" {
			check.AuthPassword = crypto.Secret("kept")
		}
	}
	if err := check.normalize(); err != nil {
		return dbgen.SmtpBackend{}, err
	}

	sealed := ""
	if p.RotatePassword {
		var err error
		if sealed, err = s.sealBackendPassword(p.AuthPassword); err != nil {
			return dbgen.SmtpBackend{}, err
		}
	}

	row, err := s.q.UpdateSMTPBackend(ctx, dbgen.UpdateSMTPBackendParams{
		ID:                 p.ID,
		Name:               check.Name,
		Host:               check.Host,
		Port:               check.Port,
		TlsMode:            check.TLSMode,
		AuthUser:           check.AuthUser,
		RotatePassword:     p.RotatePassword,
		AuthPasswordSealed: sealed,
		HeloName:           check.HeloName,
		MaxConcurrency:     check.MaxConcurrency,
		Enabled:            p.Enabled,
	})
	if err != nil {
		return dbgen.SmtpBackend{}, wrap("update smtp backend", err)
	}
	return row, nil
}

// UpdateDomain edits a domain.
func (s *Store) UpdateDomain(ctx context.Context, id uuid.UUID, p NewDomainParams) (dbgen.Domain, error) {
	name, err := frompattern.NormalizeDomain(p.Name)
	if err != nil {
		return dbgen.Domain{}, err
	}
	if p.BackendID == uuid.Nil {
		return dbgen.Domain{}, invalid("domain %q: a backend is required", name)
	}

	row, err := s.q.UpdateDomain(ctx, dbgen.UpdateDomainParams{
		ID:                id,
		Name:              name,
		SmtpBackendID:     p.BackendID,
		IncludeSubdomains: p.IncludeSubdomains,
		Enabled:           p.Enabled,
	})
	if err != nil {
		return dbgen.Domain{}, wrap("update domain", err)
	}
	return row, nil
}

// UpdateCredentialParams describes a credential edit.
//
// The secret is absent on purpose: relais holds only a fingerprint, so there is
// no old value to edit relative to. Replacing it is its own operation, with its
// own show-once response — see RotateCredentialSecret.
type UpdateCredentialParams struct {
	ID             uuid.UUID
	Name           string
	Enabled        bool
	RateLimitRPS   *float64
	RateLimitBurst *int32
}

// UpdateCredential edits a credential's name, state and limits.
func (s *Store) UpdateCredential(ctx context.Context, p UpdateCredentialParams) (dbgen.Credential, error) {
	name := strings.TrimSpace(p.Name)
	switch {
	case name == "":
		return dbgen.Credential{}, fmt.Errorf("credential name is required")
	case p.RateLimitRPS != nil && *p.RateLimitRPS <= 0:
		return dbgen.Credential{}, fmt.Errorf("rate limit rps must be greater than zero")
	case p.RateLimitBurst != nil && *p.RateLimitBurst <= 0:
		return dbgen.Credential{}, fmt.Errorf("rate limit burst must be greater than zero")
	}

	row, err := s.q.UpdateCredential(ctx, dbgen.UpdateCredentialParams{
		ID:             p.ID,
		Name:           name,
		Enabled:        p.Enabled,
		RateLimitRps:   p.RateLimitRPS,
		RateLimitBurst: p.RateLimitBurst,
	})
	if err != nil {
		return dbgen.Credential{}, wrap("update credential", err)
	}
	return row, nil
}

// MessageFilter narrows a message listing.
type MessageFilter struct {
	// Status filters on one status. Empty means all.
	Status string
	// CredentialID filters on one credential. Nil UUID means all.
	CredentialID uuid.UUID
	// Limit caps the page.
	Limit int32

	// BeforeCreatedAt and BeforeID are the keyset cursor: the last row of the
	// previous page. Keyset rather than OFFSET because the offset cost grows with
	// the table, and a message arriving mid-scroll would shift every later page.
	BeforeCreatedAt time.Time
	BeforeID        uuid.UUID
}

// ListMessages returns a page of messages, newest first.
func (s *Store) ListMessages(ctx context.Context, filter MessageFilter) ([]dbgen.ListEmailMessagesRow, error) {
	if filter.Limit <= 0 {
		filter.Limit = 50
	}

	// Absent filters are sent as NULL, which is what the query's IS NULL branches
	// test for. Sending a zero value instead would match nothing.
	params := dbgen.ListEmailMessagesParams{RowLimit: filter.Limit}
	if filter.Status != "" {
		params.Status = &filter.Status
	}
	if filter.CredentialID != uuid.Nil {
		params.CredentialFilter = &filter.CredentialID
	}
	if !filter.BeforeCreatedAt.IsZero() {
		params.BeforeCreatedAt = &filter.BeforeCreatedAt
		params.BeforeID = &filter.BeforeID
	}

	rows, err := s.q.ListEmailMessages(ctx, params)
	if err != nil {
		return nil, wrap("list messages", err)
	}
	return rows, nil
}

// PatternTestResult answers "would this credential be allowed to send as this
// address, and by which pattern?".
//
// It exists so the admin UI never has to reimplement the grammar: the answer comes
// from the same matcher the mail path uses, so the two cannot disagree.
type PatternTestResult struct {
	// Address is the normalized form of what was asked about.
	Address string
	Allowed bool
	// MatchedPattern is the pattern that authorized it, when one did.
	MatchedPattern string
	// Patterns is the credential's whole allow-list, for display.
	Patterns []string

	// RoutableDomain reports whether an enabled domain covers the sender. A
	// pattern can allow an address that no domain routes — the classic
	// "*@*.example.com without include_subdomains" mistake — and an operator
	// needs to see both answers at once.
	RoutableDomain bool
	BackendName    string
}

// TestPattern evaluates one address against one credential's allow-list.
func (s *Store) TestPattern(ctx context.Context, credentialID uuid.UUID, address string) (PatternTestResult, error) {
	auth, err := s.LoadCredential(ctx, credentialID)
	if err != nil {
		return PatternTestResult{}, err
	}

	addr, err := frompattern.ParseAddress(address)
	if err != nil {
		return PatternTestResult{}, err
	}

	result := PatternTestResult{Address: addr.String()}
	for _, pattern := range auth.Patterns.Patterns() {
		result.Patterns = append(result.Patterns, pattern.String())
	}

	if matched, ok := auth.Patterns.Match(addr); ok {
		result.Allowed = true
		result.MatchedPattern = matched.String()
	}

	// Answered whether or not the pattern matched: knowing that the domain is
	// unroutable is exactly as useful when the pattern is the thing that is wrong.
	route, err := s.ResolveSender(ctx, addr.Domain)
	switch {
	case err == nil:
		result.RoutableDomain = true
		result.BackendName = route.BackendName
	case isNotFound(err):
	default:
		return PatternTestResult{}, err
	}

	return result, nil
}

func isNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}
