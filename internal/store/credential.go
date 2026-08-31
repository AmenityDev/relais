package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/amenitydev/relais/internal/crypto"
	dbgen "github.com/amenitydev/relais/internal/db/gen"
	"github.com/amenitydev/relais/internal/frompattern"
)

// Credential types accepted by credential.type.
const (
	// CredentialTypeAPIKey authenticates over the REST façade with a bearer token.
	CredentialTypeAPIKey = "api_key"
	// CredentialTypeSMTPUser authenticates over the submission server with
	// AUTH PLAIN or AUTH LOGIN, after STARTTLS.
	CredentialTypeSMTPUser = "smtp_user"
)

// lookupCollisionRetries bounds how many times a generated lookup is re-drawn
// after a uniqueness collision. A collision is astronomically unlikely; the
// retry exists so that the impossible case is not an outage.
const lookupCollisionRetries = 3

// touchInterval is how coarse credential.last_used_at is allowed to be. Writing
// on every request would put a row update on the hot path for no benefit.
const touchInterval = 5 * time.Minute

// NewCredentialParams describes a credential to mint.
type NewCredentialParams struct {
	Name string
	// Type is one of the CredentialType* constants.
	Type string
	// SMTPUsername is used only for CredentialTypeSMTPUser. Empty means "generate
	// one", which is the safe default for machine-to-machine use.
	SMTPUsername string
	// Patterns is the sender allow-list. It may be empty, and an empty list means
	// the credential can send as nobody until patterns are added.
	Patterns []string
	// RecipientPatterns is the recipient allow-list, and an empty list means the
	// opposite of the one above: no restriction, so the credential may mail
	// anyone. See RecipientRules.
	RecipientPatterns []string
	// RateLimitRPS and RateLimitBurst override the process defaults when set.
	RateLimitRPS   *float64
	RateLimitBurst *int32
	// CreatedBy records the actor: an OIDC subject from the admin API, or a CLI
	// marker.
	CreatedBy string
	Enabled   bool
}

func (p *NewCredentialParams) normalize() error {
	p.Name = strings.TrimSpace(p.Name)
	p.Type = strings.ToLower(strings.TrimSpace(p.Type))
	p.CreatedBy = strings.TrimSpace(p.CreatedBy)

	switch {
	case p.Name == "":
		return invalid("credential name is required")
	case p.Type != CredentialTypeAPIKey && p.Type != CredentialTypeSMTPUser:
		return invalid("credential type %q: want %s or %s", p.Type, CredentialTypeAPIKey, CredentialTypeSMTPUser)
	case p.Type == CredentialTypeAPIKey && p.SMTPUsername != "":
		return invalid("an SMTP username makes no sense for an api_key credential")
	case p.RateLimitRPS != nil && *p.RateLimitRPS <= 0:
		return invalid("rate limit rps must be greater than zero")
	case p.RateLimitBurst != nil && *p.RateLimitBurst <= 0:
		return invalid("rate limit burst must be greater than zero")
	}
	return nil
}

// CreatedCredential is the result of minting a credential.
//
// Secret is the only moment the plaintext exists. It is not stored anywhere and
// cannot be recovered: the caller must show it to the operator once and then
// forget it.
type CreatedCredential struct {
	Credential dbgen.Credential
	Secret     crypto.Secret
	Patterns   []string
	// RecipientPatterns is empty both when none were asked for and when the
	// credential is deliberately unrestricted — those are the same state.
	RecipientPatterns []string
}

// CreateCredential mints a secret and inserts the credential with its patterns
// in a single transaction.
//
// Either the credential and all of its patterns exist, or none of them do: a
// credential that came into being with a partial allow-list would be a
// credential whose authority nobody had reviewed.
func (s *Store) CreateCredential(ctx context.Context, p NewCredentialParams) (CreatedCredential, error) {
	if err := p.normalize(); err != nil {
		return CreatedCredential{}, err
	}

	patterns, err := normalizePatterns(p.Patterns)
	if err != nil {
		return CreatedCredential{}, err
	}
	recipientPatterns, err := normalizePatterns(p.RecipientPatterns)
	if err != nil {
		return CreatedCredential{}, invalid("recipient patterns: %w", err)
	}

	for attempt := range lookupCollisionRetries {
		minted, err := s.mintFor(p)
		if err != nil {
			return CreatedCredential{}, err
		}

		var row dbgen.Credential
		err = s.withTx(ctx, func(q *dbgen.Queries) error {
			var txErr error
			row, txErr = q.CreateCredential(ctx, dbgen.CreateCredentialParams{
				Name:           p.Name,
				Type:           p.Type,
				Lookup:         minted.Lookup,
				SecretHmac:     minted.HMAC,
				Enabled:        p.Enabled,
				RateLimitRps:   p.RateLimitRPS,
				RateLimitBurst: p.RateLimitBurst,
				CreatedBy:      p.CreatedBy,
			})
			if txErr != nil {
				return txErr
			}
			for _, pattern := range patterns {
				if _, txErr := q.AddFromPattern(ctx, dbgen.AddFromPatternParams{
					CredentialID: row.ID,
					Pattern:      pattern,
				}); txErr != nil {
					return txErr
				}
			}
			// Same transaction as the credential and its sender patterns: a
			// credential that came into being restricted-in-intent but unrestricted
			// in fact is the one shape of partial creation that matters here.
			for _, pattern := range recipientPatterns {
				if _, txErr := q.AddRecipientPattern(ctx, dbgen.AddRecipientPatternParams{
					CredentialID: row.ID,
					Pattern:      pattern,
				}); txErr != nil {
					return txErr
				}
			}
			return nil
		})

		switch {
		case err == nil:
			return CreatedCredential{
				Credential:        row,
				Secret:            crypto.Secret(minted.Plaintext),
				Patterns:          patterns,
				RecipientPatterns: recipientPatterns,
			}, nil

		// Only a collision on the generated lookup is worth retrying, and only
		// when we are the ones who generated it. A duplicate name, or an SMTP
		// username the operator chose, must be reported so they can pick another.
		case ConstraintName(classify(err)) == "credential_lookup_key" &&
			p.Type == CredentialTypeAPIKey &&
			attempt < lookupCollisionRetries-1:
			continue

		default:
			return CreatedCredential{}, wrap("create credential", err)
		}
	}
	return CreatedCredential{}, errors.New("create credential: could not draw a unique lookup value")
}

func (s *Store) mintFor(p NewCredentialParams) (crypto.Minted, error) {
	if p.Type == CredentialTypeAPIKey {
		return s.hasher.MintAPIKey()
	}

	username := p.SMTPUsername
	if strings.TrimSpace(username) == "" {
		generated, err := crypto.GenerateSMTPUsername()
		if err != nil {
			return crypto.Minted{}, err
		}
		username = generated
	}
	return s.hasher.MintSMTPPassword(username)
}

// AuthCredential is a credential together with its compiled allow-lists, which
// is everything the pipeline needs to authenticate a submission and decide
// whether the sender is permitted and the recipients are in bounds.
type AuthCredential struct {
	Credential dbgen.Credential
	Patterns   frompattern.Set
	Recipients RecipientRules
}

// RecipientRules is a credential's recipient allow-list: which addresses it may
// send *to*.
//
// The empty value allows everything, and that is the whole reason this type
// exists rather than a bare frompattern.Set. The sender allow-list reads
// "an empty set matches nothing"; this one reads "an unrestricted credential may
// mail anyone". Both are correct and they are opposites, so a caller reaching for
// Set.Allows on recipient patterns would invert the policy — silently, and in the
// direction that refuses every legitimate send. Wrapping the set in a type whose
// only matching method carries the right default makes that mistake unwriteable.
//
// A recipient allow-list is a guardrail, not an authentication primitive: it
// exists so a staging credential cannot mail a real customer by accident. The
// sender allow-list is what answers "who is this and what may they claim to be",
// and it stays closed by default.
type RecipientRules struct {
	set frompattern.Set
}

// NewRecipientRules compiles a recipient allow-list. An empty input is valid and
// means unrestricted.
func NewRecipientRules(raw []string) (RecipientRules, error) {
	set, err := frompattern.NewSet(raw)
	if err != nil {
		return RecipientRules{}, err
	}
	return RecipientRules{set: set}, nil
}

// Restricted reports whether the credential is limited to particular recipients.
func (r RecipientRules) Restricted() bool { return r.set.Len() > 0 }

// Allows reports whether addr may be mailed. An unrestricted credential allows
// every address.
func (r RecipientRules) Allows(addr frompattern.Address) bool {
	if !r.Restricted() {
		return true
	}
	return r.set.Allows(addr)
}

// MatchedBy returns the pattern that authorizes addr, when one does.
//
// Deliberately not the same question as Allows: an unrestricted credential
// allows every address and is matched by no pattern, so this returns false where
// Allows returns true. Anything deciding whether to deliver must call Allows;
// this exists to explain an answer to an operator.
func (r RecipientRules) MatchedBy(addr frompattern.Address) (frompattern.Pattern, bool) {
	return r.set.Match(addr)
}

// Patterns returns the compiled patterns, for display. Empty means unrestricted.
func (r RecipientRules) Patterns() []frompattern.Pattern { return r.set.Patterns() }

// Strings returns the patterns in canonical form.
func (r RecipientRules) Strings() []string {
	out := make([]string, 0, r.set.Len())
	for _, p := range r.set.Patterns() {
		out = append(out, p.String())
	}
	return out
}

// Usable reports whether the credential may be used right now.
func (c AuthCredential) Usable() bool {
	return c.Credential.Enabled && c.Credential.RevokedAt == nil
}

// RateLimit returns the credential's overrides, falling back to the supplied
// defaults.
func (c AuthCredential) RateLimit(defaultRPS float64, defaultBurst int) (float64, int) {
	rps, burst := defaultRPS, defaultBurst
	if c.Credential.RateLimitRps != nil {
		rps = *c.Credential.RateLimitRps
	}
	if c.Credential.RateLimitBurst != nil {
		burst = int(*c.Credential.RateLimitBurst)
	}
	return rps, burst
}

// LoadCredentialByLookup fetches a credential and its allow-list by lookup value.
//
// Disabled and revoked credentials are returned too: the caller checks Usable
// and logs the distinction, because "a revoked key is still being used" is a
// materially different signal from "an unknown key was presented". Clients are
// told nothing beyond a generic authentication failure either way.
func (s *Store) LoadCredentialByLookup(ctx context.Context, lookup string) (AuthCredential, error) {
	row, err := s.q.GetCredentialByLookup(ctx, lookup)
	if err != nil {
		return AuthCredential{}, wrap("get credential by lookup", err)
	}
	return s.withPatterns(ctx, row)
}

// LoadCredential fetches a credential and its allow-list by id.
func (s *Store) LoadCredential(ctx context.Context, id uuid.UUID) (AuthCredential, error) {
	row, err := s.q.GetCredential(ctx, id)
	if err != nil {
		return AuthCredential{}, wrap("get credential", err)
	}
	return s.withPatterns(ctx, row)
}

func (s *Store) withPatterns(ctx context.Context, row dbgen.Credential) (AuthCredential, error) {
	stored, err := s.q.ListFromPatterns(ctx, row.ID)
	if err != nil {
		return AuthCredential{}, wrap("list sender patterns", err)
	}

	raw := make([]string, 0, len(stored))
	for _, p := range stored {
		raw = append(raw, p.Pattern)
	}

	set, err := frompattern.NewSet(raw)
	if err != nil {
		// A stored pattern that no longer parses means the grammar changed under
		// existing data. Failing closed is the only safe response: the
		// alternative is guessing which patterns the operator still meant.
		return AuthCredential{}, invalid("credential %q has an unparsable sender pattern: %w", row.Name, err)
	}

	storedRecipients, err := s.q.ListRecipientPatterns(ctx, row.ID)
	if err != nil {
		return AuthCredential{}, wrap("list recipient patterns", err)
	}
	rawRecipients := make([]string, 0, len(storedRecipients))
	for _, p := range storedRecipients {
		rawRecipients = append(rawRecipients, p.Pattern)
	}
	// Failing closed here means refusing the send, exactly as above. An
	// unparsable recipient pattern must not degrade to "unrestricted": that would
	// turn a corrupted guardrail into no guardrail, which is the one outcome the
	// operator who configured it was protecting against.
	recipients, err := NewRecipientRules(rawRecipients)
	if err != nil {
		return AuthCredential{}, invalid("credential %q has an unparsable recipient pattern: %w", row.Name, err)
	}

	return AuthCredential{Credential: row, Patterns: set, Recipients: recipients}, nil
}

// VerifySecret checks a presented secret against the stored fingerprint.
func (s *Store) VerifySecret(secret string, c AuthCredential) bool {
	return s.hasher.Verify(secret, c.Credential.SecretHmac)
}

// ListCredentials returns every credential with how many patterns it carries.
func (s *Store) ListCredentials(ctx context.Context) ([]dbgen.ListCredentialsRow, error) {
	rows, err := s.q.ListCredentials(ctx)
	if err != nil {
		return nil, wrap("list credentials", err)
	}
	return rows, nil
}

// RevokeCredential disables a credential permanently. It is idempotent, and
// there is no un-revoke: restoring access means issuing a new secret.
func (s *Store) RevokeCredential(ctx context.Context, id uuid.UUID) (dbgen.Credential, error) {
	row, err := s.q.RevokeCredential(ctx, id)
	if err != nil {
		return dbgen.Credential{}, wrap("revoke credential", err)
	}
	return row, nil
}

// RotateCredentialSecret mints a fresh secret for an existing credential and
// replaces the stored fingerprint, which invalidates the old secret at once:
// nothing is left to verify it against.
//
// Everything else about the credential survives — its id, name, limits,
// allow-list and the messages that point at it — so rotating is not the same
// thing as replacing. That is the whole reason it exists: the alternative,
// "create a new credential and revoke this one", also throws away the allow-list
// an operator reviewed and the id everything else recorded.
//
// An smtp_user keeps its username. SMTP AUTH sends the two halves separately, so
// there is no reason to make an operator re-key both, and the username is not
// secret. An api_key cannot keep its lookup, because the lookup is a slice of the
// token itself: a rotated key is a new token in full.
//
// A revoked credential cannot be rotated. Revocation is permanent, and rotating
// past it would restore authority that was deliberately withdrawn.
func (s *Store) RotateCredentialSecret(ctx context.Context, id uuid.UUID) (CreatedCredential, error) {
	existing, err := s.q.GetCredential(ctx, id)
	if err != nil {
		return CreatedCredential{}, wrap("get credential", err)
	}
	if existing.RevokedAt != nil {
		return CreatedCredential{}, invalid(
			"credential %q is revoked: revocation is permanent, so a new credential is the only way back",
			existing.Name)
	}

	for attempt := range lookupCollisionRetries {
		// SMTPUsername is the current lookup, so an smtp_user is re-minted against
		// the username it already has; mintFor ignores the field for an api_key.
		minted, err := s.mintFor(NewCredentialParams{Type: existing.Type, SMTPUsername: existing.Lookup})
		if err != nil {
			return CreatedCredential{}, err
		}

		row, err := s.q.RotateCredentialSecret(ctx, dbgen.RotateCredentialSecretParams{
			ID:         id,
			Lookup:     minted.Lookup,
			SecretHmac: minted.HMAC,
		})
		switch {
		case err == nil:
			patterns, err := s.q.ListFromPatterns(ctx, id)
			if err != nil {
				return CreatedCredential{}, wrap("list sender patterns", err)
			}
			raw := make([]string, 0, len(patterns))
			for _, p := range patterns {
				raw = append(raw, p.Pattern)
			}
			return CreatedCredential{
				Credential: row,
				Secret:     crypto.Secret(minted.Plaintext),
				Patterns:   raw,
			}, nil

		// The query's revoked_at guard matched nothing, and the row was there a
		// moment ago: a revocation landed in between and it wins.
		case errors.Is(classify(err), ErrNotFound):
			return CreatedCredential{}, invalid(
				"credential %q was revoked while its secret was being rotated", existing.Name)

		// Same reasoning as CreateCredential: only a collision on a lookup *we*
		// drew is worth re-drawing, which is api_key only — an smtp_user rotation
		// writes its own username back and cannot collide with anything else.
		case ConstraintName(classify(err)) == "credential_lookup_key" &&
			existing.Type == CredentialTypeAPIKey &&
			attempt < lookupCollisionRetries-1:
			continue

		default:
			return CreatedCredential{}, wrap("rotate credential secret", err)
		}
	}
	return CreatedCredential{}, errors.New("rotate credential secret: could not draw a unique lookup value")
}

// DeleteCredential removes a credential row outright.
//
// This is not a heavier revoke, it is a different trade. Revocation keeps the row
// so "which credential sent this?" stays answerable forever; a delete drops it
// and email_message.credential_id falls to NULL (ON DELETE SET NULL). The
// messages survive with their sender, subject and status, but they no longer name
// what submitted them. Cutting off a leaked secret is a revoke; this is for
// clearing out a credential whose history nobody needs.
func (s *Store) DeleteCredential(ctx context.Context, id uuid.UUID) error {
	affected, err := s.q.DeleteCredential(ctx, id)
	if err != nil {
		return wrap("delete credential", err)
	}
	if affected == 0 {
		return fmt.Errorf("delete credential: %w", ErrNotFound)
	}
	return nil
}

// AddPatterns extends a credential's allow-list.
//
// Every pattern is validated first, so a malformed one rejects the whole call
// rather than leaving the allow-list half-extended.
func (s *Store) AddPatterns(ctx context.Context, credentialID uuid.UUID, raw []string) ([]string, error) {
	patterns, err := normalizePatterns(raw)
	if err != nil {
		return nil, err
	}
	if len(patterns) == 0 {
		return nil, invalid("no patterns to add")
	}

	err = s.withTx(ctx, func(q *dbgen.Queries) error {
		for _, pattern := range patterns {
			if _, err := q.AddFromPattern(ctx, dbgen.AddFromPatternParams{
				CredentialID: credentialID,
				Pattern:      pattern,
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, wrap("add sender patterns", err)
	}
	return patterns, nil
}

// RemovePattern drops one pattern from a credential's allow-list.
func (s *Store) RemovePattern(ctx context.Context, credentialID, patternID uuid.UUID) error {
	affected, err := s.q.DeleteFromPattern(ctx, dbgen.DeleteFromPatternParams{
		CredentialID: credentialID,
		ID:           patternID,
	})
	if err != nil {
		return wrap("remove sender pattern", err)
	}
	if affected == 0 {
		return fmt.Errorf("remove sender pattern: %w", ErrNotFound)
	}
	return nil
}

// ListPatterns returns a credential's stored patterns.
func (s *Store) ListPatterns(ctx context.Context, credentialID uuid.UUID) ([]dbgen.CredentialFromPattern, error) {
	rows, err := s.q.ListFromPatterns(ctx, credentialID)
	if err != nil {
		return nil, wrap("list sender patterns", err)
	}
	return rows, nil
}

// AddRecipientPatterns extends a credential's recipient allow-list.
//
// Adding the first pattern is the moment a credential stops being able to mail
// anyone, so this is a narrowing operation even though it is spelled "add".
func (s *Store) AddRecipientPatterns(ctx context.Context, credentialID uuid.UUID, raw []string) ([]string, error) {
	patterns, err := normalizePatterns(raw)
	if err != nil {
		return nil, err
	}
	if len(patterns) == 0 {
		return nil, invalid("no patterns to add")
	}

	err = s.withTx(ctx, func(q *dbgen.Queries) error {
		for _, pattern := range patterns {
			if _, err := q.AddRecipientPattern(ctx, dbgen.AddRecipientPatternParams{
				CredentialID: credentialID,
				Pattern:      pattern,
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, wrap("add recipient patterns", err)
	}
	return patterns, nil
}

// RemoveRecipientPattern drops one pattern from a credential's recipient
// allow-list.
//
// Removing the last one leaves the credential unrestricted again, which is a
// widening. Callers that audit this should say so.
func (s *Store) RemoveRecipientPattern(ctx context.Context, credentialID, patternID uuid.UUID) error {
	affected, err := s.q.DeleteRecipientPattern(ctx, dbgen.DeleteRecipientPatternParams{
		CredentialID: credentialID,
		ID:           patternID,
	})
	if err != nil {
		return wrap("remove recipient pattern", err)
	}
	if affected == 0 {
		return fmt.Errorf("remove recipient pattern: %w", ErrNotFound)
	}
	return nil
}

// ListRecipientPatterns returns a credential's stored recipient patterns. An
// empty result means the credential may send to anyone.
func (s *Store) ListRecipientPatterns(ctx context.Context, credentialID uuid.UUID) ([]dbgen.CredentialRecipientPattern, error) {
	rows, err := s.q.ListRecipientPatterns(ctx, credentialID)
	if err != nil {
		return nil, wrap("list recipient patterns", err)
	}
	return rows, nil
}

// TouchCredential records that a credential was used, at most once per
// touchInterval.
//
// Failure is not propagated to the caller's critical path by design: the caller
// logs it and carries on, because losing a usage timestamp must never fail a
// legitimate send.
func (s *Store) TouchCredential(ctx context.Context, id uuid.UUID) error {
	if err := s.q.TouchCredentialLastUsed(ctx, dbgen.TouchCredentialLastUsedParams{
		ID:          id,
		MinInterval: intervalOf(touchInterval),
	}); err != nil {
		return wrap("touch credential", err)
	}
	return nil
}

// intervalOf converts a Go duration into the pgtype.Interval that pgx expects
// for an `interval` parameter.
func intervalOf(d time.Duration) pgtype.Interval {
	return pgtype.Interval{Microseconds: d.Microseconds(), Valid: true}
}
