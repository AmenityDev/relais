// Package authn proves who a submitter is.
//
// It answers exactly one question — "which credential is this?" — and stops
// there. Deciding what that credential may do belongs to internal/ingest, which
// is the single chokepoint both façades go through.
//
// Two properties are deliberate:
//
//   - Every failure looks the same to the client. Whether a credential is
//     unknown, revoked, disabled or simply presented with the wrong secret, the
//     answer is "authentication failed". The distinction is logged, because it is
//     the difference between a typo and a leaked key, but it is never told to
//     whoever is failing to authenticate.
//   - There is no cache. One lookup on a unique index costs almost nothing, and a
//     revoked credential has to stop working immediately: a cache would put a
//     window between "revoke" and "actually revoked", which is the one moment
//     revocation matters.
package authn

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/amenitydev/relais/internal/crypto"
	"github.com/amenitydev/relais/internal/store"
)

// ErrUnauthenticated is returned for every authentication failure, whatever the
// cause. Callers map it to a single generic response.
var ErrUnauthenticated = errors.New("authentication failed")

// Reasons recorded in the logs. These are for operators, never for clients.
const (
	reasonMalformed   = "malformed_credential"
	reasonUnknown     = "unknown_credential"
	reasonRevoked     = "revoked_credential"
	reasonDisabled    = "disabled_credential"
	reasonWrongSecret = "wrong_secret"
	reasonWrongType   = "wrong_credential_type"
)

// Authenticator resolves credentials.
type Authenticator struct {
	store *store.Store
	log   *slog.Logger
}

// New builds an Authenticator.
func New(st *store.Store, log *slog.Logger) (*Authenticator, error) {
	if st == nil {
		return nil, errors.New("authn: a store is required")
	}
	if log == nil {
		log = slog.Default()
	}
	return &Authenticator{store: st, log: log}, nil
}

// BearerToken extracts the token from an Authorization header value.
//
// Only the Bearer scheme is accepted. The prefix comparison is
// case-insensitive because RFC 7235 says the scheme is, and clients disagree
// about capitalisation.
func BearerToken(header string) (string, error) {
	const prefix = "bearer "

	value := strings.TrimSpace(header)
	if value == "" {
		return "", fmt.Errorf("%w: no Authorization header", ErrUnauthenticated)
	}
	if len(value) < len(prefix) || !strings.EqualFold(value[:len(prefix)], prefix) {
		return "", fmt.Errorf("%w: expected the Bearer scheme", ErrUnauthenticated)
	}

	token := strings.TrimSpace(value[len(prefix):])
	if token == "" {
		return "", fmt.Errorf("%w: empty bearer token", ErrUnauthenticated)
	}
	return token, nil
}

// APIKey authenticates a REST submission from its bearer token.
func (a *Authenticator) APIKey(ctx context.Context, token string, remoteIP string) (store.AuthCredential, error) {
	lookup, secret, err := crypto.ParseAPIKey(token)
	if err != nil {
		// A malformed token never reaches the database: there is nothing to look
		// up, and the shape of a key is not a secret.
		a.reject(reasonMalformed, "", remoteIP, err)
		return store.AuthCredential{}, ErrUnauthenticated
	}
	return a.verify(ctx, lookup, secret, store.CredentialTypeAPIKey, remoteIP)
}

// SMTPUser authenticates a submission-server session from its AUTH credentials.
//
// The username is the credential's lookup value, which is what makes one query
// path serve both façades.
func (a *Authenticator) SMTPUser(ctx context.Context, username, password, remoteIP string) (store.AuthCredential, error) {
	lookup, err := crypto.NormalizeSMTPUsername(username)
	if err != nil {
		a.reject(reasonMalformed, "", remoteIP, err)
		return store.AuthCredential{}, ErrUnauthenticated
	}
	return a.verify(ctx, lookup, password, store.CredentialTypeSMTPUser, remoteIP)
}

// verify is the shared path: find the credential, check its state, check the
// secret.
func (a *Authenticator) verify(
	ctx context.Context,
	lookup, secret, wantType, remoteIP string,
) (store.AuthCredential, error) {
	auth, err := a.store.LoadCredentialByLookup(ctx, lookup)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// A dummy verification, so that a present credential and an absent one
			// take comparable time. The lookup value has 60 bits of entropy, which
			// already makes enumeration hopeless; this simply removes the signal
			// rather than relying on that.
			a.store.VerifySecret(secret, store.AuthCredential{})
			a.reject(reasonUnknown, lookup, remoteIP, nil)
			return store.AuthCredential{}, ErrUnauthenticated
		}
		// A database failure is not an authentication failure: the caller must
		// answer 503, not 401, or an outage would look like a credential problem.
		return store.AuthCredential{}, fmt.Errorf("load credential: %w", err)
	}

	// The secret is checked before the state, so that a wrong secret against a
	// revoked credential is reported as a wrong secret. Reporting "revoked" would
	// confirm to whoever holds a stale key that the key was once real.
	if !a.store.VerifySecret(secret, auth) {
		a.rejectCredential(reasonWrongSecret, auth, remoteIP)
		return store.AuthCredential{}, ErrUnauthenticated
	}

	if auth.Credential.Type != wantType {
		// An API key presented over SMTP AUTH, or the reverse. Both are real
		// mistakes worth logging, and neither should work: the two types have
		// different secret formats and different intended surfaces.
		a.rejectCredential(reasonWrongType, auth, remoteIP)
		return store.AuthCredential{}, ErrUnauthenticated
	}

	switch {
	case auth.Credential.RevokedAt != nil:
		// The signal that matters most here: a revoked credential is still being
		// used, by something that has not been told to stop.
		a.rejectCredential(reasonRevoked, auth, remoteIP)
		return store.AuthCredential{}, ErrUnauthenticated
	case !auth.Credential.Enabled:
		a.rejectCredential(reasonDisabled, auth, remoteIP)
		return store.AuthCredential{}, ErrUnauthenticated
	}

	return auth, nil
}

// reject logs a failure that could not be attributed to a known credential.
func (a *Authenticator) reject(reason, lookup, remoteIP string, cause error) {
	attrs := []any{
		slog.String("reason", reason),
		slog.String("remote_ip", remoteIP),
	}
	if lookup != "" {
		// The lookup is the public half of the credential, so recording it is
		// safe and it is what lets an operator recognise a stale deployment.
		attrs = append(attrs, slog.String("credential_lookup", lookup))
	}
	if cause != nil {
		attrs = append(attrs, slog.String("detail", cause.Error()))
	}
	a.log.Warn("authentication failed", attrs...)
}

// rejectCredential logs a failure against a credential that does exist.
func (a *Authenticator) rejectCredential(reason string, auth store.AuthCredential, remoteIP string) {
	a.log.Warn("authentication failed",
		slog.String("reason", reason),
		slog.String("remote_ip", remoteIP),
		slog.String("credential_id", auth.Credential.ID.String()),
		slog.String("credential_name", auth.Credential.Name),
		slog.String("credential_type", auth.Credential.Type),
	)
}
