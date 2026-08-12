// Package adminauth verifies admin identities against Authentik.
//
// relais never handles an admin password. Authentik issues a signed JWT, the
// browser never sees it (the SvelteKit server holds it and forwards it), and this
// package checks the signature against the issuer's JWKS, the audience, and the
// group membership that decides what the holder may do.
//
// The load-bearing operational decision: **nothing here runs at startup**. The
// identity provider is discovered on the first admin request, not when the
// process boots. Mail delivery must never depend on Authentik being reachable —
// a service that refuses to start because the admin UI's identity provider is
// down is a service that stops relaying mail for a reason unrelated to mail.
package adminauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Errors callers map onto HTTP statuses. The three are genuinely different and
// must not be collapsed: a bad token is the caller's problem, a missing group is
// an authorisation decision, and an unreachable provider is ours.
var (
	// ErrUnauthenticated means the token is absent, malformed, expired, or not
	// signed by the configured issuer. Maps to 401.
	ErrUnauthenticated = errors.New("admin authentication failed")
	// ErrForbidden means the token is valid but its holder is in none of the
	// configured groups. Maps to 403: they exist, they are simply not allowed.
	ErrForbidden = errors.New("admin authorisation failed")
	// ErrProviderUnavailable means the identity provider could not be reached.
	// Maps to 503, never to 401: telling an admin their credentials are wrong when
	// Authentik is down sends them looking in the wrong place entirely.
	ErrProviderUnavailable = errors.New("identity provider unavailable")
	// ErrNotConfigured means no issuer was configured, so the admin API is off.
	ErrNotConfigured = errors.New("admin authentication is not configured")
)

// Role is what an identity may do.
type Role string

const (
	// RoleAdmin may read and write.
	RoleAdmin Role = "admin"
	// RoleViewer may only read.
	RoleViewer Role = "viewer"
)

// Identity is a verified admin.
type Identity struct {
	Subject string
	Email   string
	Name    string
	Groups  []string
	Role    Role
}

// CanWrite reports whether this identity may change anything.
func (i Identity) CanWrite() bool { return i.Role == RoleAdmin }

// String renders the identity for a log line, preferring whatever is most
// recognisable to an operator.
func (i Identity) String() string {
	switch {
	case i.Email != "":
		return i.Email
	case i.Name != "":
		return i.Name
	default:
		return i.Subject
	}
}

// Config parameterizes verification. It mirrors config.OIDC.
type Config struct {
	// Issuer is the Authentik application's issuer URL. Empty disables the admin
	// API entirely.
	Issuer string
	// Audience is the expected `aud` claim. Required alongside Issuer: an issuer
	// without an expected audience accepts tokens minted for any other client of
	// the same provider.
	Audience string
	// JWKSURL skips discovery when set. Setting it removes even the first-request
	// dependency on the discovery document.
	JWKSURL string

	GroupsClaim string
	AdminGroup  string
	ViewerGroup string

	// DiscoveryTimeout bounds one discovery attempt.
	DiscoveryTimeout time.Duration
	// DiscoveryRetryAfter is how long a failed discovery is remembered before
	// another attempt, so a down provider is not hammered once per request.
	DiscoveryRetryAfter time.Duration
}

// Verifier checks tokens.
type Verifier struct {
	cfg Config
	log *slog.Logger

	mu       sync.Mutex
	verifier *oidc.IDTokenVerifier
	// lastFailure and lastAttempt implement the retry window.
	lastFailure error
	lastAttempt time.Time
}

// New builds a Verifier without touching the network.
//
// It returns ErrNotConfigured when no issuer is set, which the caller treats as
// "the admin API is disabled" rather than as an error.
func New(cfg Config, log *slog.Logger) (*Verifier, error) {
	if strings.TrimSpace(cfg.Issuer) == "" {
		return nil, ErrNotConfigured
	}
	if strings.TrimSpace(cfg.Audience) == "" {
		// Refusing to start is right here: an issuer with no expected audience
		// accepts tokens minted for other applications of the same provider, which
		// looks like it works and is not authentication at all.
		return nil, errors.New("adminauth: an audience is required alongside the issuer")
	}

	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
	}
	if cfg.AdminGroup == "" {
		cfg.AdminGroup = "relais-admin"
	}
	if cfg.DiscoveryTimeout <= 0 {
		cfg.DiscoveryTimeout = 10 * time.Second
	}
	if cfg.DiscoveryRetryAfter <= 0 {
		cfg.DiscoveryRetryAfter = 15 * time.Second
	}
	if log == nil {
		log = slog.Default()
	}

	return &Verifier{cfg: cfg, log: log}, nil
}

// Verify checks a raw bearer token and resolves the identity behind it.
func (v *Verifier) Verify(ctx context.Context, rawToken string) (Identity, error) {
	token := strings.TrimSpace(rawToken)
	if token == "" {
		return Identity{}, fmt.Errorf("%w: no token", ErrUnauthenticated)
	}

	verifier, err := v.resolve(ctx)
	if err != nil {
		return Identity{}, err
	}

	verified, err := verifier.Verify(ctx, token)
	if err != nil {
		// Signature, expiry, issuer and audience failures all land here, and all
		// are the caller's problem. The reason is logged, not returned.
		v.log.Warn("admin token rejected", slog.String("detail", err.Error()))
		return Identity{}, fmt.Errorf("%w: %v", ErrUnauthenticated, err)
	}

	identity, err := v.identityOf(verified)
	if err != nil {
		return Identity{}, err
	}
	return identity, nil
}

// resolve returns the verifier, building it on first use.
//
// Discovery happens here rather than in New so that a provider outage affects the
// admin API and nothing else.
func (v *Verifier) resolve(ctx context.Context) (*oidc.IDTokenVerifier, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.verifier != nil {
		return v.verifier, nil
	}

	// A failed attempt is remembered briefly, so a down provider is not asked
	// once per request by every open browser tab.
	if v.lastFailure != nil && time.Since(v.lastAttempt) < v.cfg.DiscoveryRetryAfter {
		return nil, v.lastFailure
	}
	v.lastAttempt = time.Now()

	oidcConfig := &oidc.Config{
		ClientID: v.cfg.Audience,
		// Only asymmetric signatures: an HMAC-signed token would be verifiable by
		// anyone holding the shared secret, and there is no shared secret here.
		SupportedSigningAlgs: []string{oidc.RS256, oidc.RS384, oidc.RS512, oidc.ES256, oidc.ES384, oidc.ES512},
	}

	// With an explicit JWKS URL there is nothing to discover: keys are fetched
	// lazily on the first verification and cached from then on.
	if v.cfg.JWKSURL != "" {
		keySet := oidc.NewRemoteKeySet(context.WithoutCancel(ctx), v.cfg.JWKSURL)
		v.verifier = oidc.NewVerifier(v.cfg.Issuer, keySet, oidcConfig)
		v.lastFailure = nil
		v.log.Info("admin authentication ready",
			slog.String("issuer", v.cfg.Issuer),
			slog.String("jwks_url", v.cfg.JWKSURL),
		)
		return v.verifier, nil
	}

	discoveryCtx, cancel := context.WithTimeout(ctx, v.cfg.DiscoveryTimeout)
	defer cancel()

	provider, err := oidc.NewProvider(discoveryCtx, v.cfg.Issuer)
	if err != nil {
		v.lastFailure = fmt.Errorf("%w: discovering %s: %v", ErrProviderUnavailable, v.cfg.Issuer, err)
		v.log.Error("could not reach the identity provider",
			slog.String("issuer", v.cfg.Issuer),
			slog.Any("error", err),
			slog.Duration("retry_after", v.cfg.DiscoveryRetryAfter),
		)
		return nil, v.lastFailure
	}

	// The provider's key set outlives this request, so it must not be built on a
	// context that ends with it.
	v.verifier = provider.VerifierContext(context.WithoutCancel(ctx), oidcConfig)
	v.lastFailure = nil
	v.log.Info("admin authentication ready", slog.String("issuer", v.cfg.Issuer))
	return v.verifier, nil
}

// identityOf extracts the claims and resolves the role.
func (v *Verifier) identityOf(token *oidc.IDToken) (Identity, error) {
	var claims map[string]any
	if err := token.Claims(&claims); err != nil {
		return Identity{}, fmt.Errorf("%w: cannot read claims: %v", ErrUnauthenticated, err)
	}

	identity := Identity{
		Subject: token.Subject,
		Email:   stringClaim(claims, "email"),
		Name:    stringClaim(claims, "name"),
		Groups:  stringsClaim(claims, v.cfg.GroupsClaim),
	}

	switch {
	case containsFold(identity.Groups, v.cfg.AdminGroup):
		identity.Role = RoleAdmin
	case v.cfg.ViewerGroup != "" && containsFold(identity.Groups, v.cfg.ViewerGroup):
		identity.Role = RoleViewer
	default:
		// A valid token from someone with no relais group. They authenticated; they
		// are simply not authorised, which is a 403 and a different log line.
		v.log.Warn("admin token carries no recognised group",
			slog.String("subject", identity.Subject),
			slog.String("email", identity.Email),
			slog.String("groups_claim", v.cfg.GroupsClaim),
			slog.Int("groups_present", len(identity.Groups)),
		)
		return Identity{}, fmt.Errorf("%w: no recognised group in the %q claim", ErrForbidden, v.cfg.GroupsClaim)
	}

	return identity, nil
}

func stringClaim(claims map[string]any, key string) string {
	value, _ := claims[key].(string)
	return value
}

// stringsClaim reads a claim that may be a list or a single string.
//
// Identity providers disagree: some emit ["a","b"], some emit "a" when there is
// one value, and a group claim that silently reads as empty would mean an
// operator locked out of their own admin UI with no indication why.
func stringsClaim(claims map[string]any, key string) []string {
	raw, present := claims[key]
	if !present {
		return nil
	}

	switch value := raw.(type) {
	case []any:
		out := make([]string, 0, len(value))
		for _, item := range value {
			if text, ok := item.(string); ok {
				out = append(out, text)
			}
		}
		return out
	case []string:
		return value
	case string:
		return []string{value}
	case json.Number:
		return []string{value.String()}
	default:
		return nil
	}
}

func containsFold(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), want) {
			return true
		}
	}
	return false
}
