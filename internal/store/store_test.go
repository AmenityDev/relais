package store

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/amenitydev/relais/internal/crypto"
	"github.com/amenitydev/relais/internal/dbtest"
	"github.com/amenitydev/relais/internal/frompattern"
)

// These tests need a real Postgres with the schema applied, because most of what
// the store guarantees lives in the database: uniqueness, referential actions
// and CHECK constraints. A mock would assert nothing.
//
//	docker compose up -d && go run ./cmd/relais migrate up && go test ./internal/store/
//
// See internal/dbtest for how the database is resolved, and why an unreachable
// one fails in CI but skips locally.

type fixture struct {
	store *Store
	pool  *pgxpool.Pool
	ctx   context.Context
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	ctx := context.Background()
	pool := dbtest.Pool(t)

	keyring, err := crypto.ParseKeyring("1:"+testKey(0x11), "")
	if err != nil {
		t.Fatalf("ParseKeyring: %v", err)
	}
	hasher, err := crypto.NewHasher(testKey(0x55))
	if err != nil {
		t.Fatalf("NewHasher: %v", err)
	}
	st, err := New(pool, keyring, hasher)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &fixture{store: st, pool: pool, ctx: ctx}
}

// testKey mirrors the helper in the crypto tests: a deterministic 32-byte key,
// so a failure is reproducible.
func testKey(fill byte) string {
	raw := make([]byte, crypto.KeySize)
	for i := range raw {
		raw[i] = fill + byte(i)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func (f *fixture) mustBackend(t *testing.T, name string, password crypto.Secret) uuid.UUID {
	t.Helper()
	params := NewBackendParams{
		Name: name, Host: "smtp.example.test", Port: 587,
		TLSMode: TLSModeSTARTTLS, Enabled: true,
	}
	if !password.IsEmpty() {
		params.AuthUser = "sender@example.test"
		params.AuthPassword = password
	}
	backend, err := f.store.CreateBackend(f.ctx, params)
	if err != nil {
		t.Fatalf("CreateBackend(%q): %v", name, err)
	}
	return backend.ID
}

// --- backends ---------------------------------------------------------------

func TestBackendPasswordIsSealedAtRest(t *testing.T) {
	f := newFixture(t)
	const password = "0CI-s3cret/with+specials:and=padding"

	id := f.mustBackend(t, "oci", crypto.Secret(password))

	var stored string
	if err := f.pool.QueryRow(f.ctx, "SELECT auth_password_sealed FROM smtp_backend WHERE id = $1", id).Scan(&stored); err != nil {
		t.Fatalf("read sealed password: %v", err)
	}
	if strings.Contains(stored, password) {
		t.Fatal("the password is stored in cleartext")
	}
	if !crypto.IsSealed(stored) {
		t.Fatalf("stored value %q is not a sealed envelope", stored)
	}

	opened, err := f.store.OpenBackendPassword(stored)
	if err != nil {
		t.Fatalf("OpenBackendPassword: %v", err)
	}
	if opened.Reveal() != password {
		t.Fatalf("round trip: got %q, want %q", opened.Reveal(), password)
	}
	// The wrapper type must not print the secret by accident.
	if strings.Contains(opened.String(), password) {
		t.Fatal("crypto.Secret.String leaked the password")
	}
}

func TestBackendRejectsPlaintextAuth(t *testing.T) {
	f := newFixture(t)

	_, err := f.store.CreateBackend(f.ctx, NewBackendParams{
		Name: "bad", Host: "127.0.0.1", Port: 1025, TLSMode: TLSModeNone,
		AuthUser: "someone", AuthPassword: "pw", Enabled: true,
	})
	if err == nil {
		t.Fatal("CreateBackend accepted SMTP AUTH over a plaintext connection")
	}
	if !strings.Contains(err.Error(), "plaintext") {
		t.Fatalf("error %q does not explain the refusal", err)
	}
}

func TestBackendHalfConfiguredAuthIsRefused(t *testing.T) {
	f := newFixture(t)

	for _, params := range []NewBackendParams{
		{Name: "user-only", Host: "h.example.test", Port: 587, TLSMode: TLSModeSTARTTLS, AuthUser: "u"},
		{Name: "pass-only", Host: "h.example.test", Port: 587, TLSMode: TLSModeSTARTTLS, AuthPassword: "p"},
	} {
		if _, err := f.store.CreateBackend(f.ctx, params); err == nil {
			t.Fatalf("CreateBackend accepted a half-configured AUTH (%+v)", params.Name)
		}
	}
}

func TestBackendNameConflict(t *testing.T) {
	f := newFixture(t)
	f.mustBackend(t, "oci", "")

	// Names are unique case-insensitively, so "OCI" collides with "oci".
	_, err := f.store.CreateBackend(f.ctx, NewBackendParams{
		Name: "OCI", Host: "other.example.test", Port: 587, TLSMode: TLSModeSTARTTLS, Enabled: true,
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("CreateBackend: got %v, want ErrConflict", err)
	}
}

// A backend with domains attached must not be deletable: silently orphaning a
// domain would turn an edit-time mistake into a delivery-time failure.
func TestDeleteBackendIsBlockedByDomains(t *testing.T) {
	f := newFixture(t)
	backendID := f.mustBackend(t, "oci", "")

	if _, err := f.store.CreateDomain(f.ctx, NewDomainParams{
		Name: "example.com", BackendID: backendID, Enabled: true,
	}); err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}

	err := f.store.DeleteBackend(f.ctx, backendID)
	if !errors.Is(err, ErrReference) {
		t.Fatalf("DeleteBackend: got %v, want ErrReference", err)
	}

	if err := f.store.DeleteBackend(f.ctx, uuid.New()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteBackend(unknown): got %v, want ErrNotFound", err)
	}
}

func TestRewrapBackendPasswords(t *testing.T) {
	f := newFixture(t)
	const password = "rotate-me"
	id := f.mustBackend(t, "oci", crypto.Secret(password))

	keyID := func() string {
		t.Helper()
		var sealed string
		if err := f.pool.QueryRow(f.ctx, "SELECT auth_password_sealed FROM smtp_backend WHERE id = $1", id).Scan(&sealed); err != nil {
			t.Fatalf("read sealed password: %v", err)
		}
		return strings.Split(sealed, ":")[1]
	}

	if got := keyID(); got != "1" {
		t.Fatalf("sealed under key %q, want 1", got)
	}

	// Rotate: both keys configured, the new one active.
	rotated, err := crypto.ParseKeyring("1:"+testKey(0x11)+",2:"+testKey(0x77), "2")
	if err != nil {
		t.Fatalf("ParseKeyring: %v", err)
	}
	f.store.keyring = rotated

	count, err := f.store.RewrapBackendPasswords(f.ctx)
	if err != nil {
		t.Fatalf("RewrapBackendPasswords: %v", err)
	}
	if count != 1 {
		t.Fatalf("rewrapped %d rows, want 1", count)
	}
	if got := keyID(); got != "2" {
		t.Fatalf("sealed under key %q after rotation, want 2", got)
	}

	// Idempotent: nothing left to do on a second pass.
	if count, err = f.store.RewrapBackendPasswords(f.ctx); err != nil || count != 0 {
		t.Fatalf("second pass: count=%d err=%v, want 0 and no error", count, err)
	}

	// With the old key dropped from the environment — the final step of a
	// rotation — the password must still open.
	newOnly, err := crypto.ParseKeyring("2:"+testKey(0x77), "")
	if err != nil {
		t.Fatalf("ParseKeyring: %v", err)
	}
	f.store.keyring = newOnly

	var sealed string
	if err := f.pool.QueryRow(f.ctx, "SELECT auth_password_sealed FROM smtp_backend WHERE id = $1", id).Scan(&sealed); err != nil {
		t.Fatalf("read sealed password: %v", err)
	}
	opened, err := f.store.OpenBackendPassword(sealed)
	if err != nil {
		t.Fatalf("opening after the old key was dropped: %v", err)
	}
	if opened.Reveal() != password {
		t.Fatalf("got %q, want %q", opened.Reveal(), password)
	}
}

// --- domains ----------------------------------------------------------------

func TestCreateDomainNormalizes(t *testing.T) {
	f := newFixture(t)
	backendID := f.mustBackend(t, "oci", "")

	domain, err := f.store.CreateDomain(f.ctx, NewDomainParams{
		Name: "  Exemplé.COM  ", BackendID: backendID, Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	if domain.Name != "xn--exempl-gva.com" {
		t.Fatalf("stored name %q, want the punycode form", domain.Name)
	}

	// The unicode and punycode spellings are the same domain, so the second
	// insert must conflict rather than create a duplicate route.
	_, err = f.store.CreateDomain(f.ctx, NewDomainParams{
		Name: "xn--exempl-gva.com", BackendID: backendID, Enabled: true,
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("CreateDomain: got %v, want ErrConflict", err)
	}

	if _, err := f.store.CreateDomain(f.ctx, NewDomainParams{
		Name: "localhost", BackendID: backendID, Enabled: true,
	}); err == nil {
		t.Fatal("CreateDomain accepted a single-label domain")
	}
}

// Resolution is where D6 lives: an exact match wins, and a subdomain only
// resolves when the parent opted in.
func TestResolveSender(t *testing.T) {
	f := newFixture(t)
	openID := f.mustBackend(t, "open-subdomains", "")
	strictID := f.mustBackend(t, "strict", "")

	if _, err := f.store.CreateDomain(f.ctx, NewDomainParams{
		Name: "open.test", BackendID: openID, IncludeSubdomains: true, Enabled: true,
	}); err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	if _, err := f.store.CreateDomain(f.ctx, NewDomainParams{
		Name: "strict.test", BackendID: strictID, Enabled: true,
	}); err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	// A more specific row must win over its opted-in parent.
	if _, err := f.store.CreateDomain(f.ctx, NewDomainParams{
		Name: "mail.open.test", BackendID: strictID, Enabled: true,
	}); err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}

	tests := []struct {
		sender      string
		wantBackend string
		wantErr     bool
		why         string
	}{
		{"open.test", "open-subdomains", false, "exact match"},
		{"deep.sub.open.test", "open-subdomains", false, "subdomain via include_subdomains"},
		{"mail.open.test", "strict", false, "the most specific row wins"},
		{"strict.test", "strict", false, "exact match"},
		{"mail.strict.test", "", true, "subdomains are not included"},
		{"unknown.test", "", true, "unconfigured domain"},
		{"notopen.test", "", true, "suffix lookalike"},
	}
	for _, tc := range tests {
		t.Run(tc.sender, func(t *testing.T) {
			route, err := f.store.ResolveSender(f.ctx, tc.sender)
			switch {
			case tc.wantErr:
				if !errors.Is(err, ErrNotFound) {
					t.Fatalf("ResolveSender(%q) = %v, want ErrNotFound (%s)", tc.sender, err, tc.why)
				}
			case err != nil:
				t.Fatalf("ResolveSender(%q): %v (%s)", tc.sender, err, tc.why)
			case route.BackendName != tc.wantBackend:
				t.Fatalf("ResolveSender(%q) routed to %q, want %q (%s)", tc.sender, route.BackendName, tc.wantBackend, tc.why)
			}
		})
	}
}

func TestResolveSenderSkipsDisabledRows(t *testing.T) {
	f := newFixture(t)
	backendID := f.mustBackend(t, "oci", "")

	if _, err := f.store.CreateDomain(f.ctx, NewDomainParams{
		Name: "disabled-domain.test", BackendID: backendID, Enabled: false,
	}); err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	if _, err := f.store.ResolveSender(f.ctx, "disabled-domain.test"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ResolveSender on a disabled domain: got %v, want ErrNotFound", err)
	}

	// A disabled backend must also take its domains out of service, rather than
	// letting messages queue up for a relay nobody intends to use.
	disabledBackend, err := f.store.CreateBackend(f.ctx, NewBackendParams{
		Name: "disabled-backend", Host: "h.example.test", Port: 587,
		TLSMode: TLSModeSTARTTLS, Enabled: false,
	})
	if err != nil {
		t.Fatalf("CreateBackend: %v", err)
	}
	if _, err := f.store.CreateDomain(f.ctx, NewDomainParams{
		Name: "orphan.test", BackendID: disabledBackend.ID, Enabled: true,
	}); err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	if _, err := f.store.ResolveSender(f.ctx, "orphan.test"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ResolveSender through a disabled backend: got %v, want ErrNotFound", err)
	}
}

// --- credentials ------------------------------------------------------------

func TestCreateAPIKeyCredential(t *testing.T) {
	f := newFixture(t)

	created, err := f.store.CreateCredential(f.ctx, NewCredentialParams{
		Name: "billing", Type: CredentialTypeAPIKey, Enabled: true,
		Patterns:  []string{"invoices@Billing.Example.com", "*@mail.example.com"},
		CreatedBy: "test",
	})
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	// Patterns are stored normalized, so matching never has to re-normalize.
	if got := created.Patterns; len(got) != 2 || got[0] != "invoices@billing.example.com" {
		t.Fatalf("stored patterns %v, want the normalized forms", got)
	}

	lookup, secret, err := crypto.ParseAPIKey(created.Secret.Reveal())
	if err != nil {
		t.Fatalf("ParseAPIKey: %v", err)
	}
	if lookup != created.Credential.Lookup {
		t.Fatalf("parsed lookup %q, stored %q", lookup, created.Credential.Lookup)
	}

	auth, err := f.store.LoadCredentialByLookup(f.ctx, lookup)
	if err != nil {
		t.Fatalf("LoadCredentialByLookup: %v", err)
	}
	if !auth.Usable() {
		t.Fatal("a freshly created credential is not usable")
	}
	if !f.store.VerifySecret(secret, auth) {
		t.Fatal("VerifySecret rejected the minted secret")
	}
	if f.store.VerifySecret(secret+"x", auth) {
		t.Fatal("VerifySecret accepted a wrong secret")
	}

	// The allow-list must behave exactly as the pattern grammar says.
	allowed, err := frompattern.ParseAddress("invoices@billing.example.com")
	if err != nil {
		t.Fatalf("ParseAddress: %v", err)
	}
	if !auth.Patterns.Allows(allowed) {
		t.Fatal("the granted sender is not allowed")
	}
	denied, err := frompattern.ParseAddress("invoices@example.com")
	if err != nil {
		t.Fatalf("ParseAddress: %v", err)
	}
	if auth.Patterns.Allows(denied) {
		t.Fatal("an ungranted sender is allowed")
	}

	// Nothing resembling the secret may be recoverable from the row.
	var storedHash []byte
	if err := f.pool.QueryRow(f.ctx, "SELECT secret_hmac FROM credential WHERE id = $1", created.Credential.ID).Scan(&storedHash); err != nil {
		t.Fatalf("read fingerprint: %v", err)
	}
	if len(storedHash) != 32 {
		t.Fatalf("fingerprint is %d bytes, want 32", len(storedHash))
	}
	if strings.Contains(string(storedHash), secret) {
		t.Fatal("the fingerprint contains the secret")
	}
}

func TestCreateSMTPUserCredential(t *testing.T) {
	f := newFixture(t)

	created, err := f.store.CreateCredential(f.ctx, NewCredentialParams{
		Name: "wordpress", Type: CredentialTypeSMTPUser, SMTPUsername: "  Blog  ",
		Patterns: []string{"*@blog.example.com"}, Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}
	if created.Credential.Lookup != "blog" {
		t.Fatalf("lookup %q, want the normalized username", created.Credential.Lookup)
	}

	auth, err := f.store.LoadCredentialByLookup(f.ctx, "blog")
	if err != nil {
		t.Fatalf("LoadCredentialByLookup: %v", err)
	}
	// For an SMTP credential the whole secret is the password: there is no
	// prefix to strip, because AUTH sends the username separately.
	if !f.store.VerifySecret(created.Secret.Reveal(), auth) {
		t.Fatal("VerifySecret rejected the minted password")
	}

	// A generated username must be produced when none is supplied.
	generated, err := f.store.CreateCredential(f.ctx, NewCredentialParams{
		Name: "auto", Type: CredentialTypeSMTPUser, Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}
	if !strings.HasPrefix(generated.Credential.Lookup, "relais_") {
		t.Fatalf("generated username %q does not look generated", generated.Credential.Lookup)
	}

	// Taking a username already in use must be reported, not silently retried.
	_, err = f.store.CreateCredential(f.ctx, NewCredentialParams{
		Name: "another", Type: CredentialTypeSMTPUser, SMTPUsername: "blog", Enabled: true,
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("CreateCredential with a taken username: got %v, want ErrConflict", err)
	}
	if got := ConstraintName(err); got != "credential_lookup_key" {
		t.Fatalf("constraint %q, want credential_lookup_key", got)
	}
}

// A credential with no pattern must be inert: this is the property that makes
// "no relaying without an explicit grant" true by construction.
func TestCredentialWithoutPatternsCanSendNothing(t *testing.T) {
	f := newFixture(t)

	created, err := f.store.CreateCredential(f.ctx, NewCredentialParams{
		Name: "empty", Type: CredentialTypeAPIKey, Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	auth, err := f.store.LoadCredential(f.ctx, created.Credential.ID)
	if err != nil {
		t.Fatalf("LoadCredential: %v", err)
	}
	if auth.Patterns.Len() != 0 {
		t.Fatalf("pattern count %d, want 0", auth.Patterns.Len())
	}
	for _, address := range []string{"a@example.com", "root@localhost.example.com", "anyone@anywhere.test"} {
		addr, err := frompattern.ParseAddress(address)
		if err != nil {
			continue
		}
		if auth.Patterns.Allows(addr) {
			t.Fatalf("a credential with no patterns authorized %q", address)
		}
	}
}

func TestCreateCredentialRejectsInvalidPatternAtomically(t *testing.T) {
	f := newFixture(t)

	_, err := f.store.CreateCredential(f.ctx, NewCredentialParams{
		Name: "half-configured", Type: CredentialTypeAPIKey, Enabled: true,
		Patterns: []string{"valid@example.com", "no-*@example.com"},
	})
	if err == nil {
		t.Fatal("CreateCredential accepted an invalid pattern")
	}

	// No credential row may exist: a credential whose allow-list nobody reviewed
	// is worse than no credential at all.
	var count int
	if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM credential").Scan(&count); err != nil {
		t.Fatalf("count credentials: %v", err)
	}
	if count != 0 {
		t.Fatalf("%d credential rows survived a rejected creation", count)
	}
}

// A conflict partway through must leave nothing behind, including no orphan
// patterns for the credential that already existed.
func TestCreateCredentialRollsBackOnConflict(t *testing.T) {
	f := newFixture(t)

	first, err := f.store.CreateCredential(f.ctx, NewCredentialParams{
		Name: "billing", Type: CredentialTypeAPIKey, Enabled: true,
		Patterns: []string{"a@example.com"},
	})
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	if _, err := f.store.CreateCredential(f.ctx, NewCredentialParams{
		Name: "Billing", Type: CredentialTypeAPIKey, Enabled: true,
		Patterns: []string{"b@example.com", "c@example.com"},
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("CreateCredential with a duplicate name: got %v, want ErrConflict", err)
	}

	var credentials, patterns int
	if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM credential").Scan(&credentials); err != nil {
		t.Fatalf("count credentials: %v", err)
	}
	if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM credential_from_pattern").Scan(&patterns); err != nil {
		t.Fatalf("count patterns: %v", err)
	}
	if credentials != 1 || patterns != 1 {
		t.Fatalf("after a rejected creation: %d credentials and %d patterns, want 1 and 1", credentials, patterns)
	}

	auth, err := f.store.LoadCredential(f.ctx, first.Credential.ID)
	if err != nil {
		t.Fatalf("LoadCredential: %v", err)
	}
	if auth.Patterns.Len() != 1 {
		t.Fatalf("the surviving credential has %d patterns, want 1", auth.Patterns.Len())
	}
}

func TestAddPatternsIsIdempotentAndValidated(t *testing.T) {
	f := newFixture(t)

	created, err := f.store.CreateCredential(f.ctx, NewCredentialParams{
		Name: "app", Type: CredentialTypeAPIKey, Enabled: true,
		Patterns: []string{"a@example.com"},
	})
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}
	id := created.Credential.ID

	// Granting a pattern that is already granted is a no-op, not an error.
	if _, err := f.store.AddPatterns(f.ctx, id, []string{"a@example.com", "b@example.com"}); err != nil {
		t.Fatalf("AddPatterns: %v", err)
	}
	stored, err := f.store.ListPatterns(f.ctx, id)
	if err != nil {
		t.Fatalf("ListPatterns: %v", err)
	}
	if len(stored) != 2 {
		t.Fatalf("%d patterns, want 2", len(stored))
	}

	// An invalid pattern rejects the whole call, leaving the list unchanged.
	if _, err := f.store.AddPatterns(f.ctx, id, []string{"c@example.com", "*@*"}); err == nil {
		t.Fatal("AddPatterns accepted an invalid pattern")
	}
	if stored, err = f.store.ListPatterns(f.ctx, id); err != nil {
		t.Fatalf("ListPatterns: %v", err)
	}
	if len(stored) != 2 {
		t.Fatalf("%d patterns after a rejected call, want 2", len(stored))
	}

	// Removal is scoped to the credential: another credential's pattern id must
	// not be removable through this one.
	if err := f.store.RemovePattern(f.ctx, id, stored[0].ID); err != nil {
		t.Fatalf("RemovePattern: %v", err)
	}
	if err := f.store.RemovePattern(f.ctx, uuid.New(), stored[1].ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RemovePattern with the wrong credential: got %v, want ErrNotFound", err)
	}
}

func TestAddPatternsToUnknownCredential(t *testing.T) {
	f := newFixture(t)
	_, err := f.store.AddPatterns(f.ctx, uuid.New(), []string{"a@example.com"})
	if !errors.Is(err, ErrReference) {
		t.Fatalf("AddPatterns: got %v, want ErrReference", err)
	}
}

func TestRevokeCredential(t *testing.T) {
	f := newFixture(t)

	created, err := f.store.CreateCredential(f.ctx, NewCredentialParams{
		Name: "leaked", Type: CredentialTypeAPIKey, Enabled: true,
		Patterns: []string{"a@example.com"},
	})
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	revoked, err := f.store.RevokeCredential(f.ctx, created.Credential.ID)
	if err != nil {
		t.Fatalf("RevokeCredential: %v", err)
	}
	if revoked.RevokedAt == nil {
		t.Fatal("RevokedAt was not set")
	}
	if revoked.Enabled {
		t.Fatal("a revoked credential is still enabled")
	}

	// The row is still loadable, so the pipeline can log "a revoked credential
	// was used" instead of the much less useful "unknown credential".
	auth, err := f.store.LoadCredentialByLookup(f.ctx, created.Credential.Lookup)
	if err != nil {
		t.Fatalf("LoadCredentialByLookup after revocation: %v", err)
	}
	if auth.Usable() {
		t.Fatal("a revoked credential reports itself usable")
	}

	// Revocation is idempotent and does not move the timestamp.
	again, err := f.store.RevokeCredential(f.ctx, created.Credential.ID)
	if err != nil {
		t.Fatalf("RevokeCredential (second): %v", err)
	}
	if !again.RevokedAt.Equal(*revoked.RevokedAt) {
		t.Fatalf("the revocation timestamp moved: %v then %v", revoked.RevokedAt, again.RevokedAt)
	}
}

func TestRateLimitOverrides(t *testing.T) {
	f := newFixture(t)

	rps := 42.0
	burst := int32(99)
	created, err := f.store.CreateCredential(f.ctx, NewCredentialParams{
		Name: "throttled", Type: CredentialTypeAPIKey, Enabled: true,
		RateLimitRPS: &rps, RateLimitBurst: &burst,
	})
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	auth, err := f.store.LoadCredential(f.ctx, created.Credential.ID)
	if err != nil {
		t.Fatalf("LoadCredential: %v", err)
	}
	if gotRPS, gotBurst := auth.RateLimit(10, 20); gotRPS != 42 || gotBurst != 99 {
		t.Fatalf("RateLimit = %v, %d; want the credential's overrides", gotRPS, gotBurst)
	}

	plain, err := f.store.CreateCredential(f.ctx, NewCredentialParams{
		Name: "default-limits", Type: CredentialTypeAPIKey, Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}
	auth, err = f.store.LoadCredential(f.ctx, plain.Credential.ID)
	if err != nil {
		t.Fatalf("LoadCredential: %v", err)
	}
	if gotRPS, gotBurst := auth.RateLimit(10, 20); gotRPS != 10 || gotBurst != 20 {
		t.Fatalf("RateLimit = %v, %d; want the supplied defaults", gotRPS, gotBurst)
	}
}

// last_used_at is intentionally coarse: a row update on every request would put
// a write on the hot path for no operational gain.
func TestTouchCredentialIsRateLimited(t *testing.T) {
	f := newFixture(t)

	created, err := f.store.CreateCredential(f.ctx, NewCredentialParams{
		Name: "used", Type: CredentialTypeAPIKey, Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}
	id := created.Credential.ID

	lastUsed := func() *time.Time {
		t.Helper()
		var at *time.Time
		if err := f.pool.QueryRow(f.ctx, "SELECT last_used_at FROM credential WHERE id = $1", id).Scan(&at); err != nil {
			t.Fatalf("read last_used_at: %v", err)
		}
		return at
	}

	if lastUsed() != nil {
		t.Fatal("last_used_at is set on a credential that was never used")
	}
	if err := f.store.TouchCredential(f.ctx, id); err != nil {
		t.Fatalf("TouchCredential: %v", err)
	}
	first := lastUsed()
	if first == nil {
		t.Fatal("TouchCredential did not record the first use")
	}

	if err := f.store.TouchCredential(f.ctx, id); err != nil {
		t.Fatalf("TouchCredential (second): %v", err)
	}
	second := lastUsed()
	if !second.Equal(*first) {
		t.Fatalf("a second touch within the interval moved the timestamp: %v then %v", first, second)
	}
}

func TestCreateCredentialValidatesParams(t *testing.T) {
	f := newFixture(t)

	cases := []struct {
		name   string
		params NewCredentialParams
	}{
		{"no name", NewCredentialParams{Type: CredentialTypeAPIKey}},
		{"unknown type", NewCredentialParams{Name: "x", Type: "oauth"}},
		{"username on an api key", NewCredentialParams{Name: "x", Type: CredentialTypeAPIKey, SMTPUsername: "bob"}},
		{"bad smtp username", NewCredentialParams{Name: "x", Type: CredentialTypeSMTPUser, SMTPUsername: "a b"}},
		{"negative rate limit", NewCredentialParams{Name: "x", Type: CredentialTypeAPIKey, RateLimitRPS: ptr(-1.0)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := f.store.CreateCredential(f.ctx, tc.params); err == nil {
				t.Fatal("CreateCredential accepted invalid parameters")
			}
		})
	}
}

func ptr[T any](v T) *T { return &v }
