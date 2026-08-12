package authn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/amenitydev/relais/internal/crypto"
	"github.com/amenitydev/relais/internal/dbtest"
	"github.com/amenitydev/relais/internal/store"
)

// The credential-resolving tests need a real Postgres, because what they check is
// how real rows in real states behave. See internal/dbtest.
//
// TestBearerToken needs nothing and runs everywhere.

// --- BearerToken ------------------------------------------------------------

func TestBearerToken(t *testing.T) {
	valid := map[string]string{
		"Bearer abc123":        "abc123",
		"bearer abc123":        "abc123",
		"BEARER abc123":        "abc123",
		"BeArEr abc123":        "abc123",
		"  Bearer   abc123   ": "abc123",
		"Bearer relais_sk_a_b": "relais_sk_a_b",
		// A token with an internal space is returned as-is and rejected later by
		// its shape. Splitting on whitespace here would silently accept the first
		// word of a mangled header.
		"Bearer abc 123": "abc 123",
	}
	for header, want := range valid {
		t.Run("valid: "+header, func(t *testing.T) {
			got, err := BearerToken(header)
			if err != nil {
				t.Fatalf("BearerToken(%q): %v", header, err)
			}
			if got != want {
				t.Fatalf("BearerToken(%q) = %q, want %q", header, got, want)
			}
		})
	}

	invalid := map[string]string{
		"empty":             "",
		"whitespace only":   "   ",
		"no scheme":         "abc123",
		"basic scheme":      "Basic dXNlcjpwYXNz",
		"scheme only":       "Bearer",
		"scheme and space":  "Bearer ",
		"scheme and spaces": "Bearer     ",
		"truncated scheme":  "Bear abc123",
		"scheme glued":      "Bearerabc123",
		"other scheme":      "Token abc123",
		// RFC 7235 spells the separator as SP, not HTAB: "credentials =
		// auth-scheme [ 1*SP token68 ]". No real client sends a tab, and being
		// strict keeps the check to one comparison.
		"tab separator": "Bearer\tabc123",
	}
	for name, header := range invalid {
		t.Run("invalid: "+name, func(t *testing.T) {
			got, err := BearerToken(header)
			if err == nil {
				t.Fatalf("BearerToken(%q) = %q, want an error", header, got)
			}
			// Callers switch on this sentinel to decide 401 versus 503.
			if !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("BearerToken(%q) = %v, want ErrUnauthenticated", header, err)
			}
		})
	}
}

// A parse failure must not echo the token: the header is the secret.
func TestBearerTokenErrorDoesNotEchoTheToken(t *testing.T) {
	const secret = "relais_sk_supersecretvalue_thatmustnotleak"

	_, err := BearerToken("Basic " + secret)
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("the error echoes the token: %q", err)
	}
}

// --- fixture ----------------------------------------------------------------

type fixture struct {
	t     *testing.T
	ctx   context.Context
	store *store.Store
	authn *Authenticator

	// logs captures what the authenticator recorded, which is where the
	// distinction between failure causes lives.
	logs *logBuffer
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	ctx := context.Background()
	pool := dbtest.Pool(t)

	keyring, err := crypto.ParseKeyring("1:"+testKey(0xa1), "")
	if err != nil {
		t.Fatalf("ParseKeyring: %v", err)
	}
	hasher, err := crypto.NewHasher(testKey(0xb1))
	if err != nil {
		t.Fatalf("NewHasher: %v", err)
	}
	st, err := store.New(pool, keyring, hasher)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}

	logs := &logBuffer{}
	authenticator, err := New(st, slog.New(slog.NewJSONHandler(logs, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return &fixture{t: t, ctx: ctx, store: st, authn: authenticator, logs: logs}
}

func testKey(fill byte) string {
	raw := make([]byte, crypto.KeySize)
	for i := range raw {
		raw[i] = fill + byte(i)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// logBuffer collects JSON log records so a test can assert on the recorded reason.
type logBuffer struct {
	mu      sync.Mutex
	records []map[string]any
}

func (b *logBuffer) Write(p []byte) (int, error) {
	var record map[string]any
	if err := json.Unmarshal(p, &record); err == nil {
		b.mu.Lock()
		b.records = append(b.records, record)
		b.mu.Unlock()
	}
	return len(p), nil
}

// reasons returns the "reason" of every recorded failure, in order.
func (b *logBuffer) reasons() []string {
	b.mu.Lock()
	defer b.mu.Unlock()

	out := make([]string, 0, len(b.records))
	for _, record := range b.records {
		if reason, ok := record["reason"].(string); ok {
			out = append(out, reason)
		}
	}
	return out
}

func (b *logBuffer) lastReason() string {
	reasons := b.reasons()
	if len(reasons) == 0 {
		return ""
	}
	return reasons[len(reasons)-1]
}

func (b *logBuffer) text() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	var builder strings.Builder
	for _, record := range b.records {
		encoded, _ := json.Marshal(record)
		builder.Write(encoded)
		builder.WriteByte('\n')
	}
	return builder.String()
}

func (b *logBuffer) reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.records = nil
}

// mintAPIKey creates an api_key credential and returns its plaintext token.
func (f *fixture) mintAPIKey(name string) (store.AuthCredential, string) {
	f.t.Helper()

	created, err := f.store.CreateCredential(f.ctx, store.NewCredentialParams{
		Name: name, Type: store.CredentialTypeAPIKey, Enabled: true,
		Patterns: []string{"no-reply@example.com"},
	})
	if err != nil {
		f.t.Fatalf("CreateCredential(%q): %v", name, err)
	}
	auth, err := f.store.LoadCredential(f.ctx, created.Credential.ID)
	if err != nil {
		f.t.Fatalf("LoadCredential: %v", err)
	}
	return auth, created.Secret.Reveal()
}

// mintSMTPUser creates an smtp_user credential and returns its password.
func (f *fixture) mintSMTPUser(name, username string) (store.AuthCredential, string) {
	f.t.Helper()

	created, err := f.store.CreateCredential(f.ctx, store.NewCredentialParams{
		Name: name, Type: store.CredentialTypeSMTPUser, SMTPUsername: username,
		Enabled: true, Patterns: []string{"no-reply@example.com"},
	})
	if err != nil {
		f.t.Fatalf("CreateCredential(%q): %v", name, err)
	}
	auth, err := f.store.LoadCredential(f.ctx, created.Credential.ID)
	if err != nil {
		f.t.Fatalf("LoadCredential: %v", err)
	}
	return auth, created.Secret.Reveal()
}

// --- APIKey -----------------------------------------------------------------

func TestAPIKeySucceeds(t *testing.T) {
	f := newFixture(t)
	created, token := f.mintAPIKey("billing")

	auth, err := f.authn.APIKey(f.ctx, token, "203.0.113.7")
	if err != nil {
		t.Fatalf("APIKey: %v", err)
	}
	if auth.Credential.ID != created.Credential.ID {
		t.Fatalf("resolved %s, want %s", auth.Credential.ID, created.Credential.ID)
	}
	// The allow-list must come back with it: the pipeline needs it immediately.
	if auth.Patterns.Len() != 1 {
		t.Fatalf("pattern count = %d, want 1", auth.Patterns.Len())
	}
	if !auth.Usable() {
		t.Fatal("a fresh credential is not usable")
	}
	// A success is not a failure, so nothing should have been logged as one.
	if reasons := f.logs.reasons(); len(reasons) != 0 {
		t.Fatalf("a successful authentication logged failures: %v", reasons)
	}
}

// Every failure returns the same sentinel, and the recorded reason is what
// distinguishes them — for an operator, never for the client.
func TestAPIKeyFailures(t *testing.T) {
	f := newFixture(t)
	_, valid := f.mintAPIKey("good")
	_, revokedToken := f.mintAPIKey("revoked")
	_, disabledToken := f.mintAPIKey("disabled")
	_, smtpPassword := f.mintSMTPUser("smtp-only", "blog")

	// Revoke one and disable another, so real-but-unusable rows are covered.
	credentials, err := f.store.ListCredentials(f.ctx)
	if err != nil {
		t.Fatalf("ListCredentials: %v", err)
	}
	for _, c := range credentials {
		switch c.Name {
		case "revoked":
			if _, err := f.store.RevokeCredential(f.ctx, c.ID); err != nil {
				t.Fatalf("RevokeCredential: %v", err)
			}
		case "disabled":
			if _, err := f.store.Pool().Exec(f.ctx,
				"UPDATE credential SET enabled = false WHERE id = $1", c.ID); err != nil {
				t.Fatalf("disable: %v", err)
			}
		}
	}

	tests := []struct {
		name       string
		token      string
		wantReason string
	}{
		{
			name:       "empty token",
			token:      "",
			wantReason: reasonMalformed,
		},
		{
			name:       "not a relais key",
			token:      "sk_live_something_else",
			wantReason: reasonMalformed,
		},
		{
			name:       "right prefix, wrong shape",
			token:      crypto.APIKeyPrefix + "tooshort",
			wantReason: reasonMalformed,
		},
		{
			name:       "well-formed but unknown",
			token:      crypto.APIKeyPrefix + "abcdefghijkl_" + strings.Repeat("A", 43),
			wantReason: reasonUnknown,
		},
		{
			name:       "known lookup, wrong secret",
			token:      tamperLastChar(valid),
			wantReason: reasonWrongSecret,
		},
		{
			name:       "revoked credential",
			token:      revokedToken,
			wantReason: reasonRevoked,
		},
		{
			name:       "disabled credential",
			token:      disabledToken,
			wantReason: reasonDisabled,
		},
		{
			// An SMTP password is not a bearer token; it does not even have the
			// prefix, so it is refused on shape.
			name:       "smtp password as a bearer token",
			token:      smtpPassword,
			wantReason: reasonMalformed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f.logs.reset()

			auth, err := f.authn.APIKey(f.ctx, tc.token, "203.0.113.7")
			if err == nil {
				t.Fatalf("APIKey succeeded for %q (credential %q)", tc.name, auth.Credential.Name)
			}
			// One sentinel for every cause: the caller has nothing to branch on.
			if !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("error = %v, want ErrUnauthenticated", err)
			}
			// The cause is recorded, for whoever is investigating.
			if got := f.logs.lastReason(); got != tc.wantReason {
				t.Fatalf("logged reason = %q, want %q\n%s", got, tc.wantReason, f.logs.text())
			}
		})
	}
}

// An api_key credential is not an smtp_user credential and vice versa. A mix-up is
// a real mistake worth logging, and it must not work.
func TestCredentialTypesAreNotInterchangeable(t *testing.T) {
	f := newFixture(t)
	_, smtpPassword := f.mintSMTPUser("smtp-cred", "blog")
	_, apiToken := f.mintAPIKey("api-cred")

	t.Run("smtp credential over the REST façade", func(t *testing.T) {
		f.logs.reset()
		// The username is the lookup, so a well-formed bearer token cannot even
		// name it. Presenting the password alone fails on shape.
		if _, err := f.authn.APIKey(f.ctx, smtpPassword, ""); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("error = %v, want ErrUnauthenticated", err)
		}
	})

	t.Run("api key over SMTP AUTH", func(t *testing.T) {
		f.logs.reset()
		lookup, secret, err := crypto.ParseAPIKey(apiToken)
		if err != nil {
			t.Fatalf("ParseAPIKey: %v", err)
		}
		// The api_key's lookup ("k_...") happens to satisfy the SMTP username
		// grammar, so this reaches the type check rather than failing on shape —
		// which is exactly the case worth covering.
		if _, err := f.authn.SMTPUser(f.ctx, lookup, secret, ""); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("error = %v, want ErrUnauthenticated", err)
		}
		if got := f.logs.lastReason(); got != reasonWrongType {
			t.Fatalf("logged reason = %q, want %q\n%s", got, reasonWrongType, f.logs.text())
		}
	})
}

// The secret is verified before the credential's state, on purpose: reporting
// "revoked" to someone holding a wrong secret would confirm that the credential
// exists.
func TestWrongSecretOnARevokedCredentialReportsTheSecret(t *testing.T) {
	f := newFixture(t)
	created, token := f.mintAPIKey("leaked")

	if _, err := f.store.RevokeCredential(f.ctx, created.Credential.ID); err != nil {
		t.Fatalf("RevokeCredential: %v", err)
	}

	f.logs.reset()
	if _, err := f.authn.APIKey(f.ctx, tamperLastChar(token), ""); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("error = %v, want ErrUnauthenticated", err)
	}
	if got := f.logs.lastReason(); got != reasonWrongSecret {
		t.Fatalf("logged reason = %q, want %q: the state must not be revealed before the secret is proven",
			got, reasonWrongSecret)
	}

	// With the right secret, the revocation is what gets reported.
	f.logs.reset()
	if _, err := f.authn.APIKey(f.ctx, token, ""); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("error = %v, want ErrUnauthenticated", err)
	}
	if got := f.logs.lastReason(); got != reasonRevoked {
		t.Fatalf("logged reason = %q, want %q", got, reasonRevoked)
	}
}

// A database failure is not an authentication failure. Getting this wrong would
// make an outage look to every client like its key stopped working, which is the
// worst possible time to send everyone hunting for a credential problem.
func TestDatabaseFailureIsNotAnAuthenticationFailure(t *testing.T) {
	ctx := context.Background()

	// A pool this test owns outright, because it is about to close it. Closing the
	// shared fixture's pool would deadlock: that one holds a connection for the
	// exclusive test lock until cleanup, and Close waits for it.
	pool, err := pgxpool.New(ctx, dbtest.DSN(t))
	if err != nil {
		t.Fatalf("build a pool: %v", err)
	}
	keyring, err := crypto.ParseKeyring("1:"+testKey(0xa1), "")
	if err != nil {
		t.Fatalf("ParseKeyring: %v", err)
	}
	hasher, err := crypto.NewHasher(testKey(0xb1))
	if err != nil {
		t.Fatalf("NewHasher: %v", err)
	}
	st, err := store.New(pool, keyring, hasher)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	authenticator, err := New(st, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Every query now fails for a reason that has nothing to do with any
	// credential.
	pool.Close()

	// A well-formed token, so parsing succeeds and the lookup is actually
	// attempted.
	token := crypto.APIKeyPrefix + "abcdefghijkl_" + strings.Repeat("A", 43)

	_, err = authenticator.APIKey(ctx, token, "")
	if err == nil {
		t.Fatal("APIKey succeeded against a closed pool")
	}
	// The whole point: a façade reads this to decide 503 rather than 401. Getting
	// it wrong would make an outage look to every client like its key stopped
	// working, which is the worst possible moment to send everyone hunting for a
	// credential problem.
	if errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("a database failure was reported as an authentication failure: %v", err)
	}
}

// --- SMTPUser ---------------------------------------------------------------

func TestSMTPUserSucceeds(t *testing.T) {
	f := newFixture(t)
	created, password := f.mintSMTPUser("wordpress", "blog")

	auth, err := f.authn.SMTPUser(f.ctx, "blog", password, "203.0.113.7")
	if err != nil {
		t.Fatalf("SMTPUser: %v", err)
	}
	if auth.Credential.ID != created.Credential.ID {
		t.Fatalf("resolved %s, want %s", auth.Credential.ID, created.Credential.ID)
	}
}

// Legacy clients capitalise inconsistently, and the username is a lookup value
// that was normalized on the way in.
func TestSMTPUsernameIsNormalized(t *testing.T) {
	f := newFixture(t)
	_, password := f.mintSMTPUser("wordpress", "blog")

	for _, username := range []string{"blog", "BLOG", "Blog", "  blog  "} {
		if _, err := f.authn.SMTPUser(f.ctx, username, password, ""); err != nil {
			t.Fatalf("SMTPUser(%q): %v", username, err)
		}
	}
}

func TestSMTPUserFailures(t *testing.T) {
	f := newFixture(t)
	_, password := f.mintSMTPUser("wordpress", "blog")

	tests := []struct {
		name       string
		username   string
		password   string
		wantReason string
	}{
		{"empty username", "", password, reasonMalformed},
		{"username with a space", "my blog", password, reasonMalformed},
		{"username too short", "ab", password, reasonMalformed},
		{"username with an at sign", "blog@example.com", password, reasonMalformed},
		{"unknown username", "nobody", password, reasonUnknown},
		{"wrong password", "blog", "wrong", reasonWrongSecret},
		{"empty password", "blog", "", reasonWrongSecret},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f.logs.reset()

			if _, err := f.authn.SMTPUser(f.ctx, tc.username, tc.password, "203.0.113.7"); !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("error = %v, want ErrUnauthenticated", err)
			}
			if got := f.logs.lastReason(); got != tc.wantReason {
				t.Fatalf("logged reason = %q, want %q\n%s", got, tc.wantReason, f.logs.text())
			}
		})
	}
}

// --- what must never reach a log --------------------------------------------

// The logs are the one place the failure cause is recorded, which makes them the
// one place a secret could plausibly end up.
func TestLogsNeverContainSecrets(t *testing.T) {
	f := newFixture(t)
	_, apiToken := f.mintAPIKey("app")
	_, smtpPassword := f.mintSMTPUser("wordpress", "blog")

	_, secret, err := crypto.ParseAPIKey(apiToken)
	if err != nil {
		t.Fatalf("ParseAPIKey: %v", err)
	}

	// Exercise every path that logs: malformed, unknown, wrong secret, and the
	// successful ones.
	_, _ = f.authn.APIKey(f.ctx, "garbage-"+secret, "203.0.113.7")
	_, _ = f.authn.APIKey(f.ctx, tamperLastChar(apiToken), "203.0.113.7")
	_, _ = f.authn.APIKey(f.ctx, apiToken, "203.0.113.7")
	_, _ = f.authn.SMTPUser(f.ctx, "blog", "wrong-"+smtpPassword, "203.0.113.7")
	_, _ = f.authn.SMTPUser(f.ctx, "blog", smtpPassword, "203.0.113.7")

	output := f.logs.text()
	for _, forbidden := range []string{secret, apiToken, smtpPassword} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("a secret reached the logs:\n%s", output)
		}
	}

	// The logs must still be useful: the public half of a credential is safe to
	// record and is what identifies a stale deployment.
	if !strings.Contains(output, "remote_ip") {
		t.Fatalf("the logs do not record the client address:\n%s", output)
	}
	if !strings.Contains(output, "credential_lookup") && !strings.Contains(output, "credential_name") {
		t.Fatalf("the logs identify nothing:\n%s", output)
	}
}

// The returned error is handed to a façade that may log it. It must carry no
// secret and no hint about the cause.
func TestReturnedErrorRevealsNothing(t *testing.T) {
	f := newFixture(t)
	_, apiToken := f.mintAPIKey("app")

	created, _ := f.mintAPIKey("revoked-one")
	if _, err := f.store.RevokeCredential(f.ctx, created.Credential.ID); err != nil {
		t.Fatalf("RevokeCredential: %v", err)
	}

	var messages []string
	for _, token := range []string{
		"",
		"garbage",
		crypto.APIKeyPrefix + "abcdefghijkl_" + strings.Repeat("A", 43),
		tamperLastChar(apiToken),
	} {
		_, err := f.authn.APIKey(f.ctx, token, "")
		if err == nil {
			t.Fatalf("APIKey(%q) succeeded", token)
		}
		if strings.Contains(err.Error(), token) && token != "" {
			t.Fatalf("the error echoes the token: %q", err)
		}
		messages = append(messages, err.Error())
	}

	// Every cause yields the identical message: no oracle.
	for i := 1; i < len(messages); i++ {
		if messages[i] != messages[0] {
			t.Fatalf("errors differ between causes: %q vs %q", messages[0], messages[i])
		}
	}
}

// --- construction -----------------------------------------------------------

func TestNewRequiresAStore(t *testing.T) {
	if _, err := New(nil, nil); err == nil {
		t.Fatal("New succeeded with no store")
	}
}

func TestNewDefaultsTheLogger(t *testing.T) {
	f := newFixture(t)

	// A nil logger must not panic on the first failure.
	authenticator, err := New(f.store, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := authenticator.APIKey(f.ctx, "garbage", ""); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("error = %v, want ErrUnauthenticated", err)
	}
}

// --- helpers ----------------------------------------------------------------

// tamperLastChar keeps a token's lookup half intact and breaks its secret, so it
// names a real credential with the wrong secret.
func tamperLastChar(token string) string {
	if token == "" {
		return "x"
	}
	last := token[len(token)-1]
	replacement := byte('a')
	if last == 'a' {
		replacement = 'b'
	}
	return token[:len(token)-1] + string(replacement)
}
