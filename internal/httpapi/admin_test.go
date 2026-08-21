package httpapi

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/amenitydev/relais/internal/adminauth"
	"github.com/amenitydev/relais/internal/crypto"
	"github.com/amenitydev/relais/internal/db"
	"github.com/amenitydev/relais/internal/dbtest"
	"github.com/amenitydev/relais/internal/oidctest"
	"github.com/amenitydev/relais/internal/sender"
	"github.com/amenitydev/relais/internal/store"
)

// These tests drive the assembled admin router against a real database and a real
// (throwaway) OIDC issuer, so signature verification, group mapping and RBAC are
// exercised as they will be in production.

const testAudience = "relais"

type adminFixture struct {
	t     *testing.T
	ctx   context.Context
	store *store.Store
	pool  *db.Pool

	issuer  *oidctest.Issuer
	handler http.Handler
	logs    *bytes.Buffer

	prober *stubProber
}

// stubProber stands in for the SMTP sender: the admin API's job is to translate a
// probe result into a response, and dialling a relay is already tested elsewhere.
type stubProber struct {
	result sender.ProbeResult
	err    error
	// probed records the routes it was asked about, so a test can check that the
	// stored password actually reached it.
	probed []store.SenderRoute
}

func (p *stubProber) Probe(_ context.Context, route store.SenderRoute) (sender.ProbeResult, error) {
	p.probed = append(p.probed, route)
	return p.result, p.err
}

func newAdminFixture(t *testing.T) *adminFixture {
	t.Helper()

	ctx := context.Background()
	pool := dbtest.Pool(t)

	keyring, err := crypto.ParseKeyring("1:"+testKey(0xc1), "")
	if err != nil {
		t.Fatalf("ParseKeyring: %v", err)
	}
	hasher, err := crypto.NewHasher(testKey(0xd1))
	if err != nil {
		t.Fatalf("NewHasher: %v", err)
	}
	st, err := store.New(pool, keyring, hasher)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}

	issuer := oidctest.Start(t, testAudience)
	logs := &bytes.Buffer{}
	log := slog.New(slog.NewJSONHandler(logs, nil))

	verifier, err := adminauth.New(adminauth.Config{
		Issuer:      issuer.URL,
		Audience:    testAudience,
		GroupsClaim: "groups",
		AdminGroup:  "relais-admin",
		ViewerGroup: "relais-viewer",
	}, log)
	if err != nil {
		t.Fatalf("adminauth.New: %v", err)
	}

	prober := &stubProber{result: sender.ProbeResult{UsedTLS: true, Authenticated: true,
		Extensions: []string{"AUTH PLAIN LOGIN", "STARTTLS"}}}

	server, err := NewAdminServer(AdminOptions{
		Store: st, Verifier: verifier, Pool: pool, Prober: prober,
		Log: log, Version: "test", PageSize: 3, MaxPageSize: 10,
		MaxRequestBytes: 1 << 20,
	})
	if err != nil {
		t.Fatalf("NewAdminServer: %v", err)
	}

	return &adminFixture{
		t: t, ctx: ctx, store: st, pool: pool,
		issuer: issuer, handler: server.Handler(), logs: logs, prober: prober,
	}
}

// adminToken mints a token for a member of the admin group.
func (f *adminFixture) adminToken() string {
	return f.issuer.Token(oidctest.Claims{
		Subject: "admin-subject", Email: "ops@example.com",
		Groups: []string{"relais-admin"},
	})
}

// viewerToken mints a token for a member of the read-only group.
func (f *adminFixture) viewerToken() string {
	return f.issuer.Token(oidctest.Claims{
		Subject: "viewer-subject", Email: "readonly@example.com",
		Groups: []string{"relais-viewer"},
	})
}

func (f *adminFixture) do(method, path, token, body string) *httptest.ResponseRecorder {
	f.t.Helper()

	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.RemoteAddr = "203.0.113.9:5000"

	recorder := httptest.NewRecorder()
	f.handler.ServeHTTP(recorder, req)
	return recorder
}

// seed creates a backend, a domain and a credential, returning their ids.
func (f *adminFixture) seed() (backendID, domainID, credentialID uuid.UUID) {
	f.t.Helper()

	backend, err := f.store.CreateBackend(f.ctx, store.NewBackendParams{
		Name: "oci", Host: "smtp.example.test", Port: 587,
		TLSMode: store.TLSModeSTARTTLS, AuthUser: "sender", AuthPassword: "pw", Enabled: true,
	})
	if err != nil {
		f.t.Fatalf("CreateBackend: %v", err)
	}
	domain, err := f.store.CreateDomain(f.ctx, store.NewDomainParams{
		Name: "example.com", BackendID: backend.ID, IncludeSubdomains: true, Enabled: true,
	})
	if err != nil {
		f.t.Fatalf("CreateDomain: %v", err)
	}
	credential, err := f.store.CreateCredential(f.ctx, store.NewCredentialParams{
		Name: "app", Type: store.CredentialTypeAPIKey, Enabled: true,
		Patterns: []string{"no-reply@example.com"},
	})
	if err != nil {
		f.t.Fatalf("CreateCredential: %v", err)
	}
	return backend.ID, domain.ID, credential.Credential.ID
}

// --- authentication ---------------------------------------------------------

// The property the whole admin surface rests on: a token relais did not have
// signed by its configured issuer is refused.
func TestAdminRejectsUnacceptableTokens(t *testing.T) {
	f := newAdminFixture(t)
	other := oidctest.Start(t, testAudience)

	tests := map[string]string{
		"no token":              "",
		"not a jwt":             "garbage",
		"forged signature":      f.issuer.TokenSignedByAnotherKey(oidctest.Claims{Groups: []string{"relais-admin"}}),
		"signed by another idp": other.Token(oidctest.Claims{Groups: []string{"relais-admin"}}),
		"expired": f.issuer.Token(oidctest.Claims{
			Groups: []string{"relais-admin"},
			Expiry: time.Now().Add(-time.Minute),
		}),
		// An issuer with no audience check would accept tokens minted for any other
		// client of the same provider, which looks like it works and is not
		// authentication at all.
		"wrong audience": f.issuer.Token(oidctest.Claims{
			Groups: []string{"relais-admin"}, Audience: "some-other-app",
		}),
		"wrong issuer claim": f.issuer.Token(oidctest.Claims{
			Groups: []string{"relais-admin"}, Issuer: "https://evil.test",
		}),
	}

	for name, token := range tests {
		t.Run(name, func(t *testing.T) {
			recorder := f.do(http.MethodGet, "/admin/v1/backends", token, "")
			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401: %s", recorder.Code, recorder.Body)
			}
			if got := recorder.Header().Get("WWW-Authenticate"); !strings.Contains(got, "Bearer") {
				t.Fatalf("WWW-Authenticate = %q", got)
			}
			// Identical body for every cause: no oracle.
			body := decodeBody[errorEnvelope](t, recorder)
			if body.Error.Code != codeUnauthorized || body.Error.Message != "authentication failed" {
				t.Fatalf("the response distinguishes the cause: %+v", body.Error)
			}
		})
	}
}

// A valid token from someone in no relais group is 403, not 401: they exist and
// they authenticated; they are simply not allowed. A 401 would send them
// re-logging-in forever.
func TestAdminRejectsUnknownGroupWith403(t *testing.T) {
	f := newAdminFixture(t)

	for name, groups := range map[string][]string{
		"no groups at all": nil,
		"unrelated groups": {"engineering", "everyone"},
		"lookalike group":  {"relais-admins"},
	} {
		t.Run(name, func(t *testing.T) {
			token := f.issuer.Token(oidctest.Claims{Subject: "someone", Groups: groups})
			recorder := f.do(http.MethodGet, "/admin/v1/backends", token, "")

			if recorder.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403: %s", recorder.Code, recorder.Body)
			}
			if got := decodeBody[errorEnvelope](t, recorder).Error.Code; got != codeForbidden {
				t.Fatalf("code = %q, want %q", got, codeForbidden)
			}
		})
	}
}

// Group names are matched case-insensitively, because directory tooling is
// inconsistent about capitalisation and an operator locked out of their own admin
// UI over a capital letter has no way to diagnose it.
func TestAdminGroupMatchingIsCaseInsensitive(t *testing.T) {
	f := newAdminFixture(t)

	for _, group := range []string{"relais-admin", "Relais-Admin", "RELAIS-ADMIN"} {
		token := f.issuer.Token(oidctest.Claims{Groups: []string{group}})
		if got := f.do(http.MethodGet, "/admin/v1/backends", token, "").Code; got != http.StatusOK {
			t.Fatalf("group %q: status = %d, want 200", group, got)
		}
	}
}

// An identity provider that emits a single group as a bare string rather than a
// list must still work: reading it as empty would lock an operator out.
func TestAdminAcceptsScalarGroupsClaim(t *testing.T) {
	f := newAdminFixture(t)

	token := f.issuer.Token(oidctest.Claims{
		Subject: "someone",
		Extra:   map[string]any{"groups": "relais-admin"},
	})
	if got := f.do(http.MethodGet, "/admin/v1/backends", token, "").Code; got != http.StatusOK {
		t.Fatalf("status = %d, want 200", got)
	}
}

// An unreachable identity provider must be a 503, never a 401. Reporting bad
// credentials while Authentik is down sends an operator looking in the wrong
// place, at the worst moment.
func TestAdminReportsProviderOutageAs503(t *testing.T) {
	f := newAdminFixture(t)
	token := f.adminToken()

	// Stop the issuer before its discovery document has ever been fetched.
	f.issuer.Close()

	recorder := f.do(http.MethodGet, "/admin/v1/backends", token, "")
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: %s", recorder.Code, recorder.Body)
	}
	if recorder.Header().Get("Retry-After") == "" {
		t.Fatal("no Retry-After on a 503")
	}
}

func TestAdminIdentityEndpoint(t *testing.T) {
	f := newAdminFixture(t)

	recorder := f.do(http.MethodGet, "/admin/v1/identity", f.adminToken(), "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", recorder.Code, recorder.Body)
	}
	body := decodeBody[identityResponse](t, recorder)
	if body.Role != string(adminauth.RoleAdmin) || !body.CanWrite {
		t.Fatalf("identity = %+v, want an admin who can write", body)
	}
	if body.Email != "ops@example.com" {
		t.Fatalf("email = %q", body.Email)
	}

	recorder = f.do(http.MethodGet, "/admin/v1/identity", f.viewerToken(), "")
	body = decodeBody[identityResponse](t, recorder)
	if body.Role != string(adminauth.RoleViewer) || body.CanWrite {
		t.Fatalf("identity = %+v, want a viewer who cannot write", body)
	}
}

// --- RBAC -------------------------------------------------------------------

// Go is the authority on this. The UI hides what a viewer cannot do, but a hidden
// button is not an authorisation check, and this is the check.
func TestViewerCannotWrite(t *testing.T) {
	f := newAdminFixture(t)
	backendID, domainID, credentialID := f.seed()
	viewer := f.viewerToken()

	writes := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodPost, "/admin/v1/backends", `{"name":"new","host":"h.test","port":587,"tls_mode":"starttls"}`},
		{http.MethodPatch, "/admin/v1/backends/" + backendID.String(), `{"name":"renamed"}`},
		{http.MethodDelete, "/admin/v1/backends/" + backendID.String(), ""},
		{http.MethodPost, "/admin/v1/backends/" + backendID.String() + ":test", ""},
		{http.MethodPost, "/admin/v1/domains", `{"name":"new.test","backend_id":"` + backendID.String() + `"}`},
		{http.MethodPatch, "/admin/v1/domains/" + domainID.String(), `{"enabled":false}`},
		{http.MethodDelete, "/admin/v1/domains/" + domainID.String(), ""},
		{http.MethodPost, "/admin/v1/credentials", `{"name":"new","type":"api_key"}`},
		{http.MethodPatch, "/admin/v1/credentials/" + credentialID.String(), `{"name":"renamed"}`},
		{http.MethodPost, "/admin/v1/credentials/" + credentialID.String() + ":revoke", ""},
		{http.MethodPost, "/admin/v1/credentials/" + credentialID.String() + ":rotate", ""},
		{http.MethodDelete, "/admin/v1/credentials/" + credentialID.String(), ""},
		{http.MethodPost, "/admin/v1/credentials/" + credentialID.String() + "/patterns", `{"patterns":["a@example.com"]}`},
		{http.MethodDelete, "/admin/v1/credentials/" + credentialID.String() + "/patterns/" + uuid.NewString(), ""},
	}

	for _, write := range writes {
		t.Run(write.method+" "+write.path, func(t *testing.T) {
			recorder := f.do(write.method, write.path, viewer, write.body)
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403: %s", recorder.Code, recorder.Body)
			}
			if got := decodeBody[errorEnvelope](t, recorder).Error.Code; got != codeForbidden {
				t.Fatalf("code = %q, want %q", got, codeForbidden)
			}
		})
	}

	// Nothing may have changed.
	if _, err := f.store.GetBackend(f.ctx, backendID); err != nil {
		t.Fatalf("the backend was affected by a refused write: %v", err)
	}
	auth, err := f.store.LoadCredential(f.ctx, credentialID)
	if err != nil {
		t.Fatalf("LoadCredential: %v", err)
	}
	if auth.Credential.RevokedAt != nil || auth.Patterns.Len() != 1 {
		t.Fatal("the credential was affected by a refused write")
	}
}

// A viewer must be able to read everything, including the dry runs: they change
// nothing and they are what makes the UI useful.
func TestViewerCanRead(t *testing.T) {
	f := newAdminFixture(t)
	_, _, credentialID := f.seed()
	viewer := f.viewerToken()

	reads := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, "/admin/v1/identity", ""},
		{http.MethodGet, "/admin/v1/stats", ""},
		{http.MethodGet, "/admin/v1/backends", ""},
		{http.MethodGet, "/admin/v1/domains", ""},
		{http.MethodGet, "/admin/v1/domains:resolve?sender=no-reply@example.com", ""},
		{http.MethodGet, "/admin/v1/credentials", ""},
		{http.MethodGet, "/admin/v1/credentials/" + credentialID.String(), ""},
		{http.MethodGet, "/admin/v1/credentials/" + credentialID.String() + "/patterns", ""},
		{http.MethodGet, "/admin/v1/messages", ""},
		{http.MethodPost, "/admin/v1/patterns:validate", `{"pattern":"*@example.com"}`},
		{http.MethodPost, "/admin/v1/credentials/" + credentialID.String() + "/patterns:test", `{"address":"no-reply@example.com"}`},
	}

	for _, read := range reads {
		t.Run(read.method+" "+read.path, func(t *testing.T) {
			recorder := f.do(read.method, read.path, viewer, read.body)
			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body)
			}
		})
	}
}

// --- no secret ever leaves ---------------------------------------------------

// The database rows carry a sealed password and a secret fingerprint. Serialising
// a row directly would publish both, so every response goes through an explicit
// type — and this test is what keeps that true.
func TestAdminResponsesNeverCarrySecrets(t *testing.T) {
	f := newAdminFixture(t)
	const password = "0CI-super-secret-password"

	backend, err := f.store.CreateBackend(f.ctx, store.NewBackendParams{
		Name: "oci", Host: "smtp.example.test", Port: 587,
		TLSMode: store.TLSModeSTARTTLS, AuthUser: "sender",
		AuthPassword: crypto.Secret(password), Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateBackend: %v", err)
	}
	created, err := f.store.CreateCredential(f.ctx, store.NewCredentialParams{
		Name: "app", Type: store.CredentialTypeAPIKey, Enabled: true,
		Patterns: []string{"no-reply@example.com"},
	})
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	// The sealed envelope, so the test catches a leak of the ciphertext too.
	var sealed string
	if err := f.pool.QueryRow(f.ctx,
		"SELECT auth_password_sealed FROM smtp_backend WHERE id = $1", backend.ID).Scan(&sealed); err != nil {
		t.Fatalf("read the sealed password: %v", err)
	}

	token := f.adminToken()
	for _, path := range []string{
		"/admin/v1/backends",
		"/admin/v1/credentials",
		"/admin/v1/credentials/" + created.Credential.ID.String(),
		"/admin/v1/stats",
		"/admin/v1/messages",
	} {
		t.Run(path, func(t *testing.T) {
			recorder := f.do(http.MethodGet, path, token, "")
			body := recorder.Body.String()

			for _, forbidden := range []string{password, sealed, created.Secret.Reveal(), "secret_hmac", "auth_password"} {
				if strings.Contains(body, forbidden) {
					t.Fatalf("the response carries %q:\n%s", forbidden, body)
				}
			}
		})
	}

	// The backend response says a password exists without disclosing it, which is
	// all the UI needs to choose between "set" and "rotate".
	recorder := f.do(http.MethodGet, "/admin/v1/backends", token, "")
	backends := decodeBody[listResponse[backendResponse]](t, recorder)
	if len(backends.Data) != 1 || !backends.Data[0].HasPassword {
		t.Fatalf("backends = %+v, want has_password true", backends.Data)
	}
}

// The secret is returned exactly once, at creation, and the payload says so.
func TestCreateCredentialReturnsTheSecretOnce(t *testing.T) {
	f := newAdminFixture(t)
	token := f.adminToken()

	recorder := f.do(http.MethodPost, "/admin/v1/credentials", token,
		`{"name":"billing","type":"api_key","patterns":["invoices@example.com"]}`)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", recorder.Code, recorder.Body)
	}

	created := decodeBody[createdCredentialResponse](t, recorder)
	if created.Secret == "" {
		t.Fatal("no secret returned at creation")
	}
	if created.Warning == "" {
		t.Fatal("no warning that the secret cannot be shown again")
	}
	if !strings.Contains(created.Warning, "once") {
		t.Fatalf("warning = %q", created.Warning)
	}

	// And it is gone: no endpoint can return it, because relais does not have it.
	detail := f.do(http.MethodGet, "/admin/v1/credentials/"+created.Credential.ID, token, "")
	if strings.Contains(detail.Body.String(), created.Secret) {
		t.Fatalf("the secret is readable after creation:\n%s", detail.Body)
	}

	// The created key must actually work, which is the only proof that what was
	// returned is the real secret.
	lookup, secret, err := crypto.ParseAPIKey(created.Secret)
	if err != nil {
		t.Fatalf("ParseAPIKey: %v", err)
	}
	auth, err := f.store.LoadCredentialByLookup(f.ctx, lookup)
	if err != nil {
		t.Fatalf("LoadCredentialByLookup: %v", err)
	}
	if !f.store.VerifySecret(secret, auth) {
		t.Fatal("the returned secret does not verify against the stored fingerprint")
	}
}

func TestCreateSMTPCredentialReturnsItsUsername(t *testing.T) {
	f := newAdminFixture(t)

	recorder := f.do(http.MethodPost, "/admin/v1/credentials", f.adminToken(),
		`{"name":"wordpress","type":"smtp_user","username":"blog","patterns":["*@example.com"]}`)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d: %s", recorder.Code, recorder.Body)
	}
	created := decodeBody[createdCredentialResponse](t, recorder)
	// SMTP AUTH sends the username separately, so a response without it would be
	// unusable.
	if created.Username != "blog" {
		t.Fatalf("username = %q", created.Username)
	}
}

// A credential with no pattern can send as nobody, and the payload says so rather
// than looking like a finished job.
func TestCreateCredentialWithoutPatternsWarns(t *testing.T) {
	f := newAdminFixture(t)

	recorder := f.do(http.MethodPost, "/admin/v1/credentials", f.adminToken(),
		`{"name":"empty","type":"api_key"}`)
	created := decodeBody[createdCredentialResponse](t, recorder)
	if !strings.Contains(created.Warning, "cannot send anything") {
		t.Fatalf("warning = %q, want it to say the credential cannot send yet", created.Warning)
	}
}

// --- CRUD -------------------------------------------------------------------

func TestBackendCRUD(t *testing.T) {
	f := newAdminFixture(t)
	token := f.adminToken()

	created := decodeBody[backendResponse](t, f.do(http.MethodPost, "/admin/v1/backends", token,
		`{"name":"oci","host":"smtp.example.test","port":587,"tls_mode":"starttls","auth_user":"u","password":"p"}`))
	if created.ID == "" || !created.HasPassword {
		t.Fatalf("created = %+v", created)
	}

	// A PATCH that omits a field leaves it alone, rather than resetting it.
	updated := decodeBody[backendResponse](t, f.do(http.MethodPatch, "/admin/v1/backends/"+created.ID, token,
		`{"max_concurrency":8}`))
	if updated.Name != "oci" || updated.Host != "smtp.example.test" {
		t.Fatalf("a partial update reset other fields: %+v", updated)
	}
	if updated.MaxConcurrency != 8 {
		t.Fatalf("max_concurrency = %d", updated.MaxConcurrency)
	}
	// And it must not have wiped the password: an admin renaming a backend cannot
	// re-enter a password relais never shows them.
	if !updated.HasPassword {
		t.Fatal("a partial update cleared the stored password")
	}

	if got := f.do(http.MethodDelete, "/admin/v1/backends/"+created.ID, token, "").Code; got != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204", got)
	}
	if got := f.do(http.MethodGet, "/admin/v1/backends", token, ""); len(decodeBody[listResponse[backendResponse]](t, got).Data) != 0 {
		t.Fatal("the backend survived deletion")
	}
}

func TestBackendDeleteBlockedByDomain(t *testing.T) {
	f := newAdminFixture(t)
	backendID, _, _ := f.seed()

	recorder := f.do(http.MethodDelete, "/admin/v1/backends/"+backendID.String(), f.adminToken(), "")
	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", recorder.Code, recorder.Body)
	}
	if got := decodeBody[errorEnvelope](t, recorder).Error.Code; got != codeInUse {
		t.Fatalf("code = %q, want %q", got, codeInUse)
	}
}

func TestBackendNameConflictIs409(t *testing.T) {
	f := newAdminFixture(t)
	f.seed()

	recorder := f.do(http.MethodPost, "/admin/v1/backends", f.adminToken(),
		`{"name":"oci","host":"other.test","port":587,"tls_mode":"starttls"}`)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", recorder.Code, recorder.Body)
	}
	body := decodeBody[errorEnvelope](t, recorder)
	if body.Error.Field != "name" {
		t.Fatalf("field = %q, want name so a UI can place the error", body.Error.Field)
	}
}

// The invariant the schema enforces must surface as a 422, not a 500.
func TestBackendPlaintextAuthIs422(t *testing.T) {
	f := newAdminFixture(t)

	recorder := f.do(http.MethodPost, "/admin/v1/backends", f.adminToken(),
		`{"name":"bad","host":"127.0.0.1","port":1025,"tls_mode":"none","auth_user":"u","password":"p"}`)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422: %s", recorder.Code, recorder.Body)
	}
	if !strings.Contains(recorder.Body.String(), "plaintext") {
		t.Fatalf("the response does not explain the refusal: %s", recorder.Body)
	}
}

func TestDomainCRUDAndBackendState(t *testing.T) {
	f := newAdminFixture(t)
	backendID, domainID, _ := f.seed()
	token := f.adminToken()

	// A domain pointing at a disabled backend delivers nothing, and that state is
	// invisible from the domain alone.
	if _, err := f.pool.Exec(f.ctx, "UPDATE smtp_backend SET enabled = false WHERE id = $1", backendID); err != nil {
		t.Fatalf("disable the backend: %v", err)
	}

	list := decodeBody[listResponse[domainResponse]](t, f.do(http.MethodGet, "/admin/v1/domains", token, ""))
	if len(list.Data) != 1 {
		t.Fatalf("domains = %+v", list.Data)
	}
	if list.Data[0].BackendEnabled == nil || *list.Data[0].BackendEnabled {
		t.Fatal("the list does not surface that the backend is disabled")
	}
	if list.Data[0].BackendName != "oci" {
		t.Fatalf("backend_name = %q", list.Data[0].BackendName)
	}

	updated := decodeBody[domainResponse](t, f.do(http.MethodPatch, "/admin/v1/domains/"+domainID.String(), token,
		`{"include_subdomains":false}`))
	if updated.IncludeSubdomains {
		t.Fatal("include_subdomains was not updated")
	}
	if updated.Name != "example.com" {
		t.Fatalf("a partial update changed the name: %q", updated.Name)
	}
}

func TestDomainNameIsNormalized(t *testing.T) {
	f := newAdminFixture(t)
	backendID, _, _ := f.seed()

	created := decodeBody[domainResponse](t, f.do(http.MethodPost, "/admin/v1/domains", f.adminToken(),
		`{"name":"  Exemplé.COM  ","backend_id":"`+backendID.String()+`"}`))
	// An operator should see the punycode the moment they save, not discover it
	// later.
	if created.Name != "xn--exempl-gva.com" {
		t.Fatalf("name = %q, want the punycode form", created.Name)
	}
}

// Revocation is permanent. Re-enabling would produce a credential nobody can use,
// because relais holds no secret to restore access with.
func TestRevokedCredentialCannotBeReEnabled(t *testing.T) {
	f := newAdminFixture(t)
	_, _, credentialID := f.seed()
	token := f.adminToken()

	if got := f.do(http.MethodPost, "/admin/v1/credentials/"+credentialID.String()+":revoke", token, "").Code; got != http.StatusOK {
		t.Fatalf("revoke status = %d", got)
	}

	recorder := f.do(http.MethodPatch, "/admin/v1/credentials/"+credentialID.String(), token, `{"enabled":true}`)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422: %s", recorder.Code, recorder.Body)
	}
	if !strings.Contains(recorder.Body.String(), "permanent") {
		t.Fatalf("the response does not explain why: %s", recorder.Body)
	}
}

// Rotation is the operation that exists so a leak does not cost an operator their
// allow-list. What it must change is the secret, and only the secret.
func TestRotateCredentialKeepsEverythingButTheSecret(t *testing.T) {
	f := newAdminFixture(t)
	_, _, credentialID := f.seed()
	token := f.adminToken()

	before := decodeBody[credentialResponse](t,
		f.do(http.MethodGet, "/admin/v1/credentials/"+credentialID.String(), token, ""))

	recorder := f.do(http.MethodPost, "/admin/v1/credentials/"+credentialID.String()+":rotate", token, "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body)
	}
	rotated := decodeBody[createdCredentialResponse](t, recorder)

	if rotated.Secret == "" {
		t.Fatal("the response carries no secret, which is the only reason it exists")
	}
	if rotated.Credential.ID != before.ID {
		t.Fatalf("id = %q, want %q", rotated.Credential.ID, before.ID)
	}
	if rotated.Credential.Name != before.Name {
		t.Fatalf("name = %q, want %q", rotated.Credential.Name, before.Name)
	}
	if rotated.Credential.PatternCount != before.PatternCount {
		t.Fatalf("pattern_count = %d, want %d", rotated.Credential.PatternCount, before.PatternCount)
	}
	if rotated.Credential.Lookup == before.Lookup {
		t.Fatal("an api_key kept its lookup, so the old token still names this row")
	}
	// The warning is the payload's only defence against a UI that loses the modal.
	if !strings.Contains(rotated.Warning, "cannot be recovered") {
		t.Fatalf("the response does not say the secret is unrecoverable: %q", rotated.Warning)
	}

	// The presented secret is the one now stored, and the store is the authority.
	lookup, secret, err := crypto.ParseAPIKey(rotated.Secret)
	if err != nil {
		t.Fatalf("ParseAPIKey: %v", err)
	}
	auth, err := f.store.LoadCredentialByLookup(f.ctx, lookup)
	if err != nil {
		t.Fatalf("LoadCredentialByLookup: %v", err)
	}
	if !f.store.VerifySecret(secret, auth) {
		t.Fatal("the secret the API returned does not authenticate")
	}
}

// A revoked credential must not be rotated back to life, for the same reason it
// must not be re-enabled: revocation is the one promise that has to hold.
func TestRevokedCredentialCannotBeRotated(t *testing.T) {
	f := newAdminFixture(t)
	_, _, credentialID := f.seed()
	token := f.adminToken()

	if got := f.do(http.MethodPost, "/admin/v1/credentials/"+credentialID.String()+":revoke", token, "").Code; got != http.StatusOK {
		t.Fatalf("revoke status = %d", got)
	}

	recorder := f.do(http.MethodPost, "/admin/v1/credentials/"+credentialID.String()+":rotate", token, "")
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422: %s", recorder.Code, recorder.Body)
	}
	if !strings.Contains(recorder.Body.String(), "permanent") {
		t.Fatalf("the response does not explain why: %s", recorder.Body)
	}
}

func TestDeleteCredential(t *testing.T) {
	f := newAdminFixture(t)
	_, _, credentialID := f.seed()
	token := f.adminToken()

	if got := f.do(http.MethodDelete, "/admin/v1/credentials/"+credentialID.String(), token, "").Code; got != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", got)
	}
	if got := f.do(http.MethodGet, "/admin/v1/credentials/"+credentialID.String(), token, "").Code; got != http.StatusNotFound {
		t.Fatalf("the credential is still readable: status = %d, want 404", got)
	}
	// Deleting twice is a 404, not a 204: the second caller is telling us about a
	// row they think exists, and it does not.
	if got := f.do(http.MethodDelete, "/admin/v1/credentials/"+credentialID.String(), token, "").Code; got != http.StatusNotFound {
		t.Fatalf("a second delete = %d, want 404", got)
	}
}

func TestPatternCRUD(t *testing.T) {
	f := newAdminFixture(t)
	_, _, credentialID := f.seed()
	token := f.adminToken()

	added := decodeBody[listResponse[patternResponse]](t, f.do(http.MethodPost,
		"/admin/v1/credentials/"+credentialID.String()+"/patterns", token,
		`{"patterns":["*@mail.example.com","Billing@Example.COM"]}`))
	if len(added.Data) != 3 {
		t.Fatalf("%d patterns, want 3: %+v", len(added.Data), added.Data)
	}

	// Stored normalized, and each carries the explanation of what it grants.
	var found bool
	for _, pattern := range added.Data {
		if pattern.Pattern == "billing@example.com" {
			found = true
		}
		if pattern.Explanation == "" {
			t.Fatalf("pattern %q has no explanation", pattern.Pattern)
		}
	}
	if !found {
		t.Fatalf("the pattern was not normalized: %+v", added.Data)
	}

	// The subdomain wildcard's explanation must state the surprising rule.
	for _, pattern := range added.Data {
		if pattern.Pattern == "*@mail.example.com" {
			if !strings.Contains(pattern.Explanation, "exactly mail.example.com") {
				t.Fatalf("explanation = %q", pattern.Explanation)
			}
		}
	}

	var toDelete string
	for _, pattern := range added.Data {
		if pattern.Pattern == "*@mail.example.com" {
			toDelete = pattern.ID
		}
	}
	if got := f.do(http.MethodDelete,
		"/admin/v1/credentials/"+credentialID.String()+"/patterns/"+toDelete, token, "").Code; got != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204", got)
	}
}

func TestAddInvalidPatternIs422(t *testing.T) {
	f := newAdminFixture(t)
	_, _, credentialID := f.seed()

	recorder := f.do(http.MethodPost, "/admin/v1/credentials/"+credentialID.String()+"/patterns",
		f.adminToken(), `{"patterns":["no-*@example.com"]}`)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422: %s", recorder.Code, recorder.Body)
	}
	if got := decodeBody[errorEnvelope](t, recorder).Error.Field; got != "patterns" {
		t.Fatalf("field = %q, want patterns", got)
	}
}

// --- dry runs ---------------------------------------------------------------

// These endpoints exist so the frontend never reimplements the grammar. A
// TypeScript copy would drift, and the day it drifts the UI misreports what a
// credential may send as.
func TestValidatePattern(t *testing.T) {
	f := newAdminFixture(t)
	token := f.adminToken()

	valid := decodeBody[patternValidationResponse](t, f.do(http.MethodPost, "/admin/v1/patterns:validate", token,
		`{"pattern":"*@*.Exemplé.COM"}`))
	if !valid.Valid {
		t.Fatalf("a valid pattern was refused: %+v", valid)
	}
	// The canonical form is the point of the endpoint.
	if valid.Normalized != "*@*.xn--exempl-gva.com" {
		t.Fatalf("normalized = %q", valid.Normalized)
	}
	// And the explanation must state the rule that surprises everyone.
	if !strings.Contains(valid.Explanation, "not xn--exempl-gva.com itself") {
		t.Fatalf("explanation = %q, want it to say the apex is excluded", valid.Explanation)
	}

	// An invalid pattern is a successful answer to "is this valid?", so 200 with
	// valid=false rather than a 4xx.
	invalid := f.do(http.MethodPost, "/admin/v1/patterns:validate", token, `{"pattern":"no-*@example.com"}`)
	if invalid.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", invalid.Code)
	}
	body := decodeBody[patternValidationResponse](t, invalid)
	if body.Valid || body.Error == "" {
		t.Fatalf("response = %+v, want valid=false with a reason", body)
	}
}

// The endpoint that saves an hour per configuration: it answers both halves of the
// question at once, because a pattern can allow an address that no domain routes.
func TestTestPattern(t *testing.T) {
	f := newAdminFixture(t)
	_, _, credentialID := f.seed()
	token := f.adminToken()

	allowed := decodeBody[patternTestResponse](t, f.do(http.MethodPost,
		"/admin/v1/credentials/"+credentialID.String()+"/patterns:test", token,
		`{"address":"No-Reply@Example.com"}`))
	if !allowed.Allowed {
		t.Fatalf("response = %+v, want allowed", allowed)
	}
	if allowed.Address != "no-reply@example.com" {
		t.Fatalf("address = %q, want the normalized form", allowed.Address)
	}
	if allowed.MatchedPattern != "no-reply@example.com" {
		t.Fatalf("matched_pattern = %q", allowed.MatchedPattern)
	}
	if !allowed.RoutableDomain || allowed.BackendName != "oci" {
		t.Fatalf("response = %+v, want the routing answer too", allowed)
	}

	denied := decodeBody[patternTestResponse](t, f.do(http.MethodPost,
		"/admin/v1/credentials/"+credentialID.String()+"/patterns:test", token,
		`{"address":"ceo@example.com"}`))
	if denied.Allowed {
		t.Fatal("an address outside the allow-list was reported as allowed")
	}
	// The domain still routes, which is exactly the distinction an operator needs.
	if !denied.RoutableDomain {
		t.Fatalf("response = %+v, want routable_domain true", denied)
	}
}

// The classic misconfiguration: a pattern that allows an address no domain routes.
// Seeing only "allowed" would send an operator away believing the setup works.
func TestTestPatternSurfacesUnroutableDomain(t *testing.T) {
	f := newAdminFixture(t)
	token := f.adminToken()

	created, err := f.store.CreateCredential(f.ctx, store.NewCredentialParams{
		Name: "app", Type: store.CredentialTypeAPIKey, Enabled: true,
		Patterns: []string{"*@*.unrouted.test"},
	})
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	result := decodeBody[patternTestResponse](t, f.do(http.MethodPost,
		"/admin/v1/credentials/"+created.Credential.ID.String()+"/patterns:test", token,
		`{"address":"a@mail.unrouted.test"}`))
	if !result.Allowed {
		t.Fatal("the pattern should allow this address")
	}
	if result.RoutableDomain {
		t.Fatal("no domain routes this sender, and the response claims otherwise")
	}
}

func TestResolveDomain(t *testing.T) {
	f := newAdminFixture(t)
	f.seed()
	token := f.adminToken()

	// A full address is accepted, because an operator debugging a rejection has an
	// address in hand rather than a domain.
	resolved := decodeBody[resolveResponse](t, f.do(http.MethodGet,
		"/admin/v1/domains:resolve?sender=no-reply@mail.example.com", token, ""))
	if !resolved.Resolved {
		t.Fatalf("response = %+v, want resolved", resolved)
	}
	if resolved.Backend != "oci" || resolved.DomainName != "example.com" {
		t.Fatalf("response = %+v", resolved)
	}
	if !resolved.UsesAuth {
		t.Fatal("uses_auth = false on a backend with credentials")
	}

	unresolved := decodeBody[resolveResponse](t, f.do(http.MethodGet,
		"/admin/v1/domains:resolve?sender=nobody@unknown.test", token, ""))
	if unresolved.Resolved {
		t.Fatal("an unconfigured domain resolved")
	}
	// The reason must name the usual cause, which is a missing include_subdomains.
	if !strings.Contains(unresolved.Reason, "include_subdomains") {
		t.Fatalf("reason = %q", unresolved.Reason)
	}
}

func TestProbeBackend(t *testing.T) {
	f := newAdminFixture(t)
	backendID, _, _ := f.seed()
	token := f.adminToken()

	ok := decodeBody[probeResponse](t, f.do(http.MethodPost, "/admin/v1/backends/"+backendID.String()+":test", token, ""))
	if !ok.OK || !ok.UsedTLS || !ok.Authenticated {
		t.Fatalf("response = %+v", ok)
	}
	// The probe must have received the opened password, or it could not have
	// authenticated.
	if len(f.prober.probed) != 1 {
		t.Fatalf("%d probes, want 1", len(f.prober.probed))
	}
	if f.prober.probed[0].AuthPassword.Reveal() != "pw" {
		t.Fatal("the probe did not receive the stored password")
	}

	// A failure is a 200 with ok=false: the request succeeded, the connection did
	// not, and a form error is the right rendering.
	f.prober.err = &sender.Error{Kind: sender.KindPermanent, Code: sender.CodeAuthFailed, Detail: "535 bad credentials"}
	failed := f.do(http.MethodPost, "/admin/v1/backends/"+backendID.String()+":test", token, "")
	if failed.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", failed.Code, failed.Body)
	}
	body := decodeBody[probeResponse](t, failed)
	if body.OK || body.Error == nil || body.Error.Code != sender.CodeAuthFailed {
		t.Fatalf("response = %+v", body)
	}
}

// --- messages ---------------------------------------------------------------

func TestListMessagesPaginates(t *testing.T) {
	f := newAdminFixture(t)
	backendID, _, credentialID := f.seed()
	token := f.adminToken()

	// Seven messages, page size three.
	for i := range 7 {
		if _, err := f.store.InsertQueuedMessage(f.ctx, store.NewMessageParams{
			CredentialID: credentialID, Facade: store.FacadeREST,
			FromAddr: "no-reply@example.com", FromDomain: "example.com",
			EnvelopeRecipients: []string{"a@elsewhere.test"},
			Subject:            "message " + string(rune('a'+i)),
			MessageID:          "<m@example.com>", SizeBytes: 10, BackendID: backendID,
		}, []byte("raw"), func(context.Context, pgx.Tx, uuid.UUID) error { return nil }); err != nil {
			t.Fatalf("InsertQueuedMessage: %v", err)
		}
	}

	seen := map[string]bool{}
	cursor := ""
	for page := range 5 {
		path := "/admin/v1/messages"
		if cursor != "" {
			path += "?cursor=" + cursor
		}
		body := decodeBody[listResponse[messageResponseAdmin]](t, f.do(http.MethodGet, path, token, ""))

		for _, message := range body.Data {
			if seen[message.ID] {
				t.Fatalf("page %d returned a message already seen: keyset pagination is not advancing", page+1)
			}
			seen[message.ID] = true
			// The admin view names the credential, which the client-facing one does
			// not need to.
			if message.CredentialName != "app" {
				t.Fatalf("credential_name = %q", message.CredentialName)
			}
		}

		if body.NextCursor == "" {
			break
		}
		cursor = body.NextCursor
	}

	if len(seen) != 7 {
		t.Fatalf("%d distinct messages across pages, want 7", len(seen))
	}
}

func TestListMessagesFilters(t *testing.T) {
	f := newAdminFixture(t)
	backendID, _, credentialID := f.seed()
	token := f.adminToken()

	if _, err := f.store.InsertQueuedMessage(f.ctx, store.NewMessageParams{
		CredentialID: credentialID, Facade: store.FacadeREST,
		FromAddr: "no-reply@example.com", FromDomain: "example.com",
		EnvelopeRecipients: []string{"a@elsewhere.test"}, MessageID: "<a@example.com>",
		BackendID: backendID,
	}, []byte("raw"), func(context.Context, pgx.Tx, uuid.UUID) error { return nil }); err != nil {
		t.Fatalf("InsertQueuedMessage: %v", err)
	}
	if _, err := f.store.InsertRejectedMessage(f.ctx, store.RejectedMessageParams{
		CredentialID: credentialID, Facade: store.FacadeSMTP, Reason: "sender_not_allowed",
		FromAddr: "ceo@example.com", FromDomain: "example.com",
	}); err != nil {
		t.Fatalf("InsertRejectedMessage: %v", err)
	}

	rejected := decodeBody[listResponse[messageResponseAdmin]](t,
		f.do(http.MethodGet, "/admin/v1/messages?status=rejected", token, ""))
	if len(rejected.Data) != 1 || rejected.Data[0].From != "ceo@example.com" {
		t.Fatalf("rejected filter returned %+v", rejected.Data)
	}
	if rejected.Data[0].RejectionReason == nil || *rejected.Data[0].RejectionReason != "sender_not_allowed" {
		t.Fatalf("rejection_reason = %v", rejected.Data[0].RejectionReason)
	}

	byCredential := decodeBody[listResponse[messageResponseAdmin]](t,
		f.do(http.MethodGet, "/admin/v1/messages?credential_id="+credentialID.String(), token, ""))
	if len(byCredential.Data) != 2 {
		t.Fatalf("credential filter returned %d rows, want 2", len(byCredential.Data))
	}

	// A malformed cursor is the caller's fault and must say so, not 500.
	if got := f.do(http.MethodGet, "/admin/v1/messages?cursor=not-a-cursor", token, "").Code; got != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", got)
	}
}

// An admin sees metadata and delivery status. The body is not theirs to read, and
// an endpoint that returned it would make the admin API a mail archive.
func TestGetMessageNeverReturnsThePayload(t *testing.T) {
	f := newAdminFixture(t)
	backendID, _, credentialID := f.seed()

	const body = "SECRET MESSAGE BODY CONTENT"
	row, err := f.store.InsertQueuedMessage(f.ctx, store.NewMessageParams{
		CredentialID: credentialID, Facade: store.FacadeREST,
		FromAddr: "no-reply@example.com", FromDomain: "example.com",
		EnvelopeRecipients: []string{"a@elsewhere.test"}, Subject: "Subject line",
		MessageID: "<a@example.com>", BackendID: backendID,
	}, []byte("From: no-reply@example.com\r\n\r\n"+body), func(context.Context, pgx.Tx, uuid.UUID) error { return nil })
	if err != nil {
		t.Fatalf("InsertQueuedMessage: %v", err)
	}

	recorder := f.do(http.MethodGet, "/admin/v1/messages/"+row.ID.String(), f.adminToken(), "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", recorder.Code, recorder.Body)
	}
	if strings.Contains(recorder.Body.String(), body) {
		t.Fatalf("the admin API returned the message body:\n%s", recorder.Body)
	}
	// The metadata an operator does need is there.
	detail := decodeBody[messageResponseAdmin](t, recorder)
	if detail.Subject != "Subject line" || detail.Status != store.StatusQueued {
		t.Fatalf("detail = %+v", detail)
	}
}

func TestStats(t *testing.T) {
	f := newAdminFixture(t)
	f.seed()

	body := decodeBody[statsResponse](t, f.do(http.MethodGet, "/admin/v1/stats", f.adminToken(), ""))
	if body.Backends != 1 || body.Domains != 1 {
		t.Fatalf("stats = %+v", body)
	}
	if body.Credentials["active"] != 1 {
		t.Fatalf("credentials = %+v", body.Credentials)
	}
	// Every status present even at zero, so a dashboard never has to guess.
	for _, status := range []string{
		store.StatusQueued, store.StatusSending, store.StatusSent,
		store.StatusFailed, store.StatusRejected,
	} {
		if _, present := body.Messages[status]; !present {
			t.Fatalf("status %q is missing from the payload: %+v", status, body.Messages)
		}
	}
}

// --- audit trail ------------------------------------------------------------

// Who changed what is the point of an admin audit trail, and a change nobody can
// attribute is a change nobody can review.
func TestAdminWritesAreAudited(t *testing.T) {
	f := newAdminFixture(t)
	_, _, credentialID := f.seed()
	token := f.adminToken()

	f.logs.Reset()
	if got := f.do(http.MethodPost, "/admin/v1/credentials/"+credentialID.String()+":revoke", token, "").Code; got != http.StatusOK {
		t.Fatalf("revoke status = %d", got)
	}

	output := f.logs.String()
	for _, wanted := range []string{"credential revoked", "ops@example.com", credentialID.String(), "admin_role"} {
		if !strings.Contains(output, wanted) {
			t.Fatalf("the audit log is missing %q:\n%s", wanted, output)
		}
	}
}

// Granting a pattern changes what a credential may send as, which is the most
// security-relevant admin action there is.
func TestPatternGrantsAreAudited(t *testing.T) {
	f := newAdminFixture(t)
	_, _, credentialID := f.seed()

	f.logs.Reset()
	f.do(http.MethodPost, "/admin/v1/credentials/"+credentialID.String()+"/patterns",
		f.adminToken(), `{"patterns":["*@mail.example.com"]}`)

	output := f.logs.String()
	if !strings.Contains(output, "sender patterns granted") {
		t.Fatalf("the grant was not audited:\n%s", output)
	}
	if !strings.Contains(output, "mail.example.com") {
		t.Fatalf("the audit line does not say what was granted:\n%s", output)
	}
}

// A refused write must be recorded too: an attempt is a signal.
func TestRefusedWriteIsLogged(t *testing.T) {
	f := newAdminFixture(t)
	_, _, credentialID := f.seed()

	f.logs.Reset()
	f.do(http.MethodPost, "/admin/v1/credentials/"+credentialID.String()+":revoke", f.viewerToken(), "")

	output := f.logs.String()
	if !strings.Contains(output, "viewer attempted a write") {
		t.Fatalf("a refused write was not logged:\n%s", output)
	}
	if !strings.Contains(output, "readonly@example.com") {
		t.Fatalf("the log does not name who attempted it:\n%s", output)
	}
}

// --- routing ----------------------------------------------------------------

func TestAdminRoutingEdges(t *testing.T) {
	f := newAdminFixture(t)
	token := f.adminToken()

	if got := f.do(http.MethodGet, "/admin/v1/nope", token, "").Code; got != http.StatusNotFound {
		t.Fatalf("unknown endpoint: status = %d, want 404", got)
	}
	if got := f.do(http.MethodPut, "/admin/v1/backends", token, "{}").Code; got != http.StatusMethodNotAllowed {
		t.Fatalf("wrong method: status = %d, want 405", got)
	}
	// A malformed id is answered like an unknown one: there is nothing to learn
	// from the difference.
	if got := f.do(http.MethodGet, "/admin/v1/credentials/not-a-uuid", token, "").Code; got != http.StatusNotFound {
		t.Fatalf("malformed id: status = %d, want 404", got)
	}
	// The probes stay reachable without a token: this listener may be the only one
	// an orchestrator can see.
	for _, path := range []string{"/healthz", "/readyz"} {
		if got := f.do(http.MethodGet, path, "", "").Code; got != http.StatusOK {
			t.Fatalf("GET %s without a token: status = %d, want 200", path, got)
		}
	}
}

func TestAdminRejectsUnknownFields(t *testing.T) {
	f := newAdminFixture(t)

	recorder := f.do(http.MethodPost, "/admin/v1/backends", f.adminToken(),
		`{"name":"x","host":"h.test","port":587,"tls_mode":"starttls","typo_field":1}`)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", recorder.Code, recorder.Body)
	}
}

func TestNewAdminServerRequiresDependencies(t *testing.T) {
	if _, err := NewAdminServer(AdminOptions{}); err == nil {
		t.Fatal("NewAdminServer accepted no store")
	}
	if _, err := NewAdminServer(AdminOptions{Store: &store.Store{}}); err == nil {
		t.Fatal("NewAdminServer accepted no verifier: an unauthenticated admin API is worse than none")
	}
}
