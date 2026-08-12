package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/amenitydev/relais/internal/authn"
	"github.com/amenitydev/relais/internal/crypto"
	"github.com/amenitydev/relais/internal/db"
	"github.com/amenitydev/relais/internal/dbtest"
	"github.com/amenitydev/relais/internal/ingest"
	"github.com/amenitydev/relais/internal/ratelimit"
	"github.com/amenitydev/relais/internal/store"
)

// These tests exercise the real router against a real database. See internal/dbtest.

type fixture struct {
	t     *testing.T
	ctx   context.Context
	store *store.Store
	// handler is the assembled router, so tests go through every middleware the
	// production surface has, including authentication.
	handler http.Handler

	// enqueued records what the pipeline would have scheduled.
	enqueued []uuid.UUID
	// apiKey is the plaintext key for the fixture credential.
	apiKey string

	// Kept so a test can rebuild a Server with a different logger.
	pool          *db.Pool
	ingest        *ingest.Service
	authenticator *authn.Authenticator
}

func newFixture(t *testing.T, patterns ...string) *fixture {
	t.Helper()

	if len(patterns) == 0 {
		patterns = []string{"no-reply@example.com", "*@mail.example.com"}
	}

	ctx := context.Background()
	pool := dbtest.Pool(t)

	keyring, err := crypto.ParseKeyring("1:"+testKey(0x61), "")
	if err != nil {
		t.Fatalf("ParseKeyring: %v", err)
	}
	hasher, err := crypto.NewHasher(testKey(0x71))
	if err != nil {
		t.Fatalf("NewHasher: %v", err)
	}
	st, err := store.New(pool, keyring, hasher)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}

	backend, err := st.CreateBackend(ctx, store.NewBackendParams{
		Name: "sink", Host: "127.0.0.1", Port: 1025,
		TLSMode: store.TLSModeNone, Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateBackend: %v", err)
	}
	if _, err := st.CreateDomain(ctx, store.NewDomainParams{
		Name: "example.com", BackendID: backend.ID, IncludeSubdomains: true, Enabled: true,
	}); err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}

	f := &fixture{t: t, ctx: ctx, store: st}

	created, err := st.CreateCredential(ctx, store.NewCredentialParams{
		Name: "app", Type: store.CredentialTypeAPIKey, Enabled: true, Patterns: patterns,
	})
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}
	f.apiKey = created.Secret.Reveal()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	service, err := ingest.New(ingest.Options{
		Store: st,
		Enqueuer: enqueuerFunc(func(_ context.Context, _ pgx.Tx, id uuid.UUID) error {
			f.enqueued = append(f.enqueued, id)
			return nil
		}),
		Limiter: ratelimit.New(ratelimit.Options{}),
		Config: ingest.Config{
			MaxMessageBytes:        1 << 20,
			MaxRecipients:          5,
			DefaultRateLimitRPS:    1000,
			DefaultRateLimitBurst:  1000,
			RejectedRateLimitRPS:   1000,
			RejectedRateLimitBurst: 1000,
			IdempotencyTTL:         time.Hour,
		},
		Log:   log,
		Now:   func() time.Time { return time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC) },
		NewID: func() string { return "generated-id" },
	})
	if err != nil {
		t.Fatalf("ingest.New: %v", err)
	}

	authenticator, err := authn.New(st, log)
	if err != nil {
		t.Fatalf("authn.New: %v", err)
	}

	server, err := NewServer(Options{
		Ingest: service, Store: st, Authenticator: authenticator, Pool: pool,
		Limits: Limits{MaxMessageBytes: 1 << 20, MaxRequestBytes: 2 << 20, MaxRecipients: 5},
		Log:    log, Version: "test",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	f.pool = pool
	f.ingest = service
	f.authenticator = authenticator
	f.handler = server.Handler()
	return f
}

type enqueuerFunc func(context.Context, pgx.Tx, uuid.UUID) error

func (fn enqueuerFunc) Enqueue(ctx context.Context, tx pgx.Tx, id uuid.UUID) error {
	return fn(ctx, tx, id)
}

func testKey(fill byte) string {
	raw := make([]byte, crypto.KeySize)
	for i := range raw {
		raw[i] = fill + byte(i)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// newCredential mints a second credential, for the isolation tests.
func (f *fixture) newCredential(name string, patterns ...string) string {
	f.t.Helper()
	created, err := f.store.CreateCredential(f.ctx, store.NewCredentialParams{
		Name: name, Type: store.CredentialTypeAPIKey, Enabled: true, Patterns: patterns,
	})
	if err != nil {
		f.t.Fatalf("CreateCredential(%q): %v", name, err)
	}
	return created.Secret.Reveal()
}

// post sends a submission and returns the recorder.
func (f *fixture) post(body string, headers map[string]string) *httptest.ResponseRecorder {
	f.t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/v1/emails", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+f.apiKey)
	req.RemoteAddr = "203.0.113.7:54321"
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	recorder := httptest.NewRecorder()
	f.handler.ServeHTTP(recorder, req)
	return recorder
}

func (f *fixture) get(path, apiKey string) *httptest.ResponseRecorder {
	f.t.Helper()

	req := httptest.NewRequest(http.MethodGet, path, nil)
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	req.RemoteAddr = "203.0.113.7:54321"

	recorder := httptest.NewRecorder()
	f.handler.ServeHTTP(recorder, req)
	return recorder
}

func decodeBody[T any](t *testing.T, recorder *httptest.ResponseRecorder) T {
	t.Helper()
	var out T
	if err := json.Unmarshal(recorder.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v\nbody: %s", err, recorder.Body.String())
	}
	return out
}

const minimalBody = `{"from":"App <no-reply@example.com>","to":["someone@elsewhere.test"],"subject":"Hello","text":"Body."}`

// --- the happy path ---------------------------------------------------------

func TestPostEmailAccepts(t *testing.T) {
	f := newFixture(t)

	recorder := f.post(minimalBody, nil)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", recorder.Code, recorder.Body)
	}
	if got := recorder.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Fatalf("Content-Type = %q", got)
	}

	response := decodeBody[sendResponse](t, recorder)
	if response.ID == "" {
		t.Fatal("no id returned")
	}
	if response.Status != store.StatusQueued {
		t.Fatalf("status = %q, want queued", response.Status)
	}
	if response.MessageID != "<generated-id@example.com>" {
		t.Fatalf("message_id = %q", response.MessageID)
	}
	if response.Idempotent {
		t.Fatal("a first submission was reported as a replay")
	}

	if len(f.enqueued) != 1 {
		t.Fatalf("%d jobs enqueued, want 1", len(f.enqueued))
	}

	// The stored message must reflect what was submitted.
	id := uuid.MustParse(response.ID)
	row, err := f.store.GetMessage(f.ctx, id)
	if err != nil {
		t.Fatalf("GetMessage: %v", err)
	}
	if row.FromAddr != "no-reply@example.com" {
		t.Fatalf("from_addr = %q", row.FromAddr)
	}
	if row.RemoteIp == nil || row.RemoteIp.String() != "203.0.113.7" {
		t.Fatalf("remote_ip = %v, want the socket peer", row.RemoteIp)
	}
}

// "to": "a@b.test" and "to": ["a@b.test"] both appear in the wild.
func TestPostEmailAcceptsScalarAddresses(t *testing.T) {
	f := newFixture(t)

	body := `{"from":"no-reply@example.com","to":"someone@elsewhere.test","reply_to":"support@example.com","subject":"s","text":"t"}`
	recorder := f.post(body, nil)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", recorder.Code, recorder.Body)
	}
	if got := decodeBody[sendResponse](t, recorder); len(got.Recipients) != 1 {
		t.Fatalf("recipients = %v", got.Recipients)
	}
}

func TestPostEmailWithAttachment(t *testing.T) {
	f := newFixture(t)

	content := base64.StdEncoding.EncodeToString([]byte("%PDF-1.7 fake"))
	body := `{"from":"no-reply@example.com","to":["a@elsewhere.test"],"subject":"s","text":"t",
	          "attachments":[{"filename":"f.pdf","content_type":"application/pdf","content":"` + content + `"}]}`

	recorder := f.post(body, nil)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", recorder.Code, recorder.Body)
	}

	id := uuid.MustParse(decodeBody[sendResponse](t, recorder).ID)
	payload, err := f.store.GetPayload(f.ctx, id)
	if err != nil {
		t.Fatalf("GetPayload: %v", err)
	}
	if !strings.Contains(string(payload), "f.pdf") {
		t.Fatalf("the attachment is missing from the payload:\n%s", payload)
	}
}

// Base64 arrives in several flavours depending on the client and whether it was
// pasted out of a file.
func TestDecodeBase64Variants(t *testing.T) {
	want := "hello"
	variants := map[string]string{
		"standard":          base64.StdEncoding.EncodeToString([]byte(want)),
		"raw standard":      base64.RawStdEncoding.EncodeToString([]byte(want)),
		"url safe":          base64.URLEncoding.EncodeToString([]byte(want)),
		"raw url safe":      base64.RawURLEncoding.EncodeToString([]byte(want)),
		"wrapped in blanks": "  aGVs\n bG8=  \r\n",
	}
	for name, encoded := range variants {
		t.Run(name, func(t *testing.T) {
			got, err := decodeBase64(encoded)
			if err != nil {
				t.Fatalf("decodeBase64(%q): %v", encoded, err)
			}
			if string(got) != want {
				t.Fatalf("got %q, want %q", got, want)
			}
		})
	}

	for _, bad := range []string{"", "   ", "not base64!!!"} {
		if _, err := decodeBase64(bad); err == nil {
			t.Fatalf("decodeBase64(%q) succeeded", bad)
		}
	}
}

// --- authentication ---------------------------------------------------------

// Every authentication failure looks the same to the client: whether a key is
// unknown, revoked or simply wrong is an operator's business, not the caller's.
func TestPostEmailRequiresAuthentication(t *testing.T) {
	f := newFixture(t)
	revoked := f.newCredential("revoked", "no-reply@example.com")

	// Revoke it, so a real-but-dead key is among the cases.
	credentials, err := f.store.ListCredentials(f.ctx)
	if err != nil {
		t.Fatalf("ListCredentials: %v", err)
	}
	for _, c := range credentials {
		if c.Name == "revoked" {
			if _, err := f.store.RevokeCredential(f.ctx, c.ID); err != nil {
				t.Fatalf("RevokeCredential: %v", err)
			}
		}
	}

	tests := map[string]string{
		"no header":                 "",
		"wrong scheme":              "Basic " + base64.StdEncoding.EncodeToString([]byte("a:b")),
		"empty bearer":              "Bearer ",
		"not a relais key":          "Bearer sk_live_something_else",
		"well-formed unknown":       "Bearer " + crypto.APIKeyPrefix + "abcdefghijkl_" + strings.Repeat("A", 43),
		"revoked key":               "Bearer " + revoked,
		"right prefix wrong secret": "Bearer " + tamperSecret(f.apiKey),
	}

	for name, header := range tests {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/emails", strings.NewReader(minimalBody))
			req.Header.Set("Content-Type", "application/json")
			if header != "" {
				req.Header.Set("Authorization", header)
			}
			recorder := httptest.NewRecorder()
			f.handler.ServeHTTP(recorder, req)

			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401: %s", recorder.Code, recorder.Body)
			}
			// RFC 7235 wants a challenge on a 401.
			if got := recorder.Header().Get("WWW-Authenticate"); !strings.Contains(got, "Bearer") {
				t.Fatalf("WWW-Authenticate = %q", got)
			}

			// The body must be identical for every cause: no oracle.
			body := decodeBody[errorEnvelope](t, recorder)
			if body.Error.Code != codeUnauthorized || body.Error.Message != "authentication failed" {
				t.Fatalf("the response distinguishes the cause: %+v", body.Error)
			}
		})
	}
}

// The bearer scheme is case-insensitive per RFC 7235, and clients disagree.
func TestBearerSchemeIsCaseInsensitive(t *testing.T) {
	f := newFixture(t)

	for _, scheme := range []string{"Bearer", "bearer", "BEARER"} {
		req := httptest.NewRequest(http.MethodPost, "/v1/emails", strings.NewReader(minimalBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", scheme+" "+f.apiKey)
		recorder := httptest.NewRecorder()
		f.handler.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusAccepted {
			t.Fatalf("scheme %q: status = %d, want 202: %s", scheme, recorder.Code, recorder.Body)
		}
	}
}

// --- rejections -------------------------------------------------------------

// A client has to be able to tell "fix your configuration" from "try again". A
// library that retries every 4xx would hammer relais over a From it may not use.
func TestPostEmailRejectionStatusCodes(t *testing.T) {
	tests := []struct {
		name       string
		patterns   []string
		body       string
		wantStatus int
		wantCode   string
	}{
		{
			name:       "sender outside the allow-list is 403",
			patterns:   []string{"no-reply@example.com"},
			body:       `{"from":"ceo@example.com","to":["a@elsewhere.test"],"subject":"s","text":"t"}`,
			wantStatus: http.StatusForbidden,
			wantCode:   ingest.ReasonSenderNotAllowed,
		},
		{
			name:       "domain with no route is 422",
			patterns:   []string{"*@*.other.test"},
			body:       `{"from":"a@mail.other.test","to":["a@elsewhere.test"],"subject":"s","text":"t"}`,
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   ingest.ReasonDomainNotConfigured,
		},
		{
			name:       "no recipients is 422",
			patterns:   []string{"no-reply@example.com"},
			body:       `{"from":"no-reply@example.com","to":[],"subject":"s","text":"t"}`,
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   "missing_recipients",
		},
		{
			name:       "too many recipients is 422",
			patterns:   []string{"no-reply@example.com"},
			body:       `{"from":"no-reply@example.com","to":["a@e.test","b@e.test","c@e.test","d@e.test","e@e.test","f@e.test"],"subject":"s","text":"t"}`,
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   "too_many_recipients",
		},
		{
			name:       "no body is 422",
			patterns:   []string{"no-reply@example.com"},
			body:       `{"from":"no-reply@example.com","to":["a@elsewhere.test"],"subject":"s"}`,
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   "missing_body",
		},
		{
			name:       "unusable sender address is 422",
			patterns:   []string{"no-reply@example.com"},
			body:       `{"from":"not an address","to":["a@elsewhere.test"],"subject":"s","text":"t"}`,
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   "invalid_from",
		},
		{
			name:       "reserved header is 422",
			patterns:   []string{"no-reply@example.com"},
			body:       `{"from":"no-reply@example.com","to":["a@elsewhere.test"],"subject":"s","text":"t","headers":{"From":"ceo@example.com"}}`,
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   "invalid_header",
		},
		{
			name:       "header injection is 422",
			patterns:   []string{"no-reply@example.com"},
			body:       `{"from":"no-reply@example.com","to":["a@elsewhere.test"],"subject":"s","text":"t","headers":{"X-A":"v\r\nX-Injected: yes"}}`,
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   "invalid_header",
		},
		{
			name:       "bad base64 attachment is 422",
			patterns:   []string{"no-reply@example.com"},
			body:       `{"from":"no-reply@example.com","to":["a@elsewhere.test"],"subject":"s","text":"t","attachments":[{"filename":"f.bin","content":"!!!"}]}`,
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   "invalid_attachment",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, tc.patterns...)

			recorder := f.post(tc.body, nil)
			if recorder.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d: %s", recorder.Code, tc.wantStatus, recorder.Body)
			}
			body := decodeBody[errorEnvelope](t, recorder)
			if body.Error.Code != tc.wantCode {
				t.Fatalf("code = %q, want %q (%s)", body.Error.Code, tc.wantCode, recorder.Body)
			}
			// Nothing may have been queued.
			if len(f.enqueued) != 0 {
				t.Fatalf("%d jobs enqueued for a rejected submission", len(f.enqueued))
			}
		})
	}
}

// A refused sender is recorded, and the response points at the row so an operator
// can find the explanation.
func TestRejectionResponseCarriesMessageID(t *testing.T) {
	f := newFixture(t, "no-reply@example.com")

	recorder := f.post(`{"from":"ceo@example.com","to":["a@elsewhere.test"],"subject":"s","text":"t"}`, nil)
	body := decodeBody[errorEnvelope](t, recorder)
	if body.Error.MessageID == "" {
		t.Fatal("no message_id on a recorded rejection")
	}

	row, err := f.store.GetMessage(f.ctx, uuid.MustParse(body.Error.MessageID))
	if err != nil {
		t.Fatalf("GetMessage: %v", err)
	}
	if row.Status != store.StatusRejected {
		t.Fatalf("status = %q, want rejected", row.Status)
	}
}

func TestPostEmailRateLimitReturns429(t *testing.T) {
	f := newFixture(t, "no-reply@example.com")

	// A per-credential override. Set directly: the point of this test is the
	// response, not the admin path that will set it in M7.
	if _, err := f.pool.Exec(f.ctx,
		"UPDATE credential SET rate_limit_rps = 1, rate_limit_burst = 1 WHERE name = 'app'"); err != nil {
		t.Fatalf("set the rate limit: %v", err)
	}

	if got := f.post(minimalBody, nil).Code; got != http.StatusAccepted {
		t.Fatalf("first submission: status = %d, want 202", got)
	}

	recorder := f.post(minimalBody, nil)
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429: %s", recorder.Code, recorder.Body)
	}
	// Without this a client has no idea how long to wait.
	if recorder.Header().Get("Retry-After") == "" {
		t.Fatal("no Retry-After on a 429")
	}
	if got := decodeBody[errorEnvelope](t, recorder).Error.Code; got != ingest.ReasonRateLimited {
		t.Fatalf("code = %q", got)
	}
}

// --- malformed requests -----------------------------------------------------

func TestPostEmailRejectsMalformedJSON(t *testing.T) {
	f := newFixture(t)

	tests := map[string]string{
		"not json":      `nope`,
		"truncated":     `{"from":"a@example.com"`,
		"array":         `[]`,
		"two objects":   `{"from":"no-reply@example.com","to":["a@e.test"],"subject":"s","text":"t"} {"extra":1}`,
		"wrong to type": `{"from":"no-reply@example.com","to":42,"subject":"s","text":"t"}`,
		"empty body":    ``,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			recorder := f.post(body, nil)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", recorder.Code, recorder.Body)
			}
			if got := decodeBody[errorEnvelope](t, recorder).Error.Code; got != codeInvalidJSON {
				t.Fatalf("code = %q, want %q", got, codeInvalidJSON)
			}
		})
	}
}

// A misspelled "attachements" that is silently ignored means a client believes it
// attached a file and nobody finds out until a recipient complains.
func TestPostEmailRejectsUnknownFields(t *testing.T) {
	f := newFixture(t)

	body := `{"from":"no-reply@example.com","to":["a@elsewhere.test"],"subject":"s","text":"t","attachements":[]}`
	recorder := f.post(body, nil)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", recorder.Code, recorder.Body)
	}
	if !strings.Contains(recorder.Body.String(), "attachements") {
		t.Fatalf("the response does not name the offending field: %s", recorder.Body)
	}
}

func TestPostEmailEnforcesBodyLimit(t *testing.T) {
	f := newFixture(t)

	// Larger than MaxRequestBytes (2 MiB) in the fixture.
	huge := `{"from":"no-reply@example.com","to":["a@elsewhere.test"],"subject":"s","text":"` +
		strings.Repeat("x", 3<<20) + `"}`

	recorder := f.post(huge, nil)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413: %s", recorder.Code, recorder.Body)
	}
}

// --- idempotency ------------------------------------------------------------

func TestPostEmailIdempotency(t *testing.T) {
	f := newFixture(t)
	headers := map[string]string{"Idempotency-Key": "order-42"}

	first := f.post(minimalBody, headers)
	if first.Code != http.StatusAccepted {
		t.Fatalf("first: status = %d, want 202: %s", first.Code, first.Body)
	}
	firstBody := decodeBody[sendResponse](t, first)

	second := f.post(minimalBody, headers)
	// 200 rather than 202: the status code is the cheapest way to tell a client
	// whether its retry actually sent anything.
	if second.Code != http.StatusOK {
		t.Fatalf("replay: status = %d, want 200: %s", second.Code, second.Body)
	}
	secondBody := decodeBody[sendResponse](t, second)

	if secondBody.ID != firstBody.ID {
		t.Fatalf("the replay returned %s, want the original %s", secondBody.ID, firstBody.ID)
	}
	if !secondBody.Idempotent {
		t.Fatal("the replay was not flagged as one")
	}
	if len(f.enqueued) != 1 {
		t.Fatalf("%d jobs enqueued, want 1: the retry sent a second copy", len(f.enqueued))
	}
}

// --- reading a message ------------------------------------------------------

func TestGetEmail(t *testing.T) {
	f := newFixture(t)

	posted := decodeBody[sendResponse](t, f.post(minimalBody, nil))

	recorder := f.get("/v1/emails/"+posted.ID, f.apiKey)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body)
	}

	body := decodeBody[messageResponse](t, recorder)
	if body.ID != posted.ID {
		t.Fatalf("id = %q", body.ID)
	}
	if body.Status != store.StatusQueued {
		t.Fatalf("status = %q", body.Status)
	}
	if body.From != "no-reply@example.com" {
		t.Fatalf("from = %q", body.From)
	}
	if len(body.Recipients) != 1 {
		t.Fatalf("recipients = %v", body.Recipients)
	}
	// A queued message has not been sent, and null is clearer than a zero date
	// that looks like 1970.
	if body.SentAt != nil {
		t.Fatalf("sent_at = %v on a queued message", *body.SentAt)
	}
	if body.CreatedAt == "" {
		t.Fatal("created_at is empty")
	}
	if body.Error != nil {
		t.Fatalf("error = %+v on a queued message", body.Error)
	}
}

// One credential must not be able to read another's messages. A 404 rather than a
// 403, because a 403 confirms the id exists.
func TestGetEmailIsScopedToTheCredential(t *testing.T) {
	f := newFixture(t)

	posted := decodeBody[sendResponse](t, f.post(minimalBody, nil))
	other := f.newCredential("other", "no-reply@example.com")

	recorder := f.get("/v1/emails/"+posted.ID, other)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: %s", recorder.Code, recorder.Body)
	}
	if got := decodeBody[errorEnvelope](t, recorder).Error.Code; got != codeNotFound {
		t.Fatalf("code = %q", got)
	}
	// The response must not hint that the message exists.
	if strings.Contains(recorder.Body.String(), posted.ID) {
		t.Fatalf("the response echoes the id it is denying: %s", recorder.Body)
	}
}

func TestGetEmailNotFound(t *testing.T) {
	f := newFixture(t)

	for _, path := range []string{
		"/v1/emails/" + uuid.NewString(),
		"/v1/emails/not-a-uuid",
	} {
		recorder := f.get(path, f.apiKey)
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("GET %s: status = %d, want 404", path, recorder.Code)
		}
	}
}

func TestGetEmailRequiresAuthentication(t *testing.T) {
	f := newFixture(t)
	posted := decodeBody[sendResponse](t, f.post(minimalBody, nil))

	if got := f.get("/v1/emails/"+posted.ID, "").Code; got != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", got)
	}
}

// --- routing ----------------------------------------------------------------

func TestRoutingEdges(t *testing.T) {
	f := newFixture(t)

	t.Run("unknown endpoint", func(t *testing.T) {
		if got := f.get("/v1/nope", f.apiKey).Code; got != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", got)
		}
	})

	t.Run("wrong method", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/v1/emails", nil)
		req.Header.Set("Authorization", "Bearer "+f.apiKey)
		recorder := httptest.NewRecorder()
		f.handler.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d, want 405: %s", recorder.Code, recorder.Body)
		}
	})

	// Probes must stay reachable without a credential: an orchestrator has none.
	t.Run("health is public", func(t *testing.T) {
		for _, path := range []string{"/healthz", "/readyz"} {
			if got := f.get(path, "").Code; got != http.StatusOK {
				t.Fatalf("GET %s without a credential: status = %d, want 200", path, got)
			}
		}
	})
}

// A submission body is an email. It must never reach an access log.
func TestRequestLogOmitsContent(t *testing.T) {
	f := newFixture(t)

	var logged bytes.Buffer
	server, err := NewServer(Options{
		Ingest: f.ingest, Store: f.store, Authenticator: f.authenticator, Pool: f.pool,
		Limits: Limits{MaxMessageBytes: 1 << 20, MaxRequestBytes: 2 << 20, MaxRecipients: 5},
		Log:    slog.New(slog.NewTextHandler(&logged, nil)), Version: "test",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/emails",
		strings.NewReader(`{"from":"no-reply@example.com","to":["a@elsewhere.test"],"subject":"CONFIDENTIAL SUBJECT","text":"SECRET BODY CONTENT"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+f.apiKey)
	req.RemoteAddr = "203.0.113.7:1234"

	server.Handler().ServeHTTP(httptest.NewRecorder(), req)

	output := logged.String()
	for _, forbidden := range []string{"SECRET BODY CONTENT", "CONFIDENTIAL SUBJECT", f.apiKey} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("the log contains %q:\n%s", forbidden, output)
		}
	}
	// It must still be useful.
	for _, wanted := range []string{"/v1/emails", "203.0.113.7", "credential_name"} {
		if !strings.Contains(output, wanted) {
			t.Fatalf("the log is missing %q:\n%s", wanted, output)
		}
	}
}

// --- helpers ----------------------------------------------------------------

// tamperSecret keeps a token's lookup half and breaks its secret half, producing
// a well-formed key that names a real credential with the wrong secret.
func tamperSecret(token string) string {
	if token == "" {
		return token
	}
	last := token[len(token)-1]
	replacement := byte('a')
	if last == 'a' {
		replacement = 'b'
	}
	return token[:len(token)-1] + string(replacement)
}
