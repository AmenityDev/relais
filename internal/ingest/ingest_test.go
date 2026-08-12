package ingest

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/amenitydev/relais/internal/crypto"
	"github.com/amenitydev/relais/internal/dbtest"
	"github.com/amenitydev/relais/internal/mailbuild"
	"github.com/amenitydev/relais/internal/mailnorm"
	"github.com/amenitydev/relais/internal/ratelimit"
	"github.com/amenitydev/relais/internal/store"
)

// These tests need a real Postgres with the schema applied: the pipeline's
// guarantees are transactional, and a fake would assert nothing about the one
// property that matters most (message, payload and job commit together).
//
//	docker compose up -d && go run ./cmd/relais migrate up && go test ./internal/ingest/
//
// See internal/dbtest for how the database is resolved, and why an unreachable
// one fails in CI but skips locally.

// stubEnqueuer records what would be enqueued, and can be made to fail so that
// transaction rollback is observable.
type stubEnqueuer struct {
	mu sync.Mutex
	// ids are the messages handed to Enqueue.
	ids []uuid.UUID
	// txUsable records whether the transaction we were given actually worked,
	// which is what proves the job is inserted in the caller's transaction rather
	// than alongside it.
	txUsable bool
	err      error
}

func (s *stubEnqueuer) Enqueue(ctx context.Context, tx pgx.Tx, messageID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if tx != nil {
		var one int
		if err := tx.QueryRow(ctx, "SELECT 1").Scan(&one); err == nil && one == 1 {
			s.txUsable = true
		}
	}
	if s.err != nil {
		return s.err
	}
	s.ids = append(s.ids, messageID)
	return nil
}

func (s *stubEnqueuer) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.ids)
}

type fixture struct {
	t        *testing.T
	ctx      context.Context
	pool     *pgxpool.Pool
	store    *store.Store
	service  *Service
	enqueuer *stubEnqueuer

	backendID uuid.UUID
	auth      store.AuthCredential
}

func newFixture(t *testing.T, patterns ...string) *fixture {
	t.Helper()

	if len(patterns) == 0 {
		patterns = []string{"no-reply@example.com", "*@mail.example.com"}
	}

	ctx := context.Background()
	pool := dbtest.Pool(t)

	keyring, err := crypto.ParseKeyring("1:"+testKey(0x21), "")
	if err != nil {
		t.Fatalf("ParseKeyring: %v", err)
	}
	hasher, err := crypto.NewHasher(testKey(0x43))
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

	enqueuer := &stubEnqueuer{}
	service, err := New(Options{
		Store:    st,
		Enqueuer: enqueuer,
		Limiter:  ratelimit.New(ratelimit.Options{}),
		Config: Config{
			MaxMessageBytes:        1 << 20,
			MaxHeaderCount:         200,
			MaxHeaderBytes:         128 << 10,
			MaxRecipients:          5,
			DefaultRateLimitRPS:    1000,
			DefaultRateLimitBurst:  1000,
			RejectedRateLimitRPS:   1000,
			RejectedRateLimitBurst: 1000,
			IdempotencyTTL:         time.Hour,
		},
		// Discard logs: these tests assert on stored state, and the log output
		// would bury the failures.
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:   func() time.Time { return time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC) },
		NewID: func() string { return "generated-id" },
	})
	if err != nil {
		t.Fatalf("ingest.New: %v", err)
	}

	f := &fixture{t: t, ctx: ctx, pool: pool, store: st, service: service, enqueuer: enqueuer, backendID: backend.ID}
	f.credential(patterns...)
	return f
}

func testKey(fill byte) string {
	raw := make([]byte, crypto.KeySize)
	for i := range raw {
		raw[i] = fill + byte(i)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// credential creates the credential the fixture's requests are made with.
func (f *fixture) credential(patterns ...string) store.AuthCredential {
	f.t.Helper()

	created, err := f.store.CreateCredential(f.ctx, store.NewCredentialParams{
		Name: "app-" + uuid.NewString()[:8], Type: store.CredentialTypeAPIKey,
		Patterns: patterns, Enabled: true,
	})
	if err != nil {
		f.t.Fatalf("CreateCredential: %v", err)
	}
	auth, err := f.store.LoadCredential(f.ctx, created.Credential.ID)
	if err != nil {
		f.t.Fatalf("LoadCredential: %v", err)
	}
	f.auth = auth
	return auth
}

func (f *fixture) request(raw string, recipients ...string) Request {
	if len(recipients) == 0 {
		recipients = []string{"someone@elsewhere.test"}
	}
	return Request{
		Credential:         f.auth,
		Facade:             store.FacadeREST,
		Raw:                []byte(strings.ReplaceAll(raw, "\n", "\r\n")),
		EnvelopeRecipients: recipients,
		RemoteIP:           netip.MustParseAddr("203.0.113.7"),
	}
}

// message builds a minimal valid submission from the given sender.
func message(from string) string {
	return "From: " + from + "\nTo: someone@elsewhere.test\nSubject: Test\n\nBody.\n"
}

func (f *fixture) countMessages() int {
	f.t.Helper()
	var count int
	if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM email_message").Scan(&count); err != nil {
		f.t.Fatalf("count messages: %v", err)
	}
	return count
}

func (f *fixture) countPayloads() int {
	f.t.Helper()
	var count int
	if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM email_payload").Scan(&count); err != nil {
		f.t.Fatalf("count payloads: %v", err)
	}
	return count
}

// --- the happy path ---------------------------------------------------------

func TestSubmitAcceptsAuthorizedSender(t *testing.T) {
	f := newFixture(t)

	res, err := f.service.Submit(f.ctx, f.request(message("no-reply@example.com")))
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	if res.Status != store.StatusQueued {
		t.Fatalf("status = %q, want queued", res.Status)
	}
	if res.Duplicate {
		t.Fatal("a first submission was reported as a duplicate")
	}
	// The backend is resolved and pinned at ingestion, not at delivery.
	if res.BackendID != f.backendID {
		t.Fatalf("BackendID = %s, want %s", res.BackendID, f.backendID)
	}
	// A missing Message-ID is generated in the sender's own domain.
	if res.RFCMessageID != "<generated-id@example.com>" {
		t.Fatalf("RFCMessageID = %q", res.RFCMessageID)
	}

	row, err := f.store.GetMessage(f.ctx, res.ID)
	if err != nil {
		t.Fatalf("GetMessage: %v", err)
	}
	if row.FromAddr != "no-reply@example.com" || row.FromDomain != "example.com" {
		t.Fatalf("stored sender = %q / %q", row.FromAddr, row.FromDomain)
	}
	if row.Subject != "Test" {
		t.Fatalf("stored subject = %q", row.Subject)
	}
	if len(row.EnvelopeRecipients) != 1 || row.EnvelopeRecipients[0] != "someone@elsewhere.test" {
		t.Fatalf("envelope = %v", row.EnvelopeRecipients)
	}
	if row.RemoteIp == nil || row.RemoteIp.String() != "203.0.113.7" {
		t.Fatalf("remote ip = %v", row.RemoteIp)
	}
	if row.SizeBytes == 0 {
		t.Fatal("size was not recorded")
	}

	// The payload must be stored, and be exactly what will go on the wire.
	payload, err := f.store.GetPayload(f.ctx, res.ID)
	if err != nil {
		t.Fatalf("GetPayload: %v", err)
	}
	if !strings.Contains(string(payload), "Body.") {
		t.Fatalf("payload = %q", payload)
	}
	if !strings.Contains(string(payload), "Message-Id: <generated-id@example.com>") {
		t.Fatalf("the generated Message-ID is missing from the payload:\n%s", payload)
	}
	if int64(len(payload)) != int64(row.SizeBytes) {
		t.Fatalf("size_bytes = %d but the payload is %d bytes", row.SizeBytes, len(payload))
	}

	// Exactly one job, for this message, inserted through the transaction.
	if f.enqueuer.count() != 1 {
		t.Fatalf("%d jobs enqueued, want 1", f.enqueuer.count())
	}
	if f.enqueuer.ids[0] != res.ID {
		t.Fatalf("enqueued %s, want %s", f.enqueuer.ids[0], res.ID)
	}
	if !f.enqueuer.txUsable {
		t.Fatal("the enqueuer was not given a usable transaction: the job would commit separately from the message")
	}
}

func TestSubmitWildcardAndSubdomain(t *testing.T) {
	f := newFixture(t, "*@mail.example.com", "*@*.example.com")

	for _, from := range []string{"anyone@mail.example.com", "someone@deep.sub.example.com"} {
		res, err := f.service.Submit(f.ctx, f.request(message(from)))
		if err != nil {
			t.Fatalf("Submit(%s): %v", from, err)
		}
		if res.Status != store.StatusQueued {
			t.Fatalf("Submit(%s) status = %q", from, res.Status)
		}
	}
}

// The REST façade's own output must survive the pipeline: this is the seam
// between mailbuild and mailnorm, and it is where a MIME bug would hide.
func TestSubmitAcceptsMailbuildOutput(t *testing.T) {
	f := newFixture(t)

	built, err := mailbuild.Build(mailbuild.Input{
		From:    "App <no-reply@example.com>",
		To:      []string{"someone@elsewhere.test"},
		Cc:      []string{"watcher@elsewhere.test"},
		Bcc:     []string{"hidden@elsewhere.test"},
		Subject: "Café ☕",
		Text:    "Plain.",
		HTML:    "<p>Rich.</p>",
		Attachments: []mailbuild.Attachment{{
			Filename: "note.txt", ContentType: "text/plain", Content: []byte("attached"),
		}},
	}, mailbuild.Options{MaxRecipients: 50, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatalf("mailbuild.Build: %v", err)
	}

	req := Request{
		Credential:         f.auth,
		Facade:             store.FacadeREST,
		Raw:                built.Raw,
		EnvelopeRecipients: built.Envelope,
		DeclaredBcc:        built.Bcc,
		RemoteIP:           netip.MustParseAddr("203.0.113.7"),
	}
	res, err := f.service.Submit(f.ctx, req)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	row, err := f.store.GetMessage(f.ctx, res.ID)
	if err != nil {
		t.Fatalf("GetMessage: %v", err)
	}
	if len(row.EnvelopeRecipients) != 3 {
		t.Fatalf("envelope = %v, want all three recipients", row.EnvelopeRecipients)
	}
	// The declared bcc is recorded for the audit trail...
	if len(row.BccAddrs) != 1 || row.BccAddrs[0] != "hidden@elsewhere.test" {
		t.Fatalf("bcc_addrs = %v", row.BccAddrs)
	}
	// ...but must not be in the bytes that go out.
	payload, err := f.store.GetPayload(f.ctx, res.ID)
	if err != nil {
		t.Fatalf("GetPayload: %v", err)
	}
	if strings.Contains(string(payload), "hidden@elsewhere.test") {
		t.Fatalf("the blind recipient leaked into the payload:\n%s", payload)
	}
	if !strings.Contains(string(payload), "attached") && !strings.Contains(string(payload), base64.StdEncoding.EncodeToString([]byte("attached"))) {
		t.Fatal("the attachment is missing from the payload")
	}
}

// A Bcc header submitted over SMTP must be stripped from the relayed bytes while
// staying in the audit trail.
func TestSubmitStripsBccFromSMTPSubmission(t *testing.T) {
	f := newFixture(t)

	raw := "From: no-reply@example.com\nTo: someone@elsewhere.test\nBcc: hidden@elsewhere.test\nSubject: t\n\nBody.\n"
	req := f.request(raw, "someone@elsewhere.test", "hidden@elsewhere.test")
	req.Facade = store.FacadeSMTP

	res, err := f.service.Submit(f.ctx, req)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	payload, err := f.store.GetPayload(f.ctx, res.ID)
	if err != nil {
		t.Fatalf("GetPayload: %v", err)
	}
	if strings.Contains(strings.ToLower(string(payload)), "bcc:") {
		t.Fatalf("the Bcc header survived:\n%s", payload)
	}

	row, err := f.store.GetMessage(f.ctx, res.ID)
	if err != nil {
		t.Fatalf("GetMessage: %v", err)
	}
	if len(row.BccAddrs) != 1 {
		t.Fatalf("bcc_addrs = %v, want the header value retained for audit", row.BccAddrs)
	}
	// The envelope keeps both, because that is what actually gets delivered.
	if len(row.EnvelopeRecipients) != 2 {
		t.Fatalf("envelope = %v", row.EnvelopeRecipients)
	}
}

// --- rejections -------------------------------------------------------------

// The single most important behaviour in the service.
func TestSubmitRejectsUnauthorizedSender(t *testing.T) {
	f := newFixture(t, "no-reply@example.com")

	res, err := f.service.Submit(f.ctx, f.request(message("ceo@example.com")))
	if err == nil {
		t.Fatalf("Submit accepted an unauthorized sender: %+v", res)
	}

	rejection, ok := AsRejection(err)
	if !ok {
		t.Fatalf("error is not a Rejection: %v", err)
	}
	if rejection.Reason != ReasonSenderNotAllowed {
		t.Fatalf("reason = %q, want %q", rejection.Reason, ReasonSenderNotAllowed)
	}
	if rejection.Temporary {
		t.Fatal("an unauthorized sender must not be reported as retryable")
	}

	// The rejection is recorded, with enough context to investigate a leak.
	if rejection.MessageID == uuid.Nil {
		t.Fatal("the rejection was not persisted")
	}
	row, err := f.store.GetMessage(f.ctx, rejection.MessageID)
	if err != nil {
		t.Fatalf("GetMessage: %v", err)
	}
	if row.Status != store.StatusRejected {
		t.Fatalf("status = %q, want rejected", row.Status)
	}
	if row.RejectionReason == nil || *row.RejectionReason != ReasonSenderNotAllowed {
		t.Fatalf("rejection_reason = %v", row.RejectionReason)
	}
	if row.FromAddr != "ceo@example.com" {
		t.Fatalf("from_addr = %q, want the attempted sender recorded", row.FromAddr)
	}
	if row.RemoteIp == nil {
		t.Fatal("the remote ip was not recorded: a leaked credential could not be traced")
	}

	// Nothing was queued and no content was retained.
	if f.enqueuer.count() != 0 {
		t.Fatalf("%d jobs enqueued for a rejected submission", f.enqueuer.count())
	}
	if f.countPayloads() != 0 {
		t.Fatal("a payload was stored for a rejected submission")
	}
}

// A credential with no pattern can send as nobody. This is the property that
// makes a freshly created credential harmless.
func TestSubmitRejectsEverythingWithoutPatterns(t *testing.T) {
	f := newFixture(t)
	// Replace the fixture credential with one that has no patterns at all.
	created, err := f.store.CreateCredential(f.ctx, store.NewCredentialParams{
		Name: "no-patterns", Type: store.CredentialTypeAPIKey, Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}
	auth, err := f.store.LoadCredential(f.ctx, created.Credential.ID)
	if err != nil {
		t.Fatalf("LoadCredential: %v", err)
	}
	f.auth = auth

	for _, from := range []string{"no-reply@example.com", "anyone@mail.example.com", "a@b.test"} {
		_, err := f.service.Submit(f.ctx, f.request(message(from)))
		rejection, ok := AsRejection(err)
		if !ok {
			t.Fatalf("Submit(%s) = %v, want a rejection", from, err)
		}
		if rejection.Reason != ReasonSenderNotAllowed {
			t.Fatalf("Submit(%s) reason = %q", from, rejection.Reason)
		}
	}
}

// A pattern can allow a sender whose domain has no route. That is a
// configuration gap, and the message says which one.
func TestSubmitRejectsUnconfiguredDomain(t *testing.T) {
	f := newFixture(t, "*@*.other.test")

	_, err := f.service.Submit(f.ctx, f.request(message("someone@mail.other.test")))
	rejection, ok := AsRejection(err)
	if !ok {
		t.Fatalf("Submit = %v, want a rejection", err)
	}
	if rejection.Reason != ReasonDomainNotConfigured {
		t.Fatalf("reason = %q, want %q", rejection.Reason, ReasonDomainNotConfigured)
	}
	if !strings.Contains(rejection.Detail, "mail.other.test") {
		t.Fatalf("detail %q does not name the domain", rejection.Detail)
	}
	if f.enqueuer.count() != 0 {
		t.Fatal("a job was enqueued for an unroutable message")
	}
}

func TestSubmitRejectsRevokedCredential(t *testing.T) {
	f := newFixture(t)

	if _, err := f.store.RevokeCredential(f.ctx, f.auth.Credential.ID); err != nil {
		t.Fatalf("RevokeCredential: %v", err)
	}
	auth, err := f.store.LoadCredential(f.ctx, f.auth.Credential.ID)
	if err != nil {
		t.Fatalf("LoadCredential: %v", err)
	}
	f.auth = auth

	_, err = f.service.Submit(f.ctx, f.request(message("no-reply@example.com")))
	rejection, ok := AsRejection(err)
	if !ok {
		t.Fatalf("Submit = %v, want a rejection", err)
	}
	if rejection.Reason != ReasonCredentialUnusable {
		t.Fatalf("reason = %q, want %q", rejection.Reason, ReasonCredentialUnusable)
	}
}

func TestSubmitRejectsMalformedMessage(t *testing.T) {
	f := newFixture(t)

	tests := map[string]string{
		mailnorm.CodeNoFrom:       "To: someone@elsewhere.test\nSubject: t\n\nBody.\n",
		mailnorm.CodeMultipleFrom: "From: no-reply@example.com\nFrom: ceo@example.com\nSubject: t\n\nBody.\n",
		mailnorm.CodeInvalidFrom:  "From: not an address\nSubject: t\n\nBody.\n",
		mailnorm.CodeEmpty:        "",
	}
	for wantCode, raw := range tests {
		t.Run(wantCode, func(t *testing.T) {
			_, err := f.service.Submit(f.ctx, f.request(raw))
			rejection, ok := AsRejection(err)
			if !ok {
				t.Fatalf("Submit = %v, want a rejection", err)
			}
			if rejection.Reason != wantCode {
				t.Fatalf("reason = %q, want %q", rejection.Reason, wantCode)
			}
		})
	}
}

func TestSubmitRejectsRecipientProblems(t *testing.T) {
	f := newFixture(t)

	t.Run("none", func(t *testing.T) {
		req := f.request(message("no-reply@example.com"))
		req.EnvelopeRecipients = nil
		_, err := f.service.Submit(f.ctx, req)
		rejection, ok := AsRejection(err)
		if !ok || rejection.Reason != ReasonNoRecipients {
			t.Fatalf("Submit = %v, want %q", err, ReasonNoRecipients)
		}
	})

	t.Run("too many", func(t *testing.T) {
		recipients := make([]string, 0, 10)
		for i := range 10 {
			recipients = append(recipients, string(rune('a'+i))+"@elsewhere.test")
		}
		_, err := f.service.Submit(f.ctx, f.request(message("no-reply@example.com"), recipients...))
		rejection, ok := AsRejection(err)
		if !ok || rejection.Reason != ReasonTooManyRecipients {
			t.Fatalf("Submit = %v, want %q", err, ReasonTooManyRecipients)
		}
	})

	t.Run("unusable address", func(t *testing.T) {
		_, err := f.service.Submit(f.ctx, f.request(message("no-reply@example.com"), "root@localhost"))
		rejection, ok := AsRejection(err)
		if !ok || rejection.Reason != ReasonInvalidRecipient {
			t.Fatalf("Submit = %v, want %q", err, ReasonInvalidRecipient)
		}
	})

	t.Run("duplicates collapse", func(t *testing.T) {
		res, err := f.service.Submit(f.ctx, f.request(message("no-reply@example.com"),
			"dup@elsewhere.test", "DUP@Elsewhere.test", "other@elsewhere.test"))
		if err != nil {
			t.Fatalf("Submit: %v", err)
		}
		if len(res.Recipients) != 2 {
			t.Fatalf("recipients = %v, want duplicates collapsed", res.Recipients)
		}
	})
}

// --- rate limiting ----------------------------------------------------------

func TestSubmitRateLimits(t *testing.T) {
	f := newFixture(t)
	f.service.cfg.DefaultRateLimitRPS = 1
	f.service.cfg.DefaultRateLimitBurst = 2
	f.service.limiter = ratelimit.New(ratelimit.Options{
		Now: func() time.Time { return time.Unix(0, 0) },
	})

	for i := range 2 {
		if _, err := f.service.Submit(f.ctx, f.request(message("no-reply@example.com"))); err != nil {
			t.Fatalf("submission %d inside the burst: %v", i+1, err)
		}
	}

	_, err := f.service.Submit(f.ctx, f.request(message("no-reply@example.com")))
	rejection, ok := AsRejection(err)
	if !ok {
		t.Fatalf("Submit = %v, want a rejection", err)
	}
	if rejection.Reason != ReasonRateLimited {
		t.Fatalf("reason = %q, want %q", rejection.Reason, ReasonRateLimited)
	}
	// A client can usefully retry this one, unlike an authorisation failure.
	if !rejection.Temporary {
		t.Fatal("a rate limit rejection must be marked temporary")
	}
	// It must not be persisted: recording it would be the very write the limit
	// exists to prevent.
	if got := f.countMessages(); got != 2 {
		t.Fatalf("%d message rows, want 2: the rate-limited submission was persisted", got)
	}
}

// A credential looping against a misconfigured From must not fill the table.
func TestRejectionRecordsAreRateLimited(t *testing.T) {
	f := newFixture(t, "no-reply@example.com")
	f.service.cfg.RejectedRateLimitRPS = 1
	f.service.cfg.RejectedRateLimitBurst = 3
	f.service.limiter = ratelimit.New(ratelimit.Options{
		Now: func() time.Time { return time.Unix(0, 0) },
	})

	for range 20 {
		_, err := f.service.Submit(f.ctx, f.request(message("ceo@example.com")))
		if _, ok := AsRejection(err); !ok {
			t.Fatalf("Submit = %v, want a rejection every time", err)
		}
	}

	// Every attempt is refused, but only the first few are recorded.
	rows := f.countMessages()
	if rows == 0 {
		t.Fatal("no rejection was recorded at all")
	}
	if rows > 3 {
		t.Fatalf("%d rejection rows, want at most the burst of 3", rows)
	}
}

// --- idempotency ------------------------------------------------------------

func TestSubmitIsIdempotent(t *testing.T) {
	f := newFixture(t)

	req := f.request(message("no-reply@example.com"))
	req.IdempotencyKey = "order-42"

	first, err := f.service.Submit(f.ctx, req)
	if err != nil {
		t.Fatalf("first Submit: %v", err)
	}
	if first.Duplicate {
		t.Fatal("the first submission was reported as a duplicate")
	}

	second, err := f.service.Submit(f.ctx, req)
	if err != nil {
		t.Fatalf("second Submit: %v", err)
	}
	if !second.Duplicate {
		t.Fatal("the replay was not reported as a duplicate")
	}
	if second.ID != first.ID {
		t.Fatalf("the replay returned %s, want the original %s", second.ID, first.ID)
	}

	// One message, one payload, one job: the retry sent nothing new.
	if got := f.countMessages(); got != 1 {
		t.Fatalf("%d message rows, want 1", got)
	}
	if got := f.enqueuer.count(); got != 1 {
		t.Fatalf("%d jobs, want 1", got)
	}

	// A different key is a different message.
	req.IdempotencyKey = "order-43"
	third, err := f.service.Submit(f.ctx, req)
	if err != nil {
		t.Fatalf("third Submit: %v", err)
	}
	if third.Duplicate || third.ID == first.ID {
		t.Fatal("a different idempotency key was treated as a replay")
	}
}

// Keys are scoped per credential: two applications may both use "order-1".
func TestIdempotencyKeyIsScopedToCredential(t *testing.T) {
	f := newFixture(t)

	req := f.request(message("no-reply@example.com"))
	req.IdempotencyKey = "shared"
	first, err := f.service.Submit(f.ctx, req)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	other := f.credential("no-reply@example.com")
	req.Credential = other
	second, err := f.service.Submit(f.ctx, req)
	if err != nil {
		t.Fatalf("Submit as the other credential: %v", err)
	}
	if second.Duplicate || second.ID == first.ID {
		t.Fatal("an idempotency key leaked across credentials")
	}
}

// --- atomicity --------------------------------------------------------------

// If enqueuing fails, the message must not exist. A queued row with no job would
// sit there forever with nobody noticing.
func TestSubmitRollsBackWhenEnqueueFails(t *testing.T) {
	f := newFixture(t)
	f.enqueuer.err = errors.New("queue unavailable")

	_, err := f.service.Submit(f.ctx, f.request(message("no-reply@example.com")))
	if err == nil {
		t.Fatal("Submit succeeded although enqueuing failed")
	}
	if _, ok := AsRejection(err); ok {
		t.Fatalf("a queue failure was reported as a rejection: %v", err)
	}

	if got := f.countMessages(); got != 0 {
		t.Fatalf("%d message rows survived a failed enqueue", got)
	}
	if got := f.countPayloads(); got != 0 {
		t.Fatalf("%d payload rows survived a failed enqueue", got)
	}
}

func TestSubmitRequiresDependencies(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("New accepted no store")
	}
	if _, err := New(Options{Store: &store.Store{}}); err == nil {
		t.Fatal("New accepted no enqueuer")
	}
}
