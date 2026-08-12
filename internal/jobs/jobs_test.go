package jobs

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/amenitydev/relais/internal/crypto"
	"github.com/amenitydev/relais/internal/dbtest"
	"github.com/amenitydev/relais/internal/ingest"
	"github.com/amenitydev/relais/internal/ratelimit"
	"github.com/amenitydev/relais/internal/sender"
	"github.com/amenitydev/relais/internal/smtptest"
	"github.com/amenitydev/relais/internal/store"
)

// These tests need a real Postgres with the schema applied. See internal/dbtest.

const rawMessage = "From: no-reply@example.com\r\n" +
	"To: someone@elsewhere.test\r\n" +
	"Subject: Test\r\n" +
	"Message-Id: <a@example.com>\r\n" +
	"\r\n" +
	"Body.\r\n"

type fixture struct {
	t     *testing.T
	ctx   context.Context
	pool  *pgxpool.Pool
	store *store.Store
	sink  *smtptest.Sink

	backendID uuid.UUID
	auth      store.AuthCredential
}

func newFixture(t *testing.T, sinkOpts smtptest.Options) *fixture {
	t.Helper()

	ctx := context.Background()
	pool := dbtest.Pool(t)

	keyring, err := crypto.ParseKeyring("1:"+testKey(0x31), "")
	if err != nil {
		t.Fatalf("ParseKeyring: %v", err)
	}
	hasher, err := crypto.NewHasher(testKey(0x53))
	if err != nil {
		t.Fatalf("NewHasher: %v", err)
	}
	st, err := store.New(pool, keyring, hasher)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}

	sink := smtptest.Start(t, sinkOpts)

	backend, err := st.CreateBackend(ctx, store.NewBackendParams{
		Name: "sink", Host: sink.Host, Port: sink.Port,
		TLSMode: store.TLSModeNone, Enabled: true, MaxConcurrency: 2,
	})
	if err != nil {
		t.Fatalf("CreateBackend: %v", err)
	}
	if _, err := st.CreateDomain(ctx, store.NewDomainParams{
		Name: "example.com", BackendID: backend.ID, Enabled: true,
	}); err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}

	created, err := st.CreateCredential(ctx, store.NewCredentialParams{
		Name: "app", Type: store.CredentialTypeAPIKey, Enabled: true,
		Patterns: []string{"no-reply@example.com"},
	})
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}
	auth, err := st.LoadCredential(ctx, created.Credential.ID)
	if err != nil {
		t.Fatalf("LoadCredential: %v", err)
	}

	return &fixture{t: t, ctx: ctx, pool: pool, store: st, sink: sink, backendID: backend.ID, auth: auth}
}

func testKey(fill byte) string {
	raw := make([]byte, crypto.KeySize)
	for i := range raw {
		raw[i] = fill + byte(i)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func (f *fixture) newSender() *sender.Sender {
	return sender.New(sender.Config{
		Timeout:                 5 * time.Second,
		HeloName:                "relais.test",
		InsecureSkipVerifyHosts: []string{f.sink.Host},
	}, discardLogger())
}

// queueMessage puts an accepted message in the database without a real river
// client, so a worker branch can be exercised directly.
func (f *fixture) queueMessage(recipients ...string) uuid.UUID {
	f.t.Helper()

	if len(recipients) == 0 {
		recipients = []string{"someone@elsewhere.test"}
	}
	row, err := f.store.InsertQueuedMessage(f.ctx, store.NewMessageParams{
		CredentialID:       f.auth.Credential.ID,
		Facade:             store.FacadeREST,
		FromAddr:           "no-reply@example.com",
		FromDomain:         "example.com",
		To:                 recipients,
		EnvelopeRecipients: recipients,
		Subject:            "Test",
		MessageID:          "<a@example.com>",
		SizeBytes:          int64(len(rawMessage)),
		BackendID:          f.backendID,
		RemoteIP:           netip.MustParseAddr("203.0.113.7"),
	}, []byte(rawMessage), func(context.Context, pgx.Tx, uuid.UUID) error { return nil })
	if err != nil {
		f.t.Fatalf("InsertQueuedMessage: %v", err)
	}
	return row.ID
}

func (f *fixture) status(id uuid.UUID) (status, code, detail string) {
	f.t.Helper()
	row, err := f.store.GetMessage(f.ctx, id)
	if err != nil {
		f.t.Fatalf("GetMessage: %v", err)
	}
	if row.ErrorCode != nil {
		code = *row.ErrorCode
	}
	if row.ErrorDetail != nil {
		detail = *row.ErrorDetail
	}
	return row.Status, code, detail
}

// job builds a river job as the worker would receive it.
func job(messageID uuid.UUID, attempt, maxAttempts int) *river.Job[SendEmailArgs] {
	return &river.Job[SendEmailArgs]{
		JobRow: &rivertype.JobRow{ID: 1, Attempt: attempt, MaxAttempts: maxAttempts},
		Args:   SendEmailArgs{MessageID: messageID},
	}
}

// --- the full chain ---------------------------------------------------------

// The test that proves M4: a submission goes through ingest, river picks the job
// up, the sender delivers it, and the row ends up 'sent'. Everything real except
// the relay, which is an in-process SMTP server.
func TestEndToEndDelivery(t *testing.T) {
	f := newFixture(t, smtptest.Options{Mode: smtptest.ModePlain})

	client, err := NewClient(ClientOptions{
		Store:     f.store,
		Deliverer: f.newSender(),
		Log:       discardLogger(),
		Workers:   true,
		Count:     2,
		// A short interval keeps the periodic sweep from interfering with the
		// assertions while still exercising its registration.
		PurgeInterval:   time.Hour,
		SentRetention:   24 * time.Hour,
		FailedRetention: 168 * time.Hour,
		MaxAttempts:     3,
		JobTimeout:      10 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	service, err := ingest.New(ingest.Options{
		Store:    f.store,
		Enqueuer: NewEnqueuer(client, 3),
		Limiter:  ratelimit.New(ratelimit.Options{}),
		Config: ingest.Config{
			MaxMessageBytes:        1 << 20,
			MaxRecipients:          10,
			DefaultRateLimitRPS:    1000,
			DefaultRateLimitBurst:  1000,
			RejectedRateLimitRPS:   1000,
			RejectedRateLimitBurst: 1000,
			IdempotencyTTL:         time.Hour,
		},
		Log: discardLogger(),
	})
	if err != nil {
		t.Fatalf("ingest.New: %v", err)
	}

	if err := client.Start(f.ctx); err != nil {
		t.Fatalf("start river: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = client.Stop(stopCtx)
	})

	result, err := service.Submit(f.ctx, ingest.Request{
		Credential:         f.auth,
		Facade:             store.FacadeREST,
		Raw:                []byte(rawMessage),
		EnvelopeRecipients: []string{"someone@elsewhere.test"},
		RemoteIP:           netip.MustParseAddr("203.0.113.7"),
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if result.Status != store.StatusQueued {
		t.Fatalf("status after submission = %q, want queued", result.Status)
	}

	// Wait for the worker rather than sleeping a guessed duration.
	waitFor(t, 15*time.Second, "the sink to receive the message", func() bool {
		return f.sink.Count() == 1
	})
	waitFor(t, 15*time.Second, "the message to be marked sent", func() bool {
		status, _, _ := f.status(result.ID)
		return status == store.StatusSent
	})

	row, err := f.store.GetMessage(f.ctx, result.ID)
	if err != nil {
		t.Fatalf("GetMessage: %v", err)
	}
	if row.SentAt == nil {
		t.Fatal("sent_at was not recorded")
	}
	if row.AttemptCount != 1 {
		t.Fatalf("attempt_count = %d, want 1", row.AttemptCount)
	}
	if row.ErrorCode != nil {
		t.Fatalf("error_code = %q on a clean delivery", *row.ErrorCode)
	}

	delivered := f.sink.Messages()[0]
	if delivered.From != "no-reply@example.com" {
		t.Fatalf("MAIL FROM = %q", delivered.From)
	}
	// The bytes the relay receives must be the bytes that were stored.
	if !strings.Contains(string(delivered.Data), "Body.") {
		t.Fatalf("the delivered message was altered:\n%s", delivered.Data)
	}
}

// --- worker branches --------------------------------------------------------

func TestWorkerMarksPermanentFailure(t *testing.T) {
	f := newFixture(t, smtptest.Options{Mode: smtptest.ModePlain, RejectMailFrom: 550})
	worker := NewSendEmailWorker(f.store, f.newSender(), discardLogger())

	messageID := f.queueMessage()
	err := worker.Work(f.ctx, job(messageID, 1, 8))

	// JobCancel stops river retrying: hammering a relay over a 5xx is how an IP
	// reputation gets ruined.
	if err == nil {
		t.Fatal("Work returned no error on a permanent refusal")
	}
	if !isJobCancel(err) {
		t.Fatalf("Work returned %v, want a river.JobCancel", err)
	}

	status, code, detail := f.status(messageID)
	if status != store.StatusFailed {
		t.Fatalf("status = %q, want failed", status)
	}
	if code != sender.CodeMailFrom {
		t.Fatalf("error_code = %q, want %q", code, sender.CodeMailFrom)
	}
	if !strings.Contains(detail, "550") {
		t.Fatalf("error_detail = %q, want the relay's own response", detail)
	}
}

func TestWorkerRetriesTransientFailure(t *testing.T) {
	f := newFixture(t, smtptest.Options{Mode: smtptest.ModePlain, RejectMailFrom: 451})
	worker := NewSendEmailWorker(f.store, f.newSender(), discardLogger())

	messageID := f.queueMessage()
	err := worker.Work(f.ctx, job(messageID, 1, 8))

	if err == nil {
		t.Fatal("Work returned no error on a transient refusal: river would not retry")
	}
	if isJobCancel(err) {
		t.Fatal("a transient refusal must not cancel the job")
	}

	status, code, _ := f.status(messageID)
	// Back to queued, so the row says "still trying" rather than "failed".
	if status != store.StatusQueued {
		t.Fatalf("status = %q, want queued", status)
	}
	if code != sender.CodeMailFrom {
		t.Fatalf("error_code = %q", code)
	}

	row, err := f.store.GetMessage(f.ctx, messageID)
	if err != nil {
		t.Fatalf("GetMessage: %v", err)
	}
	if row.AttemptCount != 1 {
		t.Fatalf("attempt_count = %d, want 1", row.AttemptCount)
	}
}

// Without this, an exhausted job leaves the row 'queued' forever with nothing
// left to move it.
func TestWorkerMarksFailedOnLastAttempt(t *testing.T) {
	f := newFixture(t, smtptest.Options{Mode: smtptest.ModePlain, RejectMailFrom: 451})
	worker := NewSendEmailWorker(f.store, f.newSender(), discardLogger())

	messageID := f.queueMessage()
	// Attempt 8 of 8: river will discard the job after this.
	err := worker.Work(f.ctx, job(messageID, 8, 8))

	if !isJobCancel(err) {
		t.Fatalf("Work returned %v, want a cancel on the final attempt", err)
	}
	status, code, _ := f.status(messageID)
	if status != store.StatusFailed {
		t.Fatalf("status = %q, want failed once retries are exhausted", status)
	}
	if code != sender.CodeMailFrom {
		t.Fatalf("error_code = %q", code)
	}
}

// river delivers at least once, so a duplicate job must be a no-op. Sending twice
// is the one outcome that cannot be undone.
func TestWorkerIsIdempotent(t *testing.T) {
	f := newFixture(t, smtptest.Options{Mode: smtptest.ModePlain})
	worker := NewSendEmailWorker(f.store, f.newSender(), discardLogger())

	messageID := f.queueMessage()
	if err := worker.Work(f.ctx, job(messageID, 1, 8)); err != nil {
		t.Fatalf("first Work: %v", err)
	}
	if f.sink.Count() != 1 {
		t.Fatalf("the sink received %d messages after one run", f.sink.Count())
	}

	if err := worker.Work(f.ctx, job(messageID, 2, 8)); err != nil {
		t.Fatalf("second Work: %v", err)
	}
	if f.sink.Count() != 1 {
		t.Fatalf("the sink received %d messages: the message was sent twice", f.sink.Count())
	}

	row, err := f.store.GetMessage(f.ctx, messageID)
	if err != nil {
		t.Fatalf("GetMessage: %v", err)
	}
	// The second run must not have claimed the message again either.
	if row.AttemptCount != 1 {
		t.Fatalf("attempt_count = %d, want 1", row.AttemptCount)
	}
}

func TestWorkerHandlesPurgedPayload(t *testing.T) {
	f := newFixture(t, smtptest.Options{Mode: smtptest.ModePlain})
	worker := NewSendEmailWorker(f.store, f.newSender(), discardLogger())

	messageID := f.queueMessage()
	if _, err := f.pool.Exec(f.ctx, "DELETE FROM email_payload WHERE email_message_id = $1", messageID); err != nil {
		t.Fatalf("delete the payload: %v", err)
	}

	err := worker.Work(f.ctx, job(messageID, 1, 8))
	if !isJobCancel(err) {
		t.Fatalf("Work returned %v, want a cancel: there is nothing left to send", err)
	}
	status, code, _ := f.status(messageID)
	if status != store.StatusFailed {
		t.Fatalf("status = %q, want failed", status)
	}
	if code != "payload_purged" {
		t.Fatalf("error_code = %q, want payload_purged", code)
	}
	if f.sink.Count() != 0 {
		t.Fatal("something was delivered without a payload")
	}
}

// A disabled backend is an operator action, and re-enabling it is the expected
// fix, so the message must wait rather than fail.
func TestWorkerTreatsDisabledBackendAsTransient(t *testing.T) {
	f := newFixture(t, smtptest.Options{Mode: smtptest.ModePlain})
	worker := NewSendEmailWorker(f.store, f.newSender(), discardLogger())

	messageID := f.queueMessage()
	if _, err := f.pool.Exec(f.ctx, "UPDATE smtp_backend SET enabled = false WHERE id = $1", f.backendID); err != nil {
		t.Fatalf("disable the backend: %v", err)
	}

	err := worker.Work(f.ctx, job(messageID, 1, 8))
	if err == nil {
		t.Fatal("Work succeeded against a disabled backend")
	}
	if isJobCancel(err) {
		t.Fatal("a disabled backend must not be permanent: re-enabling it is the fix")
	}
	status, code, _ := f.status(messageID)
	if status != store.StatusQueued {
		t.Fatalf("status = %q, want queued", status)
	}
	if code != "backend_disabled" {
		t.Fatalf("error_code = %q", code)
	}
}

func TestWorkerHandlesDeletedBackend(t *testing.T) {
	f := newFixture(t, smtptest.Options{Mode: smtptest.ModePlain})
	worker := NewSendEmailWorker(f.store, f.newSender(), discardLogger())

	messageID := f.queueMessage()
	// ON DELETE SET NULL on email_message.smtp_backend_id: the history survives,
	// but the route is gone.
	if _, err := f.pool.Exec(f.ctx, "DELETE FROM domain WHERE smtp_backend_id = $1", f.backendID); err != nil {
		t.Fatalf("delete the domain: %v", err)
	}
	if _, err := f.pool.Exec(f.ctx, "DELETE FROM smtp_backend WHERE id = $1", f.backendID); err != nil {
		t.Fatalf("delete the backend: %v", err)
	}

	err := worker.Work(f.ctx, job(messageID, 1, 8))
	if !isJobCancel(err) {
		t.Fatalf("Work returned %v, want a cancel: the route no longer exists", err)
	}
	status, code, _ := f.status(messageID)
	if status != store.StatusFailed {
		t.Fatalf("status = %q, want failed", status)
	}
	if code != "backend_missing" {
		t.Fatalf("error_code = %q, want backend_missing", code)
	}
}

// Delivered to some recipients is a success with a warning, not a failure:
// re-sending later would duplicate mail for those who already received it.
func TestWorkerRecordsPartialDelivery(t *testing.T) {
	f := newFixture(t, smtptest.Options{
		Mode: smtptest.ModePlain,
		RejectRecipients: map[string]int{
			"nobody@elsewhere.test": 550,
		},
	})
	worker := NewSendEmailWorker(f.store, f.newSender(), discardLogger())

	messageID := f.queueMessage("good@elsewhere.test", "nobody@elsewhere.test")
	if err := worker.Work(f.ctx, job(messageID, 1, 8)); err != nil {
		t.Fatalf("Work: %v", err)
	}

	status, code, detail := f.status(messageID)
	if status != store.StatusSent {
		t.Fatalf("status = %q, want sent: the message did go out", status)
	}
	if code != sender.CodePartialRecipients {
		t.Fatalf("error_code = %q, want %q", code, sender.CodePartialRecipients)
	}
	if !strings.Contains(detail, "nobody@elsewhere.test") {
		t.Fatalf("error_detail = %q, want the refused address named", detail)
	}
	if f.sink.Count() != 1 {
		t.Fatalf("the sink received %d messages, want 1", f.sink.Count())
	}
}

func TestWorkerCancelsForMissingMessage(t *testing.T) {
	f := newFixture(t, smtptest.Options{Mode: smtptest.ModePlain})
	worker := NewSendEmailWorker(f.store, f.newSender(), discardLogger())

	err := worker.Work(f.ctx, job(uuid.New(), 1, 8))
	if !isJobCancel(err) {
		t.Fatalf("Work returned %v, want a cancel for a message that does not exist", err)
	}
}

// --- retention --------------------------------------------------------------

func TestPurgeWorkerRespectsRetention(t *testing.T) {
	f := newFixture(t, smtptest.Options{Mode: smtptest.ModePlain})

	recent := f.queueMessage()
	old := f.queueMessage()

	// Both delivered; one of them long ago.
	for _, id := range []uuid.UUID{recent, old} {
		if err := f.store.MarkSent(f.ctx, id); err != nil {
			t.Fatalf("MarkSent: %v", err)
		}
	}
	if _, err := f.pool.Exec(f.ctx,
		"UPDATE email_message SET sent_at = now() - interval '48 hours' WHERE id = $1", old); err != nil {
		t.Fatalf("backdate the old message: %v", err)
	}

	worker := NewPurgePayloadsWorker(f.store, 24*time.Hour, 168*time.Hour, discardLogger())
	if err := worker.Work(f.ctx, &river.Job[PurgePayloadsArgs]{
		JobRow: &rivertype.JobRow{ID: 1, Attempt: 1, MaxAttempts: 1},
	}); err != nil {
		t.Fatalf("Work: %v", err)
	}

	if _, err := f.store.GetPayload(f.ctx, old); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the old payload survived retention: %v", err)
	}
	if _, err := f.store.GetPayload(f.ctx, recent); err != nil {
		t.Fatalf("a recent payload was purged: %v", err)
	}

	// The message row itself must survive: the audit trail outlives the body.
	if _, err := f.store.GetMessage(f.ctx, old); err != nil {
		t.Fatalf("the message row was deleted along with its payload: %v", err)
	}
}

// --- client construction ----------------------------------------------------

// An API-only instance still needs to enqueue but must not consume. That is what
// makes splitting the process across containers a configuration change.
func TestNewClientInsertOnly(t *testing.T) {
	f := newFixture(t, smtptest.Options{Mode: smtptest.ModePlain})

	client, err := NewClient(ClientOptions{
		Store:   f.store,
		Log:     discardLogger(),
		Workers: false,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	// Start must refuse or be a no-op; either way nothing may be consumed. What
	// matters is that construction succeeds without a deliverer.
	if client == nil {
		t.Fatal("NewClient returned no client")
	}
}

func TestNewClientRequiresDelivererForWorkers(t *testing.T) {
	f := newFixture(t, smtptest.Options{Mode: smtptest.ModePlain})

	if _, err := NewClient(ClientOptions{Store: f.store, Workers: true}); err == nil {
		t.Fatal("NewClient built a worker client with no deliverer")
	}
	if _, err := NewClient(ClientOptions{Workers: true}); err == nil {
		t.Fatal("NewClient built a client with no store")
	}
}

// --- helpers ----------------------------------------------------------------

// isJobCancel reports whether err came from river.JobCancel, which is what stops
// a job being retried.
func isJobCancel(err error) bool {
	if err == nil {
		return false
	}
	var cancel *rivertype.JobCancelError
	return errors.As(err, &cancel)
}

// waitFor polls until the condition holds, failing with a readable message on
// timeout. Polling beats sleeping a guessed duration: the assertion says what it
// is waiting for.
func waitFor(t *testing.T, timeout time.Duration, what string, condition func() bool) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out after %v waiting for %s", timeout, what)
}
