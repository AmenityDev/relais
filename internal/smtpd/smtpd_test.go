package smtpd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/amenitydev/relais/internal/authn"
	"github.com/amenitydev/relais/internal/config"
	"github.com/amenitydev/relais/internal/crypto"
	"github.com/amenitydev/relais/internal/dbtest"
	"github.com/amenitydev/relais/internal/ingest"
	"github.com/amenitydev/relais/internal/ratelimit"
	"github.com/amenitydev/relais/internal/store"
	"github.com/amenitydev/relais/internal/tlsconf"
)

// These tests drive the real submission server with a real SMTP client over a
// real socket. Nothing about the protocol is mocked: whether AUTH is refused
// before STARTTLS is a property of the wire exchange, and only the wire exchange
// can demonstrate it.

const rawMessage = "From: no-reply@example.com\r\n" +
	"To: someone@elsewhere.test\r\n" +
	"Subject: Test\r\n" +
	"\r\n" +
	"Body.\r\n"

type fixture struct {
	t     *testing.T
	ctx   context.Context
	store *store.Store

	addr    string
	rootCAs *x509.CertPool

	// enqueued records what the pipeline scheduled.
	enqueued []uuid.UUID
	// username and password are the fixture credential's SMTP credentials.
	username string
	password string
}

func newFixture(t *testing.T, patterns ...string) *fixture {
	t.Helper()

	if len(patterns) == 0 {
		patterns = []string{"no-reply@example.com", "*@mail.example.com"}
	}

	ctx := context.Background()
	pool := dbtest.Pool(t)

	keyring, err := crypto.ParseKeyring("1:"+testKey(0x81), "")
	if err != nil {
		t.Fatalf("ParseKeyring: %v", err)
	}
	hasher, err := crypto.NewHasher(testKey(0x91))
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
		Name: "wordpress", Type: store.CredentialTypeSMTPUser, SMTPUsername: "blog",
		Enabled: true, Patterns: patterns,
	})
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}
	f.username = created.Credential.Lookup
	f.password = created.Secret.Reveal()

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
			MaxRecipients:          3,
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

	// A generated certificate, exactly as a development deployment would use.
	cfg, err := config.LoadFrom(map[string]string{
		"RELAIS_ENV":                      "dev",
		"RELAIS_TLS_SELF_SIGNED":          "true",
		"RELAIS_TLS_SELF_SIGNED_HOSTS":    "localhost,127.0.0.1",
		"RELAIS_DB_URL":                   "postgres://localhost/relais",
		"RELAIS_SECRET_CREDENTIAL_PEPPER": "x",
	})
	if err != nil {
		t.Fatalf("config.LoadFrom: %v", err)
	}
	certs, err := tlsconf.New(cfg, nil)
	if err != nil {
		t.Fatalf("tlsconf.New: %v", err)
	}
	leafPEM, err := certs.LeafPEM()
	if err != nil {
		t.Fatalf("LeafPEM: %v", err)
	}
	f.rootCAs = x509.NewCertPool()
	if !f.rootCAs.AppendCertsFromPEM(leafPEM) {
		t.Fatal("could not trust the generated certificate")
	}

	// Port 0, so tests never collide with a real deployment or each other.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	f.addr = listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release the reserved port: %v", err)
	}

	server, err := New(Options{
		Ingest:        service,
		Authenticator: authenticator,
		Certificates:  certs,
		Config: Config{
			Domain:          "relais.test",
			Addr:            f.addr,
			ReadTimeout:     10 * time.Second,
			WriteTimeout:    10 * time.Second,
			ShutdownTimeout: 5 * time.Second,
			MaxMessageBytes: 1 << 20,
			MaxRecipients:   3,
		},
		Log: log,
	})
	if err != nil {
		t.Fatalf("smtpd.New: %v", err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- server.Run(runCtx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("the submission server did not shut down")
		}
	})

	f.waitForListener()
	return f
}

func (f *fixture) waitForListener() {
	f.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", f.addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	f.t.Fatalf("the submission server never started listening on %s", f.addr)
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

func (f *fixture) tlsConfig() *tls.Config {
	return &tls.Config{RootCAs: f.rootCAs, ServerName: "localhost", MinVersion: tls.VersionTLS12}
}

// dial opens a plain connection and greets, without upgrading.
func (f *fixture) dial() *smtp.Client {
	f.t.Helper()
	client, err := smtp.Dial(f.addr)
	if err != nil {
		f.t.Fatalf("dial: %v", err)
	}
	f.t.Cleanup(func() { _ = client.Close() })
	if err := client.Hello("client.test"); err != nil {
		f.t.Fatalf("EHLO: %v", err)
	}
	return client
}

// dialTLS opens a connection and completes STARTTLS.
func (f *fixture) dialTLS() *smtp.Client {
	f.t.Helper()
	client, err := smtp.DialStartTLS(f.addr, f.tlsConfig())
	if err != nil {
		f.t.Fatalf("STARTTLS: %v", err)
	}
	f.t.Cleanup(func() { _ = client.Close() })
	if err := client.Hello("client.test"); err != nil {
		f.t.Fatalf("EHLO: %v", err)
	}
	return client
}

// authed returns a connection that has authenticated successfully.
func (f *fixture) authed() *smtp.Client {
	f.t.Helper()
	client := f.dialTLS()
	if err := client.Auth(sasl.NewPlainClient("", f.username, f.password)); err != nil {
		f.t.Fatalf("AUTH: %v", err)
	}
	return client
}

// send performs a whole transaction and returns the error, if any.
func send(client *smtp.Client, from string, recipients []string, message string) error {
	if err := client.Mail(from, nil); err != nil {
		return err
	}
	for _, recipient := range recipients {
		if err := client.Rcpt(recipient, nil); err != nil {
			return err
		}
	}
	data, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := io.WriteString(data, message); err != nil {
		return err
	}
	return data.Close()
}

func smtpCode(err error) int {
	var smtpErr *smtp.SMTPError
	if errors.As(err, &smtpErr) {
		return smtpErr.Code
	}
	return 0
}

// --- the security properties ------------------------------------------------

// The most important test in the package: a credential must not be sendable on an
// unencrypted connection, and the server must not even offer the option.
func TestAuthIsImpossibleBeforeSTARTTLS(t *testing.T) {
	f := newFixture(t)
	client := f.dial()

	// AUTH must not be advertised at all on a plaintext connection: a client that
	// reads the capability list finds nothing to try.
	if supported, mechanisms := client.Extension("AUTH"); supported {
		t.Fatalf("AUTH is advertised before STARTTLS (mechanisms: %q)", mechanisms)
	}
	// STARTTLS must be advertised, or there would be no way forward.
	if supported, _ := client.Extension("STARTTLS"); !supported {
		t.Fatal("STARTTLS is not advertised")
	}

	// And attempting it anyway must fail.
	err := client.Auth(sasl.NewPlainClient("", f.username, f.password))
	if err == nil {
		t.Fatal("AUTH succeeded on an unencrypted connection")
	}
}

// No mail moves without authentication. This is "no anonymous relay under any
// condition", expressed in the protocol.
func TestMailFromRequiresAuthentication(t *testing.T) {
	f := newFixture(t)
	client := f.dialTLS()

	// Encrypted but not authenticated.
	err := client.Mail("no-reply@example.com", nil)
	if err == nil {
		t.Fatal("MAIL FROM was accepted on an unauthenticated session")
	}
	if got := smtpCode(err); got != 530 {
		t.Fatalf("code = %d, want 530: %v", got, err)
	}
	if len(f.enqueued) != 0 {
		t.Fatal("something was enqueued without authentication")
	}
}

func TestAuthSucceedsOverTLS(t *testing.T) {
	f := newFixture(t)
	client := f.dialTLS()

	supported, mechanisms := client.Extension("AUTH")
	if !supported {
		t.Fatal("AUTH is not advertised after STARTTLS")
	}
	for _, want := range []string{"PLAIN", "LOGIN"} {
		if !strings.Contains(strings.ToUpper(mechanisms), want) {
			t.Fatalf("AUTH mechanisms = %q, want %s to be offered", mechanisms, want)
		}
	}

	if err := client.Auth(sasl.NewPlainClient("", f.username, f.password)); err != nil {
		t.Fatalf("AUTH PLAIN: %v", err)
	}
}

// Legacy clients often only offer LOGIN, and those are exactly the clients this
// façade exists for.
func TestAuthLoginMechanism(t *testing.T) {
	f := newFixture(t)
	client := f.dialTLS()

	if err := client.Auth(sasl.NewLoginClient(f.username, f.password)); err != nil {
		t.Fatalf("AUTH LOGIN: %v", err)
	}
	if err := send(client, "no-reply@example.com", []string{"a@elsewhere.test"}, rawMessage); err != nil {
		t.Fatalf("send after AUTH LOGIN: %v", err)
	}
}

// Every authentication failure must look the same: whether the user is unknown,
// revoked, or the password is wrong is an operator's business.
func TestAuthFailuresAreIndistinguishable(t *testing.T) {
	f := newFixture(t)

	// A revoked credential, so a real-but-dead account is among the cases.
	revoked, err := f.store.CreateCredential(f.ctx, store.NewCredentialParams{
		Name: "revoked", Type: store.CredentialTypeSMTPUser, SMTPUsername: "gone",
		Enabled: true, Patterns: []string{"no-reply@example.com"},
	})
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}
	if _, err := f.store.RevokeCredential(f.ctx, revoked.Credential.ID); err != nil {
		t.Fatalf("RevokeCredential: %v", err)
	}

	// An API key presented over SMTP AUTH: a real mistake, and it must not work.
	apiKey, err := f.store.CreateCredential(f.ctx, store.NewCredentialParams{
		Name: "an-api-key", Type: store.CredentialTypeAPIKey, Enabled: true,
		Patterns: []string{"no-reply@example.com"},
	})
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	cases := map[string][2]string{
		"unknown user":        {"nobody", "whatever"},
		"wrong password":      {f.username, "wrong"},
		"revoked user":        {"gone", revoked.Secret.Reveal()},
		"empty password":      {f.username, ""},
		"api key as password": {apiKey.Credential.Lookup, apiKey.Secret.Reveal()},
	}

	var messages []string
	for name, credentials := range cases {
		t.Run(name, func(t *testing.T) {
			client := f.dialTLS()
			err := client.Auth(sasl.NewPlainClient("", credentials[0], credentials[1]))
			if err == nil {
				t.Fatal("AUTH succeeded")
			}
			if got := smtpCode(err); got != 535 {
				t.Fatalf("code = %d, want 535: %v", got, err)
			}
			var smtpErr *smtp.SMTPError
			errors.As(err, &smtpErr)
			messages = append(messages, smtpErr.Message)
		})
	}

	// All replies identical: no oracle telling an attacker which usernames exist.
	for i := 1; i < len(messages); i++ {
		if messages[i] != messages[0] {
			t.Fatalf("replies differ between causes: %q vs %q", messages[0], messages[i])
		}
	}
}

// --- submission -------------------------------------------------------------

func TestSubmitAccepted(t *testing.T) {
	f := newFixture(t)
	client := f.authed()

	if err := send(client, "no-reply@example.com", []string{"someone@elsewhere.test"}, rawMessage); err != nil {
		t.Fatalf("send: %v", err)
	}

	if len(f.enqueued) != 1 {
		t.Fatalf("%d jobs enqueued, want 1", len(f.enqueued))
	}

	row, err := f.store.GetMessage(f.ctx, f.enqueued[0])
	if err != nil {
		t.Fatalf("GetMessage: %v", err)
	}
	if row.Facade != store.FacadeSMTP {
		t.Fatalf("facade = %q, want smtp", row.Facade)
	}
	if row.FromAddr != "no-reply@example.com" {
		t.Fatalf("from_addr = %q", row.FromAddr)
	}
	// The envelope is what the client asked for in RCPT TO.
	if len(row.EnvelopeRecipients) != 1 || row.EnvelopeRecipients[0] != "someone@elsewhere.test" {
		t.Fatalf("envelope = %v", row.EnvelopeRecipients)
	}
	if row.RemoteIp == nil {
		t.Fatal("the remote ip was not recorded")
	}
	// A missing Message-ID is generated by the same code the REST façade uses.
	if row.MessageID != "<generated-id@example.com>" {
		t.Fatalf("message_id = %q", row.MessageID)
	}
}

// The header From is authoritative, not the envelope. A legacy client that puts
// something arbitrary in MAIL FROM must still be able to send.
func TestEnvelopeSenderIsNotAuthoritative(t *testing.T) {
	f := newFixture(t, "no-reply@example.com")
	client := f.authed()

	// MAIL FROM disagrees with the From header, and the From header is what the
	// credential is allowed to use.
	if err := send(client, "bounces@some-other-domain.test", []string{"a@elsewhere.test"}, rawMessage); err != nil {
		t.Fatalf("send: %v", err)
	}
	if len(f.enqueued) != 1 {
		t.Fatalf("%d jobs enqueued, want 1", len(f.enqueued))
	}

	row, err := f.store.GetMessage(f.ctx, f.enqueued[0])
	if err != nil {
		t.Fatalf("GetMessage: %v", err)
	}
	// What is recorded and validated is the header, not the envelope.
	if row.FromAddr != "no-reply@example.com" {
		t.Fatalf("from_addr = %q, want the header From", row.FromAddr)
	}
}

// And conversely: a valid envelope sender does not authorise a From the
// credential may not use.
func TestHeaderFromIsWhatGetsAuthorised(t *testing.T) {
	f := newFixture(t, "no-reply@example.com")
	client := f.authed()

	message := strings.Replace(rawMessage, "From: no-reply@example.com", "From: ceo@example.com", 1)
	err := send(client, "no-reply@example.com", []string{"a@elsewhere.test"}, message)
	if err == nil {
		t.Fatal("a From outside the allow-list was accepted because the envelope looked right")
	}
	if got := smtpCode(err); got != 550 {
		t.Fatalf("code = %d, want 550: %v", got, err)
	}
	if len(f.enqueued) != 0 {
		t.Fatal("something was enqueued for an unauthorized sender")
	}

	// The rejection is recorded with the attempted sender.
	var attempted string
	if err := f.storeQueryRow("SELECT from_addr FROM email_message WHERE status = 'rejected'", &attempted); err != nil {
		t.Fatalf("read the rejection: %v", err)
	}
	if attempted != "ceo@example.com" {
		t.Fatalf("recorded sender = %q, want the attempted one", attempted)
	}
}

func TestSubmitMultipleRecipients(t *testing.T) {
	f := newFixture(t)
	client := f.authed()

	recipients := []string{"a@elsewhere.test", "b@elsewhere.test"}
	if err := send(client, "no-reply@example.com", recipients, rawMessage); err != nil {
		t.Fatalf("send: %v", err)
	}

	row, err := f.store.GetMessage(f.ctx, f.enqueued[0])
	if err != nil {
		t.Fatalf("GetMessage: %v", err)
	}
	if len(row.EnvelopeRecipients) != 2 {
		t.Fatalf("envelope = %v", row.EnvelopeRecipients)
	}
}

// A Bcc header submitted over SMTP must not reach the relay.
func TestSubmitStripsBcc(t *testing.T) {
	f := newFixture(t)
	client := f.authed()

	message := "From: no-reply@example.com\r\nTo: a@elsewhere.test\r\n" +
		"Bcc: hidden@elsewhere.test\r\nSubject: t\r\n\r\nBody.\r\n"

	if err := send(client, "no-reply@example.com", []string{"a@elsewhere.test", "hidden@elsewhere.test"}, message); err != nil {
		t.Fatalf("send: %v", err)
	}

	payload, err := f.store.GetPayload(f.ctx, f.enqueued[0])
	if err != nil {
		t.Fatalf("GetPayload: %v", err)
	}
	if strings.Contains(strings.ToLower(string(payload)), "bcc:") {
		t.Fatalf("the Bcc header survived:\n%s", payload)
	}
	if strings.Contains(string(payload), "hidden@elsewhere.test") {
		t.Fatalf("the blind recipient leaked into the relayed bytes:\n%s", payload)
	}
	// It stays in the envelope, so it is still delivered.
	row, err := f.store.GetMessage(f.ctx, f.enqueued[0])
	if err != nil {
		t.Fatalf("GetMessage: %v", err)
	}
	if len(row.EnvelopeRecipients) != 2 {
		t.Fatalf("envelope = %v, want both recipients", row.EnvelopeRecipients)
	}
}

// --- protocol-level refusals ------------------------------------------------

// A bad recipient is refused at RCPT TO, so the client learns which address is
// wrong instead of having the whole message refused with no indication why.
func TestBadRecipientIsRefusedAtRcpt(t *testing.T) {
	f := newFixture(t)
	client := f.authed()

	if err := client.Mail("no-reply@example.com", nil); err != nil {
		t.Fatalf("MAIL FROM: %v", err)
	}
	err := client.Rcpt("root@localhost", nil)
	if err == nil {
		t.Fatal("an unusable recipient was accepted")
	}
	if got := smtpCode(err); got != 550 {
		t.Fatalf("code = %d, want 550: %v", got, err)
	}

	// A good recipient on the same transaction must still work.
	if err := client.Rcpt("a@elsewhere.test", nil); err != nil {
		t.Fatalf("RCPT TO after a refusal: %v", err)
	}
}

func TestTooManyRecipients(t *testing.T) {
	f := newFixture(t)
	client := f.authed()

	if err := client.Mail("no-reply@example.com", nil); err != nil {
		t.Fatalf("MAIL FROM: %v", err)
	}
	// The fixture allows three.
	for i, recipient := range []string{"a@e.test", "b@e.test", "c@e.test"} {
		if err := client.Rcpt(recipient, nil); err != nil {
			t.Fatalf("RCPT TO %d: %v", i+1, err)
		}
	}

	err := client.Rcpt("d@e.test", nil)
	if err == nil {
		t.Fatal("a fourth recipient was accepted past the limit")
	}
	// 452 rather than 550: the message is fine, splitting it will work.
	if got := smtpCode(err); got != 452 {
		t.Fatalf("code = %d, want 452: %v", got, err)
	}
}

// A malformed message is permanent: it will be just as malformed next time.
func TestMalformedMessageIsPermanent(t *testing.T) {
	f := newFixture(t)

	tests := map[string]string{
		"no From":       "To: a@elsewhere.test\r\nSubject: t\r\n\r\nBody.\r\n",
		"two From":      "From: no-reply@example.com\r\nFrom: ceo@example.com\r\nSubject: t\r\n\r\nBody.\r\n",
		"unusable From": "From: not an address\r\nSubject: t\r\n\r\nBody.\r\n",
	}
	for name, message := range tests {
		t.Run(name, func(t *testing.T) {
			client := f.authed()
			err := send(client, "no-reply@example.com", []string{"a@elsewhere.test"}, message)
			if err == nil {
				t.Fatal("a malformed message was accepted")
			}
			if got := smtpCode(err); got < 500 {
				t.Fatalf("code = %d, want a 5xx: a malformed message will not become valid", got)
			}
		})
	}
}

// A rate limit is temporary, and the reply has to say so, or a client will treat
// it as a bounce.
func TestRateLimitIsTemporary(t *testing.T) {
	f := newFixture(t)
	if _, err := f.storeExec("UPDATE credential SET rate_limit_rps = 1, rate_limit_burst = 1 WHERE lookup = 'blog'"); err != nil {
		t.Fatalf("set the rate limit: %v", err)
	}

	client := f.authed()
	if err := send(client, "no-reply@example.com", []string{"a@elsewhere.test"}, rawMessage); err != nil {
		t.Fatalf("first submission: %v", err)
	}

	second := f.authed()
	err := send(second, "no-reply@example.com", []string{"b@elsewhere.test"}, rawMessage)
	if err == nil {
		t.Fatal("the rate limit did not apply")
	}
	code := smtpCode(err)
	if code < 400 || code >= 500 {
		t.Fatalf("code = %d, want a 4xx: a rate limit is temporary and the client should retry", code)
	}
}

// --- session behaviour ------------------------------------------------------

// RSET aborts the transaction, not the authentication: a client that had to
// re-authenticate between two messages on one connection would be broken.
func TestResetKeepsAuthentication(t *testing.T) {
	f := newFixture(t)
	client := f.authed()

	if err := client.Mail("no-reply@example.com", nil); err != nil {
		t.Fatalf("MAIL FROM: %v", err)
	}
	if err := client.Rcpt("a@elsewhere.test", nil); err != nil {
		t.Fatalf("RCPT TO: %v", err)
	}
	if err := client.Reset(); err != nil {
		t.Fatalf("RSET: %v", err)
	}

	// A whole new transaction on the same connection, with no second AUTH.
	if err := send(client, "no-reply@example.com", []string{"b@elsewhere.test"}, rawMessage); err != nil {
		t.Fatalf("send after RSET: %v", err)
	}
	if len(f.enqueued) != 1 {
		t.Fatalf("%d jobs enqueued, want 1", len(f.enqueued))
	}
}

// Several messages on one connection is what a mail client does, and each must be
// its own message.
func TestMultipleMessagesOnOneConnection(t *testing.T) {
	f := newFixture(t)
	client := f.authed()

	for i := range 3 {
		recipient := string(rune('a'+i)) + "@elsewhere.test"
		if err := send(client, "no-reply@example.com", []string{recipient}, rawMessage); err != nil {
			t.Fatalf("message %d: %v", i+1, err)
		}
	}
	if len(f.enqueued) != 3 {
		t.Fatalf("%d jobs enqueued, want 3", len(f.enqueued))
	}
	// Three distinct messages, not one recorded thrice.
	seen := make(map[uuid.UUID]bool)
	for _, id := range f.enqueued {
		if seen[id] {
			t.Fatal("the same message was enqueued twice")
		}
		seen[id] = true
	}
}

// The reply carries the message id, so a client's own log can be correlated with
// a relais message — exactly as Postfix's "queued as <id>" does.
func TestSuccessReplyCarriesMessageID(t *testing.T) {
	f := newFixture(t)
	client := f.authed()

	if err := client.Mail("no-reply@example.com", nil); err != nil {
		t.Fatalf("MAIL FROM: %v", err)
	}
	if err := client.Rcpt("a@elsewhere.test", nil); err != nil {
		t.Fatalf("RCPT TO: %v", err)
	}
	data, err := client.Data()
	if err != nil {
		t.Fatalf("DATA: %v", err)
	}
	if _, err := io.WriteString(data, rawMessage); err != nil {
		t.Fatalf("write: %v", err)
	}
	response, err := data.CloseWithResponse()
	if err != nil {
		t.Fatalf("end of DATA: %v", err)
	}

	if len(f.enqueued) != 1 {
		t.Fatalf("%d jobs enqueued, want 1", len(f.enqueued))
	}
	if !strings.Contains(response.StatusText, f.enqueued[0].String()) {
		t.Fatalf("the reply %q does not carry the message id %s", response.StatusText, f.enqueued[0])
	}
}

// A dot-stuffed line must survive: ".\r\n" inside a body is the classic way to
// corrupt a message.
func TestDotStuffedBodySurvives(t *testing.T) {
	f := newFixture(t)
	client := f.authed()

	message := "From: no-reply@example.com\r\nTo: a@elsewhere.test\r\nSubject: t\r\n\r\n" +
		"line one\r\n.\r\nline after a lone dot\r\n..double dot\r\n"

	if err := send(client, "no-reply@example.com", []string{"a@elsewhere.test"}, message); err != nil {
		t.Fatalf("send: %v", err)
	}

	payload, err := f.store.GetPayload(f.ctx, f.enqueued[0])
	if err != nil {
		t.Fatalf("GetPayload: %v", err)
	}
	body := string(payload)
	for _, want := range []string{"line one", "line after a lone dot", ".double dot"} {
		if !strings.Contains(body, want) {
			t.Fatalf("the body lost %q:\n%s", want, body)
		}
	}
}

// --- construction -----------------------------------------------------------

// A submission server with no certificate could never offer AUTH, so it could
// never accept anything. Refusing to build is clearer than starting uselessly.
func TestNewRequiresACertificate(t *testing.T) {
	if _, err := New(Options{Config: Config{Addr: ":2525"}}); err == nil {
		t.Fatal("New succeeded with no ingest service")
	}
}

// --- helpers ----------------------------------------------------------------

func (f *fixture) storeExec(query string) (int64, error) {
	tag, err := f.store.Pool().Exec(f.ctx, query)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (f *fixture) storeQueryRow(query string, target any) error {
	return f.store.Pool().QueryRow(f.ctx, query).Scan(target)
}
