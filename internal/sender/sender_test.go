package sender

import (
	"context"
	"crypto/tls"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/amenitydev/relais/internal/crypto"
	"github.com/amenitydev/relais/internal/smtptest"
	"github.com/amenitydev/relais/internal/store"
)

const rawMessage = "From: no-reply@example.com\r\n" +
	"To: someone@elsewhere.test\r\n" +
	"Subject: Test\r\n" +
	"Message-Id: <a@example.com>\r\n" +
	"\r\n" +
	"Body.\r\n"

func testSender(t *testing.T, sink *smtptest.Sink) *Sender {
	t.Helper()
	// The sink presents a generated certificate on a loopback address, which is
	// exactly the case the local-only verification bypass exists for.
	return New(Config{
		Timeout:                 10 * time.Second,
		HeloName:                "relais.test",
		InsecureSkipVerifyHosts: []string{sink.Host},
	}, nil)
}

func route(sink *smtptest.Sink, tlsMode string) store.SenderRoute {
	return store.SenderRoute{
		DomainID:       uuid.New(),
		DomainName:     "example.com",
		BackendID:      uuid.New(),
		BackendName:    "sink",
		Host:           sink.Host,
		Port:           sink.Port,
		TLSMode:        tlsMode,
		MaxConcurrency: 2,
	}
}

func message(recipients ...string) Message {
	if len(recipients) == 0 {
		recipients = []string{"someone@elsewhere.test"}
	}
	return Message{
		From:       "no-reply@example.com",
		Recipients: recipients,
		Raw:        []byte(rawMessage),
	}
}

// --- the happy paths --------------------------------------------------------

func TestSendPlain(t *testing.T) {
	sink := smtptest.Start(t, smtptest.Options{Mode: smtptest.ModePlain})
	s := testSender(t, sink)

	result, err := s.Send(context.Background(), route(sink, store.TLSModeNone), message())
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if result.Partial() {
		t.Fatalf("unexpected refusals: %s", result.RejectedDetail())
	}
	if result.UsedTLS {
		t.Fatal("UsedTLS is set on a plaintext connection")
	}

	if sink.Count() != 1 {
		t.Fatalf("the sink received %d messages, want 1", sink.Count())
	}
	got := sink.Messages()[0]
	if got.From != "no-reply@example.com" {
		t.Fatalf("MAIL FROM = %q", got.From)
	}
	if len(got.Recipients) != 1 || got.Recipients[0] != "someone@elsewhere.test" {
		t.Fatalf("RCPT TO = %v", got.Recipients)
	}
	// The bytes must arrive unchanged: the sender relays, it does not rewrite.
	if !strings.Contains(string(got.Data), "Body.") || !strings.Contains(string(got.Data), "Message-Id: <a@example.com>") {
		t.Fatalf("the delivered message was altered:\n%s", got.Data)
	}
}

func TestSendSTARTTLS(t *testing.T) {
	sink := smtptest.Start(t, smtptest.Options{Mode: smtptest.ModeSTARTTLS})
	s := testSender(t, sink)

	result, err := s.Send(context.Background(), route(sink, store.TLSModeSTARTTLS), message())
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !result.UsedTLS {
		t.Fatal("the connection was not encrypted after STARTTLS")
	}
	if sink.Count() != 1 {
		t.Fatalf("the sink received %d messages, want 1", sink.Count())
	}
	if !sink.Messages()[0].OverTLS {
		t.Fatal("the sink saw a plaintext connection")
	}
}

func TestSendImplicitTLS(t *testing.T) {
	sink := smtptest.Start(t, smtptest.Options{Mode: smtptest.ModeImplicitTLS})
	s := testSender(t, sink)

	result, err := s.Send(context.Background(), route(sink, store.TLSModeImplicit), message())
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !result.UsedTLS {
		t.Fatal("the connection was not encrypted")
	}
	if sink.Count() != 1 {
		t.Fatalf("the sink received %d messages, want 1", sink.Count())
	}
}

func TestSendMultipleRecipients(t *testing.T) {
	sink := smtptest.Start(t, smtptest.Options{Mode: smtptest.ModePlain})
	s := testSender(t, sink)

	recipients := []string{"a@elsewhere.test", "b@elsewhere.test", "c@elsewhere.test"}
	result, err := s.Send(context.Background(), route(sink, store.TLSModeNone), message(recipients...))
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(result.Accepted) != 3 {
		t.Fatalf("Accepted = %v, want all three", result.Accepted)
	}
	if got := sink.Messages()[0].Recipients; len(got) != 3 {
		t.Fatalf("the sink saw %v", got)
	}
}

// --- authentication ---------------------------------------------------------

func TestSendWithAuthPlain(t *testing.T) {
	sink := smtptest.Start(t, smtptest.Options{
		Mode:     smtptest.ModeSTARTTLS,
		Username: "ocid1.user.oc1..aaaa",
		Password: "s3cret",
	})
	s := testSender(t, sink)

	r := route(sink, store.TLSModeSTARTTLS)
	r.AuthUser = "ocid1.user.oc1..aaaa"
	r.AuthPassword = crypto.Secret("s3cret")

	if _, err := s.Send(context.Background(), r, message()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := sink.Messages()[0].AuthenticatedAs; got != "ocid1.user.oc1..aaaa" {
		t.Fatalf("AuthenticatedAs = %q", got)
	}
}

// Some relays only offer the obsolete LOGIN mechanism. An untested fallback is a
// fallback that does not work.
func TestSendWithAuthLoginFallback(t *testing.T) {
	sink := smtptest.Start(t, smtptest.Options{
		Mode:                 smtptest.ModeSTARTTLS,
		Username:             "legacy",
		Password:             "pw",
		AdvertisedMechanisms: []string{"LOGIN"},
	})
	s := testSender(t, sink)

	r := route(sink, store.TLSModeSTARTTLS)
	r.AuthUser = "legacy"
	r.AuthPassword = crypto.Secret("pw")

	if _, err := s.Send(context.Background(), r, message()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := sink.Messages()[0].AuthenticatedAs; got != "legacy" {
		t.Fatalf("AuthenticatedAs = %q", got)
	}
}

// The load-bearing security test: a password must never cross an unencrypted
// connection, whatever the stored configuration says.
//
// The schema forbids storing a password next to tls_mode='none', so this route is
// built by hand — which is exactly the state a hand-edited database, or a relay
// that failed to negotiate TLS, would produce.
func TestSendRefusesAuthWithoutTLS(t *testing.T) {
	sink := smtptest.Start(t, smtptest.Options{
		Mode:     smtptest.ModePlain,
		Username: "user",
		Password: "pw",
	})
	s := testSender(t, sink)

	r := route(sink, store.TLSModeNone)
	r.AuthUser = "user"
	r.AuthPassword = crypto.Secret("pw")

	_, err := s.Send(context.Background(), r, message())
	if err == nil {
		t.Fatal("Send authenticated over an unencrypted connection")
	}
	if CodeOf(err) != CodeAuthInsecure {
		t.Fatalf("code = %q, want %q (%v)", CodeOf(err), CodeAuthInsecure, err)
	}
	if !IsPermanent(err) {
		t.Fatal("refusing to leak a password must be permanent, not retried")
	}
	// Nothing must have been delivered, and no credential offered.
	if sink.Count() != 0 {
		t.Fatal("a message was delivered despite the refusal")
	}
}

func TestSendAuthFailureIsPermanent(t *testing.T) {
	sink := smtptest.Start(t, smtptest.Options{
		Mode:     smtptest.ModeSTARTTLS,
		Username: "right",
		Password: "right",
	})
	s := testSender(t, sink)

	r := route(sink, store.TLSModeSTARTTLS)
	r.AuthUser = "right"
	r.AuthPassword = crypto.Secret("wrong")

	_, err := s.Send(context.Background(), r, message())
	if err == nil {
		t.Fatal("Send succeeded with a wrong password")
	}
	if CodeOf(err) != CodeAuthFailed {
		t.Fatalf("code = %q, want %q (%v)", CodeOf(err), CodeAuthFailed, err)
	}
	// Retrying the same wrong credential eight times helps nobody, and some
	// providers lock an account for it.
	if !IsPermanent(err) {
		t.Fatal("an authentication failure must be permanent")
	}
}

func TestSendAuthUnsupportedMechanism(t *testing.T) {
	sink := smtptest.Start(t, smtptest.Options{
		Mode:                 smtptest.ModeSTARTTLS,
		Username:             "user",
		Password:             "pw",
		AdvertisedMechanisms: []string{"CRAM-MD5", "XOAUTH2"},
	})
	s := testSender(t, sink)

	r := route(sink, store.TLSModeSTARTTLS)
	r.AuthUser = "user"
	r.AuthPassword = crypto.Secret("pw")

	_, err := s.Send(context.Background(), r, message())
	if CodeOf(err) != CodeAuthUnsupported {
		t.Fatalf("code = %q, want %q (%v)", CodeOf(err), CodeAuthUnsupported, err)
	}
	if !IsPermanent(err) {
		t.Fatal("an unsupported mechanism will not become supported by retrying")
	}
}

// --- classification ---------------------------------------------------------

// The heart of the package: 4xx means try again, 5xx means stop. Getting this
// backwards either discards deliverable mail or hammers a relay for hours.
func TestClassificationOfRefusals(t *testing.T) {
	tests := []struct {
		name          string
		opts          smtptest.Options
		wantCode      string
		wantPermanent bool
	}{
		{
			name:          "4xx on MAIL FROM is transient",
			opts:          smtptest.Options{RejectMailFrom: 451},
			wantCode:      CodeMailFrom,
			wantPermanent: false,
		},
		{
			name:          "5xx on MAIL FROM is permanent",
			opts:          smtptest.Options{RejectMailFrom: 550},
			wantCode:      CodeMailFrom,
			wantPermanent: true,
		},
		{
			name:          "4xx on DATA is transient",
			opts:          smtptest.Options{RejectData: 451},
			wantCode:      CodeDataRejected,
			wantPermanent: false,
		},
		{
			name:          "5xx on DATA is permanent",
			opts:          smtptest.Options{RejectData: 552},
			wantCode:      CodeDataRejected,
			wantPermanent: true,
		},
		{
			name: "every recipient refused with 5xx is permanent",
			opts: smtptest.Options{RejectRecipients: map[string]int{
				"someone@elsewhere.test": 550,
			}},
			wantCode:      CodeAllRecipientsRejected,
			wantPermanent: true,
		},
		{
			name: "every recipient refused with 4xx is transient",
			opts: smtptest.Options{RejectRecipients: map[string]int{
				"someone@elsewhere.test": 450,
			}},
			wantCode:      CodeAllRecipientsRejected,
			wantPermanent: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.opts.Mode = smtptest.ModePlain
			sink := smtptest.Start(t, tc.opts)
			s := testSender(t, sink)

			_, err := s.Send(context.Background(), route(sink, store.TLSModeNone), message())
			if err == nil {
				t.Fatal("Send succeeded although the sink refused")
			}
			if got := CodeOf(err); got != tc.wantCode {
				t.Fatalf("code = %q, want %q (%v)", got, tc.wantCode, err)
			}
			if IsPermanent(err) != tc.wantPermanent {
				t.Fatalf("permanent = %v, want %v (%v)", IsPermanent(err), tc.wantPermanent, err)
			}
			if sink.Count() != 0 {
				t.Fatal("a refused message was recorded as delivered")
			}
		})
	}
}

// A mix of accepted and refused recipients must not abandon the deliverable
// ones: re-sending the whole message later would duplicate mail for those who
// already received it.
func TestSendPartialRecipients(t *testing.T) {
	sink := smtptest.Start(t, smtptest.Options{
		Mode: smtptest.ModePlain,
		RejectRecipients: map[string]int{
			"nobody@elsewhere.test": 550,
			"slow@elsewhere.test":   451,
		},
	})
	s := testSender(t, sink)

	result, err := s.Send(context.Background(), route(sink, store.TLSModeNone), message(
		"good@elsewhere.test", "nobody@elsewhere.test", "slow@elsewhere.test", "also-good@elsewhere.test",
	))
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	if !result.Partial() {
		t.Fatal("Partial() is false although two recipients were refused")
	}
	if len(result.Accepted) != 2 {
		t.Fatalf("Accepted = %v, want the two deliverable recipients", result.Accepted)
	}
	if len(result.Rejected) != 2 {
		t.Fatalf("Rejected = %v, want two", result.Rejected)
	}

	// The operator needs to know which addresses failed and why.
	detail := result.RejectedDetail()
	for _, want := range []string{"nobody@elsewhere.test", "550", "slow@elsewhere.test", "451"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("RejectedDetail() = %q, missing %q", detail, want)
		}
	}

	// The message was delivered to whoever accepted it.
	if sink.Count() != 1 {
		t.Fatalf("the sink received %d messages, want 1", sink.Count())
	}
	if got := sink.Messages()[0].Recipients; len(got) != 2 {
		t.Fatalf("the sink saw %v", got)
	}
}

func TestSendDialFailureIsTransient(t *testing.T) {
	s := New(Config{Timeout: 2 * time.Second}, nil)

	// Port 1 on loopback: nothing listens, and the refusal is immediate.
	r := store.SenderRoute{
		BackendID: uuid.New(), BackendName: "unreachable",
		Host: "127.0.0.1", Port: 1, TLSMode: store.TLSModeNone, MaxConcurrency: 1,
	}

	_, err := s.Send(context.Background(), r, message())
	if err == nil {
		t.Fatal("Send succeeded against a closed port")
	}
	if CodeOf(err) != CodeDial {
		t.Fatalf("code = %q, want %q (%v)", CodeOf(err), CodeDial, err)
	}
	// A relay that is down comes back up. Giving up here would lose mail.
	if IsPermanent(err) {
		t.Fatal("a dial failure must be transient")
	}
}

func TestSendRespectsContextCancellation(t *testing.T) {
	sink := smtptest.Start(t, smtptest.Options{Mode: smtptest.ModePlain})
	s := testSender(t, sink)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := s.Send(ctx, route(sink, store.TLSModeNone), message())
	if err == nil {
		t.Fatal("Send succeeded with a cancelled context")
	}
	// A shutdown says nothing about whether the message is deliverable.
	if IsPermanent(err) {
		t.Fatalf("a cancellation must be transient (%v)", err)
	}
	if code := CodeOf(err); code != CodeCanceled && code != CodeDial {
		t.Fatalf("code = %q, want %q or %q", code, CodeCanceled, CodeDial)
	}
}

func TestSendTimesOut(t *testing.T) {
	sink := smtptest.Start(t, smtptest.Options{
		Mode: smtptest.ModePlain,
		// Stall inside DATA for longer than the sender's own budget.
		DataDelay: 2 * time.Second,
	})
	s := New(Config{Timeout: 300 * time.Millisecond, InsecureSkipVerifyHosts: []string{sink.Host}}, nil)

	start := time.Now()
	_, err := s.Send(context.Background(), route(sink, store.TLSModeNone), message())
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Send succeeded although the sink stalled past the timeout")
	}
	if IsPermanent(err) {
		t.Fatalf("a timeout must be transient (%v)", err)
	}
	// The point of the deadline: a silent relay must not hold a worker.
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("Send took %v, want it bounded by the configured timeout", elapsed)
	}
}

func TestSendRejectsEmptyInput(t *testing.T) {
	s := New(Config{}, nil)
	r := store.SenderRoute{BackendID: uuid.New(), Host: "127.0.0.1", Port: 25, MaxConcurrency: 1}

	if _, err := s.Send(context.Background(), r, Message{From: "a@b.test", Raw: []byte("x")}); !IsPermanent(err) {
		t.Fatalf("a message with no recipients: %v, want a permanent error", err)
	}
	if _, err := s.Send(context.Background(), r, Message{From: "a@b.test", Recipients: []string{"c@d.test"}}); !IsPermanent(err) {
		t.Fatalf("a message with no body: %v, want a permanent error", err)
	}
}

// --- concurrency ------------------------------------------------------------

// Providers rate-limit connections independently of how many workers we run, so
// the ceiling has to hold.
func TestSendRespectsBackendConcurrency(t *testing.T) {
	sink := smtptest.Start(t, smtptest.Options{
		Mode:      smtptest.ModePlain,
		DataDelay: 150 * time.Millisecond,
	})
	s := testSender(t, sink)

	r := route(sink, store.TLSModeNone)
	r.MaxConcurrency = 2

	const attempts = 6
	var wg sync.WaitGroup
	errs := make(chan error, attempts)

	start := time.Now()
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.Send(context.Background(), r, message())
			errs <- err
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("Send: %v", err)
		}
	}
	if sink.Count() != attempts {
		t.Fatalf("the sink received %d messages, want %d", sink.Count(), attempts)
	}

	// Six deliveries of 150ms at two at a time cannot finish faster than three
	// batches. A generous floor, so the assertion is about the ceiling holding,
	// not about scheduler precision.
	if minimum := 2 * 150 * time.Millisecond; elapsed < minimum {
		t.Fatalf("6 deliveries took %v with a concurrency of 2: the ceiling is not being applied", elapsed)
	}
}

func TestConcurrencyCeilingCanChange(t *testing.T) {
	sink := smtptest.Start(t, smtptest.Options{Mode: smtptest.ModePlain})
	s := testSender(t, sink)

	r := route(sink, store.TLSModeNone)
	r.MaxConcurrency = 1
	if _, err := s.Send(context.Background(), r, message()); err != nil {
		t.Fatalf("Send: %v", err)
	}

	// An admin raising the ceiling must take effect without a restart.
	r.MaxConcurrency = 4
	if _, err := s.Send(context.Background(), r, message()); err != nil {
		t.Fatalf("Send after the ceiling changed: %v", err)
	}
	if got := s.slots[r.BackendID].size; got != 4 {
		t.Fatalf("slot size = %d, want 4", got)
	}
}

// --- TLS verification -------------------------------------------------------

// The verification bypass exists for a local sink with a generated certificate.
// It must not be reachable for anything else, whatever is configured.
func TestInsecureSkipVerifyIsLocalOnly(t *testing.T) {
	tests := []struct {
		host       string
		configured []string
		wantSkip   bool
		why        string
	}{
		{"127.0.0.1", []string{"127.0.0.1"}, true, "loopback, explicitly listed"},
		{"localhost", []string{"localhost"}, true, "loopback by name"},
		{"mailpit", []string{"mailpit"}, true, "the development sink"},
		{"10.1.2.3", []string{"10.1.2.3"}, true, "private address"},
		{"127.0.0.1", nil, false, "local but not listed"},
		{"smtp.example.com", []string{"smtp.example.com"}, false, "listed but public: must never be skipped"},
		{"8.8.8.8", []string{"8.8.8.8"}, false, "public address, listed"},
		{"smtp.email.eu-zurich-1.oci.oraclecloud.com", []string{"*"}, false, "a wildcard must not work"},
	}

	for _, tc := range tests {
		t.Run(tc.host+" "+tc.why, func(t *testing.T) {
			s := New(Config{InsecureSkipVerifyHosts: tc.configured}, nil)
			cfg := s.tlsConfig(store.SenderRoute{Host: tc.host})

			if cfg.InsecureSkipVerify != tc.wantSkip {
				t.Fatalf("InsecureSkipVerify = %v, want %v (%s)", cfg.InsecureSkipVerify, tc.wantSkip, tc.why)
			}
			// The server name must always be set, or STARTTLS would verify
			// against nothing.
			if cfg.ServerName != tc.host {
				t.Fatalf("ServerName = %q, want %q", cfg.ServerName, tc.host)
			}
			if cfg.MinVersion < tls.VersionTLS12 {
				t.Fatalf("MinVersion = %#x, want at least TLS 1.2", cfg.MinVersion)
			}
		})
	}
}

// A relay presenting an untrusted certificate must fail, not silently downgrade.
func TestSendFailsOnUntrustedCertificate(t *testing.T) {
	sink := smtptest.Start(t, smtptest.Options{Mode: smtptest.ModeSTARTTLS})
	// No InsecureSkipVerifyHosts: the sink's generated certificate is not trusted.
	s := New(Config{Timeout: 5 * time.Second}, nil)

	_, err := s.Send(context.Background(), route(sink, store.TLSModeSTARTTLS), message())
	if err == nil {
		t.Fatal("Send accepted an untrusted certificate")
	}
	if CodeOf(err) != CodeTLS {
		t.Fatalf("code = %q, want %q (%v)", CodeOf(err), CodeTLS, err)
	}
	if sink.Count() != 0 {
		t.Fatal("a message was delivered over an unverified connection")
	}
}

func TestHeloNameFallsBackToConfig(t *testing.T) {
	s := New(Config{HeloName: "configured.test"}, nil)

	if got := s.heloName(store.SenderRoute{}); got != "configured.test" {
		t.Fatalf("heloName = %q, want the configured default", got)
	}
	if got := s.heloName(store.SenderRoute{HeloName: "backend.test"}); got != "backend.test" {
		t.Fatalf("heloName = %q, want the backend override", got)
	}
}
