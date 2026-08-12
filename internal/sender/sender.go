// Package sender delivers a message to an outbound relay over SMTP.
//
// It is the only place that opens an outbound connection, and it holds two
// responsibilities that must not leak elsewhere:
//
//   - Classifying a failure as transient or permanent. That classification is
//     what decides whether river retries, so getting it wrong either abandons
//     deliverable mail (a 4xx treated as permanent) or hammers a relay for hours
//     over a mailbox that will never exist (a 5xx treated as transient).
//   - Refusing to authenticate over an unencrypted connection, whatever the
//     database says. The schema already forbids storing a password next to
//     tls_mode='none'; this is the second lock on the same door.
package sender

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/google/uuid"

	"github.com/amenitydev/relais/internal/store"
)

// Kind says whether a failure is worth retrying.
type Kind int

const (
	// KindTransient means try again later: a network hiccup, a 4xx, a relay
	// asking us to slow down.
	KindTransient Kind = iota
	// KindPermanent means stop: a 5xx, a mailbox that does not exist, a
	// configuration the relay will keep refusing.
	KindPermanent
)

func (k Kind) String() string {
	if k == KindPermanent {
		return "permanent"
	}
	return "transient"
}

// Error codes. Stored in email_message.error_code, so they are an operational
// contract: an operator greps for these.
const (
	CodeDial            = "dial_failed"
	CodeTLS             = "tls_failed"
	CodeGreeting        = "greeting_failed"
	CodeEHLO            = "ehlo_failed"
	CodeAuthUnsupported = "auth_unsupported"
	CodeAuthFailed      = "auth_failed"
	// CodeAuthInsecure is refused locally, before any byte leaves: the relay
	// offered no TLS and we hold a password.
	CodeAuthInsecure = "auth_insecure"

	CodeMailFrom              = "mail_from_rejected"
	CodeAllRecipientsRejected = "all_recipients_rejected"
	CodeDataRejected          = "data_rejected"
	CodeWriteFailed           = "write_failed"

	CodeTimeout  = "timeout"
	CodeCanceled = "canceled"
	CodeInternal = "internal_error"

	// CodePartialRecipients is not a failure. It is recorded on a message that
	// was delivered to some recipients while the relay refused others.
	CodePartialRecipients = "partial_recipients"
)

// Error is a delivery failure.
type Error struct {
	Kind Kind
	Code string
	// Detail is the relay's own response or the underlying cause. It is shown to
	// the operator and never contains message content.
	Detail string
	// SMTPCode is the numeric reply, or 0 when the failure happened before any
	// reply (a dial or TLS failure).
	SMTPCode int

	err error
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return e.Code
	}
	return e.Code + ": " + e.Detail
}

func (e *Error) Unwrap() error { return e.err }

// IsPermanent reports whether err says to stop retrying.
//
// An unclassified error is treated as transient, which is the safe default: a
// retry costs a connection, while giving up on a deliverable message loses mail.
func IsPermanent(err error) bool {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind == KindPermanent
	}
	return false
}

// CodeOf returns the machine code carried by err, or CodeInternal.
func CodeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	if err == nil {
		return ""
	}
	return CodeInternal
}

// Message is what to deliver.
type Message struct {
	// From is the envelope sender, which relais sets from the validated From
	// header (see D4). It is not read from the message bytes here.
	From string
	// Recipients is the envelope list: exactly what goes out as RCPT TO.
	Recipients []string
	// Raw is the complete RFC 5322 message, already normalized.
	Raw []byte
}

// RejectedRecipient is one address the relay refused.
type RejectedRecipient struct {
	Address  string
	SMTPCode int
	Detail   string
}

// Result describes a completed delivery.
type Result struct {
	// Accepted is the recipients the relay took.
	Accepted []string
	// Rejected is the recipients it refused, while still accepting others.
	// A non-empty Rejected with a nil error means a partial delivery.
	Rejected []RejectedRecipient
	// Response is the relay's final reply to DATA, which usually carries its
	// queue id — the thing you need when asking a provider what happened.
	Response string
	// UsedTLS records whether the connection was encrypted.
	UsedTLS bool
}

// Partial reports whether some recipients were refused.
func (r Result) Partial() bool { return len(r.Rejected) > 0 }

// RejectedDetail renders the refusals for the operator, in one line.
func (r Result) RejectedDetail() string {
	if len(r.Rejected) == 0 {
		return ""
	}
	parts := make([]string, 0, len(r.Rejected))
	for _, rejected := range r.Rejected {
		parts = append(parts, fmt.Sprintf("%s (%d %s)", rejected.Address, rejected.SMTPCode, rejected.Detail))
	}
	return strings.Join(parts, "; ")
}

// Config parameterizes the sender.
type Config struct {
	// Timeout bounds a whole delivery attempt, from dial to QUIT.
	Timeout time.Duration
	// HeloName is the EHLO name used when a backend does not override it.
	HeloName string
	// MinTLSVersion applies to outbound connections.
	MinTLSVersion uint16
	// InsecureSkipVerifyHosts lists relay hostnames whose certificate is not
	// verified. It exists only for a local sink with a self-signed certificate
	// and is refused for anything that is not obviously local.
	InsecureSkipVerifyHosts []string
}

// Sender delivers messages, bounding concurrency per backend.
type Sender struct {
	cfg Config
	log *slog.Logger

	mu    sync.Mutex
	slots map[uuid.UUID]*backendSlots
}

// backendSlots caps simultaneous connections to one relay.
//
// Providers rate-limit connections independently of how many workers we run, so
// the ceiling belongs to the backend, not to the worker pool.
type backendSlots struct {
	tokens chan struct{}
	size   int32
}

// New builds a Sender.
func New(cfg Config, log *slog.Logger) *Sender {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Minute
	}
	if cfg.MinTLSVersion == 0 {
		cfg.MinTLSVersion = tls.VersionTLS12
	}
	if cfg.HeloName == "" {
		cfg.HeloName = "localhost"
	}
	if log == nil {
		log = slog.Default()
	}
	return &Sender{cfg: cfg, log: log, slots: make(map[uuid.UUID]*backendSlots)}
}

// Send delivers msg through route.
//
// A nil error means the message was accepted by the relay. Check Result.Partial
// to find out whether every recipient made it.
func (s *Sender) Send(ctx context.Context, route store.SenderRoute, msg Message) (Result, error) {
	if len(msg.Recipients) == 0 {
		// Would be a bug upstream: ingest refuses a message with no recipients.
		return Result{}, &Error{Kind: KindPermanent, Code: CodeInternal, Detail: "no recipients"}
	}
	if len(msg.Raw) == 0 {
		return Result{}, &Error{Kind: KindPermanent, Code: CodeInternal, Detail: "empty message"}
	}

	release, err := s.acquire(ctx, route)
	if err != nil {
		return Result{}, err
	}
	defer release()

	// One deadline for the whole attempt. The SMTP client has no per-command
	// timeout, so without this a relay that accepts the connection and then goes
	// silent would hold a worker forever.
	attemptCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		attemptCtx, cancel = context.WithTimeout(ctx, s.cfg.Timeout)
		defer cancel()
	}

	conn, err := s.dial(attemptCtx, route)
	if err != nil {
		return Result{}, err
	}

	// A watchdog, because go-smtp manages its own deadlines: it sets one per
	// command and then *clears* it (SetDeadline(time.Time{})), so a deadline set
	// on the connection here is wiped by the first command. Closing the
	// connection is what actually unblocks a read from a relay that has gone
	// silent, and it is what makes context cancellation real.
	watchdogDone := make(chan struct{})
	defer close(watchdogDone)
	go func() {
		select {
		case <-attemptCtx.Done():
			_ = conn.Close()
		case <-watchdogDone:
		}
	}()

	client, err := s.handshake(attemptCtx, conn, route)
	if err != nil {
		_ = conn.Close()
		return Result{}, err
	}
	defer func() {
		// Close, not Quit: Quit is attempted on the success path, and closing an
		// already-quit connection is harmless.
		_ = client.Close()
	}()

	return s.deliver(attemptCtx, client, route, msg)
}

// ProbeResult describes what a connection test found.
type ProbeResult struct {
	// UsedTLS reports whether the connection was encrypted.
	UsedTLS bool
	// Authenticated reports whether SMTP AUTH succeeded. False with no error means
	// the backend is configured without credentials.
	Authenticated bool
	// Greeting is the relay's banner, which usually names the software and is the
	// quickest confirmation that the right host answered.
	Greeting string
	// Extensions is what the relay advertised, so an operator can see whether AUTH
	// and STARTTLS are actually offered.
	Extensions []string
}

// Probe opens a connection, authenticates, and hangs up without sending anything.
//
// It exists so an operator can find out that a backend's credentials are wrong
// before the first real message does — the alternative is discovering it from a
// queue of failed deliveries. Nothing is sent: no MAIL FROM, no DATA, so the
// relay records no attempt and no quota is consumed.
func (s *Sender) Probe(ctx context.Context, route store.SenderRoute) (ProbeResult, error) {
	release, err := s.acquire(ctx, route)
	if err != nil {
		return ProbeResult{}, err
	}
	defer release()

	attemptCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		attemptCtx, cancel = context.WithTimeout(ctx, s.cfg.Timeout)
		defer cancel()
	}

	conn, err := s.dial(attemptCtx, route)
	if err != nil {
		return ProbeResult{}, err
	}

	watchdogDone := make(chan struct{})
	defer close(watchdogDone)
	go func() {
		select {
		case <-attemptCtx.Done():
			_ = conn.Close()
		case <-watchdogDone:
		}
	}()

	client, err := s.handshake(attemptCtx, conn, route)
	if err != nil {
		_ = conn.Close()
		return ProbeResult{}, err
	}
	defer func() { _ = client.Close() }()

	result := ProbeResult{Authenticated: route.UsesAuth()}
	if _, encrypted := client.TLSConnectionState(); encrypted {
		result.UsedTLS = true
	}
	for _, extension := range []string{"AUTH", "STARTTLS", "SIZE", "8BITMIME", "PIPELINING", "ENHANCEDSTATUSCODES"} {
		if supported, params := client.Extension(extension); supported {
			entry := extension
			if params != "" {
				entry += " " + params
			}
			result.Extensions = append(result.Extensions, entry)
		}
	}

	if err := client.Quit(); err != nil {
		s.log.Debug("QUIT failed after a successful probe",
			slog.String("backend", route.BackendName), slog.Any("error", err))
	}
	return result, nil
}

// handshake brings an open connection up to the point where mail can be sent:
// TLS established if required, EHLO done, AUTH done.
func (s *Sender) handshake(ctx context.Context, conn net.Conn, route store.SenderRoute) (*smtp.Client, error) {
	var client *smtp.Client
	var err error

	switch route.TLSMode {
	case store.TLSModeSTARTTLS:
		client, err = smtp.NewClientStartTLS(conn, s.tlsConfig(route))
		if err != nil {
			return nil, classify(CodeTLS, "STARTTLS with "+route.Host, err)
		}
	default:
		client = smtp.NewClient(conn)
	}

	// go-smtp's defaults are 5 and 12 minutes, far beyond a delivery attempt's
	// budget. Narrowing them means a stalled relay fails inside the attempt
	// rather than holding a worker for a quarter of an hour.
	client.CommandTimeout = s.cfg.Timeout
	client.SubmissionTimeout = s.cfg.Timeout
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining > 0 {
			client.CommandTimeout = remaining
			client.SubmissionTimeout = remaining
		}
	}

	if err := client.Hello(s.heloName(route)); err != nil {
		client.Close()
		return nil, classify(CodeEHLO, "EHLO", err)
	}

	if err := s.authenticate(client, route); err != nil {
		client.Close()
		return nil, err
	}
	return client, nil
}

// dial opens the TCP (or TLS) connection, honouring the context.
//
// go-smtp's own Dial helpers take no context, so the connection is made here and
// handed to NewClient: a cancelled job must not sit in a 30 second dial.
func (s *Sender) dial(ctx context.Context, route store.SenderRoute) (net.Conn, error) {
	address := route.Address()
	dialer := &net.Dialer{}

	if route.TLSMode == store.TLSModeImplicit {
		tlsDialer := &tls.Dialer{NetDialer: dialer, Config: s.tlsConfig(route)}
		conn, err := tlsDialer.DialContext(ctx, "tcp", address)
		if err != nil {
			// A handshake failure and a refused connection are both transient as
			// far as retrying goes, but they are different problems, so they get
			// different codes.
			code := CodeDial
			if isTLSError(err) {
				code = CodeTLS
			}
			return nil, classify(code, "connect to "+address, err)
		}
		return conn, nil
	}

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, classify(CodeDial, "connect to "+address, err)
	}
	return conn, nil
}

// authenticate performs SMTP AUTH, or refuses to.
func (s *Sender) authenticate(client *smtp.Client, route store.SenderRoute) error {
	if !route.UsesAuth() {
		return nil
	}

	// The load-bearing check. The schema forbids storing a password alongside
	// tls_mode='none', but a backend could have been edited, or a relay could
	// have failed to negotiate TLS while still accepting commands. A password
	// must never cross an unencrypted connection, so this is verified against
	// the live connection state rather than against configuration.
	if _, encrypted := client.TLSConnectionState(); !encrypted {
		return &Error{
			Kind:   KindPermanent,
			Code:   CodeAuthInsecure,
			Detail: "refusing to send SMTP AUTH over an unencrypted connection to " + route.Host,
		}
	}

	mechanism, err := s.pickAuthMechanism(client, route)
	if err != nil {
		return err
	}
	if err := client.Auth(mechanism); err != nil {
		// An authentication failure is permanent: retrying the same wrong
		// credentials eight times helps nobody, and some providers lock an
		// account for it.
		return &Error{
			Kind:     KindPermanent,
			Code:     CodeAuthFailed,
			Detail:   summarize(err),
			SMTPCode: smtpCode(err),
			err:      err,
		}
	}
	return nil
}

// pickAuthMechanism prefers PLAIN and falls back to LOGIN, which some older
// relays are the only thing they offer.
func (s *Sender) pickAuthMechanism(client *smtp.Client, route store.SenderRoute) (sasl.Client, error) {
	supported, mechanisms := client.Extension("AUTH")
	if !supported {
		return nil, &Error{
			Kind:   KindPermanent,
			Code:   CodeAuthUnsupported,
			Detail: route.Host + " does not advertise AUTH, but a credential is configured for it",
		}
	}

	offered := strings.ToUpper(mechanisms)
	switch {
	case strings.Contains(offered, sasl.Plain):
		return sasl.NewPlainClient("", route.AuthUser, route.AuthPassword.Reveal()), nil
	case strings.Contains(offered, sasl.Login):
		return sasl.NewLoginClient(route.AuthUser, route.AuthPassword.Reveal()), nil
	default:
		return nil, &Error{
			Kind:   KindPermanent,
			Code:   CodeAuthUnsupported,
			Detail: fmt.Sprintf("%s offers AUTH %s; relais supports PLAIN and LOGIN", route.Host, mechanisms),
		}
	}
}

// deliver runs the MAIL/RCPT/DATA exchange.
func (s *Sender) deliver(ctx context.Context, client *smtp.Client, route store.SenderRoute, msg Message) (Result, error) {
	result := Result{}
	if _, encrypted := client.TLSConnectionState(); encrypted {
		result.UsedTLS = true
	}

	if err := client.Mail(msg.From, nil); err != nil {
		// A refused envelope sender is usually the relay saying "this address is
		// not an approved sender", which no amount of retrying will change if it
		// is a 5xx.
		return result, classify(CodeMailFrom, "MAIL FROM "+msg.From, err)
	}

	for _, recipient := range msg.Recipients {
		if err := client.Rcpt(recipient, nil); err != nil {
			// A transient refusal for one recipient is treated as a refusal of
			// that recipient, not of the message: the others may still be
			// deliverable now, and re-sending the whole message later would
			// duplicate mail for those who already received it.
			result.Rejected = append(result.Rejected, RejectedRecipient{
				Address:  recipient,
				SMTPCode: smtpCode(err),
				Detail:   summarize(err),
			})
			continue
		}
		result.Accepted = append(result.Accepted, recipient)
	}

	if len(result.Accepted) == 0 {
		// Nobody accepted. Whether to retry follows the strictest refusal: if
		// any of them was transient, the message may still go out later.
		kind := KindPermanent
		for _, rejected := range result.Rejected {
			if rejected.SMTPCode >= 400 && rejected.SMTPCode < 500 {
				kind = KindTransient
				break
			}
		}
		return result, &Error{
			Kind:   kind,
			Code:   CodeAllRecipientsRejected,
			Detail: result.RejectedDetail(),
		}
	}

	data, err := client.Data()
	if err != nil {
		return result, classify(CodeDataRejected, "DATA", err)
	}
	if _, err := data.Write(msg.Raw); err != nil {
		return result, classify(CodeWriteFailed, "writing the message", err)
	}
	response, err := data.CloseWithResponse()
	if err != nil {
		return result, classify(CodeDataRejected, "end of DATA", err)
	}
	if response != nil {
		// The relay's final reply usually carries its queue id, which is exactly
		// what a provider's support will ask for.
		result.Response = strings.TrimSpace(response.StatusText)
	}

	// QUIT is best effort: the relay has already accepted the message, so a
	// failure here changes nothing about whether it was delivered.
	if err := client.Quit(); err != nil {
		s.log.Debug("QUIT failed after a successful delivery",
			slog.String("backend", route.BackendName), slog.Any("error", err))
	}
	return result, nil
}

// tlsConfig builds the outbound TLS configuration.
func (s *Sender) tlsConfig(route store.SenderRoute) *tls.Config {
	cfg := &tls.Config{
		ServerName: route.Host,
		MinVersion: s.cfg.MinTLSVersion,
	}
	// Verification is only skipped for an explicitly listed local sink. There is
	// no global switch, because a global switch is one environment variable away
	// from disabling verification in production.
	for _, host := range s.cfg.InsecureSkipVerifyHosts {
		if strings.EqualFold(strings.TrimSpace(host), route.Host) && isLocalHost(route.Host) {
			cfg.InsecureSkipVerify = true
			break
		}
	}
	return cfg
}

func (s *Sender) heloName(route store.SenderRoute) string {
	if route.HeloName != "" {
		return route.HeloName
	}
	return s.cfg.HeloName
}

// acquire takes a per-backend slot, returning the release function.
func (s *Sender) acquire(ctx context.Context, route store.SenderRoute) (func(), error) {
	size := route.MaxConcurrency
	if size < 1 {
		size = 1
	}

	s.mu.Lock()
	slots, ok := s.slots[route.BackendID]
	if !ok || slots.size != size {
		// A changed ceiling replaces the channel. In-flight deliveries release
		// into the channel they took from, so the old one simply goes away.
		slots = &backendSlots{tokens: make(chan struct{}, size), size: size}
		s.slots[route.BackendID] = slots
	}
	tokens := slots.tokens
	s.mu.Unlock()

	select {
	case tokens <- struct{}{}:
		return func() { <-tokens }, nil
	case <-ctx.Done():
		return nil, contextError(ctx.Err(), "waiting for a free connection slot to "+route.BackendName)
	}
}

// classify turns a transport or protocol error into an *Error.
func classify(code, what string, err error) *Error {
	if err == nil {
		return nil
	}

	// Context first: a cancelled job is not the relay's fault, and its status
	// must stay retryable.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return contextError(err, what)
	}

	// A TLS failure keeps its own code whatever stage it surfaces at. With
	// STARTTLS the handshake completes lazily, so an untrusted certificate is
	// first noticed during EHLO — and telling an operator "ehlo_failed" when the
	// real problem is a certificate sends them looking in the wrong place.
	if isTLSError(err) {
		return &Error{Kind: KindTransient, Code: CodeTLS, Detail: what + ": " + summarize(err), err: err}
	}

	var smtpErr *smtp.SMTPError
	if errors.As(err, &smtpErr) {
		kind := KindTransient
		// The whole classification, in one line: 4xx means try again, 5xx means
		// stop. RFC 5321 is unambiguous about this and providers rely on it.
		if smtpErr.Code >= 500 {
			kind = KindPermanent
		}
		return &Error{
			Kind:     kind,
			Code:     code,
			Detail:   what + ": " + summarize(err),
			SMTPCode: smtpErr.Code,
			err:      err,
		}
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return &Error{Kind: KindTransient, Code: CodeTimeout, Detail: what + ": timed out", err: err}
	}

	// Anything else — a reset connection, a DNS failure, a broken pipe — is
	// transient. Guessing "permanent" here would discard deliverable mail.
	return &Error{Kind: KindTransient, Code: code, Detail: what + ": " + summarize(err), err: err}
}

func contextError(err error, what string) *Error {
	code := CodeCanceled
	if errors.Is(err, context.DeadlineExceeded) {
		code = CodeTimeout
	}
	// Transient: a shutdown or a timeout says nothing about whether the message
	// is deliverable.
	return &Error{Kind: KindTransient, Code: code, Detail: what, err: err}
}

// summarize renders an error for the operator, keeping the relay's own words,
// which are what a provider's support will ask for.
func summarize(err error) string {
	var smtpErr *smtp.SMTPError
	if errors.As(err, &smtpErr) {
		message := strings.TrimSpace(smtpErr.Message)
		if message == "" {
			return fmt.Sprintf("%d", smtpErr.Code)
		}
		return fmt.Sprintf("%d %s", smtpErr.Code, message)
	}
	if errors.Is(err, io.EOF) {
		return "the relay closed the connection"
	}
	return err.Error()
}

func smtpCode(err error) int {
	var smtpErr *smtp.SMTPError
	if errors.As(err, &smtpErr) {
		return smtpErr.Code
	}
	return 0
}

func isTLSError(err error) bool {
	var recordErr tls.RecordHeaderError
	if errors.As(err, &recordErr) {
		return true
	}
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return true
	}
	var alert tls.AlertError
	return errors.As(err, &alert)
}

// isLocalHost reports whether a host is unambiguously local, which is the only
// place certificate verification may be skipped.
func isLocalHost(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1", "mailpit":
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate()
	}
	return false
}
