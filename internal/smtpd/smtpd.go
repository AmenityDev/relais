// Package smtpd is the SMTP submission façade.
//
// It exists for the applications that speak SMTP and nothing else: WordPress
// plugins, old PHP scripts, anything with a "mail server" configuration screen.
// Those clients cannot be changed, so relais meets them where they are — and then
// puts their submission through exactly the same pipeline as a REST call.
//
// Three rules are enforced here and nowhere else:
//
//   - AUTH is impossible before STARTTLS. go-smtp's AllowInsecureAuth is left
//     false, so it neither advertises nor accepts AUTH on a plaintext
//     connection, and the session re-checks the live connection state on top of
//     that.
//   - No mail moves without authentication. MAIL FROM on an unauthenticated
//     session is refused, which is what "no anonymous relay under any condition"
//     means in protocol terms.
//   - The envelope sender is not the sender. Validation runs against the From
//     header (D4); MAIL FROM is recorded and, when it disagrees, logged — legacy
//     clients put arbitrary values there and refusing them would break working
//     setups for no security gain.
package smtpd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"golang.org/x/net/netutil"
	"golang.org/x/sync/errgroup"

	"github.com/amenitydev/relais/internal/authn"
	"github.com/amenitydev/relais/internal/frompattern"
	"github.com/amenitydev/relais/internal/ingest"
	"github.com/amenitydev/relais/internal/mailnorm"
	"github.com/amenitydev/relais/internal/store"
	"github.com/amenitydev/relais/internal/tlsconf"
)

// Config parameterizes the submission server.
type Config struct {
	// Domain is the name announced in the greeting and the EHLO response.
	Domain string
	// Addr is the STARTTLS submission listener (RFC 6409 port 587).
	Addr string
	// TLSAddr is the implicit-TLS listener (port 465 style). Empty disables it.
	TLSAddr string

	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	ShutdownTimeout time.Duration

	MaxMessageBytes int64
	MaxRecipients   int
	// MaxConnections bounds concurrent sessions. go-smtp has no such setting, so
	// it is applied by wrapping the listener.
	MaxConnections int
}

// Options carries the server's dependencies.
type Options struct {
	Ingest        *ingest.Service
	Authenticator *authn.Authenticator
	// Certificates is required: without TLS there is no way to authenticate, and
	// a submission server that cannot authenticate has no purpose.
	Certificates *tlsconf.Provider
	Config       Config
	Log          *slog.Logger
}

// Server runs the submission listeners.
type Server struct {
	ingest        *ingest.Service
	authenticator *authn.Authenticator
	certs         *tlsconf.Provider
	cfg           Config
	log           *slog.Logger
}

// New builds the submission server.
func New(opts Options) (*Server, error) {
	switch {
	case opts.Ingest == nil:
		return nil, errors.New("smtpd: an ingest service is required")
	case opts.Authenticator == nil:
		return nil, errors.New("smtpd: an authenticator is required")
	case opts.Certificates == nil:
		// Not a convenience check: with no certificate there is no STARTTLS, so
		// AUTH can never be offered, so nothing can ever be submitted.
		return nil, errors.New("smtpd: a TLS certificate provider is required")
	case opts.Config.Addr == "" && opts.Config.TLSAddr == "":
		return nil, errors.New("smtpd: no listener address configured")
	}

	cfg := opts.Config
	if cfg.Domain == "" {
		cfg.Domain = "localhost"
	}
	if cfg.MaxRecipients <= 0 {
		cfg.MaxRecipients = 50
	}
	if cfg.MaxMessageBytes <= 0 {
		cfg.MaxMessageBytes = 10 << 20
	}
	if cfg.ShutdownTimeout <= 0 {
		cfg.ShutdownTimeout = 20 * time.Second
	}

	log := opts.Log
	if log == nil {
		log = slog.Default()
	}

	return &Server{
		ingest:        opts.Ingest,
		authenticator: opts.Authenticator,
		certs:         opts.Certificates,
		cfg:           cfg,
		log:           log,
	}, nil
}

// Run serves until ctx is cancelled, then shuts down gracefully.
func (s *Server) Run(ctx context.Context) error {
	group, groupCtx := errgroup.WithContext(ctx)

	if s.cfg.Addr != "" {
		if err := s.serve(group, groupCtx, s.cfg.Addr, false); err != nil {
			return err
		}
	}
	if s.cfg.TLSAddr != "" {
		if err := s.serve(group, groupCtx, s.cfg.TLSAddr, true); err != nil {
			return err
		}
	}
	return group.Wait()
}

// serve starts one listener and registers its shutdown.
func (s *Server) serve(group *errgroup.Group, ctx context.Context, addr string, implicitTLS bool) error {
	server := s.newSMTPServer(implicitTLS)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	if implicitTLS {
		listener = tls.NewListener(listener, s.certs.Config())
	}
	if s.cfg.MaxConnections > 0 {
		// go-smtp has no connection ceiling, so it is applied here. Accept blocks
		// once the limit is reached, which leaves clients in the TCP backlog
		// rather than being refused — the right trade for internal senders.
		listener = netutil.LimitListener(listener, s.cfg.MaxConnections)
	}

	mode := "starttls"
	if implicitTLS {
		mode = "implicit-tls"
	}

	group.Go(func() error {
		s.log.Info("smtp submission listener started",
			slog.String("addr", addr),
			slog.String("tls", mode),
			slog.String("domain", s.cfg.Domain),
			slog.Int64("max_message_bytes", s.cfg.MaxMessageBytes),
			slog.Int("max_recipients", s.cfg.MaxRecipients),
		)
		if err := server.Serve(listener); err != nil && !errors.Is(err, net.ErrClosed) {
			return fmt.Errorf("smtp server on %s: %w", addr, err)
		}
		return nil
	})

	group.Go(func() error {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownTimeout)
		defer cancel()
		s.log.Info("smtp submission listener stopping", slog.String("addr", addr))
		// Shutdown lets in-flight sessions finish; a message mid-DATA is either
		// fully accepted or not accepted at all.
		if err := server.Shutdown(shutdownCtx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("shut down the smtp server on %s: %w", addr, err)
		}
		return nil
	})
	return nil
}

func (s *Server) newSMTPServer(implicitTLS bool) *smtp.Server {
	server := smtp.NewServer(smtp.BackendFunc(func(c *smtp.Conn) (smtp.Session, error) {
		return s.newSession(c), nil
	}))

	server.Domain = s.cfg.Domain
	server.ReadTimeout = s.cfg.ReadTimeout
	server.WriteTimeout = s.cfg.WriteTimeout
	server.MaxMessageBytes = s.cfg.MaxMessageBytes
	server.MaxRecipients = s.cfg.MaxRecipients

	// The single most important line in this package. With it false, go-smtp
	// neither advertises AUTH nor accepts it until STARTTLS has succeeded, so a
	// credential cannot cross the network in the clear. There is no configuration
	// knob to turn this on.
	server.AllowInsecureAuth = false

	// An implicit-TLS listener is already encrypted, so STARTTLS is not offered
	// there; the STARTTLS listener needs the certificate to advertise it.
	if !implicitTLS {
		server.TLSConfig = s.certs.Config()
	}

	server.ErrorLog = smtpLogger{log: s.log}
	return server
}

// smtpLogger adapts go-smtp's logger to slog.
type smtpLogger struct {
	log *slog.Logger
}

func (l smtpLogger) Printf(format string, v ...any) {
	// Protocol-level noise (a client hanging up mid-command) is routine, so it
	// lands at debug rather than error.
	l.log.Debug("smtp protocol", slog.String("detail", fmt.Sprintf(format, v...)))
}

func (l smtpLogger) Println(v ...any) {
	l.log.Debug("smtp protocol", slog.String("detail", fmt.Sprint(v...)))
}

// session is one client connection.
type session struct {
	server *Server
	conn   *smtp.Conn
	log    *slog.Logger

	remoteIP netip.Addr

	// credential is set once AUTH succeeds. Its absence is what makes MAIL FROM
	// refuse.
	credential    store.AuthCredential
	authenticated bool

	// envelopeFrom is what the client announced in MAIL FROM. It is recorded for
	// the audit trail and is deliberately not what gets validated (D4).
	envelopeFrom string
	recipients   []string
}

func (s *Server) newSession(c *smtp.Conn) *session {
	remoteIP := remoteAddrOf(c)

	return &session{
		server:   s,
		conn:     c,
		remoteIP: remoteIP,
		log: s.log.With(
			slog.String("facade", store.FacadeSMTP),
			slog.String("remote_ip", remoteIPString(remoteIP)),
		),
	}
}

// AuthMechanisms reports what the server offers.
//
// PLAIN and LOGIN only, and only over TLS — go-smtp refuses to call this at all
// on a plaintext connection. LOGIN is obsolete but some clients offer nothing
// else.
func (s *session) AuthMechanisms() []string {
	return []string{sasl.Plain, sasl.Login}
}

// Auth returns the SASL server for a mechanism.
func (s *session) Auth(mech string) (sasl.Server, error) {
	// Defence in depth. go-smtp already refuses AUTH before STARTTLS
	// (Conn.authAllowed), but a credential crossing the network in the clear is
	// bad enough to be worth checking against the live connection rather than
	// trusting a library setting to stay as configured.
	if _, encrypted := s.conn.TLSConnectionState(); !encrypted {
		s.log.Warn("refused AUTH on an unencrypted connection")
		return nil, &smtp.SMTPError{
			Code:         538,
			EnhancedCode: smtp.EnhancedCode{5, 7, 11},
			Message:      "encryption required for requested authentication mechanism",
		}
	}

	switch strings.ToUpper(mech) {
	case sasl.Plain:
		return sasl.NewPlainServer(func(_, username, password string) error {
			return s.authenticate(username, password)
		}), nil
	case sasl.Login:
		return &loginServer{authenticate: s.authenticate}, nil
	default:
		return nil, &smtp.SMTPError{
			Code:         504,
			EnhancedCode: smtp.EnhancedCode{5, 5, 4},
			Message:      "unsupported authentication mechanism",
		}
	}
}

// authenticate resolves the credential.
func (s *session) authenticate(username, password string) error {
	auth, err := s.server.authenticator.SMTPUser(s.context(), username, password, remoteIPString(s.remoteIP))
	if err != nil {
		if !errors.Is(err, authn.ErrUnauthenticated) {
			// A database failure is not a credential problem, and telling the
			// client to fix its password would send it down the wrong path.
			s.log.Error("could not verify the credential", slog.Any("error", err))
			return &smtp.SMTPError{
				Code:         454,
				EnhancedCode: smtp.EnhancedCode{4, 7, 0},
				Message:      "temporary authentication failure, try again later",
			}
		}
		// Nothing beyond "it failed": whether the user is unknown, revoked or the
		// password is wrong is in the logs, not in the reply.
		return &smtp.SMTPError{
			Code:         535,
			EnhancedCode: smtp.EnhancedCode{5, 7, 8},
			Message:      "authentication credentials invalid",
		}
	}

	s.credential = auth
	s.authenticated = true
	s.log = s.log.With(
		slog.String("credential_id", auth.Credential.ID.String()),
		slog.String("credential_name", auth.Credential.Name),
	)
	s.log.Info("smtp session authenticated")
	return nil
}

// Mail handles MAIL FROM.
func (s *session) Mail(from string, _ *smtp.MailOptions) error {
	if !s.authenticated {
		// The protocol-level expression of "no anonymous relay under any
		// condition".
		s.log.Warn("refused MAIL FROM on an unauthenticated session",
			slog.String("envelope_from", from))
		return &smtp.SMTPError{
			Code:         530,
			EnhancedCode: smtp.EnhancedCode{5, 7, 0},
			Message:      "authentication required",
		}
	}

	// Recorded, not validated. The From header is what authorisation runs
	// against; a legacy client that puts something else here is not refused,
	// because refusing would break working setups without preventing anything.
	s.envelopeFrom = from
	s.recipients = nil
	return nil
}

// Rcpt handles RCPT TO.
//
// Addresses are validated here rather than at DATA, so a client learns which
// recipient is wrong instead of having the whole message refused with no
// indication of why.
func (s *session) Rcpt(to string, _ *smtp.RcptOptions) error {
	if !s.authenticated {
		return &smtp.SMTPError{
			Code:         530,
			EnhancedCode: smtp.EnhancedCode{5, 7, 0},
			Message:      "authentication required",
		}
	}

	addr, err := frompattern.ParseAddress(to)
	if err != nil {
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 1, 3},
			Message:      "bad destination address syntax: " + to,
		}
	}

	if len(s.recipients) >= s.server.cfg.MaxRecipients {
		// 452 rather than 550: the message is fine, there are simply too many
		// recipients for one transaction, and splitting it will work.
		return &smtp.SMTPError{
			Code:         452,
			EnhancedCode: smtp.EnhancedCode{4, 5, 3},
			Message:      fmt.Sprintf("too many recipients in one transaction (limit %d)", s.server.cfg.MaxRecipients),
		}
	}

	s.recipients = append(s.recipients, addr.String())
	return nil
}

// Data reads the message and submits it.
func (s *session) Data(r io.Reader) error {
	if !s.authenticated {
		return &smtp.SMTPError{
			Code:         530,
			EnhancedCode: smtp.EnhancedCode{5, 7, 0},
			Message:      "authentication required",
		}
	}

	raw, err := mailnorm.ReadAll(r, s.server.cfg.MaxMessageBytes)
	if err != nil {
		// go-smtp enforces MaxMessageBytes on its own reader and reports it as an
		// *SMTPError (552 5.3.4). Passing that through unchanged matters: a
		// too-large message is permanent, and reclassifying it as a temporary
		// failure would leave a client retrying something that can never succeed.
		//
		// The assertion is direct rather than errors.As because go-smtp's own
		// dataErrorToStatus does the same, so a wrapped error would lose its code.
		var smtpErr *smtp.SMTPError
		if errors.As(err, &smtpErr) {
			s.log.Warn("submission refused while reading the message",
				slog.Int("smtp_code", smtpErr.Code),
				slog.String("detail", smtpErr.Message),
			)
			return smtpErr
		}
		if mailnorm.CodeOf(err) == mailnorm.CodeTooLarge {
			return &smtp.SMTPError{
				Code:         552,
				EnhancedCode: smtp.EnhancedCode{5, 3, 4},
				Message:      fmt.Sprintf("message exceeds the %d byte limit", s.server.cfg.MaxMessageBytes),
			}
		}
		// The client hung up or the connection broke. Nothing was accepted.
		s.log.Warn("could not read the submitted message", slog.Any("error", err))
		return &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 3, 0},
			Message:      "could not read the message, try again",
		}
	}

	result, err := s.server.ingest.Submit(s.context(), ingest.Request{
		Credential: s.credential,
		Facade:     store.FacadeSMTP,
		Raw:        raw,
		// The envelope is what the client asked for in RCPT TO, which for
		// submission is authoritative for delivery. Header recipients are
		// informational.
		EnvelopeRecipients: s.recipients,
		RemoteIP:           s.remoteIP,
	})
	if err != nil {
		if rejection, ok := ingest.AsRejection(err); ok {
			return rejectionReply(rejection)
		}
		s.log.Error("could not accept the submission", slog.Any("error", err))
		return &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 3, 0},
			Message:      "temporarily unable to accept the message, try again",
		}
	}

	s.log.Info("smtp submission accepted",
		slog.String("message_id", result.ID.String()),
		slog.String("rfc_message_id", result.RFCMessageID),
		slog.String("envelope_from", s.envelopeFrom),
		slog.Int("recipients", len(result.Recipients)),
		slog.Int("size_bytes", len(raw)),
	)

	return acceptedReply(result)
}

// Reset handles RSET.
//
// The envelope is cleared, the authentication is not: RFC 5321 says RSET aborts
// the current transaction, and a client that has to re-authenticate between two
// messages on one connection would be a client that breaks.
func (s *session) Reset() {
	s.envelopeFrom = ""
	s.recipients = nil
}

// Logout releases the session.
func (s *session) Logout() error { return nil }

// context returns the session's context.
//
// go-smtp's Session interface carries no context, so there is none to inherit. A
// background context is used, and every downstream operation is bounded by its
// own timeout rather than by cancellation from here.
func (s *session) context() context.Context {
	return context.Background()
}

// acceptedReply returns the success response.
//
// go-smtp only lets a Session influence the reply through the error it returns,
// and its success message is a fixed "250 OK: queued". Returning an SMTPError
// with a 2xx code is how the message id reaches the client — which is what makes
// a client's own log correlatable with a relais message, exactly as Postfix's
// "queued as <id>" does.
func acceptedReply(result ingest.Result) error {
	message := "OK: queued as " + result.ID.String()
	if result.Duplicate {
		// An idempotent replay accepted nothing new, and saying so beats letting
		// the client believe it sent a second copy.
		message = "OK: duplicate of " + result.ID.String() + ", nothing queued"
	}
	return &smtp.SMTPError{
		Code:         250,
		EnhancedCode: smtp.EnhancedCode{2, 0, 0},
		Message:      message,
	}
}

// rejectionReply maps an ingest rejection onto an SMTP reply.
//
// The 4xx/5xx split is the whole point: a 4xx tells the client to retry, a 5xx
// tells it to give up and report a bounce. Getting it wrong either loses mail or
// leaves a client retrying forever over a From it will never be allowed to use.
func rejectionReply(rejection *ingest.Rejection) error {
	code, enhanced := 550, smtp.EnhancedCode{5, 7, 1}

	switch rejection.Reason {
	case ingest.ReasonSenderNotAllowed:
		// 5.7.1 is "delivery not authorized", which is exactly the situation.
		code, enhanced = 550, smtp.EnhancedCode{5, 7, 1}
	case ingest.ReasonDomainNotConfigured:
		code, enhanced = 550, smtp.EnhancedCode{5, 7, 1}
	case ingest.ReasonCredentialUnusable:
		code, enhanced = 530, smtp.EnhancedCode{5, 7, 0}
	case ingest.ReasonRateLimited:
		// Temporary on purpose: the client should come back, and a well-behaved
		// one will.
		code, enhanced = 451, smtp.EnhancedCode{4, 3, 2}
	case ingest.ReasonTooManyRecipients:
		code, enhanced = 452, smtp.EnhancedCode{4, 5, 3}
	case ingest.ReasonInvalidRecipient:
		code, enhanced = 550, smtp.EnhancedCode{5, 1, 3}
	case ingest.ReasonNoRecipients:
		code, enhanced = 554, smtp.EnhancedCode{5, 5, 1}
	case mailnorm.CodeTooLarge, mailnorm.CodeHeadersTooLarge, mailnorm.CodeTooManyHeaders:
		code, enhanced = 552, smtp.EnhancedCode{5, 3, 4}
	case mailnorm.CodeNoFrom, mailnorm.CodeMultipleFrom, mailnorm.CodeInvalidFrom,
		mailnorm.CodeEmpty, mailnorm.CodeMalformedHeaders:
		// A malformed message will be just as malformed next time.
		code, enhanced = 550, smtp.EnhancedCode{5, 6, 0}
	}

	message := rejection.Reason
	if rejection.Detail != "" {
		message = rejection.Detail
	}
	return &smtp.SMTPError{Code: code, EnhancedCode: enhanced, Message: message}
}

// loginServer implements the obsolete AUTH LOGIN exchange.
//
// go-sasl dropped its server-side LOGIN implementation as deprecated. PLAIN over
// TLS is strictly better, but a client that only offers LOGIN is a client that
// otherwise cannot send at all, and those are exactly the clients this façade
// exists for.
//
// The exchange matches what real clients do: the username arrives as the initial
// response, then the server challenges with "Password:".
type loginServer struct {
	authenticate func(username, password string) error
	username     string
	gotUsername  bool
}

func (l *loginServer) Next(response []byte) (challenge []byte, done bool, err error) {
	if !l.gotUsername {
		l.gotUsername = true
		l.username = string(response)
		return []byte("Password:"), false, nil
	}
	if err := l.authenticate(l.username, string(response)); err != nil {
		return nil, false, err
	}
	return nil, true, nil
}

func remoteAddrOf(c *smtp.Conn) netip.Addr {
	if c == nil || c.Conn() == nil {
		return netip.Addr{}
	}
	host, _, err := net.SplitHostPort(c.Conn().RemoteAddr().String())
	if err != nil {
		host = c.Conn().RemoteAddr().String()
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap()
}

func remoteIPString(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	return addr.String()
}
