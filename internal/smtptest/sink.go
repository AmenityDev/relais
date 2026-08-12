// Package smtptest provides a programmable SMTP sink for tests.
//
// It is a real go-smtp server on a real socket, not a mock: the sender's job is
// to speak SMTP correctly, and only an actual protocol exchange can show whether
// it does. The sink can be told to refuse at each stage, which is what makes the
// transient/permanent classification testable.
package smtptest

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"github.com/amenitydev/relais/internal/tlsconf"
)

// Mode selects how the sink expects to be reached.
type Mode int

const (
	// ModePlain accepts plaintext only, advertising no STARTTLS.
	ModePlain Mode = iota
	// ModeSTARTTLS accepts plaintext then upgrades.
	ModeSTARTTLS
	// ModeImplicitTLS wraps the connection from the first byte.
	ModeImplicitTLS
)

// Options configures a sink's behaviour.
type Options struct {
	Mode Mode

	// Username and Password, when set, make AUTH mandatory. Any other credential
	// is refused.
	Username string
	Password string
	// AdvertisedMechanisms overrides what the sink offers. Empty offers PLAIN and
	// LOGIN.
	AdvertisedMechanisms []string

	// RejectMailFrom, when non-zero, refuses MAIL FROM with that SMTP code.
	RejectMailFrom int
	// RejectRecipients maps an address to the code it is refused with. Any
	// recipient absent from the map is accepted.
	RejectRecipients map[string]int
	// RejectData, when non-zero, refuses at the end of DATA.
	RejectData int

	// DataDelay stalls inside DATA, for exercising timeouts.
	DataDelay time.Duration
}

// Message is a delivery the sink accepted.
type Message struct {
	From       string
	Recipients []string
	Data       []byte
	// AuthenticatedAs is the username that authenticated, or "".
	AuthenticatedAs string
	// OverTLS records whether the connection was encrypted.
	OverTLS bool
}

// Sink is a running SMTP server.
type Sink struct {
	// Addr is the host:port to connect to.
	Addr string
	// Host and Port split Addr, for building a route.
	Host string
	Port int32
	// RootCAs trusts the sink's generated certificate.
	RootCAs *x509.CertPool

	opts   Options
	server *smtp.Server

	mu       sync.Mutex
	messages []Message
}

// Start launches a sink on a loopback port and stops it when the test ends.
func Start(t *testing.T, opts Options) *Sink {
	t.Helper()

	sink := &Sink{opts: opts}

	certificate, certPEM, _, err := tlsconf.GenerateSelfSigned([]string{"localhost", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatalf("generate the sink certificate: %v", err)
	}
	sink.RootCAs = x509.NewCertPool()
	if !sink.RootCAs.AppendCertsFromPEM(certPEM) {
		t.Fatalf("build the sink trust store")
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{*certificate}, MinVersion: tls.VersionTLS12}

	server := smtp.NewServer(smtp.BackendFunc(func(c *smtp.Conn) (smtp.Session, error) {
		return &session{sink: sink, conn: c}, nil
	}))
	server.Domain = "sink.test"
	server.ReadTimeout = 10 * time.Second
	server.WriteTimeout = 10 * time.Second
	server.MaxMessageBytes = 10 << 20
	// The sink must be allowed to accept AUTH in the clear, so that the sender's
	// own refusal to send it is what the test observes rather than the sink's.
	server.AllowInsecureAuth = true

	if opts.Mode != ModePlain {
		server.TLSConfig = tlsConfig
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	if opts.Mode == ModeImplicitTLS {
		listener = tls.NewListener(listener, tlsConfig)
	}

	sink.Addr = listener.Addr().String()
	host, port, err := net.SplitHostPort(sink.Addr)
	if err != nil {
		t.Fatalf("split the sink address: %v", err)
	}
	sink.Host = host
	if _, err := fmt.Sscanf(port, "%d", &sink.Port); err != nil {
		t.Fatalf("parse the sink port: %v", err)
	}
	sink.server = server

	go func() {
		// Serve returns when the listener closes, which is the normal path.
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() { _ = server.Close() })

	return sink
}

// Messages returns the deliveries accepted so far.
func (s *Sink) Messages() []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Message(nil), s.messages...)
}

// Count returns how many deliveries were accepted.
func (s *Sink) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.messages)
}

func (s *Sink) record(msg Message) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.messages = append(s.messages, msg)
}

// session implements smtp.Session and smtp.AuthSession.
type session struct {
	sink *Sink
	conn *smtp.Conn

	from       string
	recipients []string
	username   string
}

func (s *session) AuthMechanisms() []string {
	if len(s.sink.opts.AdvertisedMechanisms) > 0 {
		return s.sink.opts.AdvertisedMechanisms
	}
	if s.sink.opts.Username == "" {
		// No credential configured: still advertise, so a sender that
		// unexpectedly tries to authenticate gets a clean refusal.
		return []string{sasl.Plain, sasl.Login}
	}
	return []string{sasl.Plain, sasl.Login}
}

func (s *session) Auth(mech string) (sasl.Server, error) {
	authenticate := func(username, password string) error {
		if s.sink.opts.Username == "" {
			return &smtp.SMTPError{Code: 503, Message: "this sink requires no authentication"}
		}
		if username != s.sink.opts.Username || password != s.sink.opts.Password {
			return &smtp.SMTPError{Code: 535, Message: "authentication credentials invalid"}
		}
		s.username = username
		return nil
	}

	switch strings.ToUpper(mech) {
	case sasl.Plain:
		return sasl.NewPlainServer(func(identity, username, password string) error {
			return authenticate(username, password)
		}), nil
	case sasl.Login:
		return &loginServer{authenticate: authenticate}, nil
	default:
		return nil, &smtp.SMTPError{Code: 504, Message: "unsupported authentication mechanism"}
	}
}

// loginServer implements the obsolete AUTH LOGIN exchange.
//
// go-sasl dropped its server-side LOGIN implementation as deprecated, and it is
// right to: PLAIN over TLS is strictly better. But some relays still only offer
// LOGIN, so the sender supports it — and an untested fallback is a fallback that
// does not work.
//
// The exchange follows what go-sasl's client actually does: it sends the username
// as its initial response, then expects the challenge to be exactly "Password:".
// Asking for the username first, as the original draft describes, makes that
// client fail with "unexpected server challenge".
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

func (s *session) Mail(from string, _ *smtp.MailOptions) error {
	if s.sink.opts.Username != "" && s.username == "" {
		return &smtp.SMTPError{Code: 530, Message: "authentication required"}
	}
	if code := s.sink.opts.RejectMailFrom; code != 0 {
		return &smtp.SMTPError{Code: code, Message: "sender refused by the sink"}
	}
	s.from = from
	return nil
}

func (s *session) Rcpt(to string, _ *smtp.RcptOptions) error {
	if code, rejected := s.sink.opts.RejectRecipients[to]; rejected {
		return &smtp.SMTPError{Code: code, Message: "recipient refused by the sink"}
	}
	s.recipients = append(s.recipients, to)
	return nil
}

func (s *session) Data(r io.Reader) error {
	// The reader must be drained even on refusal, or the client blocks writing.
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	if s.sink.opts.DataDelay > 0 {
		time.Sleep(s.sink.opts.DataDelay)
	}
	if code := s.sink.opts.RejectData; code != 0 {
		return &smtp.SMTPError{Code: code, Message: "message refused by the sink"}
	}

	_, overTLS := s.conn.TLSConnectionState()
	s.sink.record(Message{
		From:            s.from,
		Recipients:      append([]string(nil), s.recipients...),
		Data:            data,
		AuthenticatedAs: s.username,
		OverTLS:         overTLS,
	})
	return nil
}

func (s *session) Reset() {
	s.from = ""
	s.recipients = nil
}

func (s *session) Logout() error { return nil }
