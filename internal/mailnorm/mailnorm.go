// Package mailnorm inspects and normalizes a submitted RFC 5322 message.
//
// The guiding constraint: the body is never re-encoded. Only the header block is
// rewritten, and the body bytes are copied through verbatim apart from line
// ending normalization, which SMTP requires anyway. A full parse and
// re-serialisation through a MIME library is what breaks messages from legacy
// clients — exotic charsets, borderline transfer encodings, subtly malformed
// multiparts that every real MTA nonetheless delivers. Those messages must pass
// through unharmed; relais only needs to read the sender and fix up a couple of
// missing headers.
package mailnorm

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/mail"
	"strings"
	"time"

	"github.com/emersion/go-message/charset"
	"github.com/emersion/go-message/textproto"
	"github.com/google/uuid"

	"github.com/amenitydev/relais/internal/frompattern"
)

// Error is a parse or validation failure.
//
// Code is a stable machine token. The ingest pipeline stores it verbatim as
// email_message.rejection_reason, so these strings are part of the operational
// contract: renaming one changes what appears in an operator's audit trail.
type Error struct {
	Code string
	msg  string
}

func (e *Error) Error() string { return e.msg }

// Rejection codes.
const (
	CodeEmpty            = "empty_message"
	CodeTooLarge         = "message_too_large"
	CodeMalformedHeaders = "malformed_headers"
	CodeTooManyHeaders   = "too_many_headers"
	CodeHeadersTooLarge  = "headers_too_large"
	CodeNoFrom           = "missing_from"
	CodeMultipleFrom     = "multiple_from"
	CodeInvalidFrom      = "invalid_from"
	CodeNoBody           = "missing_body"
)

func newError(code, format string, args ...any) *Error {
	return &Error{Code: code, msg: fmt.Sprintf(format, args...)}
}

// CodeOf returns the rejection code carried by err, or "" when err is not a
// mailnorm error.
func CodeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// Options bounds and parameterizes parsing.
type Options struct {
	// MaxBytes caps the whole message. Zero means unlimited, which is only
	// appropriate in tests.
	MaxBytes int64
	// MaxHeaderCount and MaxHeaderBytes guard against header stuffing, where a
	// message is technically small but carries thousands of fields.
	MaxHeaderCount int
	MaxHeaderBytes int64

	// Now and NewID are injectable so that generated headers are deterministic
	// under test. Both default to the obvious real implementation.
	Now   func() time.Time
	NewID func() string
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

func (o Options) newID() string {
	if o.NewID != nil {
		return o.NewID()
	}
	return uuid.NewString()
}

// Message is the result of normalizing a submission.
type Message struct {
	// From is the authoritative sender: the addr-spec of the From header. This
	// is what sender-pattern validation runs against.
	From frompattern.Address
	// FromHeader is the raw header value, display name included, kept for the
	// audit trail.
	FromHeader string

	Subject   string
	MessageID string

	// To and Cc are the addresses declared in the headers. They are descriptive:
	// the authoritative delivery list is the envelope, which the caller owns.
	To []string
	Cc []string
	// Bcc holds addresses that were declared in a Bcc header. The header itself
	// is always removed from Raw.
	Bcc []string

	// Raw is the message to relay: normalized headers followed by the original
	// body bytes.
	Raw  []byte
	Size int64

	// What normalization did, for logging and for tests.
	GeneratedMessageID bool
	GeneratedDate      bool
	StrippedBcc        bool
}

// Parse validates a submitted message and returns its normalized form.
//
// Validation is strict about the sender and lenient about everything else: a
// missing or ambiguous From is fatal, because it is the value the whole
// authorisation model rests on, while an odd Content-Type is none of our
// business.
func Parse(raw []byte, opts Options) (Message, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return Message{}, newError(CodeEmpty, "the message is empty")
	}
	if opts.MaxBytes > 0 && int64(len(raw)) > opts.MaxBytes {
		return Message{}, newError(CodeTooLarge, "the message is %d bytes, over the %d byte limit", len(raw), opts.MaxBytes)
	}

	headerBlock, body, err := splitMessage(raw)
	if err != nil {
		return Message{}, err
	}
	if opts.MaxHeaderBytes > 0 && int64(len(headerBlock)) > opts.MaxHeaderBytes {
		return Message{}, newError(CodeHeadersTooLarge, "the header block is %d bytes, over the %d byte limit", len(headerBlock), opts.MaxHeaderBytes)
	}

	// textproto.ReadHeader preserves field order and the original raw bytes of
	// each field, which is what lets us rewrite the block without reflowing
	// continuation lines or re-encoding RFC 2047 words.
	header, err := textproto.ReadHeader(bufio.NewReader(bytes.NewReader(headerBlock)))
	if err != nil {
		return Message{}, newError(CodeMalformedHeaders, "cannot parse the headers: %v", err)
	}
	if opts.MaxHeaderCount > 0 && header.Len() > opts.MaxHeaderCount {
		return Message{}, newError(CodeTooManyHeaders, "the message carries %d header fields, over the %d limit", header.Len(), opts.MaxHeaderCount)
	}

	msg := Message{}

	if err := msg.readFrom(&header); err != nil {
		return Message{}, err
	}
	msg.Subject = decodeHeader(header.Get("Subject"))
	msg.To = addressList(header.Get("To"))
	msg.Cc = addressList(header.Get("Cc"))
	msg.Bcc = addressList(header.Get("Bcc"))

	// A Bcc header must never leave the building: that is the entire point of a
	// blind carbon copy, and RFC 6409 makes removing it the submission server's
	// job. Its addresses stay in Message.Bcc for the audit trail.
	if header.Has("Bcc") {
		header.Del("Bcc")
		msg.StrippedBcc = true
	}

	msg.MessageID = strings.TrimSpace(header.Get("Message-Id"))
	if msg.MessageID == "" {
		msg.MessageID = generateMessageID(opts.newID(), msg.From.Domain)
		header.Set("Message-Id", msg.MessageID)
		msg.GeneratedMessageID = true
	}

	if strings.TrimSpace(header.Get("Date")) == "" {
		header.Set("Date", opts.now().Format(time.RFC1123Z))
		msg.GeneratedDate = true
	}

	assembled, err := assemble(header, body)
	if err != nil {
		return Message{}, err
	}
	// Re-check the size: generated headers grow the message, and the limit must
	// hold for what actually goes out, not only for what came in.
	if opts.MaxBytes > 0 && int64(len(assembled)) > opts.MaxBytes {
		return Message{}, newError(CodeTooLarge, "the normalized message is %d bytes, over the %d byte limit", len(assembled), opts.MaxBytes)
	}

	msg.Raw = assembled
	msg.Size = int64(len(assembled))
	return msg, nil
}

// readFrom extracts and validates the sender.
func (m *Message) readFrom(header *textproto.Header) error {
	values := header.Values("From")
	switch {
	case len(values) == 0:
		return newError(CodeNoFrom, "the message has no From header")
	case len(values) > 1:
		// Two From headers is how a sender-spoofing attempt looks: one address
		// for the validator, another for whatever renders the message.
		return newError(CodeMultipleFrom, "the message has %d From headers", len(values))
	}

	value := strings.TrimSpace(values[0])
	if value == "" {
		return newError(CodeNoFrom, "the From header is empty")
	}

	parsed, err := mail.ParseAddressList(value)
	if err != nil {
		return newError(CodeInvalidFrom, "cannot parse the From header: %v", err)
	}
	switch {
	case len(parsed) == 0:
		// A syntactically valid but empty group ("undisclosed:;") parses fine and
		// yields no address at all. There is nobody to authorise.
		return newError(CodeInvalidFrom, "the From header contains no address")
	case len(parsed) > 1:
		// RFC 5322 permits a list of addresses in From. Allowing it would make
		// "the sender" ambiguous, and every pattern check downstream would have
		// to pick one, so it is refused.
		return newError(CodeMultipleFrom, "the From header lists %d addresses", len(parsed))
	}

	addr, err := frompattern.ParseAddress(parsed[0].Address)
	if err != nil {
		return newError(CodeInvalidFrom, "the From address is not usable: %v", err)
	}

	m.From = addr
	m.FromHeader = value
	return nil
}

// splitMessage separates the header block from the body.
//
// It accepts both CRLF and bare LF separators, because legacy clients send both,
// and returns the header block with a trailing blank line so that
// textproto.ReadHeader sees a complete block.
func splitMessage(raw []byte) (headerBlock, body []byte, err error) {
	// Look for the earliest of the two possible separators rather than trying
	// CRLF first: a message whose headers use bare LF but whose body happens to
	// contain a CRLFCRLF would otherwise be split in the wrong place.
	crlf := bytes.Index(raw, []byte("\r\n\r\n"))
	lf := bytes.Index(raw, []byte("\n\n"))

	switch {
	case crlf >= 0 && (lf < 0 || crlf <= lf):
		return raw[:crlf+2], raw[crlf+4:], nil
	case lf >= 0:
		return raw[:lf+1], raw[lf+2:], nil
	default:
		// No blank line at all: the whole input is headers. That is a valid
		// RFC 5322 message with an empty body, and refusing it would reject
		// legitimate header-only notifications.
		if bytes.HasSuffix(raw, []byte("\n")) {
			return raw, nil, nil
		}
		return append(append([]byte(nil), raw...), '\n'), nil, nil
	}
}

// assemble writes the rewritten header block followed by the untouched body,
// normalizing line endings to CRLF as SMTP requires.
func assemble(header textproto.Header, body []byte) ([]byte, error) {
	var out bytes.Buffer
	out.Grow(len(body) + 1024)

	if err := textproto.WriteHeader(&out, header); err != nil {
		return nil, newError(CodeMalformedHeaders, "cannot write the headers: %v", err)
	}
	// WriteHeader already emits the blank line that ends the block.

	if _, err := out.Write(normalizeCRLF(body)); err != nil {
		return nil, fmt.Errorf("assemble message: %w", err)
	}
	return out.Bytes(), nil
}

// normalizeCRLF rewrites every line ending to CRLF.
//
// SMTP is a CRLF protocol, and a bare LF from a legacy client makes the message
// invalid on the wire. This is the one transformation applied to the body, and
// it is safe for every transfer encoding SMTP allows: 7bit, 8bit,
// quoted-printable and base64 are all line-oriented text. ("binary" is not
// permitted over SMTP, so there is nothing to preserve there.)
//
// It returns the input unchanged when there is nothing to fix, which is the
// common case for messages relais built itself.
func normalizeCRLF(body []byte) []byte {
	if !needsCRLF(body) {
		return body
	}

	out := make([]byte, 0, len(body)+len(body)/16)
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case '\r':
			out = append(out, '\r', '\n')
			// Consume a following LF so CRLF does not become CRLFLF.
			if i+1 < len(body) && body[i+1] == '\n' {
				i++
			}
		case '\n':
			out = append(out, '\r', '\n')
		default:
			out = append(out, body[i])
		}
	}
	return out
}

// needsCRLF reports whether body contains a line ending that is not already
// CRLF, so the common case avoids an allocation and a copy.
func needsCRLF(body []byte) bool {
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case '\n':
			if i == 0 || body[i-1] != '\r' {
				return true
			}
		case '\r':
			if i+1 >= len(body) || body[i+1] != '\n' {
				return true
			}
		}
	}
	return false
}

// generateMessageID builds a Message-ID in the sender's own domain, which is
// what a reader and any downstream tooling expect to see.
func generateMessageID(id, domain string) string {
	if domain == "" {
		domain = "relais.invalid"
	}
	return "<" + id + "@" + domain + ">"
}

// addressList extracts the addr-specs from an address header, skipping anything
// unparsable.
//
// Leniency is correct here: these values are descriptive only. The authoritative
// recipient list is the envelope, which the caller supplies and validates
// separately, so a malformed Cc must not reject an otherwise good message.
func addressList(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	parsed, err := mail.ParseAddressList(value)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(parsed))
	for _, addr := range parsed {
		if normalized, err := frompattern.ParseAddress(addr.Address); err == nil {
			out = append(out, normalized.String())
		}
	}
	return out
}

// wordDecoder decodes RFC 2047 encoded words. go-message's charset reader is
// wired in because the standard library only knows utf-8 and us-ascii, while
// legacy clients still emit ISO-8859-1 and friends.
var wordDecoder = mime.WordDecoder{CharsetReader: charset.Reader}

// decodeHeader decodes RFC 2047 encoded words, falling back to the raw value.
//
// Only used for values relais displays (the subject in the admin UI); the bytes
// that go out are never touched.
func decodeHeader(value string) string {
	decoded, err := wordDecoder.DecodeHeader(value)
	if err != nil {
		return value
	}
	return decoded
}

// ReadAll reads a submission from r, refusing anything over max bytes.
//
// The read is bounded by max+1 so that an oversized message is detected without
// buffering the whole thing, which matters when the limit is the only thing
// standing between a client and the process's memory.
func ReadAll(r io.Reader, max int64) ([]byte, error) {
	if max <= 0 {
		return io.ReadAll(r)
	}
	raw, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > max {
		return nil, newError(CodeTooLarge, "the message exceeds the %d byte limit", max)
	}
	return raw, nil
}
