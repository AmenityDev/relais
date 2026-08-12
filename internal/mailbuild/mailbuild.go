// Package mailbuild assembles an RFC 5322 message from the REST API's JSON
// payload.
//
// It is the only place in relais that constructs MIME. The SMTP façade never
// comes here: it receives a message that already exists and must be relayed
// unchanged (see internal/mailnorm). Both paths converge afterwards, on the same
// bytes, in internal/ingest.
//
// Structure produced, depending on what the caller supplied:
//
//	text only                     text/plain
//	html only                     text/html
//	both                          multipart/alternative
//	any of the above + files      multipart/mixed
//
// Encoding, boundary generation and RFC 2047 header encoding are left to
// go-message: hand-rolled MIME is where subtle interoperability bugs live.
package mailbuild

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/mail"
	"strings"
	"time"

	gomail "github.com/emersion/go-message/mail"

	"github.com/amenitydev/relais/internal/frompattern"
)

// Error is a validation failure, carrying a stable machine code so the API layer
// can map it to a response without string matching.
type Error struct {
	Code  string
	Field string
	msg   string
}

func (e *Error) Error() string { return e.msg }

// Validation codes.
const (
	CodeInvalidFrom       = "invalid_from"
	CodeMissingRecipients = "missing_recipients"
	CodeInvalidRecipient  = "invalid_recipient"
	CodeTooManyRecipients = "too_many_recipients"
	CodeMissingBody       = "missing_body"
	CodeInvalidHeader     = "invalid_header"
	CodeInvalidAttachment = "invalid_attachment"
	CodeTooLarge          = "message_too_large"
)

func newError(code, field, format string, args ...any) *Error {
	return &Error{Code: code, Field: field, msg: fmt.Sprintf(format, args...)}
}

// NewError builds a validation error carrying this package's codes.
//
// It exists so that a caller doing work on mailbuild's behalf — the REST handler
// decoding base64 attachments, for instance — reports the failure in the same
// shape as everything else, instead of inventing a second error contract that the
// response writer would have to know about separately.
func NewError(code, field, format string, args ...any) *Error {
	return newError(code, field, format, args...)
}

// CodeOf returns the validation code carried by err, or "".
func CodeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// FieldOf returns the offending field name, or "".
func FieldOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Field
	}
	return ""
}

// Attachment is a file to attach. Content is the decoded bytes: base64 decoding
// belongs to the API layer, which is where a malformed payload should be
// reported.
type Attachment struct {
	Filename    string
	ContentType string
	Content     []byte
	// ContentID, when set, marks the part as inline and gives it a Content-ID so
	// an HTML body can reference it with cid:.
	ContentID string
}

// Input is the message to build. Field names mirror the REST payload.
type Input struct {
	// From may carry a display name ("App <no-reply@example.com>").
	From string
	To   []string
	Cc   []string
	// Bcc addresses are carried in the envelope only. No Bcc header is ever
	// written: see Build.
	Bcc     []string
	ReplyTo []string

	Subject string
	Text    string
	HTML    string

	// Headers are extra custom headers. A curated set of headers that relais or
	// MIME owns is refused, so a caller cannot forge a sender or corrupt the
	// structure.
	Headers map[string]string

	Attachments []Attachment
}

// Options bounds the result.
type Options struct {
	MaxRecipients int
	MaxBytes      int64
	// Now is injectable for deterministic tests.
	Now func() time.Time
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// Result is the assembled message plus the normalized addresses that went into
// it.
type Result struct {
	Raw []byte

	// From is the normalized sender, already validated.
	From frompattern.Address
	// To and Cc are the normalized header recipients.
	To []string
	Cc []string
	// Bcc is normalized but appears in no header.
	Bcc []string
	// Envelope is the deduplicated union of To, Cc and Bcc: exactly the list to
	// use for RCPT TO.
	Envelope []string
	Subject  string
}

// reservedHeaders are the fields a caller may not set.
//
// Some are refused because relais or MIME owns them and a caller-supplied value
// would either be ignored or break the message (Content-*, MIME-Version). The
// address fields are refused because they have dedicated payload fields, and
// accepting a second source for the sender would create exactly the
// two-values-one-meaning ambiguity that sender validation exists to prevent.
var reservedHeaders = map[string]string{
	"from":                      "use the from field",
	"to":                        "use the to field",
	"cc":                        "use the cc field",
	"bcc":                       "use the bcc field: a Bcc header is never written",
	"reply-to":                  "use the reply_to field",
	"subject":                   "use the subject field",
	"sender":                    "not accepted: it would contradict the validated sender",
	"return-path":               "set by the relay, not by the client",
	"mime-version":              "set by relais",
	"content-type":              "determined by the body and attachments",
	"content-transfer-encoding": "determined by relais",
	"content-disposition":       "determined by relais",
	"bcc-recipients":            "not a real header",
}

// Build assembles the message.
//
// No Bcc header is written, ever. Blind recipients travel in the envelope only,
// which is what makes them blind; writing the header and stripping it later
// would work too, but leaving it out means there is no window in which the
// addresses exist in the outgoing bytes.
func Build(in Input, opts Options) (Result, error) {
	res := Result{}

	from, fromAddress, err := parseSender(in.From)
	if err != nil {
		return Result{}, err
	}
	res.From = fromAddress

	to, err := parseAddressList(in.To, "to")
	if err != nil {
		return Result{}, err
	}
	cc, err := parseAddressList(in.Cc, "cc")
	if err != nil {
		return Result{}, err
	}
	bcc, err := parseAddressList(in.Bcc, "bcc")
	if err != nil {
		return Result{}, err
	}
	replyTo, err := parseAddressList(in.ReplyTo, "reply_to")
	if err != nil {
		return Result{}, err
	}

	res.To = addressStrings(to)
	res.Cc = addressStrings(cc)
	res.Bcc = addressStrings(bcc)
	res.Envelope = dedupe(res.To, res.Cc, res.Bcc)

	if len(res.Envelope) == 0 {
		return Result{}, newError(CodeMissingRecipients, "to", "at least one recipient is required")
	}
	if opts.MaxRecipients > 0 && len(res.Envelope) > opts.MaxRecipients {
		// Failing here yields a clear error instead of an opaque 5xx from the
		// relay several seconds later.
		return Result{}, newError(CodeTooManyRecipients, "to",
			"%d recipients, over the limit of %d", len(res.Envelope), opts.MaxRecipients)
	}

	if strings.TrimSpace(in.Text) == "" && strings.TrimSpace(in.HTML) == "" {
		return Result{}, newError(CodeMissingBody, "text", "either text or html is required")
	}

	if err := validateHeaders(in.Headers); err != nil {
		return Result{}, err
	}
	if err := validateAttachments(in.Attachments); err != nil {
		return Result{}, err
	}

	res.Subject = in.Subject

	var header gomail.Header
	header.SetAddressList("From", []*gomail.Address{from})
	if len(to) > 0 {
		header.SetAddressList("To", to)
	}
	if len(cc) > 0 {
		header.SetAddressList("Cc", cc)
	}
	if len(replyTo) > 0 {
		header.SetAddressList("Reply-To", replyTo)
	}
	header.SetSubject(in.Subject)
	header.SetDate(opts.now())
	// The Message-ID is generated downstream by mailnorm, so that a message
	// arriving over SMTP and one built here get theirs from the same code.

	for key, value := range in.Headers {
		// Field names are plain ASCII (validateHeaders enforced it); values may
		// hold anything, so a non-ASCII one is RFC 2047 encoded rather than
		// emitted as raw 8-bit, which not every relay tolerates in a header.
		header.Set(key, encodeHeaderValue(value))
	}

	raw, err := writeMessage(header, in)
	if err != nil {
		return Result{}, err
	}
	if opts.MaxBytes > 0 && int64(len(raw)) > opts.MaxBytes {
		return Result{}, newError(CodeTooLarge, "attachments",
			"the assembled message is %d bytes, over the %d byte limit", len(raw), opts.MaxBytes)
	}
	res.Raw = raw
	return res, nil
}

// writeMessage picks the MIME structure and writes it.
func writeMessage(header gomail.Header, in Input) ([]byte, error) {
	var buf bytes.Buffer

	hasText := strings.TrimSpace(in.Text) != ""
	hasHTML := strings.TrimSpace(in.HTML) != ""

	// With no attachments and a single body, a flat single-part message is both
	// smaller and what every client renders best. Wrapping it in a multipart
	// would be needless ceremony.
	if len(in.Attachments) == 0 && (hasText != hasHTML) {
		// CreateSingleInlineWriter writes the header it is given verbatim, so the
		// content type has to go on the top-level header here.
		body, contentType := in.Text, "text/plain"
		if hasHTML {
			body, contentType = in.HTML, "text/html"
		}
		header.SetContentType(contentType, map[string]string{"charset": "utf-8"})

		writer, err := gomail.CreateSingleInlineWriter(&buf, header)
		if err != nil {
			return nil, fmt.Errorf("create message writer: %w", err)
		}
		if _, err := io.WriteString(writer, body); err != nil {
			return nil, fmt.Errorf("write body: %w", err)
		}
		if err := writer.Close(); err != nil {
			return nil, fmt.Errorf("close message writer: %w", err)
		}
		return buf.Bytes(), nil
	}

	writer, err := gomail.CreateWriter(&buf, header)
	if err != nil {
		return nil, fmt.Errorf("create message writer: %w", err)
	}

	if err := writeBodyParts(writer, in, hasText, hasHTML); err != nil {
		return nil, err
	}
	for _, attachment := range in.Attachments {
		if err := writeAttachment(writer, attachment); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("close message writer: %w", err)
	}
	return buf.Bytes(), nil
}

// writeBodyParts writes the human-readable body, as multipart/alternative when
// both representations are present.
func writeBodyParts(writer *gomail.Writer, in Input, hasText, hasHTML bool) error {
	inline, err := writer.CreateInline()
	if err != nil {
		return fmt.Errorf("create inline part: %w", err)
	}

	// Plain text first: multipart/alternative orders parts from least to most
	// preferred, so a text-only client picks the plain part and a rich client the
	// HTML one.
	if hasText {
		if err := writePart(inline, "text/plain", in.Text); err != nil {
			return err
		}
	}
	if hasHTML {
		if err := writePart(inline, "text/html", in.HTML); err != nil {
			return err
		}
	}
	if err := inline.Close(); err != nil {
		return fmt.Errorf("close inline part: %w", err)
	}
	return nil
}

func writePart(inline *gomail.InlineWriter, contentType, body string) error {
	var header gomail.InlineHeader
	header.SetContentType(contentType, map[string]string{"charset": "utf-8"})

	part, err := inline.CreatePart(header)
	if err != nil {
		return fmt.Errorf("create %s part: %w", contentType, err)
	}
	if _, err := io.WriteString(part, body); err != nil {
		return fmt.Errorf("write %s part: %w", contentType, err)
	}
	if err := part.Close(); err != nil {
		return fmt.Errorf("close %s part: %w", contentType, err)
	}
	return nil
}

func writeAttachment(writer *gomail.Writer, attachment Attachment) error {
	contentType := strings.TrimSpace(attachment.ContentType)
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	part, err := createAttachmentPart(writer, attachment, contentType)
	if err != nil {
		return err
	}
	if _, err := part.Write(attachment.Content); err != nil {
		return fmt.Errorf("write attachment %q: %w", attachment.Filename, err)
	}
	if err := part.Close(); err != nil {
		return fmt.Errorf("close attachment %q: %w", attachment.Filename, err)
	}
	return nil
}

// createAttachmentPart makes either a downloadable attachment or an inline part.
//
// The inline case has to go through CreateSingleInline rather than
// CreateAttachment, because go-message forces Content-Disposition to
// "attachment" on the latter, and a part marked as an attachment is not resolved
// as a cid: target by every client.
//
// Known limitation: inline parts sit directly under multipart/mixed rather than
// in a multipart/related sub-tree, which is the structurally correct form.
// go-message's mail writer does not expose multipart/related, and mainstream
// clients resolve cid: references at the mixed level, so this is good enough for
// v1. Building the related tree by hand would mean writing MIME by hand, which
// is a worse trade.
func createAttachmentPart(writer *gomail.Writer, attachment Attachment, contentType string) (io.WriteCloser, error) {
	if attachment.ContentID == "" {
		var header gomail.AttachmentHeader
		header.SetContentType(contentType, nil)
		header.SetFilename(attachment.Filename)

		part, err := writer.CreateAttachment(header)
		if err != nil {
			return nil, fmt.Errorf("create attachment %q: %w", attachment.Filename, err)
		}
		return part, nil
	}

	var header gomail.InlineHeader
	// The filename goes in the Content-Type "name" parameter: go-message
	// overwrites Content-Disposition on an inline part, so it cannot live there.
	header.SetContentType(contentType, map[string]string{"name": attachment.Filename})
	header.Set("Content-Id", "<"+strings.Trim(attachment.ContentID, "<>")+">")
	// Set explicitly so binary content is never quoted-printable encoded; the
	// library only defaults on an absent value.
	header.Set("Content-Transfer-Encoding", "base64")

	part, err := writer.CreateSingleInline(header)
	if err != nil {
		return nil, fmt.Errorf("create inline part %q: %w", attachment.Filename, err)
	}
	return part, nil
}

// parseSender validates the From field, returning both the display form to write
// and the normalized address to authorise against.
func parseSender(value string) (*gomail.Address, frompattern.Address, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, frompattern.Address{}, newError(CodeInvalidFrom, "from", "from is required")
	}

	parsed, err := mail.ParseAddress(trimmed)
	if err != nil {
		return nil, frompattern.Address{}, newError(CodeInvalidFrom, "from", "from is not a valid address: %v", err)
	}
	normalized, err := frompattern.ParseAddress(parsed.Address)
	if err != nil {
		return nil, frompattern.Address{}, newError(CodeInvalidFrom, "from", "from is not usable: %v", err)
	}

	return &gomail.Address{Name: parsed.Name, Address: normalized.String()}, normalized, nil
}

func parseAddressList(values []string, field string) ([]*gomail.Address, error) {
	out := make([]*gomail.Address, 0, len(values))
	for i, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			return nil, newError(CodeInvalidRecipient, field, "%s[%d] is empty", field, i)
		}
		parsed, err := mail.ParseAddress(trimmed)
		if err != nil {
			return nil, newError(CodeInvalidRecipient, field, "%s[%d] (%q) is not a valid address: %v", field, i, trimmed, err)
		}
		normalized, err := frompattern.ParseAddress(parsed.Address)
		if err != nil {
			return nil, newError(CodeInvalidRecipient, field, "%s[%d] (%q) is not usable: %v", field, i, trimmed, err)
		}
		out = append(out, &gomail.Address{Name: parsed.Name, Address: normalized.String()})
	}
	return out, nil
}

func validateHeaders(headers map[string]string) error {
	for key, value := range headers {
		trimmed := strings.TrimSpace(key)
		if trimmed == "" {
			return newError(CodeInvalidHeader, "headers", "a header name is empty")
		}
		if reason, reserved := reservedHeaders[strings.ToLower(trimmed)]; reserved {
			return newError(CodeInvalidHeader, "headers", "the %s header cannot be set: %s", trimmed, reason)
		}
		for _, r := range trimmed {
			// RFC 5322 field names are printable ASCII without colon or space.
			if r <= ' ' || r >= 0x7f || r == ':' {
				return newError(CodeInvalidHeader, "headers", "the header name %q contains an invalid character", trimmed)
			}
		}
		// A newline in a value is header injection: it would let a caller append
		// arbitrary headers, or a whole second message.
		if strings.ContainsAny(value, "\r\n") {
			return newError(CodeInvalidHeader, "headers", "the value of %s contains a line break", trimmed)
		}
	}
	return nil
}

func validateAttachments(attachments []Attachment) error {
	for i, attachment := range attachments {
		filename := strings.TrimSpace(attachment.Filename)
		switch {
		case filename == "":
			return newError(CodeInvalidAttachment, "attachments", "attachments[%d] has no filename", i)
		case strings.ContainsAny(filename, "\r\n"):
			return newError(CodeInvalidAttachment, "attachments", "attachments[%d] has a line break in its filename", i)
		case strings.ContainsAny(filename, `/\`):
			// A path would be meaningless in a MIME part and is a classic
			// path-traversal vector for whatever saves the file at the far end.
			return newError(CodeInvalidAttachment, "attachments", "attachments[%d] filename must not contain a path separator", i)
		case len(attachment.Content) == 0:
			return newError(CodeInvalidAttachment, "attachments", "attachments[%d] (%s) is empty", i, filename)
		case strings.ContainsAny(attachment.ContentType, "\r\n"):
			return newError(CodeInvalidAttachment, "attachments", "attachments[%d] has a line break in its content type", i)
		}
	}
	return nil
}

// encodeHeaderValue RFC 2047 encodes a value that is not plain ASCII, and leaves
// an ASCII value untouched so the common case stays readable on the wire.
func encodeHeaderValue(value string) string {
	for i := 0; i < len(value); i++ {
		if value[i] >= 0x80 {
			return mime.QEncoding.Encode("utf-8", value)
		}
	}
	return value
}

func addressStrings(addrs []*gomail.Address) []string {
	if len(addrs) == 0 {
		return nil
	}
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		out = append(out, addr.Address)
	}
	return out
}

// dedupe merges recipient lists, preserving order and dropping repeats.
//
// A duplicate would otherwise become a duplicate RCPT TO, which some relays
// count twice against a quota and which delivers the message twice.
func dedupe(lists ...[]string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, 8)
	for _, list := range lists {
		for _, addr := range list {
			if _, dup := seen[addr]; dup {
				continue
			}
			seen[addr] = struct{}{}
			out = append(out, addr)
		}
	}
	return out
}
