package mailbuild

import (
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
	"time"
)

func testOptions() Options {
	return Options{
		MaxRecipients: 50,
		MaxBytes:      10 << 20,
		Now:           func() time.Time { return time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC) },
	}
}

func minimalInput() Input {
	return Input{
		From:    "App <no-reply@example.com>",
		To:      []string{"someone@elsewhere.test"},
		Subject: "Hello",
		Text:    "Plain body.",
	}
}

// parseResult reads the assembled message back with the standard library, which
// is the closest available stand-in for "would a real client understand this?".
func parseResult(t *testing.T, raw []byte) *mail.Message {
	t.Helper()
	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("the assembled message does not parse: %v\n%s", err, raw)
	}
	return msg
}

func TestBuildTextOnlyIsSinglePart(t *testing.T) {
	res, err := Build(minimalInput(), testOptions())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	msg := parseResult(t, res.Raw)
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("Content-Type: %v", err)
	}
	// A single body needs no multipart wrapper.
	if mediaType != "text/plain" {
		t.Fatalf("Content-Type = %q, want text/plain", mediaType)
	}
	if params["charset"] != "utf-8" {
		t.Fatalf("charset = %q, want utf-8", params["charset"])
	}

	body, err := io.ReadAll(msg.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(string(body), "Plain body.") {
		t.Fatalf("body = %q", body)
	}

	if got := msg.Header.Get("From"); !strings.Contains(got, "no-reply@example.com") {
		t.Fatalf("From = %q", got)
	}
	if got := msg.Header.Get("Subject"); got != "Hello" {
		t.Fatalf("Subject = %q", got)
	}
	// The Message-ID is generated later, by mailnorm, so both façades get theirs
	// from the same place.
	if got := msg.Header.Get("Message-Id"); got != "" {
		t.Fatalf("Message-Id = %q, want it left for mailnorm", got)
	}

	if res.From.String() != "no-reply@example.com" {
		t.Fatalf("normalized From = %q", res.From)
	}
	if len(res.Envelope) != 1 || res.Envelope[0] != "someone@elsewhere.test" {
		t.Fatalf("Envelope = %v", res.Envelope)
	}
}

func TestBuildHTMLOnlyIsSinglePart(t *testing.T) {
	in := minimalInput()
	in.Text = ""
	in.HTML = "<p>Rich body.</p>"

	res, err := Build(in, testOptions())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	msg := parseResult(t, res.Raw)
	mediaType, _, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("Content-Type: %v", err)
	}
	if mediaType != "text/html" {
		t.Fatalf("Content-Type = %q, want text/html", mediaType)
	}
}

// Both representations means multipart/alternative, with plain text first so a
// text-only client picks it and a rich client picks the HTML.
func TestBuildBothBodiesIsAlternative(t *testing.T) {
	in := minimalInput()
	in.HTML = "<p>Rich body.</p>"

	res, err := Build(in, testOptions())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	parts := readParts(t, res.Raw)
	if len(parts) != 2 {
		t.Fatalf("%d parts, want 2: %v", len(parts), partTypes(parts))
	}
	if parts[0].mediaType != "text/plain" {
		t.Fatalf("first part is %q, want text/plain (alternative orders least to most preferred)", parts[0].mediaType)
	}
	if parts[1].mediaType != "text/html" {
		t.Fatalf("second part is %q, want text/html", parts[1].mediaType)
	}
	if !strings.Contains(parts[0].body, "Plain body.") {
		t.Fatalf("plain part = %q", parts[0].body)
	}
	if !strings.Contains(parts[1].body, "Rich body.") {
		t.Fatalf("html part = %q", parts[1].body)
	}
}

func TestBuildWithAttachment(t *testing.T) {
	in := minimalInput()
	in.Attachments = []Attachment{{
		Filename:    "facture.pdf",
		ContentType: "application/pdf",
		Content:     []byte("%PDF-1.7\nnot really a pdf\n"),
	}}

	res, err := Build(in, testOptions())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	msg := parseResult(t, res.Raw)
	mediaType, _, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("Content-Type: %v", err)
	}
	if mediaType != "multipart/mixed" {
		t.Fatalf("Content-Type = %q, want multipart/mixed", mediaType)
	}

	parts := readParts(t, res.Raw)
	if len(parts) != 2 {
		t.Fatalf("%d top-level parts, want 2: %v", len(parts), partTypes(parts))
	}
	if parts[1].mediaType != "application/pdf" {
		t.Fatalf("attachment part is %q, want application/pdf", parts[1].mediaType)
	}
	if !strings.Contains(parts[1].disposition, "attachment") {
		t.Fatalf("Content-Disposition = %q, want an attachment", parts[1].disposition)
	}
	if !strings.Contains(parts[1].disposition, "facture.pdf") {
		t.Fatalf("the filename is missing from %q", parts[1].disposition)
	}
	// The bytes must survive base64 encoding intact.
	if parts[1].body != "%PDF-1.7\nnot really a pdf\n" {
		t.Fatalf("attachment content = %q", parts[1].body)
	}
}

func TestBuildAttachmentDefaultsContentType(t *testing.T) {
	in := minimalInput()
	in.Attachments = []Attachment{{Filename: "data.bin", Content: []byte{0x00, 0x01, 0xff}}}

	res, err := Build(in, testOptions())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	parts := readParts(t, res.Raw)
	if got := parts[len(parts)-1].mediaType; got != "application/octet-stream" {
		t.Fatalf("Content-Type = %q, want application/octet-stream", got)
	}
	if parts[len(parts)-1].body != "\x00\x01\xff" {
		t.Fatalf("binary content was altered: %q", parts[len(parts)-1].body)
	}
}

func TestBuildInlineAttachmentGetsContentID(t *testing.T) {
	in := minimalInput()
	in.Text = ""
	in.HTML = `<p><img src="cid:logo"></p>`
	in.Attachments = []Attachment{{
		Filename:    "logo.png",
		ContentType: "image/png",
		Content:     []byte("PNG"),
		ContentID:   "logo",
	}}

	res, err := Build(in, testOptions())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	parts := readParts(t, res.Raw)
	last := parts[len(parts)-1]
	if last.contentID != "<logo>" {
		t.Fatalf("Content-ID = %q, want <logo>", last.contentID)
	}
	if !strings.Contains(last.disposition, "inline") {
		t.Fatalf("Content-Disposition = %q, want inline", last.disposition)
	}
}

// Bcc must never appear in the outgoing bytes. It travels in the envelope only,
// which is what makes a blind copy blind.
func TestBuildNeverWritesBcc(t *testing.T) {
	in := minimalInput()
	in.Cc = []string{"visible@elsewhere.test"}
	in.Bcc = []string{"hidden@elsewhere.test", "Secret <secret@elsewhere.test>"}

	res, err := Build(in, testOptions())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	out := string(res.Raw)
	if strings.Contains(strings.ToLower(out), "bcc") {
		t.Fatalf("a Bcc header was written:\n%s", out)
	}
	for _, hidden := range []string{"hidden@elsewhere.test", "secret@elsewhere.test"} {
		if strings.Contains(out, hidden) {
			t.Fatalf("the blind recipient %s appears in the message:\n%s", hidden, out)
		}
	}

	// ...but it must be in the envelope, or it would never be delivered.
	if len(res.Envelope) != 4 {
		t.Fatalf("Envelope = %v, want all four recipients", res.Envelope)
	}
	if res.Envelope[0] != "someone@elsewhere.test" || res.Envelope[1] != "visible@elsewhere.test" {
		t.Fatalf("Envelope order = %v, want to then cc then bcc", res.Envelope)
	}
	if len(res.Bcc) != 2 {
		t.Fatalf("Bcc = %v", res.Bcc)
	}
	// The Cc header is visible, unlike Bcc.
	if !strings.Contains(out, "visible@elsewhere.test") {
		t.Fatal("the Cc recipient is missing from the headers")
	}
}

// A duplicate recipient would become a duplicate RCPT TO: some relays count it
// twice against a quota, and the recipient receives the message twice.
func TestBuildDeduplicatesEnvelope(t *testing.T) {
	in := minimalInput()
	in.To = []string{"a@elsewhere.test", "A@Elsewhere.test"}
	in.Cc = []string{"a@elsewhere.test", "b@elsewhere.test"}
	in.Bcc = []string{"B@elsewhere.test"}

	res, err := Build(in, testOptions())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(res.Envelope) != 2 {
		t.Fatalf("Envelope = %v, want 2 unique recipients", res.Envelope)
	}
}

func TestBuildNormalizesAddresses(t *testing.T) {
	in := minimalInput()
	in.From = "  App <No-Reply@Example.COM>  "
	in.To = []string{"Someone <SOMEONE@Elsewhere.TEST>"}
	in.ReplyTo = []string{"support@example.com"}

	res, err := Build(in, testOptions())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if res.From.String() != "no-reply@example.com" {
		t.Fatalf("From = %q", res.From)
	}
	if res.To[0] != "someone@elsewhere.test" {
		t.Fatalf("To = %v", res.To)
	}

	msg := parseResult(t, res.Raw)
	// The display name survives, since that is what a recipient sees.
	if got := msg.Header.Get("From"); !strings.Contains(got, "App") {
		t.Fatalf("From = %q, want the display name kept", got)
	}
	if got := msg.Header.Get("Reply-To"); !strings.Contains(got, "support@example.com") {
		t.Fatalf("Reply-To = %q", got)
	}
}

func TestBuildCustomHeaders(t *testing.T) {
	in := minimalInput()
	in.Headers = map[string]string{
		"X-Entity-Ref-Id": "abc-123",
		"X-Priority":      "3",
	}

	res, err := Build(in, testOptions())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	msg := parseResult(t, res.Raw)
	if got := msg.Header.Get("X-Entity-Ref-Id"); got != "abc-123" {
		t.Fatalf("X-Entity-Ref-Id = %q", got)
	}
	if got := msg.Header.Get("X-Priority"); got != "3" {
		t.Fatalf("X-Priority = %q", got)
	}
}

func TestBuildEncodesNonASCIIHeaderValue(t *testing.T) {
	in := minimalInput()
	in.Subject = "Café à la crème"
	in.Headers = map[string]string{"X-Note": "déjà vu"}

	res, err := Build(in, testOptions())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	out := string(res.Raw)
	// Raw 8-bit in a header is not universally accepted; both values must be
	// RFC 2047 encoded.
	if strings.Contains(out, "Café à la crème") {
		t.Fatalf("the subject was emitted as raw 8-bit:\n%s", out)
	}
	if strings.Contains(out, "déjà vu") {
		t.Fatalf("a custom header value was emitted as raw 8-bit:\n%s", out)
	}

	msg := parseResult(t, res.Raw)
	decoder := new(mime.WordDecoder)
	subject, err := decoder.DecodeHeader(msg.Header.Get("Subject"))
	if err != nil {
		t.Fatalf("decode Subject: %v", err)
	}
	if subject != "Café à la crème" {
		t.Fatalf("decoded Subject = %q", subject)
	}
	note, err := decoder.DecodeHeader(msg.Header.Get("X-Note"))
	if err != nil {
		t.Fatalf("decode X-Note: %v", err)
	}
	if note != "déjà vu" {
		t.Fatalf("decoded X-Note = %q", note)
	}
}

// Accepting a caller-supplied From, Sender or Content-Type would create a second
// source of truth for something relais validates or owns.
func TestBuildRejectsReservedHeaders(t *testing.T) {
	reserved := []string{
		"From", "from", "To", "Cc", "Bcc", "Reply-To", "Subject", "Sender",
		"Return-Path", "MIME-Version", "Content-Type", "Content-Transfer-Encoding",
	}
	for _, name := range reserved {
		t.Run(name, func(t *testing.T) {
			in := minimalInput()
			in.Headers = map[string]string{name: "attacker@evil.test"}
			_, err := Build(in, testOptions())
			if err == nil {
				t.Fatalf("Build accepted a caller-supplied %s header", name)
			}
			if CodeOf(err) != CodeInvalidHeader {
				t.Fatalf("code = %q, want %q", CodeOf(err), CodeInvalidHeader)
			}
		})
	}
}

// A line break in a header value is header injection: it would let a caller
// append arbitrary headers, or an entire second message.
func TestBuildRejectsHeaderInjection(t *testing.T) {
	injections := map[string]string{
		"CRLF then header": "value\r\nX-Injected: yes",
		"LF then header":   "value\nX-Injected: yes",
		"CR only":          "value\rX-Injected: yes",
		"body injection":   "value\r\n\r\nInjected body",
	}
	for name, value := range injections {
		t.Run(name, func(t *testing.T) {
			in := minimalInput()
			in.Headers = map[string]string{"X-Custom": value}
			_, err := Build(in, testOptions())
			if err == nil {
				t.Fatalf("Build accepted a header value containing a line break")
			}
			if CodeOf(err) != CodeInvalidHeader {
				t.Fatalf("code = %q, want %q", CodeOf(err), CodeInvalidHeader)
			}
		})
	}

	// A subject with a newline must not inject either; go-message encodes it, so
	// the assertion is that nothing appears as a new header.
	in := minimalInput()
	in.Subject = "Legit\r\nX-Injected: yes"
	res, err := Build(in, testOptions())
	if err == nil {
		msg := parseResult(t, res.Raw)
		if msg.Header.Get("X-Injected") != "" {
			t.Fatalf("a newline in the subject injected a header:\n%s", res.Raw)
		}
	}
}

func TestBuildRejectsBadInput(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*Input)
		wantCode  string
		wantField string
	}{
		{"no from", func(in *Input) { in.From = "" }, CodeInvalidFrom, "from"},
		{"unparsable from", func(in *Input) { in.From = "not an address" }, CodeInvalidFrom, "from"},
		{"from with single-label domain", func(in *Input) { in.From = "a@localhost" }, CodeInvalidFrom, "from"},
		{"two addresses in from", func(in *Input) { in.From = "a@example.com, b@example.com" }, CodeInvalidFrom, "from"},
		{"no recipients", func(in *Input) { in.To = nil }, CodeMissingRecipients, "to"},
		{"empty recipient", func(in *Input) { in.To = []string{""} }, CodeInvalidRecipient, "to"},
		{"unparsable recipient", func(in *Input) { in.To = []string{"@@@"} }, CodeInvalidRecipient, "to"},
		{"unparsable cc", func(in *Input) { in.Cc = []string{"nope"} }, CodeInvalidRecipient, "cc"},
		{"no body", func(in *Input) { in.Text = ""; in.HTML = "" }, CodeMissingBody, "text"},
		{"blank body", func(in *Input) { in.Text = "   \n  " }, CodeMissingBody, "text"},
		{"empty header name", func(in *Input) { in.Headers = map[string]string{" ": "v"} }, CodeInvalidHeader, "headers"},
		{"header name with colon", func(in *Input) { in.Headers = map[string]string{"X:Y": "v"} }, CodeInvalidHeader, "headers"},
		{"attachment without filename", func(in *Input) {
			in.Attachments = []Attachment{{Content: []byte("x")}}
		}, CodeInvalidAttachment, "attachments"},
		{"attachment with a path", func(in *Input) {
			in.Attachments = []Attachment{{Filename: "../../etc/passwd", Content: []byte("x")}}
		}, CodeInvalidAttachment, "attachments"},
		{"empty attachment", func(in *Input) {
			in.Attachments = []Attachment{{Filename: "empty.txt"}}
		}, CodeInvalidAttachment, "attachments"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := minimalInput()
			tc.mutate(&in)
			_, err := Build(in, testOptions())
			if err == nil {
				t.Fatal("Build accepted invalid input")
			}
			if got := CodeOf(err); got != tc.wantCode {
				t.Fatalf("code = %q, want %q (%v)", got, tc.wantCode, err)
			}
			if got := FieldOf(err); got != tc.wantField {
				t.Fatalf("field = %q, want %q", got, tc.wantField)
			}
		})
	}
}

func TestBuildEnforcesLimits(t *testing.T) {
	t.Run("too many recipients", func(t *testing.T) {
		in := minimalInput()
		in.To = nil
		for i := range 10 {
			in.To = append(in.To, string(rune('a'+i))+"@elsewhere.test")
		}
		opts := testOptions()
		opts.MaxRecipients = 5

		_, err := Build(in, opts)
		if CodeOf(err) != CodeTooManyRecipients {
			t.Fatalf("code = %q, want %q", CodeOf(err), CodeTooManyRecipients)
		}
	})

	t.Run("too large", func(t *testing.T) {
		in := minimalInput()
		in.Attachments = []Attachment{{
			Filename: "big.bin",
			Content:  make([]byte, 100_000),
		}}
		opts := testOptions()
		opts.MaxBytes = 10_000

		_, err := Build(in, opts)
		if CodeOf(err) != CodeTooLarge {
			t.Fatalf("code = %q, want %q", CodeOf(err), CodeTooLarge)
		}
	})
}

// --- helpers ---------------------------------------------------------------

type part struct {
	mediaType   string
	disposition string
	contentID   string
	body        string
}

func partTypes(parts []part) []string {
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, p.mediaType)
	}
	return out
}

// readParts walks the top level of a multipart message, decoding each part's
// transfer encoding so assertions compare original bytes.
func readParts(t *testing.T, raw []byte) []part {
	t.Helper()

	msg := parseResult(t, raw)
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("Content-Type: %v", err)
	}
	if !strings.HasPrefix(mediaType, "multipart/") {
		t.Fatalf("Content-Type %q is not multipart", mediaType)
	}

	reader := multipart.NewReader(msg.Body, params["boundary"])
	var out []part
	for {
		next, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read part: %v", err)
		}

		partType, partParams, err := mime.ParseMediaType(next.Header.Get("Content-Type"))
		if err != nil {
			t.Fatalf("part Content-Type: %v", err)
		}

		// A nested multipart (the alternative inside a mixed) is flattened into
		// its own parts, since the assertions care about the leaves.
		if strings.HasPrefix(partType, "multipart/") {
			nested := multipart.NewReader(next, partParams["boundary"])
			for {
				leaf, err := nested.NextPart()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("read nested part: %v", err)
				}
				out = append(out, readOnePart(t, leaf))
			}
			continue
		}
		out = append(out, readOnePart(t, next))
	}
	return out
}

func readOnePart(t *testing.T, p *multipart.Part) part {
	t.Helper()

	// multipart.Part decodes quoted-printable transparently but not base64.
	var reader io.Reader = p
	if strings.EqualFold(p.Header.Get("Content-Transfer-Encoding"), "base64") {
		reader = base64Reader(p)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read part body: %v", err)
	}

	mediaType, _, err := mime.ParseMediaType(p.Header.Get("Content-Type"))
	if err != nil {
		mediaType = p.Header.Get("Content-Type")
	}
	return part{
		mediaType:   mediaType,
		disposition: p.Header.Get("Content-Disposition"),
		contentID:   p.Header.Get("Content-Id"),
		body:        string(body),
	}
}

func base64Reader(r io.Reader) io.Reader {
	return base64.NewDecoder(base64.StdEncoding, newlineStripper{r})
}

// newlineStripper drops the line breaks base64 bodies are wrapped at, which the
// standard decoder does not tolerate.
type newlineStripper struct{ r io.Reader }

func (s newlineStripper) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	out := p[:0]
	for _, b := range p[:n] {
		if b != '\r' && b != '\n' {
			out = append(out, b)
		}
	}
	return len(out), err
}
