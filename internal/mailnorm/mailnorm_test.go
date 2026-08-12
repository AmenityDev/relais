package mailnorm

import (
	"strings"
	"testing"
	"time"
)

// fixedOptions makes generated headers deterministic so assertions can be exact.
func fixedOptions() Options {
	return Options{
		MaxBytes:       1 << 20,
		MaxHeaderCount: 200,
		MaxHeaderBytes: 128 << 10,
		Now:            func() time.Time { return time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC) },
		NewID:          func() string { return "fixed-id" },
	}
}

// crlf turns a readable test fixture into wire format.
func crlf(s string) []byte {
	return []byte(strings.ReplaceAll(s, "\n", "\r\n"))
}

func TestParseExtractsSender(t *testing.T) {
	raw := crlf(`From: "App Notifications" <No-Reply@Example.COM>
To: someone@elsewhere.test, Other <other@elsewhere.test>
Cc: watcher@elsewhere.test
Subject: Hello
Message-Id: <original@example.com>
Date: Mon, 10 Aug 2026 09:00:00 +0000
Content-Type: text/plain; charset=utf-8

Body stays exactly as it was.
`)

	msg, err := Parse(raw, fixedOptions())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	// The display name must be discarded for matching, and the address
	// normalized, so a pattern check compares like with like.
	if msg.From.String() != "no-reply@example.com" {
		t.Fatalf("From = %q, want no-reply@example.com", msg.From)
	}
	if msg.FromHeader != `"App Notifications" <No-Reply@Example.COM>` {
		t.Fatalf("FromHeader = %q, want the raw value preserved", msg.FromHeader)
	}
	if msg.Subject != "Hello" {
		t.Fatalf("Subject = %q", msg.Subject)
	}
	if msg.MessageID != "<original@example.com>" {
		t.Fatalf("MessageID = %q, want the original to be kept", msg.MessageID)
	}
	if msg.GeneratedMessageID || msg.GeneratedDate {
		t.Fatal("nothing should have been generated: both headers were present")
	}
	if len(msg.To) != 2 || msg.To[0] != "someone@elsewhere.test" {
		t.Fatalf("To = %v", msg.To)
	}
	if len(msg.Cc) != 1 || msg.Cc[0] != "watcher@elsewhere.test" {
		t.Fatalf("Cc = %v", msg.Cc)
	}
	if !strings.Contains(string(msg.Raw), "Body stays exactly as it was.") {
		t.Fatal("the body was lost")
	}
}

func TestParseGeneratesMissingHeaders(t *testing.T) {
	raw := crlf(`From: no-reply@example.com
To: someone@elsewhere.test
Subject: No date, no id

Body.
`)

	msg, err := Parse(raw, fixedOptions())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if !msg.GeneratedMessageID {
		t.Fatal("a Message-ID should have been generated")
	}
	// The generated id lives in the sender's own domain, which is what a reader
	// and downstream tooling expect.
	if msg.MessageID != "<fixed-id@example.com>" {
		t.Fatalf("MessageID = %q, want <fixed-id@example.com>", msg.MessageID)
	}
	if !msg.GeneratedDate {
		t.Fatal("a Date should have been generated")
	}

	out := string(msg.Raw)
	if !strings.Contains(out, "Message-Id: <fixed-id@example.com>") {
		t.Fatalf("the generated Message-ID is not in the output:\n%s", out)
	}
	if !strings.Contains(out, "Date: Tue, 11 Aug 2026 12:00:00 +0000") {
		t.Fatalf("the generated Date is not in the output:\n%s", out)
	}
}

// A Bcc header must never reach a recipient. Its addresses stay available for
// the audit trail, but the field itself is removed.
func TestParseStripsBcc(t *testing.T) {
	raw := crlf(`From: no-reply@example.com
To: someone@elsewhere.test
Bcc: secret@elsewhere.test, "Hidden" <hidden@elsewhere.test>
Subject: Confidential

Body.
`)

	msg, err := Parse(raw, fixedOptions())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if !msg.StrippedBcc {
		t.Fatal("StrippedBcc was not reported")
	}
	if len(msg.Bcc) != 2 {
		t.Fatalf("Bcc = %v, want both addresses retained for the audit trail", msg.Bcc)
	}

	out := string(msg.Raw)
	if strings.Contains(strings.ToLower(out), "bcc:") {
		t.Fatalf("the Bcc header survived into the outgoing message:\n%s", out)
	}
	for _, hidden := range []string{"secret@elsewhere.test", "hidden@elsewhere.test"} {
		if strings.Contains(out, hidden) {
			t.Fatalf("a blind-copied address (%s) leaked into the message:\n%s", hidden, out)
		}
	}
}

// This is the property the whole package exists to protect: whatever the body
// is, it comes out byte-identical.
func TestParsePreservesBodyBytes(t *testing.T) {
	bodies := map[string]string{
		"quoted-printable":  "Caf=C3=A9 =E2=82=AC=0D=0A=\r\nnext line\r\n",
		"base64":            "SGVsbG8sIHdvcmxkIQ==\r\n\r\nAAAA\r\n",
		"raw 8bit":          "Café € — em dash, ünïcödé\r\n",
		"multipart":         "--b\r\nContent-Type: text/plain\r\n\r\nfirst\r\n--b\r\nContent-Type: text/html\r\n\r\n<p>second</p>\r\n--b--\r\n",
		"trailing dots":     ".\r\n..\r\nnot a terminator\r\n",
		"long line":         strings.Repeat("x", 5000) + "\r\n",
		"blank lines":       "\r\n\r\n\r\nafter blanks\r\n",
		"no trailing break": "no newline at the end",
	}

	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			raw := append(crlf("From: no-reply@example.com\nSubject: t\nMessage-Id: <a@example.com>\nDate: Mon, 10 Aug 2026 09:00:00 +0000\n\n"), body...)

			msg, err := Parse(raw, fixedOptions())
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}

			_, outBody, err := splitMessage(msg.Raw)
			if err != nil {
				t.Fatalf("splitMessage: %v", err)
			}
			if string(outBody) != body {
				t.Fatalf("the body changed:\n got %q\nwant %q", outBody, body)
			}
		})
	}
}

// Bare-LF submissions are common from old scripts. They must be converted, since
// SMTP is a CRLF protocol, but converting must be idempotent.
func TestParseNormalizesLineEndings(t *testing.T) {
	raw := []byte("From: no-reply@example.com\nSubject: bare lf\nMessage-Id: <a@example.com>\nDate: Mon, 10 Aug 2026 09:00:00 +0000\n\nline one\nline two\n")

	msg, err := Parse(raw, fixedOptions())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	out := string(msg.Raw)
	if strings.Contains(strings.ReplaceAll(out, "\r\n", ""), "\n") {
		t.Fatalf("a bare LF survived:\n%q", out)
	}
	if strings.Contains(out, "\r\r") {
		t.Fatalf("normalization doubled a CR:\n%q", out)
	}
	if !strings.Contains(out, "line one\r\nline two\r\n") {
		t.Fatalf("the body was not normalized as expected:\n%q", out)
	}

	// Feeding the output back in must change nothing.
	again, err := Parse(msg.Raw, fixedOptions())
	if err != nil {
		t.Fatalf("Parse (second pass): %v", err)
	}
	if string(again.Raw) != string(msg.Raw) {
		t.Fatalf("normalization is not idempotent:\n%q\n%q", msg.Raw, again.Raw)
	}
}

func TestNormalizeCRLF(t *testing.T) {
	tests := map[string]string{
		"":                     "",
		"no endings":           "no endings",
		"already\r\ncrlf\r\n":  "already\r\ncrlf\r\n",
		"bare\nlf\n":           "bare\r\nlf\r\n",
		"old\rmac\r":           "old\r\nmac\r\n",
		"mixed\r\nand\nbare":   "mixed\r\nand\r\nbare",
		"\n":                   "\r\n",
		"\r":                   "\r\n",
		"\r\n":                 "\r\n",
		"trailing cr at end\r": "trailing cr at end\r\n",
		"double\n\nblank":      "double\r\n\r\nblank",
	}
	for in, want := range tests {
		if got := string(normalizeCRLF([]byte(in))); got != want {
			t.Fatalf("normalizeCRLF(%q) = %q, want %q", in, got, want)
		}
	}
}

// Header order carries meaning for signature verification downstream and for
// anyone reading a raw message, so rewriting must not reshuffle fields.
func TestParsePreservesHeaderOrder(t *testing.T) {
	raw := crlf(`From: no-reply@example.com
X-First: 1
To: someone@elsewhere.test
X-Second: 2
Subject: order
X-Third: 3
Message-Id: <a@example.com>
Date: Mon, 10 Aug 2026 09:00:00 +0000

Body.
`)

	msg, err := Parse(raw, fixedOptions())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	out := string(msg.Raw)
	positions := []string{"X-First:", "X-Second:", "X-Third:"}
	last := -1
	for _, marker := range positions {
		at := strings.Index(out, marker)
		if at < 0 {
			t.Fatalf("%s is missing from the output:\n%s", marker, out)
		}
		if at < last {
			t.Fatalf("header order changed:\n%s", out)
		}
		last = at
	}
}

// A folded (continuation) header must not be reflowed: rewriting it would change
// bytes we have no reason to touch.
func TestParsePreservesFoldedHeaders(t *testing.T) {
	raw := crlf(`From: no-reply@example.com
Subject: a subject that continues
 onto a second line
X-Custom: value
	with a tab continuation
Message-Id: <a@example.com>
Date: Mon, 10 Aug 2026 09:00:00 +0000

Body.
`)

	msg, err := Parse(raw, fixedOptions())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	out := string(msg.Raw)
	if !strings.Contains(out, "\r\n onto a second line") {
		t.Fatalf("the folded Subject was reflowed:\n%s", out)
	}
	if !strings.Contains(out, "\r\n\twith a tab continuation") {
		t.Fatalf("the tab continuation was altered:\n%s", out)
	}
	// The decoded value is what the admin UI shows, so the fold collapses there.
	if !strings.Contains(msg.Subject, "a subject that continues") {
		t.Fatalf("Subject = %q", msg.Subject)
	}
}

func TestParseDecodesEncodedSubject(t *testing.T) {
	raw := crlf(`From: no-reply@example.com
Subject: =?UTF-8?B?Q2Fmw6kgw6AgbGEgY3Jsw6htZQ==?=
Message-Id: <a@example.com>
Date: Mon, 10 Aug 2026 09:00:00 +0000

Body.
`)

	msg, err := Parse(raw, fixedOptions())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if msg.Subject != "Café à la crlème" {
		t.Fatalf("Subject = %q, want the decoded form", msg.Subject)
	}
	// The wire bytes keep the encoded word: decoding is for display only.
	if !strings.Contains(string(msg.Raw), "=?UTF-8?B?") {
		t.Fatal("the encoded subject was rewritten in the outgoing message")
	}
}

// The From header is what the entire authorisation model rests on, so every
// ambiguity here is fatal rather than resolved by guessing.
func TestParseRejectsBadSender(t *testing.T) {
	tests := []struct {
		name     string
		headers  string
		wantCode string
	}{
		{
			name:     "no From at all",
			headers:  "To: someone@elsewhere.test\nSubject: t\n",
			wantCode: CodeNoFrom,
		},
		{
			name:     "empty From",
			headers:  "From:   \nSubject: t\n",
			wantCode: CodeNoFrom,
		},
		{
			name:     "two From headers",
			headers:  "From: a@example.com\nFrom: b@example.com\nSubject: t\n",
			wantCode: CodeMultipleFrom,
		},
		{
			name:     "two addresses in one From",
			headers:  "From: a@example.com, b@example.com\nSubject: t\n",
			wantCode: CodeMultipleFrom,
		},
		{
			name:     "group syntax",
			headers:  "From: undisclosed:;\nSubject: t\n",
			wantCode: CodeInvalidFrom,
		},
		{
			name:     "unparsable",
			headers:  "From: not an address\nSubject: t\n",
			wantCode: CodeInvalidFrom,
		},
		{
			name:     "single-label domain",
			headers:  "From: root@localhost\nSubject: t\n",
			wantCode: CodeInvalidFrom,
		},
		{
			name:     "unicode local part",
			headers:  "From: café@example.com\nSubject: t\n",
			wantCode: CodeInvalidFrom,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := append(crlf(tc.headers), crlf("\nBody.\n")...)
			_, err := Parse(raw, fixedOptions())
			if err == nil {
				t.Fatal("Parse accepted a message with an unusable sender")
			}
			if got := CodeOf(err); got != tc.wantCode {
				t.Fatalf("rejection code = %q, want %q (%v)", got, tc.wantCode, err)
			}
		})
	}
}

func TestParseEnforcesLimits(t *testing.T) {
	valid := "From: no-reply@example.com\nSubject: t\nMessage-Id: <a@example.com>\nDate: Mon, 10 Aug 2026 09:00:00 +0000\n\nBody.\n"

	t.Run("empty", func(t *testing.T) {
		for _, raw := range [][]byte{nil, {}, []byte("   \r\n  ")} {
			if _, err := Parse(raw, fixedOptions()); CodeOf(err) != CodeEmpty {
				t.Fatalf("Parse(%q) code = %q, want %q", raw, CodeOf(err), CodeEmpty)
			}
		}
	})

	t.Run("too large", func(t *testing.T) {
		opts := fixedOptions()
		opts.MaxBytes = 64
		big := append(crlf(valid), []byte(strings.Repeat("x", 1000))...)
		if _, err := Parse(big, opts); CodeOf(err) != CodeTooLarge {
			t.Fatalf("code = %q, want %q", CodeOf(err), CodeTooLarge)
		}
	})

	// The limit must also hold for the message after generated headers are
	// added, otherwise a submission just under the cap could go out over it.
	t.Run("too large only after normalization", func(t *testing.T) {
		body := "From: no-reply@example.com\nSubject: t\n\nBody.\n"
		opts := fixedOptions()
		opts.MaxBytes = int64(len(crlf(body))) + 10
		if _, err := Parse(crlf(body), opts); CodeOf(err) != CodeTooLarge {
			t.Fatalf("code = %q, want %q", CodeOf(err), CodeTooLarge)
		}
	})

	t.Run("too many headers", func(t *testing.T) {
		opts := fixedOptions()
		opts.MaxHeaderCount = 5
		var headers strings.Builder
		headers.WriteString("From: no-reply@example.com\n")
		for i := range 50 {
			headers.WriteString("X-Pad-")
			headers.WriteString(string(rune('a' + i%26)))
			headers.WriteString(": v\n")
		}
		raw := append(crlf(headers.String()), crlf("\nBody.\n")...)
		if _, err := Parse(raw, opts); CodeOf(err) != CodeTooManyHeaders {
			t.Fatalf("code = %q, want %q", CodeOf(err), CodeTooManyHeaders)
		}
	})

	t.Run("headers too large", func(t *testing.T) {
		opts := fixedOptions()
		opts.MaxHeaderBytes = 100
		raw := append(crlf("From: no-reply@example.com\nX-Big: "+strings.Repeat("x", 500)+"\n"), crlf("\nBody.\n")...)
		if _, err := Parse(raw, opts); CodeOf(err) != CodeHeadersTooLarge {
			t.Fatalf("code = %q, want %q", CodeOf(err), CodeHeadersTooLarge)
		}
	})
}

// A message with no body is legal and must be accepted: header-only
// notifications exist.
func TestParseAcceptsHeaderOnlyMessage(t *testing.T) {
	for _, raw := range [][]byte{
		crlf("From: no-reply@example.com\nSubject: header only\n"),
		crlf("From: no-reply@example.com\nSubject: header only\n\n"),
	} {
		msg, err := Parse(raw, fixedOptions())
		if err != nil {
			t.Fatalf("Parse(%q): %v", raw, err)
		}
		if msg.From.String() != "no-reply@example.com" {
			t.Fatalf("From = %q", msg.From)
		}
		if !strings.HasSuffix(string(msg.Raw), "\r\n\r\n") {
			t.Fatalf("the header block is not properly terminated:\n%q", msg.Raw)
		}
	}
}

func TestSplitMessage(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		wantHeader string
		wantBody   string
	}{
		{"crlf", "A: 1\r\nB: 2\r\n\r\nbody", "A: 1\r\nB: 2\r\n", "body"},
		{"bare lf", "A: 1\nB: 2\n\nbody", "A: 1\nB: 2\n", "body"},
		// A bare-LF header block whose body contains a CRLF blank line must
		// still split at the first real separator.
		{"lf headers, crlf in body", "A: 1\n\nbody\r\n\r\nmore", "A: 1\n", "body\r\n\r\nmore"},
		{"empty body", "A: 1\r\n\r\n", "A: 1\r\n", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			header, body, err := splitMessage([]byte(tc.raw))
			if err != nil {
				t.Fatalf("splitMessage: %v", err)
			}
			if string(header) != tc.wantHeader {
				t.Fatalf("header = %q, want %q", header, tc.wantHeader)
			}
			if string(body) != tc.wantBody {
				t.Fatalf("body = %q, want %q", body, tc.wantBody)
			}
		})
	}
}

func TestReadAllEnforcesLimit(t *testing.T) {
	if _, err := ReadAll(strings.NewReader(strings.Repeat("x", 100)), 10); CodeOf(err) != CodeTooLarge {
		t.Fatalf("code = %q, want %q", CodeOf(err), CodeTooLarge)
	}
	got, err := ReadAll(strings.NewReader("small"), 10)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "small" {
		t.Fatalf("got %q", got)
	}
	// Exactly at the limit is allowed.
	if _, err := ReadAll(strings.NewReader("0123456789"), 10); err != nil {
		t.Fatalf("ReadAll at exactly the limit: %v", err)
	}
}

func FuzzParse(f *testing.F) {
	f.Add("From: a@b.com\r\n\r\nbody")
	f.Add("From: a@b.com\nFrom: c@d.com\n\nbody")
	f.Add("From: a@b.com\r\nBcc: x@y.com\r\n\r\nbody")
	f.Add("\r\n\r\n")
	f.Add("From:\r\n\r\n")
	f.Add("From: a@b.com\r\nSubject: =?UTF-8?B?///?=\r\n\r\n")
	f.Add("From: a@b.com\r\n \r\n\r\nbody")

	opts := fixedOptions()

	f.Fuzz(func(t *testing.T, raw string) {
		msg, err := Parse([]byte(raw), opts)
		if err != nil {
			return
		}

		// Anything accepted must have a usable sender: no downstream code should
		// ever have to re-check this.
		if msg.From.IsZero() || msg.From.Domain == "" {
			t.Fatalf("Parse accepted %q with an empty sender", raw)
		}
		// A Bcc header must never survive.
		if headerBlock, _, err := splitMessage(msg.Raw); err == nil {
			if strings.Contains(strings.ToLower(string(headerBlock)), "\nbcc:") {
				t.Fatalf("a Bcc header survived for input %q", raw)
			}
		}
		// The output must always be re-parsable: the SMTP client will read it
		// back, and so will a replay.
		again, err := Parse(msg.Raw, opts)
		if err != nil {
			t.Fatalf("Parse accepted %q but its own output failed to re-parse: %v", raw, err)
		}
		if again.From != msg.From {
			t.Fatalf("sender changed on re-parse: %q then %q", msg.From, again.From)
		}
	})
}
