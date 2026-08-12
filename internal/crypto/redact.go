package crypto

// Secret wraps a plaintext secret so that the obvious accidents cannot happen.
//
// Formatting it with %v, %s or %+v, or serialising it to JSON, yields a
// placeholder. Reading the real value requires calling Reveal, which is easy to
// grep for during a review. This is a guard rail, not a security boundary: the
// value is still a string in memory.
type Secret string

const redacted = "[redacted]"

// String implements fmt.Stringer.
func (s Secret) String() string { return redacted }

// GoString implements fmt.GoStringer, covering %#v.
func (s Secret) GoString() string { return redacted }

// LogValue implements slog.LogValuer, covering structured logging.
func (s Secret) LogValue() any { return redacted }

// MarshalJSON keeps a secret out of any response body or job payload.
func (s Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

// MarshalText covers encoders that prefer TextMarshaler.
func (s Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// Reveal returns the underlying plaintext. Every call site is a place where a
// secret escapes into the wider program, so keep them few and obvious.
func (s Secret) Reveal() string { return string(s) }

// IsEmpty reports whether there is no secret at all, which for an SMTP backend
// means "do not attempt AUTH".
func (s Secret) IsEmpty() bool { return s == "" }
