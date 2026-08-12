package crypto

import (
	"errors"
	"strings"
	"testing"
)

func newTestHasher(t *testing.T, fill byte) *Hasher {
	t.Helper()
	h, err := NewHasher(testKey(fill))
	if err != nil {
		t.Fatalf("NewHasher: %v", err)
	}
	return h
}

func TestMintAPIKeyRoundTrip(t *testing.T) {
	h := newTestHasher(t, 0x20)

	minted, err := h.MintAPIKey()
	if err != nil {
		t.Fatalf("MintAPIKey: %v", err)
	}
	if !strings.HasPrefix(minted.Plaintext, APIKeyPrefix) {
		t.Fatalf("token %q lacks the %q prefix", minted.Plaintext, APIKeyPrefix)
	}
	if len(minted.HMAC) != 32 {
		t.Fatalf("fingerprint length: got %d, want 32", len(minted.HMAC))
	}

	// The verifier only ever sees the token, so parsing it must recover exactly
	// the lookup that was stored.
	lookup, secret, err := ParseAPIKey(minted.Plaintext)
	if err != nil {
		t.Fatalf("ParseAPIKey: %v", err)
	}
	if lookup != minted.Lookup {
		t.Fatalf("lookup mismatch: parsed %q, stored %q", lookup, minted.Lookup)
	}
	if !h.Verify(secret, minted.HMAC) {
		t.Fatal("Verify rejected the freshly minted secret")
	}

	// The stored lookup must not be enough to reconstruct the token.
	if strings.Contains(minted.Lookup, secret) {
		t.Fatal("the stored lookup contains the secret")
	}
}

func TestMintAPIKeyIsUnique(t *testing.T) {
	h := newTestHasher(t, 0x20)

	seenLookups := make(map[string]bool)
	seenTokens := make(map[string]bool)
	for range 200 {
		minted, err := h.MintAPIKey()
		if err != nil {
			t.Fatalf("MintAPIKey: %v", err)
		}
		if seenLookups[minted.Lookup] {
			t.Fatalf("duplicate lookup %q", minted.Lookup)
		}
		if seenTokens[minted.Plaintext] {
			t.Fatal("duplicate token")
		}
		seenLookups[minted.Lookup] = true
		seenTokens[minted.Plaintext] = true
	}
}

func TestVerifyRejectsWrongSecrets(t *testing.T) {
	h := newTestHasher(t, 0x20)
	minted, err := h.MintAPIKey()
	if err != nil {
		t.Fatalf("MintAPIKey: %v", err)
	}
	_, secret, err := ParseAPIKey(minted.Plaintext)
	if err != nil {
		t.Fatalf("ParseAPIKey: %v", err)
	}

	tests := []struct {
		name   string
		secret string
	}{
		{"empty", ""},
		{"truncated", secret[:len(secret)-1]},
		{"one char changed", flipLastChar(secret)},
		{"whitespace appended", secret + " "},
		{"case changed", strings.ToUpper(secret)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if h.Verify(tc.secret, minted.HMAC) {
				t.Fatalf("Verify accepted %q", tc.secret)
			}
		})
	}
}

// A different pepper must never validate the same secret: that is the whole
// point of peppering, and it is what makes a bare database dump useless.
func TestFingerprintDependsOnPepper(t *testing.T) {
	first := newTestHasher(t, 0x20)
	second := newTestHasher(t, 0x70)

	minted, err := first.MintAPIKey()
	if err != nil {
		t.Fatalf("MintAPIKey: %v", err)
	}
	_, secret, err := ParseAPIKey(minted.Plaintext)
	if err != nil {
		t.Fatalf("ParseAPIKey: %v", err)
	}

	if second.Verify(secret, minted.HMAC) {
		t.Fatal("a hasher with a different pepper validated the secret")
	}
}

func TestVerifyRejectsMalformedStoredFingerprint(t *testing.T) {
	h := newTestHasher(t, 0x20)
	// A short or empty fingerprint means a corrupt row. It must never validate,
	// least of all against an empty secret.
	for _, stored := range [][]byte{nil, {}, []byte("too short"), make([]byte, 31), make([]byte, 33)} {
		if h.Verify("", stored) {
			t.Fatalf("Verify accepted an empty secret against a %d-byte fingerprint", len(stored))
		}
		if h.Verify("anything", stored) {
			t.Fatalf("Verify accepted a secret against a %d-byte fingerprint", len(stored))
		}
	}
}

func TestParseAPIKeyRejectsMalformed(t *testing.T) {
	valid := APIKeyPrefix + "abcdefghijkl_" + strings.Repeat("A", 43)

	tests := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"no prefix", "abcdefghijkl_secret"},
		{"wrong prefix", "resend_sk_abcdefghijkl_secret"},
		{"prefix only", APIKeyPrefix},
		{"too short", APIKeyPrefix + "abc"},
		{"missing separator", APIKeyPrefix + "abcdefghijklmnop"},
		{"empty secret", APIKeyPrefix + "abcdefghijkl_"},
		{"lookup not base32", APIKeyPrefix + "ABCDEFGHIJKL_" + strings.Repeat("A", 43)},
		{"lookup with digits outside base32", APIKeyPrefix + "abcdefghij01_" + strings.Repeat("A", 43)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := ParseAPIKey(tc.token); err == nil {
				t.Fatalf("ParseAPIKey(%q) succeeded, want error", tc.token)
			} else if !errors.Is(err, ErrMalformedSecret) {
				t.Fatalf("ParseAPIKey(%q) = %v, want ErrMalformedSecret", tc.token, err)
			}
		})
	}

	// Sanity check that the fixture the negative cases are derived from parses.
	if _, _, err := ParseAPIKey(valid); err != nil {
		t.Fatalf("ParseAPIKey rejected the valid fixture: %v", err)
	}
}

func TestParseAPIKeyToleratesSurroundingWhitespace(t *testing.T) {
	h := newTestHasher(t, 0x20)
	minted, err := h.MintAPIKey()
	if err != nil {
		t.Fatalf("MintAPIKey: %v", err)
	}

	// Copy-pasting a key out of a terminal routinely picks up a newline.
	lookup, secret, err := ParseAPIKey("  " + minted.Plaintext + "\n")
	if err != nil {
		t.Fatalf("ParseAPIKey: %v", err)
	}
	if lookup != minted.Lookup || !h.Verify(secret, minted.HMAC) {
		t.Fatal("a whitespace-padded token did not verify")
	}
}

func TestMintSMTPPassword(t *testing.T) {
	h := newTestHasher(t, 0x20)

	minted, err := h.MintSMTPPassword("  WordPress_App  ")
	if err != nil {
		t.Fatalf("MintSMTPPassword: %v", err)
	}
	if minted.Lookup != "wordpress_app" {
		t.Fatalf("lookup: got %q, want %q", minted.Lookup, "wordpress_app")
	}
	if !h.Verify(minted.Plaintext, minted.HMAC) {
		t.Fatal("Verify rejected the freshly minted password")
	}
	// The password travels through legacy SMTP clients, so it must stay free of
	// characters that break naive configuration parsers.
	if strings.ContainsAny(minted.Plaintext, " \t\r\n\"'\\:;") {
		t.Fatalf("generated password %q contains awkward characters", minted.Plaintext)
	}
}

func TestNormalizeSMTPUsername(t *testing.T) {
	valid := map[string]string{
		"app":            "app",
		"App":            "app",
		"  spaced  ":     "spaced",
		"my-app_1.prod":  "my-app_1.prod",
		"relais_abcdefg": "relais_abcdefg",
	}
	for input, want := range valid {
		got, err := NormalizeSMTPUsername(input)
		if err != nil {
			t.Fatalf("NormalizeSMTPUsername(%q): %v", input, err)
		}
		if got != want {
			t.Fatalf("NormalizeSMTPUsername(%q) = %q, want %q", input, got, want)
		}
	}

	invalid := []string{
		"",
		"  ",
		"ab",                    // too short
		"-leading-dash",         // must start alphanumeric
		"_leading-underscore",   //
		"has space",             //
		"has@at",                //
		"has:colon",             // would break AUTH PLAIN framing assumptions
		strings.Repeat("a", 65), // too long
		"accentué",              // non-ASCII
	}
	for _, input := range invalid {
		if got, err := NormalizeSMTPUsername(input); err == nil {
			t.Fatalf("NormalizeSMTPUsername(%q) = %q, want error", input, got)
		} else if !errors.Is(err, ErrMalformedSecret) {
			t.Fatalf("NormalizeSMTPUsername(%q) = %v, want ErrMalformedSecret", input, err)
		}
	}
}

func TestGenerateSMTPUsernameIsValid(t *testing.T) {
	seen := make(map[string]bool)
	for range 100 {
		username, err := GenerateSMTPUsername()
		if err != nil {
			t.Fatalf("GenerateSMTPUsername: %v", err)
		}
		if _, err := NormalizeSMTPUsername(username); err != nil {
			t.Fatalf("generated username %q is not accepted by NormalizeSMTPUsername: %v", username, err)
		}
		if seen[username] {
			t.Fatalf("duplicate generated username %q", username)
		}
		seen[username] = true
	}
}

func TestNewHasherRejectsBadPepper(t *testing.T) {
	for _, pepper := range []string{"", "!!!", "c2hvcnQ="} {
		if _, err := NewHasher(pepper); err == nil {
			t.Fatalf("NewHasher(%q) succeeded, want error", pepper)
		}
	}
}

func flipLastChar(s string) string {
	if s == "" {
		return "x"
	}
	last := s[len(s)-1]
	replacement := byte('a')
	if last == 'a' {
		replacement = 'b'
	}
	return s[:len(s)-1] + string(replacement)
}
