package crypto

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// testKey returns a deterministic base64 key. Determinism matters here: a
// failing test must be reproducible.
func testKey(fill byte) string {
	raw := make([]byte, KeySize)
	for i := range raw {
		raw[i] = fill + byte(i)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func TestKeyringSealOpenRoundTrip(t *testing.T) {
	kr, err := ParseKeyring("1:"+testKey(0x10), "")
	if err != nil {
		t.Fatalf("ParseKeyring: %v", err)
	}

	const password = "ocid1.user.oc1..aaaa:S0me-Passw0rd/with+specials"
	envelope, err := kr.SealString(password)
	if err != nil {
		t.Fatalf("SealString: %v", err)
	}
	if strings.Contains(envelope, password) {
		t.Fatal("envelope contains the plaintext")
	}
	if !strings.HasPrefix(envelope, "v1:1:") {
		t.Fatalf("envelope %q does not carry the version and key id", envelope)
	}
	if !IsSealed(envelope) {
		t.Fatal("IsSealed said no on a freshly sealed value")
	}

	got, err := kr.OpenString(envelope)
	if err != nil {
		t.Fatalf("OpenString: %v", err)
	}
	if got != password {
		t.Fatalf("round trip: got %q, want %q", got, password)
	}
}

func TestKeyringSealIsNonDeterministic(t *testing.T) {
	kr, err := ParseKeyring("1:"+testKey(0x10), "")
	if err != nil {
		t.Fatalf("ParseKeyring: %v", err)
	}

	first, err := kr.SealString("same input")
	if err != nil {
		t.Fatalf("SealString: %v", err)
	}
	second, err := kr.SealString("same input")
	if err != nil {
		t.Fatalf("SealString: %v", err)
	}
	if first == second {
		t.Fatal("two seals of the same plaintext are identical: the nonce is being reused")
	}
}

// TestKeyringRotation is the scenario that matters operationally: a key is added
// and made active, and rows sealed under the old key must keep opening.
func TestKeyringRotation(t *testing.T) {
	old, err := ParseKeyring("1:"+testKey(0x10), "")
	if err != nil {
		t.Fatalf("ParseKeyring: %v", err)
	}
	envelope, err := old.SealString("legacy password")
	if err != nil {
		t.Fatalf("SealString: %v", err)
	}

	rotated, err := ParseKeyring("1:"+testKey(0x10)+",2:"+testKey(0x40), "2")
	if err != nil {
		t.Fatalf("ParseKeyring after rotation: %v", err)
	}
	if rotated.ActiveID() != "2" {
		t.Fatalf("ActiveID: got %q, want 2", rotated.ActiveID())
	}

	got, err := rotated.OpenString(envelope)
	if err != nil {
		t.Fatalf("opening a value sealed under the retired key: %v", err)
	}
	if got != "legacy password" {
		t.Fatalf("got %q, want %q", got, "legacy password")
	}
	if !rotated.NeedsRewrap(envelope) {
		t.Fatal("NeedsRewrap should flag a value sealed under a non-active key")
	}

	fresh, err := rotated.SealString("new password")
	if err != nil {
		t.Fatalf("SealString: %v", err)
	}
	if !strings.HasPrefix(fresh, "v1:2:") {
		t.Fatalf("new seal %q did not use the active key", fresh)
	}
	if rotated.NeedsRewrap(fresh) {
		t.Fatal("NeedsRewrap flagged a value sealed under the active key")
	}
}

func TestKeyringOpenRejectsTampering(t *testing.T) {
	kr, err := ParseKeyring("1:"+testKey(0x10)+",2:"+testKey(0x40), "1")
	if err != nil {
		t.Fatalf("ParseKeyring: %v", err)
	}
	envelope, err := kr.SealString("secret")
	if err != nil {
		t.Fatalf("SealString: %v", err)
	}

	parts := strings.SplitN(envelope, ":", 3)
	raw, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	t.Run("flipped ciphertext bit", func(t *testing.T) {
		mutated := append([]byte(nil), raw...)
		mutated[len(mutated)-1] ^= 0x01
		bad := parts[0] + ":" + parts[1] + ":" + base64.StdEncoding.EncodeToString(mutated)
		if _, err := kr.Open(bad); err == nil {
			t.Fatal("a flipped ciphertext bit opened successfully")
		}
	})

	t.Run("flipped nonce bit", func(t *testing.T) {
		mutated := append([]byte(nil), raw...)
		mutated[0] ^= 0x01
		bad := parts[0] + ":" + parts[1] + ":" + base64.StdEncoding.EncodeToString(mutated)
		if _, err := kr.Open(bad); err == nil {
			t.Fatal("a flipped nonce bit opened successfully")
		}
	})

	// Relabelling the envelope to another configured key must fail: the key id
	// is authenticated as associated data, so it cannot be swapped.
	t.Run("relabelled key id", func(t *testing.T) {
		bad := parts[0] + ":2:" + parts[2]
		if _, err := kr.Open(bad); err == nil {
			t.Fatal("a relabelled key id opened successfully")
		}
	})
}

func TestKeyringOpenErrors(t *testing.T) {
	kr, err := ParseKeyring("1:"+testKey(0x10), "")
	if err != nil {
		t.Fatalf("ParseKeyring: %v", err)
	}

	tests := []struct {
		name     string
		envelope string
		wantErr  error
	}{
		{"empty", "", ErrNotSealed},
		{"plaintext password", "hunter2", ErrNotSealed},
		{"missing payload", "v1:1", ErrNotSealed},
		{"empty component", "v1::abcd", ErrNotSealed},
		{"unsupported version", "v9:1:abcd", ErrNotSealed},
		{"unknown key id", "v1:99:abcd", ErrUnknownKey},
		{"payload not base64", "v1:1:!!!not-base64!!!", ErrNotSealed},
		{"payload shorter than nonce", "v1:1:" + base64.StdEncoding.EncodeToString([]byte{1, 2, 3}), ErrNotSealed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := kr.Open(tc.envelope)
			if err == nil {
				t.Fatalf("Open(%q) succeeded, want error", tc.envelope)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Open(%q) = %v, want %v", tc.envelope, err, tc.wantErr)
			}
		})
	}
}

func TestParseKeyringErrors(t *testing.T) {
	tests := []struct {
		name     string
		spec     string
		active   string
		wantText string
	}{
		{"empty spec", "", "", "no encryption key configured"},
		{"missing colon", "justakey", "", "malformed key entry"},
		{"bad key id", "this-id-is-far-too-long-to-be-valid:" + testKey(0x10), "", "invalid key id"},
		{"not base64", "1:!!!!", "", "not valid base64"},
		{"wrong length", "1:" + base64.StdEncoding.EncodeToString([]byte("short")), "", "must decode to 32 bytes"},
		{"duplicate id", "1:" + testKey(0x10) + ",1:" + testKey(0x40), "", "duplicate key id"},
		{"ambiguous active", "1:" + testKey(0x10) + ",2:" + testKey(0x40), "", "set the active key id explicitly"},
		{"unknown active", "1:" + testKey(0x10), "7", "not among the configured keys"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseKeyring(tc.spec, tc.active)
			if err == nil {
				t.Fatalf("ParseKeyring(%q, %q) succeeded, want error", tc.spec, tc.active)
			}
			if !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("error %q does not mention %q", err, tc.wantText)
			}
		})
	}
}

// A malformed entry must not echo key material into logs.
func TestParseKeyringErrorRedactsKeyMaterial(t *testing.T) {
	const material = "SUPERSECRETKEYMATERIAL"
	_, err := ParseKeyring("1:"+testKey(0x10)+",  "+material, "")
	if err == nil {
		t.Fatal("expected an error on a malformed entry")
	}
	if strings.Contains(err.Error(), material) {
		t.Fatalf("error message leaks key material: %q", err)
	}
}

func TestKeyringIgnoresBlankEntries(t *testing.T) {
	// Trailing commas and stray whitespace are common in env files; they should
	// not break a deployment.
	kr, err := ParseKeyring(" 1: "+testKey(0x10)+" , ", "")
	if err != nil {
		t.Fatalf("ParseKeyring: %v", err)
	}
	if kr.ActiveID() != "1" {
		t.Fatalf("ActiveID: got %q, want 1", kr.ActiveID())
	}
}

func TestGenerateKeyIsUsableAndDistinct(t *testing.T) {
	first, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	second, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if first == second {
		t.Fatal("GenerateKey returned the same key twice")
	}
	if _, err := ParseKeyring("1:"+first, ""); err != nil {
		t.Fatalf("a generated key is not accepted by ParseKeyring: %v", err)
	}
}
