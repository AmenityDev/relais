// Package crypto owns every secret format used by relais.
//
// Two mechanisms live here and must not be confused:
//
//   - Keyring seals backend SMTP passwords. It is reversible, because the
//     worker has to present the password to the relay.
//   - Hasher fingerprints sender credentials. It is one-way: relais only ever
//     needs to check a presented secret, never to recover it.
//
// They use separate key material on purpose, so that leaking the one-way pepper
// grants no decryption ability.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// sealedVersion prefixes every sealed value. It changes only if the wire format
// itself changes, never on key rotation.
const sealedVersion = "v1"

// keyIDPattern keeps key ids short and free of the ':' separator.
var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,16}$`)

// ErrNotSealed reports a value that is not in the sealed envelope format.
var ErrNotSealed = errors.New("value is not a sealed envelope")

// ErrUnknownKey reports a sealed value referencing a key absent from the
// keyring, which in practice means a key was removed from the environment while
// rows still reference it.
var ErrUnknownKey = errors.New("sealed value references an unknown key id")

// Keyring holds every configured encryption key and knows which one to use for
// new writes.
//
// Rotation works by adding a key and pointing the active id at it: existing
// rows keep opening with their original key until they are rewritten.
type Keyring struct {
	keys     map[string]cipher.AEAD
	activeID string
}

// KeySize is the required raw key length. AES-256 only; there is no reason to
// offer a weaker option.
const KeySize = 32

// GenerateKey returns a fresh base64 key suitable for RELAIS_SECRET_ENCRYPTION_KEYS.
func GenerateKey() (string, error) {
	buf := make([]byte, KeySize)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

// ParseKeyring builds a Keyring from the environment representation.
//
// spec is a comma-separated list of "<id>:<base64 32-byte key>" entries.
// activeID selects the key used for new writes; it may be empty when exactly
// one key is configured.
func ParseKeyring(spec, activeID string) (*Keyring, error) {
	entries := strings.Split(spec, ",")
	kr := &Keyring{keys: make(map[string]cipher.AEAD, len(entries))}

	var lastID string
	for _, raw := range entries {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		id, keyB64, ok := strings.Cut(entry, ":")
		if !ok {
			return nil, fmt.Errorf("malformed key entry %q: want \"<id>:<base64 key>\"", redactEntry(entry))
		}
		id = strings.TrimSpace(id)
		if !keyIDPattern.MatchString(id) {
			return nil, fmt.Errorf("invalid key id %q: want 1-16 chars of [A-Za-z0-9_-]", id)
		}
		if _, dup := kr.keys[id]; dup {
			return nil, fmt.Errorf("duplicate key id %q", id)
		}

		key, err := decodeKey(strings.TrimSpace(keyB64))
		if err != nil {
			return nil, fmt.Errorf("key %q: %w", id, err)
		}
		aead, err := newAEAD(key)
		if err != nil {
			return nil, fmt.Errorf("key %q: %w", id, err)
		}
		kr.keys[id] = aead
		lastID = id
	}

	switch {
	case len(kr.keys) == 0:
		return nil, errors.New("no encryption key configured")
	case activeID == "" && len(kr.keys) == 1:
		kr.activeID = lastID
	case activeID == "":
		return nil, fmt.Errorf("%d keys configured: set the active key id explicitly", len(kr.keys))
	default:
		if _, ok := kr.keys[activeID]; !ok {
			return nil, fmt.Errorf("active key id %q is not among the configured keys", activeID)
		}
		kr.activeID = activeID
	}
	return kr, nil
}

// ActiveID reports the key id used for new writes.
func (k *Keyring) ActiveID() string { return k.activeID }

// Seal encrypts plaintext with the active key and returns the envelope
// "v1:<key id>:<base64 nonce||ciphertext>".
func (k *Keyring) Seal(plaintext []byte) (string, error) {
	aead, ok := k.keys[k.activeID]
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrUnknownKey, k.activeID)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("read nonce: %w", err)
	}

	// The version and key id are authenticated but not encrypted, so a tampered
	// envelope header fails to open instead of silently decrypting under a
	// different key.
	sealed := aead.Seal(nonce, nonce, plaintext, associatedData(k.activeID))
	return sealedVersion + ":" + k.activeID + ":" + base64.StdEncoding.EncodeToString(sealed), nil
}

// SealString is a convenience wrapper for the common case of a password.
func (k *Keyring) SealString(plaintext string) (string, error) {
	return k.Seal([]byte(plaintext))
}

// Open decrypts an envelope produced by Seal, using whichever key it names.
func (k *Keyring) Open(envelope string) ([]byte, error) {
	version, keyID, payload, err := splitEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	if version != sealedVersion {
		return nil, fmt.Errorf("%w: unsupported version %q", ErrNotSealed, version)
	}
	aead, ok := k.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownKey, keyID)
	}

	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: payload is not base64", ErrNotSealed)
	}
	if len(raw) < aead.NonceSize() {
		return nil, fmt.Errorf("%w: payload shorter than the nonce", ErrNotSealed)
	}

	nonce, ciphertext := raw[:aead.NonceSize()], raw[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, ciphertext, associatedData(keyID))
	if err != nil {
		// Deliberately vague: a padding/authentication oracle is worth avoiding
		// even on a value only reachable by an authenticated admin.
		return nil, errors.New("sealed value failed authentication")
	}
	return plaintext, nil
}

// OpenString decrypts an envelope into a string.
func (k *Keyring) OpenString(envelope string) (string, error) {
	b, err := k.Open(envelope)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// NeedsRewrap reports whether an envelope is sealed under a non-active key, so
// an admin task can re-seal it after a rotation.
func (k *Keyring) NeedsRewrap(envelope string) bool {
	_, keyID, _, err := splitEnvelope(envelope)
	if err != nil {
		return false
	}
	return keyID != k.activeID
}

// IsSealed reports whether a stored value looks like an envelope. It is a shape
// check, not a validity check.
func IsSealed(value string) bool {
	_, _, _, err := splitEnvelope(value)
	return err == nil
}

func splitEnvelope(envelope string) (version, keyID, payload string, err error) {
	parts := strings.SplitN(envelope, ":", 3)
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("%w: want \"v1:<key id>:<payload>\"", ErrNotSealed)
	}
	if parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", "", fmt.Errorf("%w: empty component", ErrNotSealed)
	}
	return parts[0], parts[1], parts[2], nil
}

func associatedData(keyID string) []byte {
	return []byte(sealedVersion + ":" + keyID)
}

func decodeKey(encoded string) ([]byte, error) {
	// Accept both padded and raw base64: hand-copied keys lose their padding
	// surprisingly often, and failing on that is pure friction.
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		key, err = base64.RawStdEncoding.DecodeString(encoded)
	}
	if err != nil {
		return nil, errors.New("key is not valid base64")
	}
	if len(key) != KeySize {
		return nil, fmt.Errorf("key must decode to %d bytes, got %d", KeySize, len(key))
	}
	return key, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("build cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("build gcm: %w", err)
	}
	return aead, nil
}

// redactEntry keeps key material out of error messages, which are logged.
func redactEntry(entry string) string {
	if id, _, ok := strings.Cut(entry, ":"); ok {
		return id + ":<redacted>"
	}
	return "<redacted>"
}
