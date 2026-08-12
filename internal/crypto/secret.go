package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Credential secret layout.
//
// An API key looks like:
//
//	relais_sk_<lookup><sep><secret>
//	           └ 12 ┘ └'_'┘└─ 43 ─┘
//
// The lookup and the secret are drawn independently, so publishing the lookup in
// the database costs nothing: the secret keeps its full 256 bits. Parsing is by
// fixed offset, not by splitting on the separator, because the secret alphabet
// contains '_' too.
const (
	// APIKeyPrefix is deliberately recognisable so a leaked key can be spotted
	// by secret scanners.
	APIKeyPrefix = "relais_sk_"
	// lookupPrefix marks a lookup value that belongs to an API key rather than
	// to an SMTP username. Both share one unique index.
	lookupPrefix = "k_"

	lookupRandomChars = 12
	secretBytes       = 32
	separator         = '_'
)

// lookupEncoding is lowercase base32 without padding: unambiguous to read aloud
// and safe in the credential_lookup_shape CHECK.
var lookupEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// smtpUsernamePattern bounds admin-chosen SMTP usernames. Legacy clients
// (WordPress plugins, old PHP scripts) mishandle exotic characters, so the set
// is intentionally narrow.
var smtpUsernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,63}$`)

// ErrMalformedSecret reports a presented secret whose shape is wrong. Callers
// must treat it exactly like a wrong secret: never tell a client whether the
// shape or the value was the problem.
var ErrMalformedSecret = errors.New("malformed secret")

// Minted is the result of creating a credential secret. Plaintext is the only
// time the secret exists in a readable form; it is shown once and never stored.
type Minted struct {
	// Plaintext is what the operator copies into their application.
	Plaintext string
	// Lookup is the public half, stored in credential.lookup.
	Lookup string
	// HMAC is the 32-byte fingerprint stored in credential.secret_hmac.
	HMAC []byte
}

// Hasher fingerprints credential secrets with a keyed HMAC.
//
// The pepper lives only in the environment, so a stolen database cannot be
// tested against candidate secrets offline. A slow KDF is deliberately not used:
// verification happens on every REST request and every SMTP connection, and the
// secrets are 256-bit random values, where the brute-force cost a KDF adds is
// irrelevant next to the entropy already present.
type Hasher struct {
	pepper []byte
}

// GeneratePepper returns a fresh base64 pepper for
// RELAIS_SECRET_CREDENTIAL_PEPPER.
func GeneratePepper() (string, error) { return GenerateKey() }

// NewHasher builds a Hasher from the base64-encoded pepper.
func NewHasher(pepperB64 string) (*Hasher, error) {
	pepper, err := decodeKey(strings.TrimSpace(pepperB64))
	if err != nil {
		return nil, fmt.Errorf("credential pepper: %w", err)
	}
	return &Hasher{pepper: pepper}, nil
}

// Fingerprint returns HMAC-SHA256(pepper, secret).
func (h *Hasher) Fingerprint(secret string) []byte {
	mac := hmac.New(sha256.New, h.pepper)
	mac.Write([]byte(secret))
	return mac.Sum(nil)
}

// Verify reports whether secret matches the stored fingerprint, in constant
// time with respect to the fingerprint contents.
func (h *Hasher) Verify(secret string, stored []byte) bool {
	if len(stored) != sha256.Size {
		return false
	}
	return subtle.ConstantTimeCompare(h.Fingerprint(secret), stored) == 1
}

// MintAPIKey creates a new API key. The returned Plaintext is the only copy.
func (h *Hasher) MintAPIKey() (Minted, error) {
	lookupRand, err := randomLookup()
	if err != nil {
		return Minted{}, err
	}
	secret, err := randomSecret()
	if err != nil {
		return Minted{}, err
	}

	token := APIKeyPrefix + lookupRand + string(separator) + secret
	return Minted{
		Plaintext: token,
		Lookup:    lookupPrefix + lookupRand,
		// Only the secret half is fingerprinted: the lookup is public, so
		// including it would add nothing while coupling the two.
		HMAC: h.Fingerprint(secret),
	}, nil
}

// MintSMTPPassword creates a password for an SMTP credential. The username is
// the lookup value, since SMTP AUTH transmits it separately.
func (h *Hasher) MintSMTPPassword(username string) (Minted, error) {
	normalized, err := NormalizeSMTPUsername(username)
	if err != nil {
		return Minted{}, err
	}
	secret, err := randomSecret()
	if err != nil {
		return Minted{}, err
	}
	return Minted{
		Plaintext: secret,
		Lookup:    normalized,
		HMAC:      h.Fingerprint(secret),
	}, nil
}

// ParseAPIKey splits a presented bearer token into its lookup and secret halves.
//
// It performs no cryptography and no database access: it only tells the caller
// which row to fetch. A malformed token yields ErrMalformedSecret and must be
// reported to the client as a plain authentication failure.
func ParseAPIKey(token string) (lookup, secret string, err error) {
	token = strings.TrimSpace(token)
	if !strings.HasPrefix(token, APIKeyPrefix) {
		return "", "", fmt.Errorf("%w: missing %q prefix", ErrMalformedSecret, APIKeyPrefix)
	}

	body := token[len(APIKeyPrefix):]
	if len(body) < lookupRandomChars+1 {
		return "", "", fmt.Errorf("%w: token too short", ErrMalformedSecret)
	}
	if body[lookupRandomChars] != separator {
		return "", "", fmt.Errorf("%w: missing separator", ErrMalformedSecret)
	}

	lookupRand := body[:lookupRandomChars]
	secret = body[lookupRandomChars+1:]
	if secret == "" {
		return "", "", fmt.Errorf("%w: empty secret", ErrMalformedSecret)
	}
	if _, decErr := lookupEncoding.DecodeString(lookupRand); decErr != nil {
		return "", "", fmt.Errorf("%w: lookup is not base32", ErrMalformedSecret)
	}
	return lookupPrefix + lookupRand, secret, nil
}

// NormalizeSMTPUsername lowercases and validates an SMTP username.
func NormalizeSMTPUsername(username string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(username))
	if normalized == "" {
		return "", fmt.Errorf("%w: empty SMTP username", ErrMalformedSecret)
	}
	if !smtpUsernamePattern.MatchString(normalized) {
		return "", fmt.Errorf("%w: SMTP username must match %s", ErrMalformedSecret, smtpUsernamePattern)
	}
	return normalized, nil
}

// GenerateSMTPUsername proposes a username when the admin does not supply one.
func GenerateSMTPUsername() (string, error) {
	suffix, err := randomLookup()
	if err != nil {
		return "", err
	}
	return "relais_" + suffix, nil
}

func randomLookup() (string, error) {
	// base32 emits 8 chars per 5 bytes; take enough bytes then truncate.
	buf := make([]byte, 10)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return lookupEncoding.EncodeToString(buf)[:lookupRandomChars], nil
}

func randomSecret() (string, error) {
	buf := make([]byte, secretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	// Raw URL encoding keeps the token safe in an Authorization header and in a
	// URL, and avoids '=' padding that trips naive parsers.
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
