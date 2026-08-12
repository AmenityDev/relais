// Package oidctest runs a throwaway OpenID Connect issuer for tests.
//
// It is a real HTTP server serving a real discovery document and a real JWKS, and
// it mints real RS256-signed tokens. That matters: what the admin API must
// guarantee is that a token is refused unless it was signed by the configured
// issuer, and only an actual signature check can demonstrate that. A stubbed
// verifier would assert nothing about the property that keeps the admin API shut.
package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Issuer is a running fake identity provider.
type Issuer struct {
	// URL is the issuer identifier, which is also the discovery base.
	URL string
	// Audience is the client id tokens are minted for by default.
	Audience string

	t      *testing.T
	server *httptest.Server
	key    *rsa.PrivateKey
	keyID  string
}

// Claims describes a token to mint. Every field has a sane default so a test only
// states what it is actually varying.
type Claims struct {
	Subject string
	Email   string
	Name    string
	Groups  []string

	// Audience overrides the issuer's default, for testing that a token minted for
	// another client is refused.
	Audience string
	// Issuer overrides the real one, for testing that a token claiming to be from
	// somewhere else is refused.
	Issuer string
	// IssuedAt and Expiry default to now and one hour from now. A negative Expiry
	// mints an expired token.
	IssuedAt time.Time
	Expiry   time.Time

	// Extra adds arbitrary claims, for a differently-named groups claim.
	Extra map[string]any
}

// Start launches an issuer and stops it when the test ends.
func Start(t *testing.T, audience string) *Issuer {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate the issuer key: %v", err)
	}

	issuer := &Issuer{t: t, Audience: audience, key: key, keyID: "test-key-1"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                issuer.URL,
			"authorization_endpoint":                issuer.URL + "/authorize",
			"token_endpoint":                        issuer.URL + "/token",
			"jwks_uri":                              issuer.URL + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{{
				Key:       &key.PublicKey,
				KeyID:     issuer.keyID,
				Algorithm: string(jose.RS256),
				Use:       "sig",
			}},
		})
	})

	issuer.server = httptest.NewServer(mux)
	issuer.URL = issuer.server.URL
	t.Cleanup(issuer.server.Close)

	return issuer
}

// JWKSURL is the key set endpoint, for configuring a verifier without discovery.
func (i *Issuer) JWKSURL() string { return i.URL + "/jwks" }

// Close stops the issuer early, for testing how a caller behaves when the provider
// becomes unreachable.
func (i *Issuer) Close() { i.server.Close() }

// Token mints a signed token.
func (i *Issuer) Token(claims Claims) string {
	i.t.Helper()
	return i.sign(claims, i.key, i.keyID)
}

// TokenSignedByAnotherKey mints a well-formed token signed by a key the issuer
// does not publish — the shape a forged token takes.
func (i *Issuer) TokenSignedByAnotherKey(claims Claims) string {
	i.t.Helper()

	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		i.t.Fatalf("generate a second key: %v", err)
	}
	// The same key id, so the verifier looks up a key it knows and finds the
	// signature does not match, rather than simply failing to find a key.
	return i.sign(claims, other, i.keyID)
}

func (i *Issuer) sign(claims Claims, key *rsa.PrivateKey, keyID string) string {
	i.t.Helper()

	if claims.Subject == "" {
		claims.Subject = "test-subject"
	}
	if claims.Audience == "" {
		claims.Audience = i.Audience
	}
	if claims.Issuer == "" {
		claims.Issuer = i.URL
	}
	if claims.IssuedAt.IsZero() {
		claims.IssuedAt = time.Now()
	}
	if claims.Expiry.IsZero() {
		claims.Expiry = time.Now().Add(time.Hour)
	}

	payload := map[string]any{
		"iss": claims.Issuer,
		"sub": claims.Subject,
		"aud": claims.Audience,
		"iat": claims.IssuedAt.Unix(),
		"exp": claims.Expiry.Unix(),
	}
	if claims.Email != "" {
		payload["email"] = claims.Email
	}
	if claims.Name != "" {
		payload["name"] = claims.Name
	}
	if claims.Groups != nil {
		payload["groups"] = claims.Groups
	}
	for name, value := range claims.Extra {
		payload[name] = value
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		i.t.Fatalf("encode claims: %v", err)
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", keyID),
	)
	if err != nil {
		i.t.Fatalf("build a signer: %v", err)
	}

	signed, err := signer.Sign(encoded)
	if err != nil {
		i.t.Fatalf("sign the token: %v", err)
	}
	serialized, err := signed.CompactSerialize()
	if err != nil {
		i.t.Fatalf("serialize the token: %v", err)
	}
	return serialized
}
