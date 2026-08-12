// Package config loads the whole service configuration from the environment.
//
// Two rules hold everywhere in this package:
//
//   - Loading never reaches out to the network, the filesystem or the database.
//     It only parses and shape-checks, so that a bad deployment fails in
//     milliseconds with a precise message instead of half-starting.
//   - Secrets are kept as opaque strings here. Parsing and validating them is
//     the job of internal/crypto, which owns the key formats.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
)

// Config is the fully resolved configuration of a relais process.
type Config struct {
	// Env is a free-form deployment name ("prod", "staging", "dev"). It is
	// attached to every log line and span as deployment.environment.
	Env         string `env:"ENV" envDefault:"prod"`
	ServiceName string `env:"SERVICE_NAME" envDefault:"relais"`

	Database  Database  `envPrefix:"DB_"`
	HTTP      HTTP      `envPrefix:"HTTP_"`
	Admin     Admin     `envPrefix:"ADMIN_"`
	SMTP      SMTP      `envPrefix:"SMTP_"`
	TLS       TLS       `envPrefix:"TLS_"`
	Worker    Worker    `envPrefix:"WORKER_"`
	Sender    Sender    `envPrefix:"SENDER_"`
	Secrets   Secrets   `envPrefix:"SECRET_"`
	RateLimit RateLimit `envPrefix:"RATELIMIT_"`
	Retention Retention `envPrefix:"RETENTION_"`
	OIDC      OIDC      `envPrefix:"OIDC_"`
	Obs       Obs       `envPrefix:"OBS_"`
	Limits    Limits    `envPrefix:"LIMITS_"`
}

// Database holds the Postgres connection settings. No assumption is made about
// the topology: a single DSN is used, so Patroni/HAProxy/pgbouncer sit
// transparently behind it.
type Database struct {
	URL             string        `env:"URL"`
	MaxConns        int32         `env:"MAX_CONNS" envDefault:"10"`
	MinConns        int32         `env:"MIN_CONNS" envDefault:"0"`
	MaxConnLifetime time.Duration `env:"MAX_CONN_LIFETIME" envDefault:"1h"`
	MaxConnIdleTime time.Duration `env:"MAX_CONN_IDLE_TIME" envDefault:"30m"`
	ConnectTimeout  time.Duration `env:"CONNECT_TIMEOUT" envDefault:"10s"`
	// StatementCacheMode is exposed because pgbouncer in transaction pooling
	// mode requires "describe" (or "none") instead of pgx's default prepared
	// statement cache.
	StatementCacheMode string `env:"STATEMENT_CACHE_MODE" envDefault:"prepare"`
}

// HTTP configures the REST + admin API listener. TLS is deliberately absent:
// the HTTP surface is meant to sit behind Coolify's reverse proxy.
type HTTP struct {
	Enabled           bool          `env:"ENABLED" envDefault:"true"`
	Addr              string        `env:"ADDR" envDefault:":8080"`
	ReadHeaderTimeout time.Duration `env:"READ_HEADER_TIMEOUT" envDefault:"10s"`
	ReadTimeout       time.Duration `env:"READ_TIMEOUT" envDefault:"60s"`
	WriteTimeout      time.Duration `env:"WRITE_TIMEOUT" envDefault:"60s"`
	IdleTimeout       time.Duration `env:"IDLE_TIMEOUT" envDefault:"120s"`
	ShutdownTimeout   time.Duration `env:"SHUTDOWN_TIMEOUT" envDefault:"20s"`
	// TrustedProxyHeader names the header carrying the real client IP
	// ("X-Forwarded-For", "CF-Connecting-IP"). Empty means the header is
	// ignored and the socket peer address is used, which is the safe default:
	// an attacker-controlled header must never be able to forge the IP we log
	// on a validation rejection.
	TrustedProxyHeader string `env:"TRUSTED_PROXY_HEADER"`
}

// Admin configures the admin API's own listener.
//
// It is separate from the public one on purpose (D15). If /v1 and /admin/v1 shared
// a port, publishing /v1 for an external application would make the admin API
// reachable on the same hostname, protected by the OIDC check alone. With two
// listeners, exposure is a network decision rather than a routing rule nobody must
// get wrong.
type Admin struct {
	Enabled bool `env:"ENABLED" envDefault:"true"`
	// Addr defaults to a different port from HTTP_ADDR so the separation holds
	// even if an operator changes neither.
	Addr              string        `env:"ADDR" envDefault:":8081"`
	ReadHeaderTimeout time.Duration `env:"READ_HEADER_TIMEOUT" envDefault:"10s"`
	ReadTimeout       time.Duration `env:"READ_TIMEOUT" envDefault:"30s"`
	WriteTimeout      time.Duration `env:"WRITE_TIMEOUT" envDefault:"30s"`
	IdleTimeout       time.Duration `env:"IDLE_TIMEOUT" envDefault:"120s"`
	ShutdownTimeout   time.Duration `env:"SHUTDOWN_TIMEOUT" envDefault:"20s"`
	// MaxRequestBytes bounds an admin request body. Admin payloads are small; the
	// limit exists so a mistake cannot become a memory problem.
	MaxRequestBytes int64 `env:"MAX_REQUEST_BYTES" envDefault:"1048576"`
	// TrustedProxyHeader behaves as its HTTP counterpart, and defaults to empty for
	// the same reason.
	TrustedProxyHeader string `env:"TRUSTED_PROXY_HEADER"`
	// PageSize is the default and maximum number of rows a list endpoint returns.
	PageSize    int `env:"PAGE_SIZE" envDefault:"50"`
	MaxPageSize int `env:"MAX_PAGE_SIZE" envDefault:"200"`
}

// SMTP configures the submission server.
type SMTP struct {
	Enabled bool `env:"ENABLED" envDefault:"true"`
	// Addr is the STARTTLS submission listener (RFC 6409 port 587).
	Addr string `env:"ADDR" envDefault:":587"`
	// TLSAddr is the implicit-TLS listener (port 465). Empty disables it.
	TLSAddr string `env:"TLS_ADDR"`
	// Domain is the hostname advertised in the EHLO banner. Defaults to the
	// OS hostname.
	Domain          string        `env:"DOMAIN"`
	ReadTimeout     time.Duration `env:"READ_TIMEOUT" envDefault:"1m"`
	WriteTimeout    time.Duration `env:"WRITE_TIMEOUT" envDefault:"1m"`
	ShutdownTimeout time.Duration `env:"SHUTDOWN_TIMEOUT" envDefault:"20s"`
	MaxConnections  int           `env:"MAX_CONNECTIONS" envDefault:"100"`
}

// TLS resolves the certificate used by the SMTP listeners. The HTTP surface
// never uses it (see HTTP).
type TLS struct {
	CertFile string `env:"CERT_FILE"`
	KeyFile  string `env:"KEY_FILE"`
	// SelfSigned generates an in-process certificate at startup. Intended for
	// tests and local development; refused when Env is "prod" unless
	// SelfSignedAllowInProd is set, because silently serving an untrusted
	// certificate to real clients is worse than failing to boot.
	SelfSigned            bool          `env:"SELF_SIGNED" envDefault:"false"`
	SelfSignedAllowInProd bool          `env:"SELF_SIGNED_ALLOW_IN_PROD" envDefault:"false"`
	SelfSignedHosts       []string      `env:"SELF_SIGNED_HOSTS" envSeparator:"," envDefault:"localhost,127.0.0.1,::1"`
	SelfSignedValidity    time.Duration `env:"SELF_SIGNED_VALIDITY" envDefault:"8760h"`
	// SelfSignedDir persists the generated pair so that restarts keep the same
	// certificate (handy when a test client pins it). Empty keeps it in memory.
	SelfSignedDir string `env:"SELF_SIGNED_DIR"`
	// MinVersion is the minimum accepted TLS version ("1.2" or "1.3").
	MinVersion string `env:"MIN_VERSION" envDefault:"1.2"`
}

// Worker configures the river client embedded in this process.
type Worker struct {
	Enabled bool `env:"ENABLED" envDefault:"true"`
	// Count is the number of concurrent send jobs for the whole process. The
	// per-backend ceiling is a separate, database-driven setting
	// (smtp_backend.max_concurrency).
	Count           int           `env:"COUNT" envDefault:"5"`
	ShutdownTimeout time.Duration `env:"SHUTDOWN_TIMEOUT" envDefault:"30s"`
	// MaxAttempts bounds delivery retries on transient (4xx) SMTP failures.
	MaxAttempts int `env:"MAX_ATTEMPTS" envDefault:"8"`
	// JobTimeout caps a single delivery attempt.
	JobTimeout time.Duration `env:"JOB_TIMEOUT" envDefault:"2m"`
}

// Sender configures outbound delivery to the relays.
type Sender struct {
	// Timeout bounds a whole delivery attempt, from dial to QUIT. go-smtp's own
	// defaults are 5 and 12 minutes, which would let one silent relay hold a
	// worker for a quarter of an hour.
	Timeout time.Duration `env:"TIMEOUT" envDefault:"2m"`
	// HeloName is the EHLO name presented to a relay that does not override it.
	// Empty falls back to the SMTP domain.
	HeloName string `env:"HELO_NAME"`
	// MinTLSVersion applies to outbound connections ("1.2" or "1.3").
	MinTLSVersion string `env:"MIN_TLS_VERSION" envDefault:"1.2"`
	// InsecureVerifyExemptHosts lists relay hostnames whose certificate is not
	// verified. It exists for a local development sink with a generated
	// certificate, and the sender additionally refuses to honour it for any host
	// that is not loopback or private — so there is no single variable that
	// disables verification in production.
	InsecureVerifyExemptHosts []string `env:"INSECURE_VERIFY_EXEMPT_HOSTS" envSeparator:","`
}

// Secrets carries the two independent key materials the service needs. They are
// intentionally separate: the pepper is only ever used for one-way HMAC of
// sender credentials, the keyring is reversible and only unwraps backend
// passwords. Reusing one key for both would let a pepper leak become a
// decryption capability.
type Secrets struct {
	// EncryptionKeys is a comma-separated list of "<id>:<base64 32 bytes>"
	// entries, e.g. "1:aGVs...,2:d29y...".
	EncryptionKeys string `env:"ENCRYPTION_KEYS"`
	// EncryptionActiveKey is the key id used for new writes. It may be omitted
	// when exactly one key is configured.
	EncryptionActiveKey string `env:"ENCRYPTION_ACTIVE_KEY"`
	// CredentialPepper is a base64-encoded 32-byte HMAC key. A database dump
	// without it cannot be tested against candidate secrets.
	CredentialPepper string `env:"CREDENTIAL_PEPPER"`
}

// RateLimit holds the default per-credential ingestion limits, applied when a
// credential does not override them in the database. Limits are enforced
// per process, not cluster-wide.
type RateLimit struct {
	RPS   float64 `env:"RPS" envDefault:"10"`
	Burst int     `env:"BURST" envDefault:"20"`
	// RejectedRPS throttles how fast a single credential can create rejection
	// rows, so a compromised credential cannot flood email_message. Rejections
	// beyond this are still refused and logged, just not persisted.
	RejectedRPS   float64 `env:"REJECTED_RPS" envDefault:"1"`
	RejectedBurst int     `env:"REJECTED_BURST" envDefault:"10"`
	// MaxCredentials caps the in-memory limiter table to bound memory use.
	MaxCredentials int `env:"MAX_CREDENTIALS" envDefault:"10000"`
}

// Retention controls how long raw message payloads are kept. The payload is
// only needed until delivery succeeds; keeping failed ones longer allows a
// manual replay.
type Retention struct {
	Sent   time.Duration `env:"PAYLOAD_SENT" envDefault:"24h"`
	Failed time.Duration `env:"PAYLOAD_FAILED" envDefault:"168h"`
	// Interval is how often the purge job runs.
	Interval time.Duration `env:"PURGE_INTERVAL" envDefault:"1h"`
	// IdempotencyTTL is how long an Idempotency-Key stays bound to its result.
	IdempotencyTTL time.Duration `env:"IDEMPOTENCY_TTL" envDefault:"24h"`
}

// OIDC configures admin authentication. Tokens are issued by Authentik and
// validated here against the issuer's JWKS; relais never handles a password.
type OIDC struct {
	Issuer   string `env:"ISSUER"`
	Audience string `env:"AUDIENCE"`
	// JWKSURL skips OIDC discovery when set. Discovery already happens lazily, on
	// the first admin request rather than at startup, so that a provider outage
	// never stops relais from relaying mail; setting this removes even that first
	// dependency.
	JWKSURL string `env:"JWKS_URL"`
	// DiscoveryTimeout bounds one discovery attempt, and DiscoveryRetryAfter is how
	// long a failure is remembered so a down provider is not asked once per
	// request.
	DiscoveryTimeout    time.Duration `env:"DISCOVERY_TIMEOUT" envDefault:"10s"`
	DiscoveryRetryAfter time.Duration `env:"DISCOVERY_RETRY_AFTER" envDefault:"15s"`
	// GroupsClaim is the token claim holding group membership.
	GroupsClaim string `env:"GROUPS_CLAIM" envDefault:"groups"`
	AdminGroup  string `env:"ADMIN_GROUP" envDefault:"relais-admin"`
	ViewerGroup string `env:"VIEWER_GROUP" envDefault:"relais-viewer"`
}

// Obs configures logging and tracing export.
type Obs struct {
	LogLevel string `env:"LOG_LEVEL" envDefault:"info"`
	// LogFormat is "json" (production) or "text" (human-readable dev output).
	LogFormat string `env:"LOG_FORMAT" envDefault:"json"`
	// OTLPEndpoint is the base URL of the OTLP/HTTP collector, e.g.
	// "http://clickstack:4318". Empty disables OTLP export entirely and keeps
	// stdout logging only.
	OTLPEndpoint string `env:"OTLP_ENDPOINT"`
	// OTLPHeaders carries extra headers such as an ingestion key:
	// "authorization=Bearer xxx,x-team=abc".
	OTLPHeaders map[string]string `env:"OTLP_HEADERS"`
	OTLPTimeout time.Duration     `env:"OTLP_TIMEOUT" envDefault:"10s"`
	// TracesEnabled turns span export on. Logs are exported whenever
	// OTLPEndpoint is set.
	TracesEnabled  bool    `env:"TRACES_ENABLED" envDefault:"true"`
	TracesSampling float64 `env:"TRACES_SAMPLING" envDefault:"1.0"`
}

// Limits bounds message size and fan-out. Both façades enforce the same values
// so that a message accepted over SMTP could equally have been accepted over
// REST.
type Limits struct {
	// MaxMessageBytes is the size ceiling of the assembled RFC 5322 message.
	MaxMessageBytes int64 `env:"MAX_MESSAGE_BYTES" envDefault:"10485760"`
	// MaxRequestBytes bounds the REST JSON body. It is larger than
	// MaxMessageBytes because base64 attachments inflate by ~4/3 and JSON adds
	// its own overhead.
	MaxRequestBytes int64 `env:"MAX_REQUEST_BYTES" envDefault:"15728640"`
	// MaxRecipients is the total count of To+Cc+Bcc addresses. OCI Email
	// Delivery caps recipients per message; failing here yields a clear error
	// instead of an opaque 5xx from the backend.
	MaxRecipients int `env:"MAX_RECIPIENTS" envDefault:"50"`
	// MaxHeaderCount and MaxHeaderBytes guard against header-stuffing.
	MaxHeaderCount int   `env:"MAX_HEADER_COUNT" envDefault:"200"`
	MaxHeaderBytes int64 `env:"MAX_HEADER_BYTES" envDefault:"131072"`
}

// envPrefix namespaces every variable, so RELAIS_DB_URL, RELAIS_SMTP_ADDR, etc.
const envPrefix = "RELAIS_"

// Load reads the configuration from the process environment.
//
// It returns a Config even when validation fails, so callers may inspect what
// was parsed while reporting the error.
func Load() (*Config, error) {
	return LoadFrom(nil)
}

// LoadFrom reads the configuration, overlaying the given map on top of the
// process environment. It exists for tests; production code calls Load.
func LoadFrom(overlay map[string]string) (*Config, error) {
	cfg := &Config{}
	opts := env.Options{Prefix: envPrefix, Environment: overlay, UseFieldNameByDefault: false}
	if overlay != nil {
		merged := env.ToMap(os.Environ())
		for k, v := range overlay {
			merged[k] = v
		}
		opts.Environment = merged
	}
	if err := env.ParseWithOptions(cfg, opts); err != nil {
		return cfg, fmt.Errorf("parse environment: %w", err)
	}
	cfg.applyDefaults()
	return cfg, cfg.Validate()
}

func (c *Config) applyDefaults() {
	if c.SMTP.Domain == "" {
		if h, err := os.Hostname(); err == nil && h != "" {
			c.SMTP.Domain = h
		} else {
			c.SMTP.Domain = "localhost"
		}
	}
	c.Env = strings.TrimSpace(c.Env)
	c.Obs.LogLevel = strings.ToLower(strings.TrimSpace(c.Obs.LogLevel))
	c.Obs.LogFormat = strings.ToLower(strings.TrimSpace(c.Obs.LogFormat))
	c.Obs.OTLPEndpoint = strings.TrimRight(strings.TrimSpace(c.Obs.OTLPEndpoint), "/")
}

// IsProd reports whether this process considers itself production. It gates the
// few places where a convenience default would be dangerous.
func (c *Config) IsProd() bool {
	switch strings.ToLower(c.Env) {
	case "prod", "production":
		return true
	default:
		return false
	}
}

// Validate checks the invariants that hold for every subcommand. Requirements
// specific to a subcommand live in the Require* methods.
func (c *Config) Validate() error {
	var errs []error

	switch c.Obs.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("%sOBS_LOG_LEVEL: want one of debug|info|warn|error, got %q", envPrefix, c.Obs.LogLevel))
	}
	switch c.Obs.LogFormat {
	case "json", "text":
	default:
		errs = append(errs, fmt.Errorf("%sOBS_LOG_FORMAT: want json|text, got %q", envPrefix, c.Obs.LogFormat))
	}
	if c.Obs.TracesSampling < 0 || c.Obs.TracesSampling > 1 {
		errs = append(errs, fmt.Errorf("%sOBS_TRACES_SAMPLING: want a ratio in [0,1], got %v", envPrefix, c.Obs.TracesSampling))
	}
	if c.Obs.OTLPEndpoint != "" && !strings.HasPrefix(c.Obs.OTLPEndpoint, "http://") && !strings.HasPrefix(c.Obs.OTLPEndpoint, "https://") {
		errs = append(errs, fmt.Errorf("%sOBS_OTLP_ENDPOINT: want an http(s) URL, got %q", envPrefix, c.Obs.OTLPEndpoint))
	}

	switch c.TLS.MinVersion {
	case "1.2", "1.3":
	default:
		errs = append(errs, fmt.Errorf("%sTLS_MIN_VERSION: want 1.2|1.3, got %q", envPrefix, c.TLS.MinVersion))
	}
	switch c.Sender.MinTLSVersion {
	case "1.2", "1.3":
	default:
		errs = append(errs, fmt.Errorf("%sSENDER_MIN_TLS_VERSION: want 1.2|1.3, got %q", envPrefix, c.Sender.MinTLSVersion))
	}
	if c.Sender.Timeout <= 0 {
		errs = append(errs, fmt.Errorf("%sSENDER_TIMEOUT: want > 0", envPrefix))
	}

	if c.Limits.MaxMessageBytes <= 0 {
		errs = append(errs, fmt.Errorf("%sLIMITS_MAX_MESSAGE_BYTES: want > 0", envPrefix))
	}
	if c.Limits.MaxRequestBytes < c.Limits.MaxMessageBytes {
		errs = append(errs, fmt.Errorf("%sLIMITS_MAX_REQUEST_BYTES (%d) must be >= %sLIMITS_MAX_MESSAGE_BYTES (%d): base64 attachments only ever grow the message",
			envPrefix, c.Limits.MaxRequestBytes, envPrefix, c.Limits.MaxMessageBytes))
	}
	if c.Limits.MaxRecipients <= 0 {
		errs = append(errs, fmt.Errorf("%sLIMITS_MAX_RECIPIENTS: want > 0", envPrefix))
	}

	if c.RateLimit.RPS <= 0 {
		errs = append(errs, fmt.Errorf("%sRATELIMIT_RPS: want > 0", envPrefix))
	}
	if c.RateLimit.Burst <= 0 {
		errs = append(errs, fmt.Errorf("%sRATELIMIT_BURST: want > 0", envPrefix))
	}

	if c.Retention.Interval <= 0 {
		errs = append(errs, fmt.Errorf("%sRETENTION_PURGE_INTERVAL: want > 0", envPrefix))
	}

	return errors.Join(errs...)
}

// RequireDatabase asserts a usable DSN. Every subcommand needs it except keygen.
func (c *Config) RequireDatabase() error {
	if strings.TrimSpace(c.Database.URL) == "" {
		return fmt.Errorf("%sDB_URL is required", envPrefix)
	}
	if c.Database.MaxConns <= 0 {
		return fmt.Errorf("%sDB_MAX_CONNS: want > 0", envPrefix)
	}
	if c.Database.MinConns < 0 || c.Database.MinConns > c.Database.MaxConns {
		return fmt.Errorf("%sDB_MIN_CONNS: want between 0 and %sDB_MAX_CONNS", envPrefix, envPrefix)
	}
	switch c.Database.StatementCacheMode {
	case "prepare", "describe", "none":
	default:
		return fmt.Errorf("%sDB_STATEMENT_CACHE_MODE: want prepare|describe|none, got %q", envPrefix, c.Database.StatementCacheMode)
	}
	return nil
}

// RequirePepper asserts that sender credentials can be hashed and verified.
func (c *Config) RequirePepper() error {
	if strings.TrimSpace(c.Secrets.CredentialPepper) == "" {
		return fmt.Errorf("%sSECRET_CREDENTIAL_PEPPER is required (generate one with `relais keygen pepper`)", envPrefix)
	}
	return nil
}

// RequireKeyring asserts that backend passwords can be sealed and opened.
func (c *Config) RequireKeyring() error {
	if strings.TrimSpace(c.Secrets.EncryptionKeys) == "" {
		return fmt.Errorf("%sSECRET_ENCRYPTION_KEYS is required (generate one with `relais keygen key`)", envPrefix)
	}
	return nil
}

// RequireServe asserts everything needed by `relais serve`.
func (c *Config) RequireServe() error {
	var errs []error
	errs = append(errs, c.RequireDatabase(), c.RequirePepper(), c.RequireKeyring())

	if !c.HTTP.Enabled && !c.SMTP.Enabled && !c.Worker.Enabled && !c.AdminEnabled() {
		errs = append(errs, fmt.Errorf("nothing to run: %sHTTP_ENABLED, %sADMIN_ENABLED, %sSMTP_ENABLED and %sWORKER_ENABLED are all false",
			envPrefix, envPrefix, envPrefix, envPrefix))
	}
	if c.Admin.Enabled && c.OIDC.Issuer != "" && c.Admin.Addr == c.HTTP.Addr {
		// Sharing the port would silently undo D15: publishing the public listener
		// would publish the admin API with it.
		errs = append(errs, fmt.Errorf("%sADMIN_ADDR must differ from %sHTTP_ADDR: the admin API is kept on its own listener so that exposing one does not expose the other",
			envPrefix, envPrefix))
	}
	if c.Worker.Enabled {
		if c.Worker.Count <= 0 {
			errs = append(errs, fmt.Errorf("%sWORKER_COUNT: want > 0", envPrefix))
		}
		if c.Worker.MaxAttempts <= 0 {
			errs = append(errs, fmt.Errorf("%sWORKER_MAX_ATTEMPTS: want > 0", envPrefix))
		}
	}
	if c.SMTP.Enabled {
		errs = append(errs, c.requireTLS())
	}
	if c.AdminEnabled() && c.OIDC.Audience == "" {
		errs = append(errs, fmt.Errorf("%sOIDC_AUDIENCE is required when %sOIDC_ISSUER is set: an issuer without an expected audience accepts tokens minted for other clients", envPrefix, envPrefix))
	}
	return errors.Join(errs...)
}

// AdminEnabled reports whether the admin API will actually serve.
//
// It needs both the switch and an issuer: without an issuer there is no way to
// authenticate an admin, and an unauthenticated admin API would be worse than no
// admin API at all.
func (c *Config) AdminEnabled() bool {
	return c.Admin.Enabled && strings.TrimSpace(c.OIDC.Issuer) != ""
}

// requireTLS enforces that the submission server has a certificate. There is no
// "plaintext AUTH" escape hatch: STARTTLS must be available or the listener
// must not start.
func (c *Config) requireTLS() error {
	hasFiles := c.TLS.CertFile != "" && c.TLS.KeyFile != ""

	switch {
	case c.TLS.CertFile != "" && c.TLS.KeyFile == "":
		return fmt.Errorf("%sTLS_KEY_FILE is required alongside %sTLS_CERT_FILE", envPrefix, envPrefix)
	case c.TLS.KeyFile != "" && c.TLS.CertFile == "":
		return fmt.Errorf("%sTLS_CERT_FILE is required alongside %sTLS_KEY_FILE", envPrefix, envPrefix)
	case hasFiles && c.TLS.SelfSigned:
		return fmt.Errorf("%sTLS_SELF_SIGNED conflicts with %sTLS_CERT_FILE: pick one certificate source", envPrefix, envPrefix)
	case !hasFiles && !c.TLS.SelfSigned:
		return fmt.Errorf("the SMTP submission server requires TLS: set %sTLS_CERT_FILE and %sTLS_KEY_FILE, or %sTLS_SELF_SIGNED=true for local use",
			envPrefix, envPrefix, envPrefix)
	case c.TLS.SelfSigned && c.IsProd() && !c.TLS.SelfSignedAllowInProd:
		return fmt.Errorf("%sTLS_SELF_SIGNED is refused when %sENV=%s: mount a real certificate, or set %sTLS_SELF_SIGNED_ALLOW_IN_PROD=true if you really mean it",
			envPrefix, envPrefix, c.Env, envPrefix)
	case c.TLS.SelfSigned && len(c.TLS.SelfSignedHosts) == 0:
		return fmt.Errorf("%sTLS_SELF_SIGNED_HOSTS must not be empty", envPrefix)
	}
	return nil
}
