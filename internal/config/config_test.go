package config

import (
	"strings"
	"testing"
	"time"
)

// minimal is the smallest environment that produces a valid configuration.
func minimal() map[string]string {
	return map[string]string{
		"RELAIS_ENV":                      "dev",
		"RELAIS_DB_URL":                   "postgres://user:pass@127.0.0.1:5432/relais",
		"RELAIS_SECRET_ENCRYPTION_KEYS":   "1:aaaa",
		"RELAIS_SECRET_CREDENTIAL_PEPPER": "bbbb",
		"RELAIS_TLS_SELF_SIGNED":          "true",
	}
}

// loadWith builds a configuration from minimal() plus the given overrides. An
// override with an empty value means "this variable is not set at all", which
// only works because LoadFrom replaces the process environment rather than
// layering on top of it.
func loadWith(t *testing.T, overrides map[string]string) *Config {
	t.Helper()
	env := minimal()
	for k, v := range overrides {
		if v == "" {
			delete(env, k)
			continue
		}
		env[k] = v
	}
	cfg, err := LoadFrom(env)
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	return cfg
}

func TestDefaults(t *testing.T) {
	cfg := loadWith(t, nil)

	if cfg.HTTP.Addr != ":8080" {
		t.Fatalf("HTTP.Addr: got %q, want :8080", cfg.HTTP.Addr)
	}
	if cfg.SMTP.Addr != ":587" {
		t.Fatalf("SMTP.Addr: got %q, want :587", cfg.SMTP.Addr)
	}
	if !cfg.HTTP.Enabled || !cfg.SMTP.Enabled || !cfg.Worker.Enabled {
		t.Fatal("subsystems should default to enabled")
	}
	if cfg.Limits.MaxMessageBytes != 10<<20 {
		t.Fatalf("MaxMessageBytes: got %d, want %d", cfg.Limits.MaxMessageBytes, 10<<20)
	}
	if cfg.Retention.IdempotencyTTL != 24*time.Hour {
		t.Fatalf("IdempotencyTTL: got %v, want 24h", cfg.Retention.IdempotencyTTL)
	}
	// An empty OTLP endpoint must not be treated as configured, or every start-up
	// would try to reach a collector that does not exist.
	if cfg.Obs.OTLPEndpoint != "" {
		t.Fatalf("OTLPEndpoint should default to empty, got %q", cfg.Obs.OTLPEndpoint)
	}
	// The client IP header must be opt-in: trusting one by default would let a
	// direct client forge the address recorded on a rejected submission.
	if cfg.HTTP.TrustedProxyHeader != "" {
		t.Fatalf("TrustedProxyHeader should default to empty, got %q", cfg.HTTP.TrustedProxyHeader)
	}
	if cfg.SMTP.Domain == "" {
		t.Fatal("SMTP.Domain should fall back to the hostname")
	}
}

func TestIsProd(t *testing.T) {
	for env, want := range map[string]bool{
		"prod":       true,
		"production": true,
		"PROD":       true,
		"dev":        false,
		"staging":    false,
		"":           false,
	} {
		cfg := &Config{Env: env}
		if got := cfg.IsProd(); got != want {
			t.Fatalf("IsProd(%q) = %v, want %v", env, got, want)
		}
	}
}

func TestValidateRejectsBadValues(t *testing.T) {
	tests := []struct {
		name      string
		overrides map[string]string
		wantText  string
	}{
		{"log level", map[string]string{"RELAIS_OBS_LOG_LEVEL": "verbose"}, "OBS_LOG_LEVEL"},
		{"log format", map[string]string{"RELAIS_OBS_LOG_FORMAT": "xml"}, "OBS_LOG_FORMAT"},
		{"sampling ratio", map[string]string{"RELAIS_OBS_TRACES_SAMPLING": "2"}, "TRACES_SAMPLING"},
		{"otlp endpoint", map[string]string{"RELAIS_OBS_OTLP_ENDPOINT": "collector:4318"}, "OTLP_ENDPOINT"},
		{"tls version", map[string]string{"RELAIS_TLS_MIN_VERSION": "1.1"}, "TLS_MIN_VERSION"},
		{"message size", map[string]string{"RELAIS_LIMITS_MAX_MESSAGE_BYTES": "0"}, "MAX_MESSAGE_BYTES"},
		{"recipients", map[string]string{"RELAIS_LIMITS_MAX_RECIPIENTS": "0"}, "MAX_RECIPIENTS"},
		{"rate limit", map[string]string{"RELAIS_RATELIMIT_RPS": "0"}, "RATELIMIT_RPS"},
		// A request ceiling below the message ceiling is unsatisfiable: base64
		// attachments only ever make a message larger than its JSON body.
		{"request smaller than message", map[string]string{
			"RELAIS_LIMITS_MAX_MESSAGE_BYTES": "1000000",
			"RELAIS_LIMITS_MAX_REQUEST_BYTES": "500000",
		}, "MAX_REQUEST_BYTES"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := minimal()
			for k, v := range tc.overrides {
				env[k] = v
			}
			_, err := LoadFrom(env)
			if err == nil {
				t.Fatal("LoadFrom accepted an invalid configuration")
			}
			if !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("error %q does not mention %q", err, tc.wantText)
			}
		})
	}
}

// Validation reports every problem at once, so a misconfigured deployment does
// not need one restart per mistake.
func TestValidateReportsEveryProblem(t *testing.T) {
	env := minimal()
	env["RELAIS_OBS_LOG_LEVEL"] = "verbose"
	env["RELAIS_OBS_LOG_FORMAT"] = "xml"
	env["RELAIS_LIMITS_MAX_RECIPIENTS"] = "0"

	_, err := LoadFrom(env)
	if err == nil {
		t.Fatal("LoadFrom accepted an invalid configuration")
	}
	for _, want := range []string{"OBS_LOG_LEVEL", "OBS_LOG_FORMAT", "MAX_RECIPIENTS"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err, want)
		}
	}
}

// A configuration test that reads the ambient environment is not a test: it
// reports on the shell that launched it. This one failed in CI while passing
// locally, because CI exports RELAIS_DB_URL for the database-backed tests and
// LoadFrom used to merge that in behind the overlay's back.
func TestLoadFromIgnoresTheProcessEnvironment(t *testing.T) {
	t.Setenv("RELAIS_DB_URL", "postgres://ambient:leaked@127.0.0.1:5432/leaked")
	t.Setenv("RELAIS_HTTP_ADDR", ":9999")

	cfg := loadWith(t, map[string]string{"RELAIS_DB_URL": ""})
	if cfg.Database.URL != "" {
		t.Fatalf("Database.URL leaked from the process environment: %q", cfg.Database.URL)
	}
	if err := cfg.RequireDatabase(); err == nil {
		t.Fatal("RequireDatabase accepted an empty DSN")
	}
	if cfg.HTTP.Addr != ":8080" {
		t.Fatalf("HTTP.Addr came from the environment, not the default: %q", cfg.HTTP.Addr)
	}

	// The nil overlay is the production path and must still read the real
	// environment, or Load would configure nothing.
	live, _ := LoadFrom(nil)
	if live.HTTP.Addr != ":9999" {
		t.Fatalf("a nil overlay ignored the process environment: HTTP.Addr = %q", live.HTTP.Addr)
	}
}

func TestRequireDatabase(t *testing.T) {
	cfg := loadWith(t, map[string]string{"RELAIS_DB_URL": ""})
	if err := cfg.RequireDatabase(); err == nil {
		t.Fatal("RequireDatabase accepted an empty DSN")
	}

	cfg = loadWith(t, map[string]string{"RELAIS_DB_STATEMENT_CACHE_MODE": "magic"})
	if err := cfg.RequireDatabase(); err == nil {
		t.Fatal("RequireDatabase accepted an unknown statement cache mode")
	}

	cfg = loadWith(t, map[string]string{"RELAIS_DB_MIN_CONNS": "20", "RELAIS_DB_MAX_CONNS": "10"})
	if err := cfg.RequireDatabase(); err == nil {
		t.Fatal("RequireDatabase accepted min conns above max conns")
	}
}

func TestRequireSecrets(t *testing.T) {
	cfg := loadWith(t, map[string]string{"RELAIS_SECRET_CREDENTIAL_PEPPER": ""})
	if err := cfg.RequirePepper(); err == nil {
		t.Fatal("RequirePepper accepted a missing pepper")
	}
	cfg = loadWith(t, map[string]string{"RELAIS_SECRET_ENCRYPTION_KEYS": ""})
	if err := cfg.RequireKeyring(); err == nil {
		t.Fatal("RequireKeyring accepted a missing keyring")
	}
}

// The submission server must never come up without TLS: that is what keeps AUTH
// off a plaintext connection. These cases are the whole point of D14.
func TestRequireServeTLSRules(t *testing.T) {
	tests := []struct {
		name      string
		overrides map[string]string
		wantErr   bool
		wantText  string
	}{
		{
			name:      "self-signed in dev is fine",
			overrides: map[string]string{},
			wantErr:   false,
		},
		{
			name: "mounted files are fine",
			overrides: map[string]string{
				"RELAIS_TLS_SELF_SIGNED": "false",
				"RELAIS_TLS_CERT_FILE":   "/certs/tls.crt",
				"RELAIS_TLS_KEY_FILE":    "/certs/tls.key",
			},
			wantErr: false,
		},
		{
			name:      "no certificate source at all",
			overrides: map[string]string{"RELAIS_TLS_SELF_SIGNED": "false"},
			wantErr:   true,
			wantText:  "requires TLS",
		},
		{
			name: "cert without key",
			overrides: map[string]string{
				"RELAIS_TLS_SELF_SIGNED": "false",
				"RELAIS_TLS_CERT_FILE":   "/certs/tls.crt",
			},
			wantErr:  true,
			wantText: "TLS_KEY_FILE",
		},
		{
			name: "key without cert",
			overrides: map[string]string{
				"RELAIS_TLS_SELF_SIGNED": "false",
				"RELAIS_TLS_KEY_FILE":    "/certs/tls.key",
			},
			wantErr:  true,
			wantText: "TLS_CERT_FILE",
		},
		{
			name: "two sources at once is ambiguous",
			overrides: map[string]string{
				"RELAIS_TLS_CERT_FILE": "/certs/tls.crt",
				"RELAIS_TLS_KEY_FILE":  "/certs/tls.key",
			},
			wantErr:  true,
			wantText: "conflicts",
		},
		{
			name:      "self-signed is refused in prod",
			overrides: map[string]string{"RELAIS_ENV": "prod"},
			wantErr:   true,
			wantText:  "refused",
		},
		{
			name: "...unless explicitly overridden",
			overrides: map[string]string{
				"RELAIS_ENV":                           "prod",
				"RELAIS_TLS_SELF_SIGNED_ALLOW_IN_PROD": "true",
			},
			wantErr: false,
		},
		{
			name: "TLS is irrelevant when the submission server is off",
			overrides: map[string]string{
				"RELAIS_SMTP_ENABLED":    "false",
				"RELAIS_TLS_SELF_SIGNED": "false",
			},
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := loadWith(t, tc.overrides)
			err := cfg.RequireServe()
			switch {
			case tc.wantErr && err == nil:
				t.Fatal("RequireServe accepted a configuration it should refuse")
			case !tc.wantErr && err != nil:
				t.Fatalf("RequireServe: %v", err)
			case tc.wantErr && !strings.Contains(err.Error(), tc.wantText):
				t.Fatalf("error %q does not mention %q", err, tc.wantText)
			}
		})
	}
}

func TestRequireServeRejectsAnIdleProcess(t *testing.T) {
	cfg := loadWith(t, map[string]string{
		"RELAIS_HTTP_ENABLED":   "false",
		"RELAIS_SMTP_ENABLED":   "false",
		"RELAIS_WORKER_ENABLED": "false",
	})
	err := cfg.RequireServe()
	if err == nil {
		t.Fatal("RequireServe accepted a process with nothing to run")
	}
	if !strings.Contains(err.Error(), "nothing to run") {
		t.Fatalf("error %q does not explain the problem", err)
	}
}

// An issuer without an expected audience accepts tokens minted for any other
// client of the same identity provider.
func TestRequireServeRejectsIssuerWithoutAudience(t *testing.T) {
	cfg := loadWith(t, map[string]string{
		"RELAIS_OIDC_ISSUER": "https://auth.example.com/application/o/relais/",
	})
	if err := cfg.RequireServe(); err == nil {
		t.Fatal("RequireServe accepted an OIDC issuer with no audience")
	}

	cfg = loadWith(t, map[string]string{
		"RELAIS_OIDC_ISSUER":   "https://auth.example.com/application/o/relais/",
		"RELAIS_OIDC_AUDIENCE": "relais",
	})
	if err := cfg.RequireServe(); err != nil {
		t.Fatalf("RequireServe: %v", err)
	}
}

func TestOTLPHeadersParse(t *testing.T) {
	cfg := loadWith(t, map[string]string{
		"RELAIS_OBS_OTLP_ENDPOINT": "http://collector:4318/",
		"RELAIS_OBS_OTLP_HEADERS":  "authorization:Bearer xyz,x-team:abc",
	})
	if cfg.Obs.OTLPHeaders["authorization"] != "Bearer xyz" {
		t.Fatalf("OTLPHeaders: got %v", cfg.Obs.OTLPHeaders)
	}
	// The trailing slash is trimmed so that appending "/v1/logs" cannot produce a
	// double slash the collector may not route.
	if cfg.Obs.OTLPEndpoint != "http://collector:4318" {
		t.Fatalf("OTLPEndpoint: got %q, want the trailing slash trimmed", cfg.Obs.OTLPEndpoint)
	}
}
