// Package tlsconf resolves the certificate used by the SMTP listeners.
//
// Two sources are supported, and exactly one is chosen by configuration:
//
//   - Mounted PEM files, which is how production works. Any tool that writes a
//     cert to disk fits (certbot, Caddy, cert-manager, a mounted volume), and
//     Reload picks up a renewal without a restart.
//   - A generated self-signed certificate, for tests and local development.
//     It is refused in a production environment unless explicitly forced,
//     because quietly serving an untrusted certificate is worse than not
//     starting.
//
// The HTTP surface never uses this package: it is expected to sit behind a
// TLS-terminating reverse proxy.
package tlsconf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/amenitydev/relais/internal/config"
)

const (
	selfSignedCertName = "relais-selfsigned.crt"
	selfSignedKeyName  = "relais-selfsigned.key"
	// clockSkew backdates generated certificates so a client whose clock runs
	// slightly behind still accepts them.
	clockSkew = time.Hour
)

// Source describes where the active certificate came from, for logging.
type Source string

const (
	SourceFiles      Source = "files"
	SourceSelfSigned Source = "self-signed"
)

// Provider holds the active certificate and hands out *tls.Config values that
// always read the current one.
//
// It is safe for concurrent use: listeners resolve the certificate per handshake
// through GetCertificate, so a Reload takes effect on the next connection
// without touching the listener.
type Provider struct {
	source     Source
	minVersion uint16
	load       func() (*tls.Certificate, error)

	mu   sync.RWMutex
	cert *tls.Certificate
}

// New builds a Provider from the configuration.
//
// The certificate is loaded eagerly: a missing or unreadable certificate must
// fail at startup, not on the first client connection.
func New(cfg *config.Config, log *slog.Logger) (*Provider, error) {
	minVersion, err := parseMinVersion(cfg.TLS.MinVersion)
	if err != nil {
		return nil, err
	}

	p := &Provider{minVersion: minVersion}

	switch {
	case cfg.TLS.CertFile != "" && cfg.TLS.KeyFile != "":
		p.source = SourceFiles
		certFile, keyFile := cfg.TLS.CertFile, cfg.TLS.KeyFile
		p.load = func() (*tls.Certificate, error) { return loadFiles(certFile, keyFile) }

	case cfg.TLS.SelfSigned:
		if cfg.IsProd() && !cfg.TLS.SelfSignedAllowInProd {
			// Config validation already refuses this; the duplicate check keeps
			// the guarantee if the package is ever used directly.
			return nil, errors.New("refusing to generate a self-signed certificate in a production environment")
		}
		p.source = SourceSelfSigned
		opts := SelfSignedOptions{
			Hosts:     cfg.TLS.SelfSignedHosts,
			Validity:  cfg.TLS.SelfSignedValidity,
			CacheDir:  cfg.TLS.SelfSignedDir,
			LogWriter: log,
		}
		p.load = func() (*tls.Certificate, error) { return selfSigned(opts) }

	default:
		return nil, errors.New("no TLS certificate source configured")
	}

	if err := p.Reload(); err != nil {
		return nil, err
	}

	if log != nil {
		log.Info("tls certificate loaded",
			slog.String("source", string(p.source)),
			slog.String("fingerprint", p.Fingerprint()),
			slog.Time("not_after", p.NotAfter()),
		)
		if p.source == SourceSelfSigned {
			log.Warn("serving a self-signed certificate: clients must be configured to trust it",
				slog.String("fingerprint", p.Fingerprint()))
		}
	}
	return p, nil
}

// Reload re-reads the certificate from its source and swaps it in atomically.
//
// A failed reload leaves the previous certificate in place: a botched renewal
// must not take the listener down.
func (p *Provider) Reload() error {
	cert, err := p.load()
	if err != nil {
		return fmt.Errorf("load %s certificate: %w", p.source, err)
	}
	p.mu.Lock()
	p.cert = cert
	p.mu.Unlock()
	return nil
}

// Source reports where the active certificate came from.
func (p *Provider) Source() Source { return p.source }

// Certificate returns the active certificate.
func (p *Provider) Certificate() *tls.Certificate {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.cert
}

// Config returns a server TLS configuration that resolves the certificate at
// handshake time, so reloads apply without rebuilding listeners.
func (p *Provider) Config() *tls.Config {
	return &tls.Config{
		MinVersion: p.minVersion,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert := p.Certificate()
			if cert == nil {
				return nil, errors.New("no TLS certificate available")
			}
			return cert, nil
		},
	}
}

// Fingerprint returns the SHA-256 fingerprint of the leaf certificate, in the
// colon-separated form other tools print. It is logged at startup so that a
// self-signed setup can be pinned by whoever configures the client.
func (p *Provider) Fingerprint() string {
	cert := p.Certificate()
	if cert == nil || len(cert.Certificate) == 0 {
		return ""
	}
	sum := sha256.Sum256(cert.Certificate[0])
	hexed := hex.EncodeToString(sum[:])
	out := make([]byte, 0, len(hexed)+len(hexed)/2)
	for i := 0; i < len(hexed); i += 2 {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, hexed[i], hexed[i+1])
	}
	return string(out)
}

// NotAfter reports the leaf certificate's expiry, or the zero time if unknown.
func (p *Provider) NotAfter() time.Time {
	cert := p.Certificate()
	if cert == nil || cert.Leaf == nil {
		return time.Time{}
	}
	return cert.Leaf.NotAfter
}

// LeafPEM returns the leaf certificate in PEM form, which tests use to build a
// trust store for the generated certificate.
func (p *Provider) LeafPEM() ([]byte, error) {
	cert := p.Certificate()
	if cert == nil || len(cert.Certificate) == 0 {
		return nil, errors.New("no TLS certificate available")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), nil
}

func loadFiles(certFile, keyFile string) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	// LoadX509KeyPair leaves Leaf nil; parsing it once here means expiry checks
	// and fingerprints do not re-parse on every use.
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse leaf certificate: %w", err)
	}
	cert.Leaf = leaf

	if now := time.Now(); now.After(leaf.NotAfter) {
		return nil, fmt.Errorf("certificate %s expired on %s", certFile, leaf.NotAfter.Format(time.RFC3339))
	}
	return &cert, nil
}

// SelfSignedOptions configures certificate generation.
type SelfSignedOptions struct {
	// Hosts is the SAN list. Entries that parse as IP addresses become IP SANs,
	// the rest become DNS SANs.
	Hosts []string
	// Validity defaults to a year when zero.
	Validity time.Duration
	// CacheDir persists the pair so restarts keep the same certificate. Empty
	// keeps it in memory only.
	CacheDir string
	// LogWriter is optional.
	LogWriter *slog.Logger
}

// selfSigned returns a cached certificate when one is still valid, and generates
// a new one otherwise.
func selfSigned(opts SelfSignedOptions) (*tls.Certificate, error) {
	if opts.CacheDir != "" {
		certPath := filepath.Join(opts.CacheDir, selfSignedCertName)
		keyPath := filepath.Join(opts.CacheDir, selfSignedKeyName)

		cert, err := loadFiles(certPath, keyPath)
		switch {
		case err == nil && covers(cert.Leaf, opts.Hosts):
			return cert, nil
		case err == nil && opts.LogWriter != nil:
			opts.LogWriter.Info("regenerating the cached self-signed certificate: host list changed",
				slog.String("path", certPath))
		case err != nil && !errors.Is(err, os.ErrNotExist) && opts.LogWriter != nil:
			opts.LogWriter.Warn("ignoring the cached self-signed certificate",
				slog.String("path", certPath), slog.Any("error", err))
		}
	}

	cert, certPEM, keyPEM, err := GenerateSelfSigned(opts.Hosts, opts.Validity)
	if err != nil {
		return nil, err
	}

	if opts.CacheDir != "" {
		if err := writeCache(opts.CacheDir, certPEM, keyPEM); err != nil {
			// Failing to cache is not fatal: the in-memory certificate works,
			// it just will not survive a restart.
			if opts.LogWriter != nil {
				opts.LogWriter.Warn("could not persist the self-signed certificate",
					slog.String("dir", opts.CacheDir), slog.Any("error", err))
			}
		}
	}
	return cert, nil
}

// GenerateSelfSigned creates an ECDSA P-256 self-signed certificate for the
// given hosts, returning it alongside its PEM encoding.
//
// The certificate is marked as a CA so it can be dropped straight into a
// client's trust store, which is what makes it usable in tests and for a local
// WordPress pointing at the submission port.
func GenerateSelfSigned(hosts []string, validity time.Duration) (*tls.Certificate, []byte, []byte, error) {
	if len(hosts) == 0 {
		return nil, nil, nil, errors.New("at least one host is required for a self-signed certificate")
	}
	if validity <= 0 {
		validity = 365 * 24 * time.Hour
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   hosts[0],
			Organization: []string{"relais (self-signed)"},
		},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
			continue
		}
		template.DNSNames = append(template.DNSNames, host)
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse generated certificate: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("marshal key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}, certPEM, keyPEM, nil
}

func writeCache(dir string, certPEM, keyPEM []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, selfSignedCertName), certPEM, 0o644); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}
	// The private key is never world-readable, even for a throwaway certificate.
	if err := os.WriteFile(filepath.Join(dir, selfSignedKeyName), keyPEM, 0o600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	return nil
}

// covers reports whether a cached certificate still names every requested host.
func covers(leaf *x509.Certificate, hosts []string) bool {
	if leaf == nil {
		return false
	}
	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			found := false
			for _, candidate := range leaf.IPAddresses {
				if candidate.Equal(ip) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
			continue
		}
		if err := leaf.VerifyHostname(host); err != nil {
			return false
		}
	}
	return true
}

func parseMinVersion(name string) (uint16, error) {
	switch name {
	case "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported TLS minimum version %q: want 1.2 or 1.3", name)
	}
}
