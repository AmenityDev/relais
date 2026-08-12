package tlsconf

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/amenitydev/relais/internal/config"
)

func devConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.LoadFrom(map[string]string{
		"RELAIS_ENV":                      "dev",
		"RELAIS_TLS_SELF_SIGNED":          "true",
		"RELAIS_TLS_SELF_SIGNED_HOSTS":    "localhost,127.0.0.1",
		"RELAIS_DB_URL":                   "postgres://localhost/relais",
		"RELAIS_SECRET_CREDENTIAL_PEPPER": "x",
	})
	if err != nil {
		t.Fatalf("config.LoadFrom: %v", err)
	}
	return cfg
}

// TestSelfSignedHandshake is the test that actually matters: a client must be
// able to complete a TLS handshake against the generated certificate.
func TestSelfSignedHandshake(t *testing.T) {
	p, err := New(devConfig(t), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p.Source() != SourceSelfSigned {
		t.Fatalf("Source: got %q, want %q", p.Source(), SourceSelfSigned)
	}

	leafPEM, err := p.LeafPEM()
	if err != nil {
		t.Fatalf("LeafPEM: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(leafPEM) {
		t.Fatal("the generated certificate could not be added to a trust store")
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", p.Config())
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer listener.Close()

	errCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		_, err = conn.Write([]byte("220 relais\r\n"))
		errCh <- err
	}()

	// Dialling by name exercises the DNS SAN; the listener is on a loopback IP,
	// so ServerName has to be set explicitly.
	conn, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		RootCAs:    roots,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 32)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read banner: %v", err)
	}
	if got := string(buf[:n]); got != "220 relais\r\n" {
		t.Fatalf("banner: got %q", got)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("server side: %v", err)
	}
}

// The IP SAN matters in practice: a container talking to relais by address must
// not be forced to disable verification.
func TestSelfSignedCoversIPSAN(t *testing.T) {
	p, err := New(devConfig(t), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	leaf := p.Certificate().Leaf
	if leaf == nil {
		t.Fatal("Leaf was not parsed")
	}

	var foundIP bool
	for _, ip := range leaf.IPAddresses {
		if ip.Equal(net.ParseIP("127.0.0.1")) {
			foundIP = true
		}
	}
	if !foundIP {
		t.Fatalf("127.0.0.1 is missing from the IP SANs (%v)", leaf.IPAddresses)
	}
	if err := leaf.VerifyHostname("localhost"); err != nil {
		t.Fatalf("localhost is not covered: %v", err)
	}
	if err := leaf.VerifyHostname("evil.example.com"); err == nil {
		t.Fatal("the certificate validates a host it was not issued for")
	}
}

func TestSelfSignedCacheIsReused(t *testing.T) {
	dir := t.TempDir()
	cfg := devConfig(t)
	cfg.TLS.SelfSignedDir = dir

	first, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	second, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New (second): %v", err)
	}
	if first.Fingerprint() != second.Fingerprint() {
		t.Fatal("a cached certificate was not reused across restarts")
	}

	// The private key must never be world-readable.
	info, err := os.Stat(filepath.Join(dir, selfSignedKeyName))
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key permissions: got %04o, want 0600", perm)
	}

	// Changing the host list must invalidate the cache, otherwise a stale
	// certificate silently fails to cover a newly configured name.
	cfg.TLS.SelfSignedHosts = []string{"localhost", "127.0.0.1", "smtp.example.test"}
	third, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New (new hosts): %v", err)
	}
	if third.Fingerprint() == first.Fingerprint() {
		t.Fatal("the cached certificate was reused despite a changed host list")
	}
	if err := third.Certificate().Leaf.VerifyHostname("smtp.example.test"); err != nil {
		t.Fatalf("the regenerated certificate does not cover the new host: %v", err)
	}
}

func TestFileSourceAndReload(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")

	writePair(t, certPath, keyPath, []string{"first.example.test"}, time.Hour)

	cfg := devConfig(t)
	cfg.TLS.SelfSigned = false
	cfg.TLS.CertFile = certPath
	cfg.TLS.KeyFile = keyPath

	p, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p.Source() != SourceFiles {
		t.Fatalf("Source: got %q, want %q", p.Source(), SourceFiles)
	}
	before := p.Fingerprint()

	// Simulate a certbot renewal writing new material in place.
	writePair(t, certPath, keyPath, []string{"first.example.test"}, 2*time.Hour)
	if err := p.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if p.Fingerprint() == before {
		t.Fatal("Reload did not pick up the renewed certificate")
	}
}

// A failed reload must leave the previous certificate serving traffic.
func TestReloadFailureKeepsPreviousCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	writePair(t, certPath, keyPath, []string{"first.example.test"}, time.Hour)

	cfg := devConfig(t)
	cfg.TLS.SelfSigned = false
	cfg.TLS.CertFile = certPath
	cfg.TLS.KeyFile = keyPath

	p, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	before := p.Fingerprint()

	if err := os.WriteFile(certPath, []byte("not a certificate"), 0o644); err != nil {
		t.Fatalf("corrupt cert file: %v", err)
	}
	if err := p.Reload(); err == nil {
		t.Fatal("Reload accepted a corrupt certificate")
	}
	if p.Fingerprint() != before {
		t.Fatal("a failed reload discarded the working certificate")
	}
}

func TestNewRejectsExpiredCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	// A validity of one nanosecond is already in the past by the time New runs.
	writePair(t, certPath, keyPath, []string{"expired.example.test"}, time.Nanosecond)

	cfg := devConfig(t)
	cfg.TLS.SelfSigned = false
	cfg.TLS.CertFile = certPath
	cfg.TLS.KeyFile = keyPath

	if _, err := New(cfg, nil); err == nil {
		t.Fatal("New accepted an expired certificate")
	}
}

func TestNewRefusesSelfSignedInProd(t *testing.T) {
	cfg := devConfig(t)
	cfg.Env = "prod"

	if _, err := New(cfg, nil); err == nil {
		t.Fatal("New generated a self-signed certificate in a production environment")
	}

	// The escape hatch must still work for whoever explicitly asks for it.
	cfg.TLS.SelfSignedAllowInProd = true
	if _, err := New(cfg, nil); err != nil {
		t.Fatalf("New with the explicit override: %v", err)
	}
}

func TestNewRequiresACertificateSource(t *testing.T) {
	cfg := devConfig(t)
	cfg.TLS.SelfSigned = false
	if _, err := New(cfg, nil); err == nil {
		t.Fatal("New succeeded with no certificate source: STARTTLS would be unavailable")
	}
}

func TestMinVersionIsApplied(t *testing.T) {
	cfg := devConfig(t)
	cfg.TLS.MinVersion = "1.3"
	p, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := p.Config().MinVersion; got != tls.VersionTLS13 {
		t.Fatalf("MinVersion: got %#x, want %#x", got, tls.VersionTLS13)
	}

	cfg.TLS.MinVersion = "1.1"
	if _, err := New(cfg, nil); err == nil {
		t.Fatal("New accepted an unsupported TLS minimum version")
	}
}

func TestFingerprintFormat(t *testing.T) {
	p, err := New(devConfig(t), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	fp := p.Fingerprint()
	// 32 bytes rendered as colon-separated hex pairs.
	if len(fp) != 32*3-1 {
		t.Fatalf("fingerprint %q has length %d, want %d", fp, len(fp), 32*3-1)
	}
}

func writePair(t *testing.T, certPath, keyPath string, hosts []string, validity time.Duration) {
	t.Helper()
	_, certPEM, keyPEM, err := GenerateSelfSigned(hosts, validity)
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
}
