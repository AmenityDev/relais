package tlsconf

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
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

// --- automatic reload -------------------------------------------------------
//
// A renewal is written by something else — certbot, lego, a mounted secret — and
// usually by another container, which cannot signal this process. These tests
// cover the path that makes that work without a signal.

// fingerprintOf reads back what writePair just wrote, so a test can name the
// certificate it expects to be served.
func fingerprintOf(t *testing.T, certPath string) string {
	t.Helper()
	raw, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read %s: %v", certPath, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatalf("%s is not PEM", certPath)
	}
	// Formatted through the same path Provider.Fingerprint uses, so a mismatch in
	// this test means the certificate differs and not the formatting.
	loaded := &Provider{cert: &tls.Certificate{Certificate: [][]byte{block.Bytes}}}
	return loaded.Fingerprint()
}

// renew writes a fresh pair and returns its fingerprint.
func renew(t *testing.T, certPath, keyPath string) string {
	t.Helper()
	writePair(t, certPath, keyPath, []string{"smtp.example.test"}, time.Hour)
	return fingerprintOf(t, certPath)
}

// fileProvider builds a Provider over two PEM files.
func fileProvider(t *testing.T, certPath, keyPath string) *Provider {
	t.Helper()

	cfg, err := config.LoadFrom(map[string]string{
		"RELAIS_ENV":             "dev",
		"RELAIS_TLS_CERT_FILE":   certPath,
		"RELAIS_TLS_KEY_FILE":    keyPath,
		"RELAIS_TLS_MIN_VERSION": "1.2",
	})
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	provider, err := New(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("tlsconf.New: %v", err)
	}
	return provider
}

func TestReloadIfChangedPicksUpARenewal(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")

	renew(t, certPath, keyPath)
	provider := fileProvider(t, certPath, keyPath)
	before := provider.Fingerprint()

	// Nothing changed: no reload, and no churn in the logs from pretending there
	// was one.
	reloaded, err := provider.ReloadIfChanged()
	if err != nil {
		t.Fatalf("ReloadIfChanged: %v", err)
	}
	if reloaded {
		t.Error("reloaded an unchanged certificate")
	}
	if provider.Fingerprint() != before {
		t.Error("the fingerprint moved without a reload")
	}

	// The renewal.
	waitForDistinctModTime()
	after := renew(t, certPath, keyPath)
	if after == before {
		t.Fatal("the test generated the same certificate twice")
	}

	reloaded, err = provider.ReloadIfChanged()
	if err != nil {
		t.Fatalf("ReloadIfChanged after renewal: %v", err)
	}
	if !reloaded {
		t.Fatal("the renewal was not picked up")
	}
	if got := provider.Fingerprint(); got != after {
		t.Errorf("serving %s, want the renewed %s", got, after)
	}
}

func TestReloadIfChangedRetriesAfterAHalfWrittenRenewal(t *testing.T) {
	// A renewal writes the certificate and the key as two operations, and a check
	// landing between them reads a new certificate against the old key. The failure
	// must not take down the certificate already serving.
	dir := t.TempDir()
	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")

	renew(t, certPath, keyPath)
	provider := fileProvider(t, certPath, keyPath)
	original := provider.Fingerprint()

	_, certPEM, keyPEM, err := GenerateSelfSigned([]string{"smtp.example.test"}, time.Hour)
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}
	waitForDistinctModTime()
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	if _, err := provider.ReloadIfChanged(); err == nil {
		t.Fatal("a certificate was accepted against a key that does not match it")
	}
	if provider.Fingerprint() != original {
		t.Errorf("the failed reload replaced the certificate: %s", provider.Fingerprint())
	}

	waitForDistinctModTime()
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	reloaded, err := provider.ReloadIfChanged()
	if err != nil {
		t.Fatalf("ReloadIfChanged after the key landed: %v", err)
	}
	if !reloaded {
		t.Fatal("the completed renewal was not picked up")
	}
	if got, want := provider.Fingerprint(), fingerprintOf(t, certPath); got != want {
		t.Errorf("serving %s, want %s", got, want)
	}
}

func TestReloadIfChangedRetriesAfterATransientFailure(t *testing.T) {
	// The reason a failed load must not record what it saw.
	//
	// A two-step renewal heals itself: the second write changes the observed state
	// again, so a retry happens either way. The case that does not heal is a failure
	// with the files unchanged — an unreadable key, a full disk, a volume remounted
	// mid-read. If the failure recorded that state, the retry would be skipped for
	// good: the files never change again, so nothing would ever trigger another
	// attempt, and the certificate would expire weeks later with nothing in the logs.
	if os.Geteuid() == 0 {
		t.Skip("running as root, which ignores the permission this test relies on")
	}

	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	renew(t, certPath, keyPath)
	provider := fileProvider(t, certPath, keyPath)

	// A renewal lands, and is then made unreadable before it can be loaded.
	waitForDistinctModTime()
	renewed := renew(t, certPath, keyPath)
	if err := os.Chmod(keyPath, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	if _, err := provider.ReloadIfChanged(); err == nil {
		t.Fatal("an unreadable key was accepted")
	}

	// Permissions are fixed. Note that chmod moves ctime, not mtime, so the files
	// look exactly as they did during the failure: nothing but a retry can recover.
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatalf("chmod back: %v", err)
	}

	reloaded, err := provider.ReloadIfChanged()
	if err != nil {
		t.Fatalf("ReloadIfChanged after the key became readable: %v", err)
	}
	if !reloaded {
		t.Fatal("no retry after a transient failure: the failed attempt recorded its state")
	}
	if got := provider.Fingerprint(); got != renewed {
		t.Errorf("serving %s, want %s", got, renewed)
	}
}

func TestReloadIfChangedFollowsASymlinkedRenewal(t *testing.T) {
	// The configured path is a symlink and the file behind it is replaced, with the
	// link itself untouched — a dumper writing into a directory that is linked into
	// place, for instance.
	//
	// This is what distinguishes following the link from not: the link's own
	// metadata does not move, so a check that stat'd the link would see nothing and
	// serve the old certificate until the process restarted. Repointing a link is
	// the easier case and would be caught either way, which is why this test
	// rewrites the target instead.
	dir := t.TempDir()
	archive := filepath.Join(dir, "archive")
	live := filepath.Join(dir, "live")
	for _, d := range []string{archive, live} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}

	target := filepath.Join(archive, "cert.pem")
	targetKey := filepath.Join(archive, "key.pem")
	writePair(t, target, targetKey, []string{"smtp.example.test"}, time.Hour)

	liveCert := filepath.Join(live, "cert.pem")
	liveKey := filepath.Join(live, "key.pem")
	if err := os.Symlink(target, liveCert); err != nil {
		t.Fatalf("symlink cert: %v", err)
	}
	if err := os.Symlink(targetKey, liveKey); err != nil {
		t.Fatalf("symlink key: %v", err)
	}

	provider := fileProvider(t, liveCert, liveKey)
	if got, want := provider.Fingerprint(), fingerprintOf(t, target); got != want {
		t.Fatalf("loaded %s through the link, want %s", got, want)
	}

	// The renewal replaces what the links point at. The links are not touched.
	waitForDistinctModTime()
	writePair(t, target, targetKey, []string{"smtp.example.test"}, time.Hour)

	reloaded, err := provider.ReloadIfChanged()
	if err != nil {
		t.Fatalf("ReloadIfChanged: %v", err)
	}
	if !reloaded {
		t.Fatal("a renewal behind an untouched symlink was not seen")
	}
	if got, want := provider.Fingerprint(), fingerprintOf(t, target); got != want {
		t.Errorf("serving %s, want %s", got, want)
	}
}

func TestReloadIfChangedToleratesAMissingFile(t *testing.T) {
	// A renewal can briefly remove a file, and a volume can be mounted late. Neither
	// is a reason to stop serving the certificate already in memory.
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	original := renew(t, certPath, keyPath)
	provider := fileProvider(t, certPath, keyPath)

	if err := os.Remove(certPath); err != nil {
		t.Fatalf("remove: %v", err)
	}

	reloaded, err := provider.ReloadIfChanged()
	if err != nil {
		t.Errorf("a missing file was reported as an error: %v", err)
	}
	if reloaded {
		t.Error("reloaded from a file that is not there")
	}
	if provider.Fingerprint() != original {
		t.Error("the certificate in memory was dropped")
	}
}

func TestWatchReloadsWithoutASignal(t *testing.T) {
	// The end of the story: another container writes a renewal, nothing signals
	// this process, and the next handshake gets the new certificate.
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	renew(t, certPath, keyPath)
	provider := fileProvider(t, certPath, keyPath)
	before := provider.Fingerprint()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- provider.Watch(ctx, 10*time.Millisecond, slog.New(slog.DiscardHandler)) }()

	waitForDistinctModTime()
	after := renew(t, certPath, keyPath)

	deadline := time.After(5 * time.Second)
	for provider.Fingerprint() != after {
		select {
		case <-deadline:
			t.Fatalf("Watch did not reload within 5s: still serving %s, want %s",
				provider.Fingerprint(), after)
		case <-time.After(5 * time.Millisecond):
		}
	}
	if before == after {
		t.Fatal("the test generated the same certificate twice")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Watch returned %v, want nil on cancellation", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Watch did not return when its context was cancelled")
	}
}

func TestWatchIsInertForAGeneratedCertificate(t *testing.T) {
	// Nothing writes a self-signed certificate on disk, so there is nothing to
	// watch. Watch must simply wait rather than stat paths that do not exist.
	cfg, err := config.LoadFrom(map[string]string{
		"RELAIS_ENV":                   "dev",
		"RELAIS_TLS_SELF_SIGNED":       "true",
		"RELAIS_TLS_SELF_SIGNED_HOSTS": "localhost",
	})
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	provider, err := New(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("tlsconf.New: %v", err)
	}

	if reloaded, err := provider.ReloadIfChanged(); reloaded || err != nil {
		t.Errorf("ReloadIfChanged on a generated certificate: %v %v", reloaded, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := provider.Watch(ctx, 10*time.Millisecond, slog.New(slog.DiscardHandler)); err != nil {
		t.Errorf("Watch: %v", err)
	}
}

// waitForDistinctModTime makes the next write land on a different modification
// time. Some filesystems have coarse timestamps, and a renewal written inside the
// same tick would be indistinguishable from the previous one by mtime alone.
func waitForDistinctModTime() {
	time.Sleep(10 * time.Millisecond)
}

func TestARenewalIsServedOnTheNextHandshake(t *testing.T) {
	// The promise an operator actually depends on: a certificate renewed by another
	// container is presented to the next client, on a listener that was never
	// restarted. The tests above assert the provider swapped its certificate; this
	// one asserts a client sees the swap.
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	writePair(t, certPath, keyPath, []string{"localhost", "127.0.0.1"}, time.Hour)
	provider := fileProvider(t, certPath, keyPath)

	// The listener is built once, from the provider's config. Nothing below touches
	// it again: GetCertificate resolves per handshake, which is what makes a reload
	// take effect without dropping connections.
	listener, err := tls.Listen("tcp", "127.0.0.1:0", provider.Config())
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.(*tls.Conn).Handshake()
			conn.Close()
		}
	}()

	// served returns the fingerprint the listener presents right now.
	served := func() string {
		conn, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
			InsecureSkipVerify: true, // the certificate is self-signed by design here
			ServerName:         "localhost",
			MinVersion:         tls.VersionTLS12,
		})
		if err != nil {
			t.Fatalf("client handshake: %v", err)
		}
		defer conn.Close()
		presented := conn.ConnectionState().PeerCertificates
		if len(presented) == 0 {
			t.Fatal("the server presented no certificate")
		}
		loaded := &Provider{cert: &tls.Certificate{Certificate: [][]byte{presented[0].Raw}}}
		return loaded.Fingerprint()
	}

	if got, want := served(), fingerprintOf(t, certPath); got != want {
		t.Fatalf("before the renewal the listener served %s, want %s", got, want)
	}

	// Another container renews. No signal is sent to this process.
	waitForDistinctModTime()
	writePair(t, certPath, keyPath, []string{"localhost", "127.0.0.1"}, time.Hour)
	renewed := fingerprintOf(t, certPath)

	reloaded, err := provider.ReloadIfChanged()
	if err != nil {
		t.Fatalf("ReloadIfChanged: %v", err)
	}
	if !reloaded {
		t.Fatal("the renewal was not picked up")
	}

	if got := served(); got != renewed {
		t.Errorf("after the renewal the listener still serves %s, want %s", got, renewed)
	}
}
