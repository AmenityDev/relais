// Package dbtest connects integration tests to a real Postgres.
//
// It exists so the rule below lives in one place instead of being re-derived in
// every package that needs a database:
//
//   - When RELAIS_TEST_DB_URL is set, the database is mandatory. An unreachable
//     one FAILS the test. This is the CI case, where a silently skipped
//     integration suite is indistinguishable from a passing one, and therefore
//     worse than a red build.
//   - When it is unset, the development stack is tried and the test SKIPS if it
//     is not running. This is the local case, where `go test ./...` should not
//     require Docker.
//
// Tests truncate, so a non-loopback host requires an explicit opt-in.
package dbtest

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DevDSN is the development stack's database, used when RELAIS_TEST_DB_URL is
// unset.
const DevDSN = "postgres://relais:relais@127.0.0.1:5432/relais?sslmode=disable"

// AppTables is every table an integration test may truncate, ordered so that
// CASCADE has nothing left to do. river's own tables are never touched.
var AppTables = []string{
	"email_payload", "email_message",
	"credential_from_pattern", "credential",
	"domain", "smtp_backend",
}

const (
	dsnEnv      = "RELAIS_TEST_DB_URL"
	truncateEnv = "RELAIS_TEST_DB_ALLOW_TRUNCATE"
)

// exclusiveLockKey serializes every database-backed test.
//
// This is necessary because `go test ./...` runs packages concurrently, in
// separate processes, against one shared database that each test truncates. Two
// packages interleaving produced exactly what you would expect: rows vanishing
// mid-test and TRUNCATE deadlocking against another package's transaction.
//
// A session-level advisory lock fixes it regardless of how the tests are
// invoked, which `-p 1` does not: nobody remembers a flag.
const exclusiveLockKey int64 = 0x72656c746573 // "reltes"

// Pool returns a pool against a truncated, schema-current database.
//
// The test holds an exclusive lock on the database until it finishes, so
// database-backed tests run one at a time. They are fast, so serializing them
// costs little; sharing a database without serializing them costs correctness.
//
// The lock and the pool are released when the test ends.
func Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	dsn, required := resolveDSN(t)
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		unavailable(t, required, "cannot build a pool: %v", err)
		return nil
	}

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		unavailable(t, required, "cannot reach the database: %v", err)
		return nil
	}
	t.Cleanup(pool.Close)

	lock(t, pool)

	if _, err := pool.Exec(ctx, "TRUNCATE "+strings.Join(AppTables, ", ")+" CASCADE"); err != nil {
		// A missing table means the schema was never applied; a missing column
		// means it is out of date. Both are the same fix, so the message says it.
		unavailable(t, required, "cannot truncate: %v\nrun `relais migrate up` (or `task dev:reset` after a schema change)", err)
		return nil
	}
	return pool
}

// lock takes the exclusive test lock on a dedicated connection held for the whole
// test.
func lock(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()

	ctx := context.Background()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire a connection for the test lock: %v", err)
	}

	// A generous timeout rather than none: a deadlocked or abandoned lock should
	// fail the test with a clear message instead of hanging the suite forever.
	lockCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	if _, err := conn.Exec(lockCtx, "SELECT pg_advisory_lock($1)", exclusiveLockKey); err != nil {
		conn.Release()
		t.Fatalf("take the exclusive test lock (another test suite may be stuck): %v", err)
	}

	t.Cleanup(func() {
		releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer releaseCancel()
		// Best effort: the lock dies with the session anyway, and the connection
		// is about to go back to a pool that is about to close.
		_, _ = conn.Exec(releaseCtx, "SELECT pg_advisory_unlock($1)", exclusiveLockKey)
		conn.Release()
	})
}

// DSN returns the connection string a test should use, without locking or
// truncating anything.
//
// It exists for the rare test that needs a pool it owns outright — one it can
// close, for instance, to observe how the code under test reacts to a dead
// database. Closing the pool returned by Pool would deadlock: that one holds a
// connection for the exclusive test lock until the test's cleanup runs, and
// pgxpool.Close waits for every acquired connection to come back first.
func DSN(t *testing.T) string {
	t.Helper()
	dsn, _ := resolveDSN(t)
	return dsn
}

// resolveDSN returns the DSN and whether the database is mandatory.
func resolveDSN(t *testing.T) (dsn string, required bool) {
	t.Helper()

	dsn = strings.TrimSpace(os.Getenv(dsnEnv))
	required = dsn != ""
	if !required {
		dsn = DevDSN
	}

	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("%s is not a valid URL: %v", dsnEnv, err)
	}
	switch parsed.Hostname() {
	case "127.0.0.1", "localhost", "::1", "postgres":
	default:
		// These tests TRUNCATE. Pointing them at a real deployment would be
		// destructive, so anything not obviously local needs a deliberate opt-in.
		if os.Getenv(truncateEnv) != "1" {
			t.Skipf("refusing to truncate a non-local database (host %q): set %s=1 to override", parsed.Hostname(), truncateEnv)
		}
	}
	return dsn, required
}

func unavailable(t *testing.T, required bool, format string, args ...any) {
	t.Helper()
	if required {
		t.Fatalf("%s is set, so the database is mandatory: "+format, append([]any{dsnEnv}, args...)...)
	}
	t.Skipf("no development database available (start it with `docker compose up -d`): "+format, args...)
}
