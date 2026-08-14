package db

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// migrationLockKey is the pg_advisory_lock key guarding schema changes. Any
// value works as long as it is stable; this one is "relais" in ASCII, summed.
const migrationLockKey int64 = 0x72656c616973

// MigrateResult reports what a migration run did, so the CLI can print
// something useful instead of a bare "ok".
type MigrateResult struct {
	AppSteps   []string
	RiverSteps []string
}

// Empty reports whether the run was a no-op.
func (r MigrateResult) Empty() bool { return len(r.AppSteps) == 0 && len(r.RiverSteps) == 0 }

// MigrateUp applies the application schema then the river schema.
//
// Both run while holding a session-level advisory lock, so several replicas
// starting at once, as a rolling deploy does, cannot race. Migrations are
// never triggered implicitly by `serve`; this is only reachable from
// `relais migrate`.
func MigrateUp(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger) (MigrateResult, error) {
	var res MigrateResult

	err := withMigrationLock(ctx, pool, func(ctx context.Context) error {
		appSteps, err := migrateApp(ctx, pool, modeUp)
		if err != nil {
			return fmt.Errorf("application schema: %w", err)
		}
		res.AppSteps = appSteps

		riverSteps, err := migrateRiver(ctx, pool, rivermigrate.DirectionUp, 0)
		if err != nil {
			return fmt.Errorf("river schema: %w", err)
		}
		res.RiverSteps = riverSteps
		return nil
	})
	return res, err
}

// MigrateDown rolls back exactly one step of each schema, application first.
//
// It exists for development and for backing out a bad deploy. It is not a
// disaster-recovery tool: restoring a backup is.
func MigrateDown(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger) (MigrateResult, error) {
	var res MigrateResult

	err := withMigrationLock(ctx, pool, func(ctx context.Context) error {
		appSteps, err := migrateApp(ctx, pool, modeDown)
		if err != nil {
			return fmt.Errorf("application schema: %w", err)
		}
		res.AppSteps = appSteps
		return nil
	})
	return res, err
}

// MigrationStatus is one row of `relais migrate status`.
type MigrationStatus struct {
	Version int64
	// State is "applied" or "pending".
	State  string
	Source string
}

// MigrateStatus lists the applied and pending application migrations.
func MigrateStatus(ctx context.Context, pool *pgxpool.Pool) ([]MigrationStatus, error) {
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer sqlDB.Close()

	provider, err := newGooseProvider(sqlDB)
	if err != nil {
		return nil, err
	}
	sources, err := provider.Status(ctx)
	if err != nil {
		return nil, fmt.Errorf("read migration status: %w", err)
	}

	out := make([]MigrationStatus, 0, len(sources))
	for _, s := range sources {
		state := "pending"
		if s.State == goose.StateApplied {
			state = "applied"
		}
		out = append(out, MigrationStatus{Version: s.Source.Version, State: state, Source: s.Source.Path})
	}
	return out, nil
}

// migrationMode selects the direction of an application-schema run.
type migrationMode int

const (
	modeUp migrationMode = iota
	// modeDown rolls back a single migration, which is goose's own default for
	// Down and the only rollback granularity we expose.
	modeDown
)

func migrateApp(ctx context.Context, pool *pgxpool.Pool, mode migrationMode) ([]string, error) {
	// goose speaks database/sql; stdlib wraps the existing pool so we do not
	// open a second, separately-configured set of connections.
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer sqlDB.Close()

	provider, err := newGooseProvider(sqlDB)
	if err != nil {
		return nil, err
	}

	var results []*goose.MigrationResult
	switch mode {
	case modeUp:
		results, err = provider.Up(ctx)
	case modeDown:
		var one *goose.MigrationResult
		one, err = provider.Down(ctx)
		if one != nil {
			results = []*goose.MigrationResult{one}
		}
	default:
		return nil, fmt.Errorf("unknown migration mode %d", mode)
	}
	if err != nil && !errors.Is(err, goose.ErrNoNextVersion) && !errors.Is(err, goose.ErrNoMigrations) {
		return nil, err
	}

	steps := make([]string, 0, len(results))
	for _, r := range results {
		steps = append(steps, fmt.Sprintf("%d %s (%s)", r.Source.Version, r.Source.Path, r.Duration.Round(1e6)))
	}
	return steps, nil
}

func newGooseProvider(sqlDB *sql.DB) (*goose.Provider, error) {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("open embedded migrations: %w", err)
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, sub)
	if err != nil {
		return nil, fmt.Errorf("build migration provider: %w", err)
	}
	return provider, nil
}

func migrateRiver(ctx context.Context, pool *pgxpool.Pool, dir rivermigrate.Direction, targetVersion int) ([]string, error) {
	migrator, err := rivermigrate.New(riverpgxv5.New(pool), nil)
	if err != nil {
		return nil, fmt.Errorf("build river migrator: %w", err)
	}
	opts := &rivermigrate.MigrateOpts{}
	if targetVersion != 0 {
		opts.TargetVersion = targetVersion
	}
	res, err := migrator.Migrate(ctx, dir, opts)
	if err != nil {
		return nil, err
	}
	steps := make([]string, 0, len(res.Versions))
	for _, v := range res.Versions {
		steps = append(steps, fmt.Sprintf("river %d %s", v.Version, v.Name))
	}
	return steps, nil
}

// withMigrationLock runs fn while holding a session-level advisory lock on a
// dedicated connection. The lock is released when the connection goes back to
// the pool, including on panic.
func withMigrationLock(ctx context.Context, pool *pgxpool.Pool, fn func(context.Context) error) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLockKey); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		// Best effort: releasing on a broken connection is pointless, and the
		// lock dies with the session anyway.
		if _, err := conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", migrationLockKey); err != nil {
			slog.Warn("release migration lock", slog.Any("error", err))
		}
	}()

	return fn(ctx)
}
