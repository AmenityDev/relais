// Command relais is the single binary for the whole service.
//
// One binary keeps deployment simple: Coolify runs `relais serve`, and the same
// image provides the bootstrap and maintenance commands. Subsystems inside serve
// (API, submission server, workers) are individually switchable, so splitting
// them across containers later needs no code change.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"

	"github.com/amenitydev/relais/internal/config"
	"github.com/amenitydev/relais/internal/crypto"
	"github.com/amenitydev/relais/internal/db"
	"github.com/amenitydev/relais/internal/obs"
	"github.com/amenitydev/relais/internal/store"
)

func main() {
	// Interrupt and SIGTERM cancel the context, which every command threads
	// through so a Ctrl-C during a migration or a send is a clean abort.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:]); err != nil {
		if errors.Is(err, context.Canceled) {
			// A deliberate interrupt is not a failure worth a stack of text.
			fmt.Fprintln(os.Stderr, "relais: interrupted")
			os.Exit(130)
		}
		fmt.Fprintf(os.Stderr, "relais: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		usage()
		return errors.New("a command is required")
	}

	command, rest := args[0], args[1:]
	switch command {
	case "serve":
		return cmdServe(ctx, rest)
	case "migrate":
		return cmdMigrate(ctx, rest)
	case "keygen":
		return cmdKeygen(rest)
	case "backend":
		return cmdBackend(ctx, rest)
	case "domain":
		return cmdDomain(ctx, rest)
	case "credential":
		return cmdCredential(ctx, rest)
	case "healthcheck":
		return cmdHealthcheck(ctx, rest)
	case "openapi":
		return cmdOpenAPI(rest)
	case "version":
		fmt.Println(versionString())
		return nil
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", command)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `relais - SMTP/API gateway with scoped sender credentials

Usage:
  relais <command> [flags]

Commands:
  serve                    Run the API, the submission server and the workers
  migrate up|down|status   Apply, roll back or inspect schema migrations
  keygen key|pepper        Generate key material for the environment
  backend add|list|rm|rewrap
                           Manage outbound SMTP backends
  domain add|list|rm       Manage sending domains
  credential create|list|show|revoke|pattern
                           Manage sender credentials and their allow-lists
  healthcheck              Probe the readiness endpoint (for HEALTHCHECK)
  openapi                  Emit the OpenAPI description of a surface
  version                  Print the build version

Configuration comes from the environment; every variable is prefixed RELAIS_.
Run a subcommand with -h to see its flags.
`)
}

func versionString() string {
	if obs.Version != "" {
		return obs.Version
	}
	return "(devel)"
}

// loadConfig parses the environment and reports every problem at once, so a
// misconfigured deployment does not need several restarts to be fixed.
func loadConfig() (*config.Config, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

// session bundles what most commands need: configuration, a logger, a database
// pool and a store.
type session struct {
	cfg   *config.Config
	log   *slog.Logger
	pool  *db.Pool
	store *store.Store

	closers []func()
}

func (s *session) Close() {
	for i := len(s.closers) - 1; i >= 0; i-- {
		s.closers[i]()
	}
}

// openSession wires configuration, telemetry, the database pool and the store.
//
// needSecrets controls whether the key material is required: `migrate` runs
// without it, everything that touches a credential or a backend password does
// not.
func openSession(ctx context.Context, needSecrets bool) (*session, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	if err := cfg.RequireDatabase(); err != nil {
		return nil, err
	}

	s := &session{cfg: cfg}

	provider, err := obs.Setup(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("set up telemetry: %w", err)
	}
	s.log = provider.Logger
	s.closers = append(s.closers, func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Obs.OTLPTimeout)
		defer cancel()
		if err := provider.Shutdown(shutdownCtx); err != nil {
			fmt.Fprintf(os.Stderr, "relais: telemetry shutdown: %v\n", err)
		}
	})

	pool, err := db.Open(ctx, cfg)
	if err != nil {
		s.Close()
		return nil, err
	}
	s.pool = pool
	s.closers = append(s.closers, pool.Close)

	if !needSecrets {
		return s, nil
	}

	if err := cfg.RequireKeyring(); err != nil {
		s.Close()
		return nil, err
	}
	if err := cfg.RequirePepper(); err != nil {
		s.Close()
		return nil, err
	}

	keyring, err := crypto.ParseKeyring(cfg.Secrets.EncryptionKeys, cfg.Secrets.EncryptionActiveKey)
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("RELAIS_SECRET_ENCRYPTION_KEYS: %w", err)
	}
	hasher, err := crypto.NewHasher(cfg.Secrets.CredentialPepper)
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("RELAIS_SECRET_CREDENTIAL_PEPPER: %w", err)
	}

	st, err := store.New(pool, keyring, hasher)
	if err != nil {
		s.Close()
		return nil, err
	}
	s.store = st
	return s, nil
}

// newTable returns a tab writer for aligned CLI output.
func newTable() *tabwriter.Writer {
	return tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
}
