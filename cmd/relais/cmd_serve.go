package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sync/errgroup"

	"github.com/amenitydev/relais/internal/adminauth"
	"github.com/amenitydev/relais/internal/authn"
	"github.com/amenitydev/relais/internal/config"
	"github.com/amenitydev/relais/internal/httpapi"
	"github.com/amenitydev/relais/internal/ingest"
	"github.com/amenitydev/relais/internal/jobs"
	"github.com/amenitydev/relais/internal/ratelimit"
	"github.com/amenitydev/relais/internal/sender"
	"github.com/amenitydev/relais/internal/smtpd"
	"github.com/amenitydev/relais/internal/tlsconf"
)

// buildSender assembles the outbound SMTP client from configuration.
func buildSender(cfg *config.Config, log *slog.Logger) *sender.Sender {
	heloName := cfg.Sender.HeloName
	if heloName == "" {
		// The EHLO name a relay sees should match how this host identifies
		// itself, which is the same name the submission server announces.
		heloName = cfg.SMTP.Domain
	}

	minVersion := uint16(tls.VersionTLS12)
	if cfg.Sender.MinTLSVersion == "1.3" {
		minVersion = tls.VersionTLS13
	}

	return sender.New(sender.Config{
		Timeout:                 cfg.Sender.Timeout,
		HeloName:                heloName,
		MinTLSVersion:           minVersion,
		InsecureSkipVerifyHosts: cfg.Sender.InsecureVerifyExemptHosts,
	}, log)
}

// cmdServe runs the long-lived process.
//
// The three subsystems (HTTP API, SMTP submission, river workers) are
// independently switchable so that they can be split across containers later
// without a code change. Every one of them is optional; starting with none is a
// configuration error rather than a silently idle process.
func cmdServe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("relais serve", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: relais serve

Runs the service. Which subsystems start is controlled by the environment:

  RELAIS_HTTP_ENABLED     the REST and admin API      (default true)
  RELAIS_SMTP_ENABLED     the submission server       (default true)
  RELAIS_WORKER_ENABLED   the delivery workers        (default true)

Schema migrations are not applied here; run "relais migrate up" first.
`)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Validate the configuration before touching the database, so a bad
	// deployment fails on the thing that is actually wrong.
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if err := cfg.RequireServe(); err != nil {
		return err
	}

	sess, err := openSession(ctx, true)
	if err != nil {
		return err
	}
	defer sess.Close()

	log := sess.log
	log.Info("relais starting",
		slog.String("version", versionString()),
		slog.Bool("http", cfg.HTTP.Enabled),
		slog.Bool("admin", cfg.AdminEnabled()),
		slog.Bool("smtp", cfg.SMTP.Enabled),
		slog.Bool("workers", cfg.Worker.Enabled),
	)

	// The certificate is resolved eagerly, even though only the submission
	// server uses it: discovering a missing certificate at startup beats
	// discovering it when the first client connects.
	var certs *tlsconf.Provider
	if cfg.SMTP.Enabled {
		certs, err = tlsconf.New(cfg, log)
		if err != nil {
			return err
		}
	}

	// group carries the whole process: if any subsystem exits with an error, the
	// context is cancelled and the others shut down too.
	group, groupCtx := errgroup.WithContext(ctx)

	// The river client comes first, because the API needs its enqueuer. It is
	// built whether or not this process delivers: an API-only instance still has
	// to enqueue. With workers disabled it is insert-only, which is what makes
	// splitting the process across containers a configuration change rather than a
	// code change.
	riverClient, err := jobs.NewClient(jobs.ClientOptions{
		Store:           sess.store,
		Deliverer:       buildSender(cfg, log),
		Log:             log,
		Workers:         cfg.Worker.Enabled,
		Count:           cfg.Worker.Count,
		MaxAttempts:     cfg.Worker.MaxAttempts,
		JobTimeout:      cfg.Worker.JobTimeout,
		SentRetention:   cfg.Retention.Sent,
		FailedRetention: cfg.Retention.Failed,
		PurgeInterval:   cfg.Retention.Interval,
	})
	if err != nil {
		return err
	}

	// The ingest pipeline: the single path a message can take in. Both façades
	// build a Request and call Submit, which is what keeps them from drifting
	// apart. One limiter instance is shared, so a credential's budget is the same
	// whichever façade it arrives through.
	ingestService, err := ingest.New(ingest.Options{
		Store:    sess.store,
		Enqueuer: jobs.NewEnqueuer(riverClient, cfg.Worker.MaxAttempts),
		Limiter: ratelimit.New(ratelimit.Options{
			MaxEntries: cfg.RateLimit.MaxCredentials,
		}),
		Config: ingest.Config{
			MaxMessageBytes:        cfg.Limits.MaxMessageBytes,
			MaxHeaderCount:         cfg.Limits.MaxHeaderCount,
			MaxHeaderBytes:         cfg.Limits.MaxHeaderBytes,
			MaxRecipients:          cfg.Limits.MaxRecipients,
			DefaultRateLimitRPS:    cfg.RateLimit.RPS,
			DefaultRateLimitBurst:  cfg.RateLimit.Burst,
			RejectedRateLimitRPS:   cfg.RateLimit.RejectedRPS,
			RejectedRateLimitBurst: cfg.RateLimit.RejectedBurst,
			IdempotencyTTL:         cfg.Retention.IdempotencyTTL,
		},
		Log: log,
	})
	if err != nil {
		return err
	}

	authenticator, err := authn.New(sess.store, log)
	if err != nil {
		return err
	}

	if cfg.HTTP.Enabled {
		api, err := httpapi.NewServer(httpapi.Options{
			Ingest:        ingestService,
			Store:         sess.store,
			Authenticator: authenticator,
			Pool:          sess.pool,
			Limits: httpapi.Limits{
				MaxMessageBytes: cfg.Limits.MaxMessageBytes,
				MaxRequestBytes: cfg.Limits.MaxRequestBytes,
				MaxRecipients:   cfg.Limits.MaxRecipients,
			},
			Log:                log,
			Version:            versionString(),
			TrustedProxyHeader: cfg.HTTP.TrustedProxyHeader,
		})
		if err != nil {
			return err
		}

		server := &http.Server{
			Addr:              cfg.HTTP.Addr,
			Handler:           api.Handler(),
			ReadHeaderTimeout: cfg.HTTP.ReadHeaderTimeout,
			ReadTimeout:       cfg.HTTP.ReadTimeout,
			WriteTimeout:      cfg.HTTP.WriteTimeout,
			IdleTimeout:       cfg.HTTP.IdleTimeout,
			ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
		}

		// Bind before announcing, and before the group starts. ListenAndServe binds
		// inside the goroutine, which had two consequences worth avoiding: the
		// "listener started" line was logged whether or not the port was free, and a
		// bind failure raced the sibling shutdown goroutine — Shutdown turned the real
		// error into http.ErrServerClosed, which is filtered, so the cause vanished and
		// the process exited reporting only a cancelled context. "relais: interrupted"
		// is a poor way to say "port 8080 is already in use".
		listener, err := net.Listen("tcp", cfg.HTTP.Addr)
		if err != nil {
			return fmt.Errorf("http listener on %s: %w", cfg.HTTP.Addr, err)
		}

		log.Info("http listener started",
			slog.String("addr", cfg.HTTP.Addr),
			slog.String("trusted_proxy_header", cfg.HTTP.TrustedProxyHeader),
		)

		group.Go(func() error {
			if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				return fmt.Errorf("http server: %w", err)
			}
			return nil
		})
		group.Go(func() error {
			<-groupCtx.Done()
			// A fresh context: the group's is already cancelled, and shutdown
			// needs its own budget to drain in-flight requests.
			shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.HTTP.ShutdownTimeout)
			defer cancel()
			log.Info("http listener stopping")
			return server.Shutdown(shutdownCtx)
		})
	}

	if cfg.Worker.Enabled {
		if err := riverClient.Start(groupCtx); err != nil {
			return fmt.Errorf("start the delivery workers: %w", err)
		}
		log.Info("delivery workers started",
			slog.Int("count", cfg.Worker.Count),
			slog.Int("max_attempts", cfg.Worker.MaxAttempts),
			slog.Duration("job_timeout", cfg.Worker.JobTimeout),
		)

		group.Go(func() error {
			<-groupCtx.Done()
			// A fresh context: river drains in-flight deliveries, and cutting
			// that short would leave a message marked 'sending' with no job.
			stopCtx, cancel := context.WithTimeout(context.Background(), cfg.Worker.ShutdownTimeout)
			defer cancel()
			log.Info("delivery workers stopping")
			return riverClient.Stop(stopCtx)
		})
	}

	// Always started, even with no reloadable certificate: an unhandled SIGHUP
	// terminates the process by default, so an operator reflexively sending one
	// would take the service down.
	group.Go(func() error { return watchCertificateReloads(groupCtx, certs, log) })

	// The admin API on its own listener (D15). Exposing the public one must not
	// expose this one, and a separate port makes that a network decision rather
	// than a routing rule to get right.
	if cfg.AdminEnabled() {
		verifier, err := adminauth.New(adminauth.Config{
			Issuer:              cfg.OIDC.Issuer,
			Audience:            cfg.OIDC.Audience,
			JWKSURL:             cfg.OIDC.JWKSURL,
			GroupsClaim:         cfg.OIDC.GroupsClaim,
			AdminGroup:          cfg.OIDC.AdminGroup,
			ViewerGroup:         cfg.OIDC.ViewerGroup,
			DiscoveryTimeout:    cfg.OIDC.DiscoveryTimeout,
			DiscoveryRetryAfter: cfg.OIDC.DiscoveryRetryAfter,
		}, log)
		if err != nil {
			return fmt.Errorf("configure admin authentication: %w", err)
		}

		admin, err := httpapi.NewAdminServer(httpapi.AdminOptions{
			Store:    sess.store,
			Verifier: verifier,
			Pool:     sess.pool,
			// The same sender the workers use, so a connection test exercises the
			// real code path rather than a parallel one.
			Prober:             buildSender(cfg, log),
			Log:                log,
			Version:            versionString(),
			MaxRequestBytes:    cfg.Admin.MaxRequestBytes,
			PageSize:           cfg.Admin.PageSize,
			MaxPageSize:        cfg.Admin.MaxPageSize,
			TrustedProxyHeader: cfg.Admin.TrustedProxyHeader,
		})
		if err != nil {
			return err
		}

		server := &http.Server{
			Addr:              cfg.Admin.Addr,
			Handler:           admin.Handler(),
			ReadHeaderTimeout: cfg.Admin.ReadHeaderTimeout,
			ReadTimeout:       cfg.Admin.ReadTimeout,
			WriteTimeout:      cfg.Admin.WriteTimeout,
			IdleTimeout:       cfg.Admin.IdleTimeout,
			ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
		}

		// Bound before announcing, for the reason given at the HTTP listener.
		listener, err := net.Listen("tcp", cfg.Admin.Addr)
		if err != nil {
			return fmt.Errorf("admin listener on %s: %w", cfg.Admin.Addr, err)
		}

		log.Info("admin listener started",
			slog.String("addr", cfg.Admin.Addr),
			slog.String("issuer", cfg.OIDC.Issuer),
			slog.String("admin_group", cfg.OIDC.AdminGroup),
			slog.String("viewer_group", cfg.OIDC.ViewerGroup),
		)

		group.Go(func() error {
			if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				return fmt.Errorf("admin server: %w", err)
			}
			return nil
		})
		group.Go(func() error {
			<-groupCtx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Admin.ShutdownTimeout)
			defer cancel()
			log.Info("admin listener stopping")
			return server.Shutdown(shutdownCtx)
		})
	} else if cfg.Admin.Enabled {
		// The switch is on but no issuer is configured, so there is no way to
		// authenticate an admin. Serving an unauthenticated admin API would be worse
		// than serving none, so it stays off — loudly.
		log.Warn("admin API disabled: RELAIS_OIDC_ISSUER is not set, and an unauthenticated admin API will not be served")
	}

	if cfg.SMTP.Enabled {
		submission, err := smtpd.New(smtpd.Options{
			Ingest:        ingestService,
			Authenticator: authenticator,
			Certificates:  certs,
			Config: smtpd.Config{
				Domain:          cfg.SMTP.Domain,
				Addr:            cfg.SMTP.Addr,
				TLSAddr:         cfg.SMTP.TLSAddr,
				ReadTimeout:     cfg.SMTP.ReadTimeout,
				WriteTimeout:    cfg.SMTP.WriteTimeout,
				ShutdownTimeout: cfg.SMTP.ShutdownTimeout,
				MaxMessageBytes: cfg.Limits.MaxMessageBytes,
				MaxRecipients:   cfg.Limits.MaxRecipients,
				MaxConnections:  cfg.SMTP.MaxConnections,
			},
			Log: log,
		})
		if err != nil {
			return err
		}

		// Run owns both listeners and their graceful shutdown, and returns when the
		// context is cancelled.
		group.Go(func() error { return submission.Run(groupCtx) })
	}

	if err := group.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	log.Info("relais stopped")
	return nil
}

// watchCertificateReloads reloads the TLS material on SIGHUP.
//
// This is what makes a certbot or Caddy renewal a no-downtime event: the renewal
// hook sends SIGHUP and the next handshake uses the new certificate.
//
// The handler is installed unconditionally, including when there is nothing to
// reload. Go's default action for SIGHUP is to terminate, so leaving it
// unhandled would turn a harmless operator reflex into an outage.
func watchCertificateReloads(ctx context.Context, certs *tlsconf.Provider, log *slog.Logger) error {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP)
	defer signal.Stop(signals)

	reloadable := certs != nil && certs.Source() == tlsconf.SourceFiles
	if reloadable {
		log.Info("send SIGHUP to reload the TLS certificate")
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-signals:
			if !reloadable {
				log.Info("SIGHUP ignored: no file-based TLS certificate is configured")
				continue
			}
			if err := certs.Reload(); err != nil {
				// The previous certificate stays in place, so this is a warning,
				// not a fatal error: a botched renewal must not take the
				// listener down.
				log.Warn("tls certificate reload failed, keeping the previous one", slog.Any("error", err))
				continue
			}
			log.Info("tls certificate reloaded",
				slog.String("fingerprint", certs.Fingerprint()),
				slog.Time("not_after", certs.NotAfter()),
			)
		}
	}
}
