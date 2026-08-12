// Package obs wires structured logging and tracing.
//
// Logs always go to stdout as JSON (or text in dev) so that `docker logs` stays
// useful, and are additionally exported over OTLP to ClickStack/HyperDX when an
// endpoint is configured. Application logs are never written to Postgres.
package obs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	// The semconv version must match the one resource.Default() carries, or
	// resource.Merge refuses to combine them ("conflicting Schema URL"). Bump
	// this together with the otel SDK.
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/amenitydev/relais/internal/config"
)

// Version is overridden at build time with -ldflags "-X ...obs.Version=v1.2.3".
var Version = ""

// Provider owns the telemetry pipelines created by Setup. Shutdown must be
// called before the process exits, otherwise buffered logs and spans are lost.
type Provider struct {
	Logger *slog.Logger
	Tracer trace.Tracer

	shutdowns []func(context.Context) error
	once      sync.Once
}

// Setup builds the logger and, when configured, the OTLP exporters.
//
// It installs the logger as slog.Default so that libraries logging through slog
// land in the same stream, and returns a Provider whose Shutdown flushes
// everything.
func Setup(ctx context.Context, cfg *config.Config) (*Provider, error) {
	p := &Provider{Tracer: noop.NewTracerProvider().Tracer("")}

	res, err := buildResource(cfg)
	if err != nil {
		return nil, fmt.Errorf("build otel resource: %w", err)
	}

	handlers := []slog.Handler{stdoutHandler(os.Stderr, cfg)}

	if cfg.Obs.OTLPEndpoint != "" {
		logProvider, err := newLogProvider(ctx, cfg, res)
		if err != nil {
			return nil, fmt.Errorf("otlp log exporter: %w", err)
		}
		p.shutdowns = append(p.shutdowns, logProvider.Shutdown)
		handlers = append(handlers, otelslog.NewHandler(cfg.ServiceName, otelslog.WithLoggerProvider(logProvider)))

		if cfg.Obs.TracesEnabled {
			traceProvider, err := newTraceProvider(ctx, cfg, res)
			if err != nil {
				return nil, fmt.Errorf("otlp trace exporter: %w", err)
			}
			p.shutdowns = append(p.shutdowns, traceProvider.Shutdown)
			otel.SetTracerProvider(traceProvider)
			p.Tracer = traceProvider.Tracer(cfg.ServiceName)
		}
	}

	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	// A failing exporter must never crash the service or spam stderr on every
	// batch; it is reported once per occurrence at warn level.
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
		slog.Warn("otel pipeline error", slog.Any("error", err))
	}))

	p.Logger = slog.New(newFanout(handlers...)).With(
		slog.String("service", cfg.ServiceName),
		slog.String("env", cfg.Env),
	)
	slog.SetDefault(p.Logger)

	return p, nil
}

// Shutdown flushes and stops every pipeline. It is safe to call more than once.
func (p *Provider) Shutdown(ctx context.Context) error {
	var errs []error
	p.once.Do(func() {
		// Shut down in reverse order so traces flush before the log pipeline
		// they may reference.
		for i := len(p.shutdowns) - 1; i >= 0; i-- {
			if err := p.shutdowns[i](ctx); err != nil && !errors.Is(err, context.Canceled) {
				errs = append(errs, err)
			}
		}
	})
	return errors.Join(errs...)
}

func buildResource(cfg *config.Config) (*resource.Resource, error) {
	attrs := []attribute.KeyValue{
		semconv.ServiceName(cfg.ServiceName),
		// An enum attribute in the conventions, so there is no typed helper: any
		// free-form environment name is allowed alongside the standard ones.
		semconv.DeploymentEnvironmentNameKey.String(cfg.Env),
	}
	if v := resolveVersion(); v != "" {
		attrs = append(attrs, semconv.ServiceVersion(v))
	}
	if host, err := os.Hostname(); err == nil && host != "" {
		attrs = append(attrs, semconv.HostName(host))
	}
	return resource.Merge(resource.Default(), resource.NewWithAttributes(semconv.SchemaURL, attrs...))
}

func newLogProvider(ctx context.Context, cfg *config.Config, res *resource.Resource) (*sdklog.LoggerProvider, error) {
	opts := []otlploghttp.Option{
		otlploghttp.WithEndpointURL(cfg.Obs.OTLPEndpoint + "/v1/logs"),
		otlploghttp.WithTimeout(cfg.Obs.OTLPTimeout),
	}
	if len(cfg.Obs.OTLPHeaders) > 0 {
		opts = append(opts, otlploghttp.WithHeaders(cfg.Obs.OTLPHeaders))
	}
	exp, err := otlploghttp.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exp)),
	), nil
}

func newTraceProvider(ctx context.Context, cfg *config.Config, res *resource.Resource) (*sdktrace.TracerProvider, error) {
	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpointURL(cfg.Obs.OTLPEndpoint + "/v1/traces"),
		otlptracehttp.WithTimeout(cfg.Obs.OTLPTimeout),
	}
	if len(cfg.Obs.OTLPHeaders) > 0 {
		opts = append(opts, otlptracehttp.WithHeaders(cfg.Obs.OTLPHeaders))
	}
	exp, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithBatcher(exp, sdktrace.WithBatchTimeout(5*time.Second)),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.Obs.TracesSampling))),
	), nil
}

func stdoutHandler(w io.Writer, cfg *config.Config) slog.Handler {
	opts := &slog.HandlerOptions{Level: ParseLevel(cfg.Obs.LogLevel)}
	if cfg.Obs.LogFormat == "text" {
		return slog.NewTextHandler(w, opts)
	}
	return slog.NewJSONHandler(w, opts)
}

// ParseLevel maps a configured level name to a slog level. Unknown names fall
// back to info; config validation rejects them before this is reached.
func ParseLevel(name string) slog.Level {
	switch strings.ToLower(name) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func resolveVersion() string {
	if Version != "" {
		return Version
	}
	// A container built from a tagged module gets its version for free; a plain
	// `go build` yields the VCS revision instead.
	if info, ok := debug.ReadBuildInfo(); ok {
		if info.Main.Version != "" && info.Main.Version != "(devel)" {
			return info.Main.Version
		}
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && s.Value != "" {
				if len(s.Value) > 12 {
					return s.Value[:12]
				}
				return s.Value
			}
		}
	}
	return ""
}

// fanout duplicates every record to several handlers. It exists so a single
// slog call reaches both stdout and the OTLP pipeline without the caller
// knowing.
type fanout struct {
	handlers []slog.Handler
}

func newFanout(handlers ...slog.Handler) slog.Handler {
	if len(handlers) == 1 {
		return handlers[0]
	}
	return &fanout{handlers: handlers}
}

func (f *fanout) Enabled(ctx context.Context, lvl slog.Level) bool {
	for _, h := range f.handlers {
		if h.Enabled(ctx, lvl) {
			return true
		}
	}
	return false
}

func (f *fanout) Handle(ctx context.Context, rec slog.Record) error {
	var errs []error
	for _, h := range f.handlers {
		if !h.Enabled(ctx, rec.Level) {
			continue
		}
		// Each handler gets its own clone: handlers are allowed to consume a
		// Record's attributes, and slog.Record is not safe to share.
		if err := h.Handle(ctx, rec.Clone()); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (f *fanout) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := make([]slog.Handler, len(f.handlers))
	for i, h := range f.handlers {
		next[i] = h.WithAttrs(attrs)
	}
	return &fanout{handlers: next}
}

func (f *fanout) WithGroup(name string) slog.Handler {
	if name == "" {
		return f
	}
	next := make([]slog.Handler, len(f.handlers))
	for i, h := range f.handlers {
		next[i] = h.WithGroup(name)
	}
	return &fanout{handlers: next}
}
