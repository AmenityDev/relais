package httpapi

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/amenitydev/relais/internal/authn"
	"github.com/amenitydev/relais/internal/db"
	"github.com/amenitydev/relais/internal/ingest"
	"github.com/amenitydev/relais/internal/store"
)

// Limits bounds what a submission may contain. It mirrors config.Limits, kept as
// its own type so the package is testable without an environment.
type Limits struct {
	MaxMessageBytes int64
	MaxRequestBytes int64
	MaxRecipients   int
}

// Server holds the dependencies of the HTTP surface.
type Server struct {
	ingest        *ingest.Service
	store         *store.Store
	authenticator *authn.Authenticator
	pool          *db.Pool
	limits        Limits
	log           *slog.Logger
	version       string

	trustedProxyHeader string
}

// Options carries what a Server needs.
type Options struct {
	Ingest        *ingest.Service
	Store         *store.Store
	Authenticator *authn.Authenticator
	Pool          *db.Pool
	Limits        Limits
	Log           *slog.Logger
	Version       string

	// TrustedProxyHeader names the header carrying the real client IP. Empty
	// ignores any such header, which is the safe default: see resolveClientIP.
	TrustedProxyHeader string
}

// NewServer builds the HTTP surface.
func NewServer(opts Options) (*Server, error) {
	switch {
	case opts.Ingest == nil:
		return nil, errors.New("httpapi: an ingest service is required")
	case opts.Store == nil:
		return nil, errors.New("httpapi: a store is required")
	case opts.Authenticator == nil:
		return nil, errors.New("httpapi: an authenticator is required")
	case opts.Pool == nil:
		return nil, errors.New("httpapi: a database pool is required")
	}

	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Limits.MaxRecipients <= 0 {
		opts.Limits.MaxRecipients = 50
	}

	return &Server{
		ingest:             opts.Ingest,
		store:              opts.Store,
		authenticator:      opts.Authenticator,
		pool:               opts.Pool,
		limits:             opts.Limits,
		log:                opts.Log,
		version:            opts.Version,
		trustedProxyHeader: opts.TrustedProxyHeader,
	}, nil
}

// Handler assembles the router.
//
// Route grouping is the authorisation boundary: /v1 sits inside a group carrying
// requireAPIKey, so a new endpoint added there is authenticated by default. Making
// something public requires mounting it outside that group, which is a visible act
// in the diff rather than a forgotten middleware.
func (s *Server) Handler() http.Handler {
	router := chi.NewRouter()

	router.Use(middleware.RequestID)
	router.Use(middleware.Recoverer)
	router.Use(resolveClientIP(s.trustedProxyHeader))
	router.Use(logRequests(s.log))
	// Traces carry the route pattern rather than the raw path, so a message id
	// does not become a distinct span name per request.
	router.Use(func(next http.Handler) http.Handler {
		return otelhttp.NewHandler(next, "relais.http",
			otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
				if pattern := chi.RouteContext(r.Context()).RoutePattern(); pattern != "" {
					return r.Method + " " + pattern
				}
				return r.Method
			}),
		)
	})

	// Probes are public: an orchestrator has no credential, and they reveal
	// nothing beyond up or down.
	MountHealth(router, s.pool, s.version)

	router.Route("/v1", func(v1 chi.Router) {
		v1.Use(limitBody(s.limits.MaxRequestBytes))
		v1.Use(requireAPIKey(s.authenticator, s.log))

		v1.Post("/emails", s.handleSendEmail)
		v1.Get("/emails/{id}", s.handleGetEmail)
	})

	router.NotFound(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, errorBody{Code: codeNotFound, Message: "no such endpoint"})
	})
	router.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusMethodNotAllowed, errorBody{
			Code:    codeMethodNotAllow,
			Message: "that method is not allowed on this endpoint",
		})
	})

	return router
}
