// Package httpapi serves the REST façade and the admin API.
//
// Handlers are ordinary net/http handlers routed by chi, so middleware from the
// standard library and from otelhttp composes without an adapter, and the mail
// submission logic stays reusable by the SMTP façade.
package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/amenitydev/relais/internal/db"
)

// healthTimeout bounds the readiness probe's database check. A probe that hangs
// is worse than one that fails: an orchestrator can act on a failure.
const healthTimeout = 2 * time.Second

// NewHealthRouter returns a router exposing only the probe endpoints.
//
// Probes are deliberately unauthenticated, and deliberately say nothing beyond
// what an orchestrator needs: an unauthenticated endpoint that reports version
// details or database errors is free reconnaissance.
func NewHealthRouter(pool *db.Pool, version string) http.Handler {
	router := chi.NewRouter()
	router.Use(middleware.Recoverer)
	MountHealth(router, pool, version)
	return router
}

// MountHealth attaches the probe endpoints to an existing router.
func MountHealth(router chi.Router, pool *db.Pool, version string) {
	// Liveness: the process is running and can answer. It must not depend on the
	// database, otherwise a brief database outage would have the orchestrator
	// restart healthy processes and make the outage worse.
	router.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// Readiness: this instance can serve traffic, which requires the database.
	router.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), healthTimeout)
		defer cancel()

		if err := db.Healthy(ctx, pool); err != nil {
			// The reason stays in the logs, not in the response body.
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"status": "unavailable",
				"reason": "database",
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})
}
