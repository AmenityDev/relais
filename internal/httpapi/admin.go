package httpapi

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/amenitydev/relais/internal/adminauth"
	"github.com/amenitydev/relais/internal/db"
	"github.com/amenitydev/relais/internal/frompattern"
	"github.com/amenitydev/relais/internal/sender"
	"github.com/amenitydev/relais/internal/store"
)

// Admin-specific error codes.
const (
	codeForbidden      = "forbidden"
	codeAdminDisabled  = "admin_disabled"
	codeInvalidRequest = "invalid_request"
	codeConflict       = "conflict"
	codeInUse          = "still_referenced"
	codeInvalidCursor  = "invalid_cursor"
)

// Prober tests a backend connection without sending anything.
//
// An interface rather than *sender.Sender so the admin API can be built without
// one, and so a test can assert on what was probed.
type Prober interface {
	Probe(ctx context.Context, route store.SenderRoute) (sender.ProbeResult, error)
}

// AdminOptions carries what the admin surface needs.
type AdminOptions struct {
	Store    *store.Store
	Verifier *adminauth.Verifier
	Pool     *db.Pool
	Prober   Prober
	Log      *slog.Logger
	Version  string

	MaxRequestBytes int64
	PageSize        int
	MaxPageSize     int

	TrustedProxyHeader string
}

// AdminServer serves /admin/v1.
type AdminServer struct {
	store    *store.Store
	verifier *adminauth.Verifier
	pool     *db.Pool
	prober   Prober
	log      *slog.Logger
	version  string

	maxRequestBytes int64
	pageSize        int
	maxPageSize     int

	trustedProxyHeader string
}

// NewAdminServer builds the admin surface.
func NewAdminServer(opts AdminOptions) (*AdminServer, error) {
	switch {
	case opts.Store == nil:
		return nil, errors.New("httpapi: a store is required for the admin API")
	case opts.Verifier == nil:
		// Without a verifier there is no way to authenticate an admin, and an
		// unauthenticated admin API is worse than none at all.
		return nil, errors.New("httpapi: an OIDC verifier is required for the admin API")
	case opts.Pool == nil:
		return nil, errors.New("httpapi: a database pool is required for the admin API")
	}

	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.MaxRequestBytes <= 0 {
		opts.MaxRequestBytes = 1 << 20
	}
	if opts.PageSize <= 0 {
		opts.PageSize = 50
	}
	if opts.MaxPageSize <= 0 {
		opts.MaxPageSize = 200
	}

	return &AdminServer{
		store:              opts.Store,
		verifier:           opts.Verifier,
		pool:               opts.Pool,
		prober:             opts.Prober,
		log:                opts.Log,
		version:            opts.Version,
		maxRequestBytes:    opts.MaxRequestBytes,
		pageSize:           opts.PageSize,
		maxPageSize:        opts.MaxPageSize,
		trustedProxyHeader: opts.TrustedProxyHeader,
	}, nil
}

// Handler assembles the admin router.
//
// The shape encodes the authorisation model: everything under /admin/v1 is
// authenticated, and every mutating route additionally sits behind requireWrite.
// A new read endpoint is safe by construction; a new write endpoint has to be
// placed in a group whose name says what it grants.
func (s *AdminServer) Handler() http.Handler {
	router := chi.NewRouter()

	router.Use(middleware.RequestID)
	router.Use(middleware.Recoverer)
	router.Use(resolveClientIP(s.trustedProxyHeader))
	router.Use(logRequests(s.log))
	router.Use(func(next http.Handler) http.Handler {
		return otelhttp.NewHandler(next, "relais.admin",
			otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
				if pattern := chi.RouteContext(r.Context()).RoutePattern(); pattern != "" {
					return r.Method + " " + pattern
				}
				return r.Method
			}),
		)
	})

	// The probes are mounted here too: this listener may be the only one an
	// orchestrator can reach when the public one is disabled.
	MountHealth(router, s.pool, s.version)

	router.Route("/admin/v1", func(admin chi.Router) {
		admin.Use(limitBody(s.maxRequestBytes))
		admin.Use(s.requireAdminToken)

		admin.Get("/identity", s.handleIdentity)
		admin.Get("/stats", s.handleStats)

		admin.Get("/backends", s.handleListBackends)
		admin.Get("/domains", s.handleListDomains)
		admin.Get("/domains:resolve", s.handleResolveDomain)
		admin.Get("/credentials", s.handleListCredentials)
		admin.Get("/credentials/{id}", s.handleGetCredential)
		admin.Get("/credentials/{id}/patterns", s.handleListPatterns)
		admin.Get("/messages", s.handleListMessages)
		admin.Get("/messages/{id}", s.handleGetMessage)

		// A dry-run reads nothing and writes nothing, so a viewer may run it. It is
		// also the whole reason the frontend never reimplements the grammar.
		admin.Post("/patterns:validate", s.handleValidatePattern)
		admin.Post("/credentials/{id}/patterns:test", s.handleTestPattern)

		admin.Group(func(write chi.Router) {
			write.Use(s.requireWrite)

			write.Post("/backends", s.handleCreateBackend)
			write.Patch("/backends/{id}", s.handleUpdateBackend)
			write.Delete("/backends/{id}", s.handleDeleteBackend)
			// A connection test opens a socket and authenticates, so it is a write
			// in the sense that matters: it acts outside relais using stored
			// credentials.
			write.Post("/backends/{id}:test", s.handleProbeBackend)

			write.Post("/domains", s.handleCreateDomain)
			write.Patch("/domains/{id}", s.handleUpdateDomain)
			write.Delete("/domains/{id}", s.handleDeleteDomain)

			write.Post("/credentials", s.handleCreateCredential)
			write.Patch("/credentials/{id}", s.handleUpdateCredential)
			write.Post("/credentials/{id}:revoke", s.handleRevokeCredential)
			// Rotation and deletion are separate verbs on purpose: one replaces the
			// secret and keeps everything else, the other keeps nothing.
			write.Post("/credentials/{id}:rotate", s.handleRotateCredential)
			write.Delete("/credentials/{id}", s.handleDeleteCredential)
			write.Post("/credentials/{id}/patterns", s.handleAddPatterns)
			write.Delete("/credentials/{id}/patterns/{patternID}", s.handleDeletePattern)
		})
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

// contextKeyIdentity carries the verified admin.
const contextKeyIdentity contextKey = 100

func identityFrom(ctx context.Context) (adminauth.Identity, bool) {
	identity, ok := ctx.Value(contextKeyIdentity).(adminauth.Identity)
	return identity, ok
}

// requireAdminToken verifies the bearer token and attaches the identity.
func (s *AdminServer) requireAdminToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := bearerValue(r.Header.Get("Authorization"))
		if err != nil {
			writeAdminUnauthorized(w)
			return
		}

		identity, err := s.verifier.Verify(r.Context(), token)
		if err != nil {
			switch {
			case errors.Is(err, adminauth.ErrForbidden):
				// Authenticated but in no relais group: they exist, they are simply
				// not allowed, and saying so is more useful than a 401 that sends
				// them to re-login forever.
				writeError(w, http.StatusForbidden, errorBody{
					Code:    codeForbidden,
					Message: "your account is not a member of a relais group",
				})
			case errors.Is(err, adminauth.ErrProviderUnavailable):
				// Never a 401. Telling an admin their credentials are wrong while
				// Authentik is down sends them looking in entirely the wrong place.
				writeUnavailable(w, s.log, "the identity provider is unreachable", err)
			default:
				writeAdminUnauthorized(w)
			}
			return
		}

		// Recorded on the shared holder so the access logger, which sits above this
		// middleware, can attribute the request.
		if info := infoFrom(r.Context()); info != nil {
			info.adminSubject = identity.String()
			info.adminRole = string(identity.Role)
		}

		ctx := context.WithValue(r.Context(), contextKeyIdentity, identity)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// requireWrite refuses a viewer.
//
// Go is the authority on this. The UI hides what a viewer cannot do, but a hidden
// button is not an authorisation check, and this is the check.
func (s *AdminServer) requireWrite(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, ok := identityFrom(r.Context())
		if !ok {
			writeInternal(w, s.log, "no identity on an authenticated admin route", errors.New("missing identity"))
			return
		}
		if !identity.CanWrite() {
			s.log.Warn("viewer attempted a write",
				slog.String("admin", identity.String()),
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
			)
			writeError(w, http.StatusForbidden, errorBody{
				Code:    codeForbidden,
				Message: "this account has read-only access",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// writeAdminUnauthorized answers an authentication failure, saying nothing about
// which part failed.
func writeAdminUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="relais-admin"`)
	writeError(w, http.StatusUnauthorized, errorBody{
		Code:    codeUnauthorized,
		Message: "authentication failed",
	})
}

// bearerValue extracts a bearer token, accepting the scheme in any case.
func bearerValue(header string) (string, error) {
	const prefix = "bearer "
	value := strings.TrimSpace(header)
	if len(value) < len(prefix) || !strings.EqualFold(value[:len(prefix)], prefix) {
		return "", errors.New("missing or malformed Authorization header")
	}
	token := strings.TrimSpace(value[len(prefix):])
	if token == "" {
		return "", errors.New("empty bearer token")
	}
	return token, nil
}

// --- shared request helpers -------------------------------------------------

// pathUUID reads a UUID path parameter, answering 404 on a malformed one.
//
// A malformed id and an unknown one are indistinguishable to a caller on purpose:
// there is nothing to learn from the difference.
func (s *AdminServer) pathUUID(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, name))
	if err != nil {
		writeError(w, http.StatusNotFound, errorBody{Code: codeNotFound, Message: "no such resource"})
		return uuid.Nil, false
	}
	return id, true
}

// writeStoreError maps a store failure onto a response.
//
// Centralised so every handler answers the same way: a conflict is always 409, a
// referenced row is always 409 with an explanation, and an unrecognised failure is
// never reported as the caller's fault.
func (s *AdminServer) writeStoreError(w http.ResponseWriter, what string, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, errorBody{Code: codeNotFound, Message: "no such resource"})
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, errorBody{
			Code:    codeConflict,
			Message: "that name or value is already taken",
			Field:   constraintField(store.ConstraintName(err)),
		})
	case errors.Is(err, store.ErrReference):
		writeError(w, http.StatusConflict, errorBody{
			Code:    codeInUse,
			Message: "something still references this, or what it points at does not exist",
		})
	case errors.Is(err, store.ErrConstraint):
		// A CHECK violation means the Go side should have caught it first, so this
		// is a defect worth logging loudly even though the caller sees a 422.
		s.log.Error("a database constraint rejected a write the application should have validated",
			slog.String("operation", what),
			slog.String("constraint", store.ConstraintName(err)),
			slog.Any("error", err),
		)
		writeError(w, http.StatusUnprocessableEntity, errorBody{
			Code:    codeInvalidRequest,
			Message: err.Error(),
		})
	default:
		writeUnavailable(w, s.log, what, err)
	}
}

// constraintField maps a constraint name onto the payload field that caused it,
// so a UI can put the error next to the right input.
func constraintField(constraint string) string {
	switch constraint {
	case "smtp_backend_name_key", "credential_name_key":
		return "name"
	case "domain_name_key":
		return "name"
	case "credential_lookup_key":
		return "username"
	case "credential_from_pattern_key":
		return "pattern"
	default:
		return ""
	}
}

// writeValidationError answers a request the application itself refused.
func writeValidationError(w http.ResponseWriter, field string, err error) {
	writeError(w, http.StatusUnprocessableEntity, errorBody{
		Code:    codeInvalidRequest,
		Message: err.Error(),
		Field:   field,
	})
}

// pageLimit resolves the requested page size, clamped.
func (s *AdminServer) pageLimit(r *http.Request) int32 {
	limit := s.pageSize
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	if limit > s.maxPageSize {
		limit = s.maxPageSize
	}
	return int32(limit)
}

// cursor encodes a keyset position.
//
// It is base64 of "<RFC3339Nano>|<uuid>" rather than the two values as separate
// query parameters, so that a client treats it as opaque and cannot come to depend
// on the ordering columns.
func encodeCursor(createdAt time.Time, id uuid.UUID) string {
	return base64.RawURLEncoding.EncodeToString(
		[]byte(createdAt.UTC().Format(time.RFC3339Nano) + "|" + id.String()))
}

func decodeCursor(raw string) (time.Time, uuid.UUID, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return time.Time{}, uuid.Nil, errors.New("the cursor is not valid")
	}
	createdRaw, idRaw, found := strings.Cut(string(decoded), "|")
	if !found {
		return time.Time{}, uuid.Nil, errors.New("the cursor is not valid")
	}
	createdAt, err := time.Parse(time.RFC3339Nano, createdRaw)
	if err != nil {
		return time.Time{}, uuid.Nil, errors.New("the cursor is not valid")
	}
	id, err := uuid.Parse(idRaw)
	if err != nil {
		return time.Time{}, uuid.Nil, errors.New("the cursor is not valid")
	}
	return createdAt, id, nil
}

// explainPattern renders a sender pattern in words.
//
// The grammar has one genuinely surprising rule — "*.example.com" not covering
// "example.com" — and stating it next to every pattern is cheaper than an operator
// discovering it from a rejected message.
func explainPattern(pattern string) string {
	parsed, err := frompattern.Parse(pattern)
	if err != nil {
		return ""
	}

	local, domain, _ := strings.Cut(parsed.String(), "@")
	subdomains := strings.HasPrefix(domain, "*.")
	apex := strings.TrimPrefix(domain, "*.")

	var sender string
	if local == "*" {
		sender = "any local part"
	} else {
		sender = "the local part " + local
	}

	if subdomains {
		return sender + " at any strict subdomain of " + apex +
			" (not " + apex + " itself, which needs its own pattern)"
	}
	return sender + " at exactly " + apex
}
