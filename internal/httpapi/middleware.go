package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	"github.com/amenitydev/relais/internal/authn"
	"github.com/amenitydev/relais/internal/store"
)

// uuidNil is a readable name for the zero UUID, used in comparisons.
var uuidNil = uuid.Nil

// Context keys. A private type prevents collisions with any other package's keys.
type contextKey int

const contextKeyRequestInfo contextKey = iota

// requestInfo carries per-request facts that middleware discovers at different
// depths of the chain.
//
// It is a mutable holder rather than a set of immutable context values on
// purpose. The access logger sits at the top of the chain, so it only ever sees
// the context it created; a credential attached deeper down by
// context.WithValue would be invisible to it, and the log line could never say
// which credential made the request — which is the first thing anyone wants when
// investigating. Writing into a shared struct is what lets the outermost
// middleware observe what an inner one learned.
//
// It is confined to one request and touched only from the goroutine serving it.
type requestInfo struct {
	clientIP   netip.Addr
	credential *store.AuthCredential
	// adminSubject and adminRole are the admin surface's equivalent, filled in by
	// requireAdminToken for the same reason.
	adminSubject string
	adminRole    string
}

func infoFrom(ctx context.Context) *requestInfo {
	info, _ := ctx.Value(contextKeyRequestInfo).(*requestInfo)
	return info
}

// credentialFrom returns the authenticated credential attached by requireAPIKey.
func credentialFrom(ctx context.Context) (store.AuthCredential, bool) {
	info := infoFrom(ctx)
	if info == nil || info.credential == nil {
		return store.AuthCredential{}, false
	}
	return *info.credential, true
}

// clientIPFrom returns the resolved client address, which may be invalid when it
// could not be determined.
func clientIPFrom(ctx context.Context) netip.Addr {
	info := infoFrom(ctx)
	if info == nil {
		return netip.Addr{}
	}
	return info.clientIP
}

// resolveClientIP records the client address on the request context.
//
// The proxy header is only consulted when one is explicitly configured. Trusting
// X-Forwarded-For by default would let any client forge the address that gets
// recorded on a rejected submission — which is precisely the field an operator
// relies on when investigating a leaked credential.
func resolveClientIP(trustedHeader string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			addr := peerAddr(r)

			if trustedHeader != "" {
				if value := r.Header.Get(trustedHeader); value != "" {
					// X-Forwarded-For is a list; the client is the leftmost entry.
					first := value
					if comma := strings.IndexByte(value, ','); comma >= 0 {
						first = value[:comma]
					}
					if parsed, err := netip.ParseAddr(strings.TrimSpace(first)); err == nil {
						addr = parsed
					}
				}
			}

			info := &requestInfo{clientIP: addr}
			ctx := context.WithValue(r.Context(), contextKeyRequestInfo, info)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func peerAddr(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	// A v4-in-v6 address logs better as plain v4.
	return addr.Unmap()
}

// limitBody caps the request body.
//
// http.MaxBytesReader is used rather than a Content-Length check because a
// chunked request has no length to check, and the point is to bound what gets
// read into memory.
func limitBody(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if maxBytes > 0 && r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// logRequests emits one line per request.
//
// Deliberately absent: the request body, the query string beyond the path, and
// any header. A submission body is an email, and an access log is a much wider
// audience than the admin UI.
func logRequests(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			wrapped := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			next.ServeHTTP(wrapped, r)

			attrs := []any{
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", wrapped.Status()),
				slog.Int("bytes", wrapped.BytesWritten()),
				slog.Duration("duration", time.Since(start).Round(time.Millisecond)),
				slog.String("request_id", middleware.GetReqID(r.Context())),
			}
			if addr := clientIPFrom(r.Context()); addr.IsValid() {
				attrs = append(attrs, slog.String("remote_ip", addr.String()))
			}
			if auth, ok := credentialFrom(r.Context()); ok {
				attrs = append(attrs,
					slog.String("credential_id", auth.Credential.ID.String()),
					slog.String("credential_name", auth.Credential.Name),
				)
			}
			if info := infoFrom(r.Context()); info != nil && info.adminSubject != "" {
				// Who changed what is the whole point of an admin audit trail.
				attrs = append(attrs,
					slog.String("admin", info.adminSubject),
					slog.String("admin_role", info.adminRole),
				)
			}

			// A 5xx is a defect worth surfacing; everything else is routine.
			if wrapped.Status() >= 500 {
				log.Error("request failed", attrs...)
				return
			}
			log.Info("request", attrs...)
		})
	}
}

// requireAPIKey authenticates the request and attaches the credential.
//
// Authentication is a middleware rather than a step inside each handler so that
// adding a route cannot accidentally leave it unauthenticated: an endpoint has to
// be mounted outside this group to be public, which is a visible act.
func requireAPIKey(authenticator *authn.Authenticator, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			remoteIP := ""
			if addr := clientIPFrom(r.Context()); addr.IsValid() {
				remoteIP = addr.String()
			}

			token, err := authn.BearerToken(r.Header.Get("Authorization"))
			if err != nil {
				writeUnauthorized(w)
				return
			}

			auth, err := authenticator.APIKey(r.Context(), token, remoteIP)
			if err != nil {
				// A database failure must not be reported as an authentication
				// failure: an outage would look to every client like their key
				// stopped working.
				if !isUnauthenticated(err) {
					writeUnavailable(w, log, "could not verify the credential", err)
					return
				}
				writeUnauthorized(w)
				return
			}

			// Recorded on the shared holder, so the access logger at the top of
			// the chain can attribute the request even though it never sees this
			// context.
			if info := infoFrom(r.Context()); info != nil {
				info.credential = &auth
			}
			next.ServeHTTP(w, r)
		})
	}
}

func isUnauthenticated(err error) bool {
	return errors.Is(err, authn.ErrUnauthenticated)
}
