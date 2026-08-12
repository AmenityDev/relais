package httpapi

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/amenitydev/relais/internal/ingest"
	"github.com/amenitydev/relais/internal/mailbuild"
	"github.com/amenitydev/relais/internal/mailnorm"
)

// errorEnvelope is the single shape every error response takes.
//
// One shape means a client can handle failures generically, and `code` is a
// stable token rather than prose: the codes come from mailnorm, mailbuild and
// ingest, so the API surfaces the same vocabulary the logs and the database use.
type errorEnvelope struct {
	Error errorBody `json:"error"`
}

type errorBody struct {
	// Code is stable and machine-readable.
	Code string `json:"code"`
	// Message is for a human reading a log or a terminal. It never contains
	// message content.
	Message string `json:"message"`
	// Field names the offending payload field, when there is one.
	Field string `json:"field,omitempty"`
	// MessageID is set when a rejection was recorded, so an operator can find the
	// row that explains it.
	MessageID string `json:"message_id,omitempty"`
}

// Internal error codes that do not come from a lower layer.
const (
	codeInvalidJSON    = "invalid_json"
	codeUnauthorized   = "unauthorized"
	codeNotFound       = "not_found"
	codePayloadTooBig  = "message_too_large"
	codeInternal       = "internal_error"
	codeUnavailable    = "service_unavailable"
	codeMethodNotAllow = "method_not_allowed"
)

// writeError sends an error response.
func writeError(w http.ResponseWriter, status int, body errorBody) {
	writeJSON(w, status, errorEnvelope{Error: body})
}

// writeRejection maps an ingest rejection onto an HTTP response.
//
// The mapping matters: a client has to be able to tell "fix your configuration"
// (4xx that will never succeed) from "try again" (429), and a library that
// retries blindly on every 4xx would hammer relais over a From it is not
// authorised to use.
func writeRejection(w http.ResponseWriter, log *slog.Logger, rejection *ingest.Rejection) {
	body := errorBody{Code: rejection.Reason, Message: rejection.Detail}
	if rejection.MessageID != uuidNil {
		body.MessageID = rejection.MessageID.String()
	}

	status := http.StatusUnprocessableEntity
	switch rejection.Reason {
	case ingest.ReasonSenderNotAllowed:
		// The credential is real but not permitted to send as this address. That
		// is an authorisation failure, not a malformed request.
		status = http.StatusForbidden
	case ingest.ReasonCredentialUnusable:
		status = http.StatusUnauthorized
	case ingest.ReasonRateLimited:
		status = http.StatusTooManyRequests
		// Without this a client has no idea how long to wait, and the usual
		// reaction is to retry immediately.
		w.Header().Set("Retry-After", "1")
	case mailnorm.CodeTooLarge, mailnorm.CodeHeadersTooLarge:
		status = http.StatusRequestEntityTooLarge
	}

	writeError(w, status, body)
}

// writeBuildError maps a message-assembly failure onto a response.
//
// These are all client mistakes — a malformed address, a missing body, a header
// the caller may not set — so they are 4xx and they name the field.
func writeBuildError(w http.ResponseWriter, err error) {
	body := errorBody{
		Code:    mailbuild.CodeOf(err),
		Message: err.Error(),
		Field:   mailbuild.FieldOf(err),
	}

	status := http.StatusUnprocessableEntity
	if body.Code == mailbuild.CodeTooLarge {
		status = http.StatusRequestEntityTooLarge
	}
	writeError(w, status, body)
}

// writeUnauthorized answers an authentication failure.
//
// The response says nothing beyond "it failed": whether the credential is
// unknown, revoked or simply wrong is recorded in the logs, never handed to
// whoever is failing to authenticate.
func writeUnauthorized(w http.ResponseWriter) {
	// RFC 7235 wants a challenge on a 401.
	w.Header().Set("WWW-Authenticate", `Bearer realm="relais"`)
	writeError(w, http.StatusUnauthorized, errorBody{
		Code:    codeUnauthorized,
		Message: "authentication failed",
	})
}

// writeInternal answers a server-side failure, logging the cause and telling the
// client nothing about it.
func writeInternal(w http.ResponseWriter, log *slog.Logger, what string, err error) {
	log.Error(what, slog.Any("error", err))
	writeError(w, http.StatusInternalServerError, errorBody{
		Code:    codeInternal,
		Message: "the request could not be completed",
	})
}

// writeUnavailable answers a dependency failure, which is distinct from a bug:
// the client should retry.
func writeUnavailable(w http.ResponseWriter, log *slog.Logger, what string, err error) {
	log.Error(what, slog.Any("error", err))
	w.Header().Set("Retry-After", "5")
	writeError(w, http.StatusServiceUnavailable, errorBody{
		Code:    codeUnavailable,
		Message: "the service is temporarily unable to accept submissions",
	})
}

// decodeJSON reads a JSON body, refusing unknown fields.
//
// Refusing unknown fields is a deliberate choice for a submission API: a
// misspelled "attachements" that is silently ignored means a client believes it
// attached a file and nobody finds out until a recipient complains.
func decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(target); err != nil {
		var maxBytes *http.MaxBytesError
		if errors.As(err, &maxBytes) {
			writeError(w, http.StatusRequestEntityTooLarge, errorBody{
				Code:    codePayloadTooBig,
				Message: "the request body exceeds the configured limit of " + strconv.FormatInt(maxBytes.Limit, 10) + " bytes",
			})
			return err
		}
		writeError(w, http.StatusBadRequest, errorBody{
			Code:    codeInvalidJSON,
			Message: "the request body is not valid JSON: " + err.Error(),
		})
		return err
	}

	// A second value in the stream means the client sent something other than one
	// JSON object, which is worth refusing rather than half-reading.
	if decoder.More() {
		writeError(w, http.StatusBadRequest, errorBody{
			Code:    codeInvalidJSON,
			Message: "the request body must contain exactly one JSON object",
		})
		return errors.New("trailing content after the JSON body")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	// A failed write to a disconnected client is not actionable.
	_ = json.NewEncoder(w).Encode(body)
}

// rfc3339 renders a timestamp, or nil for an absent one, so a JSON consumer sees
// null rather than a zero date that looks like 1970.
func rfc3339(t *time.Time) *string {
	if t == nil {
		return nil
	}
	formatted := t.UTC().Format(time.RFC3339)
	return &formatted
}
