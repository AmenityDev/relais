package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/amenitydev/relais/internal/ingest"
	"github.com/amenitydev/relais/internal/mailbuild"
	"github.com/amenitydev/relais/internal/store"
)

// addressList accepts either a single address or an array of them.
//
// The Resend API is permissive here and so are real clients: "to": "a@b.test"
// and "to": ["a@b.test"] both appear in the wild. Refusing the scalar form would
// be technically defensible and practically annoying.
type addressList []string

// UnmarshalJSON implements json.Unmarshaler.
func (l *addressList) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "null" {
		*l = nil
		return nil
	}

	if strings.HasPrefix(trimmed, "[") {
		var list []string
		if err := json.Unmarshal(data, &list); err != nil {
			return fmt.Errorf("expected a string or an array of strings: %w", err)
		}
		*l = list
		return nil
	}

	var single string
	if err := json.Unmarshal(data, &single); err != nil {
		return fmt.Errorf("expected a string or an array of strings: %w", err)
	}
	*l = []string{single}
	return nil
}

// sendRequest is the POST /v1/emails payload.
//
// Field names follow the Resend API so that an existing client or SDK needs as
// little adaptation as possible. Compatibility is a convenience, not a contract:
// where Resend's behaviour would conflict with a rule relais enforces, relais
// wins.
type sendRequest struct {
	From    string      `json:"from"`
	To      addressList `json:"to"`
	Cc      addressList `json:"cc"`
	Bcc     addressList `json:"bcc"`
	ReplyTo addressList `json:"reply_to"`

	Subject string `json:"subject"`
	Text    string `json:"text"`
	HTML    string `json:"html"`

	Headers     map[string]string   `json:"headers"`
	Attachments []requestAttachment `json:"attachments"`
}

type requestAttachment struct {
	Filename string `json:"filename"`
	// Content is base64. It is decoded here rather than in mailbuild so that a
	// malformed payload is reported as the client error it is.
	Content     string `json:"content"`
	ContentType string `json:"content_type"`
	ContentID   string `json:"content_id"`
}

// sendResponse is returned on acceptance.
//
// Resend returns only an id. The extra fields cost nothing and answer the two
// questions a caller immediately has: has it gone out yet, and what Message-ID
// will the recipient see.
type sendResponse struct {
	ID         string   `json:"id"`
	Status     string   `json:"status"`
	MessageID  string   `json:"message_id"`
	Recipients []string `json:"recipients"`
	Idempotent bool     `json:"idempotent_replay,omitempty"`
}

// messageResponse is returned by GET /v1/emails/{id}.
type messageResponse struct {
	ID        string   `json:"id"`
	Status    string   `json:"status"`
	From      string   `json:"from"`
	To        []string `json:"to"`
	Cc        []string `json:"cc,omitempty"`
	Bcc       []string `json:"bcc,omitempty"`
	Subject   string   `json:"subject"`
	MessageID string   `json:"message_id"`
	// Recipients is the envelope list: who this was actually relayed to.
	Recipients []string `json:"recipients"`
	SizeBytes  int32    `json:"size_bytes"`
	Attempts   int32    `json:"attempts"`
	CreatedAt  string   `json:"created_at"`
	SentAt     *string  `json:"sent_at"`
	// Error is set on a failed or partially delivered message.
	Error *messageError `json:"error,omitempty"`
	// RejectionReason is set on a message relais refused.
	RejectionReason *string `json:"rejection_reason,omitempty"`
}

type messageError struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// handleSendEmail accepts a submission.
//
// It does no validation of its own beyond decoding: assembling the message is
// mailbuild's job and authorising it is ingest's. This handler exists to turn
// JSON into an ingest.Request and an ingest outcome into a status code, and
// keeping it that thin is what guarantees the REST and SMTP façades cannot drift
// apart.
func (s *Server) handleSendEmail(w http.ResponseWriter, r *http.Request) {
	auth, ok := credentialFrom(r.Context())
	if !ok {
		// Unreachable behind requireAPIKey; a 500 rather than a silent send if the
		// middleware is ever detached by mistake.
		writeInternal(w, s.log, "no credential on an authenticated route", errors.New("missing credential"))
		return
	}

	var request sendRequest
	if err := decodeJSON(w, r, &request); err != nil {
		return
	}

	attachments, err := decodeAttachments(request.Attachments)
	if err != nil {
		writeBuildError(w, err)
		return
	}

	built, err := mailbuild.Build(mailbuild.Input{
		From:        request.From,
		To:          request.To,
		Cc:          request.Cc,
		Bcc:         request.Bcc,
		ReplyTo:     request.ReplyTo,
		Subject:     request.Subject,
		Text:        request.Text,
		HTML:        request.HTML,
		Headers:     request.Headers,
		Attachments: attachments,
	}, mailbuild.Options{
		MaxRecipients: s.limits.MaxRecipients,
		MaxBytes:      s.limits.MaxMessageBytes,
	})
	if err != nil {
		writeBuildError(w, err)
		return
	}

	result, err := s.ingest.Submit(r.Context(), ingest.Request{
		Credential: auth,
		Facade:     store.FacadeREST,
		Raw:        built.Raw,
		// The envelope is the union of to, cc and bcc: mailbuild computed it and
		// deduplicated it.
		EnvelopeRecipients: built.Envelope,
		// Blind recipients appear in no header, so they are passed separately to
		// keep them in the audit trail.
		DeclaredBcc:    built.Bcc,
		IdempotencyKey: strings.TrimSpace(r.Header.Get("Idempotency-Key")),
		RemoteIP:       clientIPFrom(r.Context()),
	})
	if err != nil {
		if rejection, ok := ingest.AsRejection(err); ok {
			writeRejection(w, s.log, rejection)
			return
		}
		// Anything else is relais failing, not the client. A submission that
		// could not be persisted must not look accepted.
		writeUnavailable(w, s.log, "could not accept the submission", err)
		return
	}

	// 200 for a replay, 202 for a fresh acceptance: the status code is the
	// cheapest way to tell a client whether its retry actually sent anything.
	status := http.StatusAccepted
	if result.Duplicate {
		status = http.StatusOK
	}

	writeJSON(w, status, sendResponse{
		ID:         result.ID.String(),
		Status:     result.Status,
		MessageID:  result.RFCMessageID,
		Recipients: result.Recipients,
		Idempotent: result.Duplicate,
	})
}

// handleGetEmail reports a message's status.
func (s *Server) handleGetEmail(w http.ResponseWriter, r *http.Request) {
	auth, ok := credentialFrom(r.Context())
	if !ok {
		writeInternal(w, s.log, "no credential on an authenticated route", errors.New("missing credential"))
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		// A malformed id is indistinguishable from an unknown one as far as the
		// client needs to know.
		writeError(w, http.StatusNotFound, errorBody{Code: codeNotFound, Message: "no such message"})
		return
	}

	msg, err := s.store.GetMessage(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, errorBody{Code: codeNotFound, Message: "no such message"})
			return
		}
		writeUnavailable(w, s.log, "could not read the message", err)
		return
	}

	// A credential may only read its own messages, and an unauthorized read is
	// answered 404 rather than 403: a 403 would confirm the id exists, which is
	// itself information the caller has no right to.
	if msg.CredentialID == nil || *msg.CredentialID != auth.Credential.ID {
		s.log.Warn("credential attempted to read another credential's message",
			slog.String("credential_id", auth.Credential.ID.String()),
			slog.String("credential_name", auth.Credential.Name),
			slog.String("message_id", id.String()),
		)
		writeError(w, http.StatusNotFound, errorBody{Code: codeNotFound, Message: "no such message"})
		return
	}

	response := messageResponse{
		ID:              msg.ID.String(),
		Status:          msg.Status,
		From:            msg.FromAddr,
		To:              msg.ToAddrs,
		Cc:              msg.CcAddrs,
		Bcc:             msg.BccAddrs,
		Subject:         msg.Subject,
		MessageID:       msg.MessageID,
		Recipients:      msg.EnvelopeRecipients,
		SizeBytes:       msg.SizeBytes,
		Attempts:        msg.AttemptCount,
		CreatedAt:       msg.CreatedAt.UTC().Format(timeLayout),
		SentAt:          rfc3339(msg.SentAt),
		RejectionReason: msg.RejectionReason,
	}
	if msg.ErrorCode != nil {
		response.Error = &messageError{Code: *msg.ErrorCode}
		if msg.ErrorDetail != nil {
			response.Error.Detail = *msg.ErrorDetail
		}
	}

	writeJSON(w, http.StatusOK, response)
}

// decodeAttachments turns base64 payloads into bytes.
//
// Decoding here rather than in mailbuild means a bad base64 blob is reported as
// what it is — a malformed request field — instead of surfacing as a MIME
// assembly failure further down.
func decodeAttachments(attachments []requestAttachment) ([]mailbuild.Attachment, error) {
	if len(attachments) == 0 {
		return nil, nil
	}

	out := make([]mailbuild.Attachment, 0, len(attachments))
	for i, attachment := range attachments {
		// Accept both standard and URL-safe base64, with or without padding:
		// clients disagree, and the distinction carries no meaning here.
		content, err := decodeBase64(attachment.Content)
		if err != nil {
			name := attachment.Filename
			if name == "" {
				name = "(unnamed)"
			}
			return nil, mailbuild.NewError(mailbuild.CodeInvalidAttachment, "attachments",
				"attachments[%d] (%s): %v", i, name, err)
		}
		out = append(out, mailbuild.Attachment{
			Filename:    attachment.Filename,
			ContentType: attachment.ContentType,
			Content:     content,
			ContentID:   attachment.ContentID,
		})
	}
	return out, nil
}

func decodeBase64(value string) ([]byte, error) {
	cleaned := strings.Map(func(r rune) rune {
		// Line breaks are common in base64 pasted from a file.
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, value)
	if cleaned == "" {
		return nil, errors.New("the content is empty")
	}

	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if decoded, err := encoding.DecodeString(cleaned); err == nil {
			return decoded, nil
		}
	}
	return nil, errors.New("the content is not valid base64")
}

const timeLayout = "2006-01-02T15:04:05Z07:00"
