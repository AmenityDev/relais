// Package ingest is the single path a message can take into relais.
//
// Both façades — the REST handler and the SMTP submission server — build a
// Request and call Submit. Neither one touches the database or the job queue
// directly, so the authorisation rules below cannot be bypassed or duplicated by
// accident: there is exactly one implementation, with exactly one set of callers.
//
// The order of the steps is load-bearing:
//
//  1. Rate limit, before any write, so a compromised credential cannot flood the
//     audit table it is being audited by.
//  2. Idempotency, so a client retrying after a timeout does not send twice.
//  3. Normalize, which extracts the sender and fixes up missing headers.
//  4. Authorise the sender against the credential's allow-list. No match is a
//     hard rejection: there is no permissive fallback and no debug bypass.
//  5. Resolve the backend from the sender's domain, pinning it to the message.
//  6. Persist and enqueue, atomically.
package ingest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/amenitydev/relais/internal/frompattern"
	"github.com/amenitydev/relais/internal/mailnorm"
	"github.com/amenitydev/relais/internal/ratelimit"
	"github.com/amenitydev/relais/internal/store"
)

// Rejection reasons, stored verbatim in email_message.rejection_reason.
//
// These strings are an operational contract: they are what an operator greps for
// and what the admin UI groups by, so renaming one rewrites history.
const (
	// ReasonSenderNotAllowed is the important one. It means a credential tried to
	// send as an address outside its allow-list, which is either a
	// misconfiguration or a leaked secret.
	ReasonSenderNotAllowed = "sender_not_allowed"
	// ReasonDomainNotConfigured means the sender's domain matched a pattern but no
	// enabled domain row routes it. That is a configuration gap, not an attack.
	ReasonDomainNotConfigured = "domain_not_configured"
	ReasonCredentialUnusable  = "credential_unusable"
	ReasonRateLimited         = "rate_limited"
	ReasonNoRecipients        = "no_recipients"
	ReasonTooManyRecipients   = "too_many_recipients"
	ReasonInvalidRecipient    = "invalid_recipient"
)

// Rejection is a refused submission.
//
// It is deliberately not an internal error: a rejection is a normal, expected
// outcome that the façades translate into a 4xx response or a 5xx SMTP reply.
type Rejection struct {
	// Reason is the machine token, one of the Reason* constants or a
	// mailnorm rejection code.
	Reason string
	// Detail is safe to show a client: it never contains message content.
	Detail string
	// MessageID is the persisted rejection row, or uuid.Nil when the rejection
	// was not recorded (which happens when the rejection rate limiter fires).
	MessageID uuid.UUID
	// Temporary marks a rejection the client may usefully retry, which maps to a
	// 429 over REST and a 4xx over SMTP.
	Temporary bool
}

func (r *Rejection) Error() string {
	if r.Detail == "" {
		return r.Reason
	}
	return r.Reason + ": " + r.Detail
}

// AsRejection extracts a Rejection from err, if it is one.
func AsRejection(err error) (*Rejection, bool) {
	var rejection *Rejection
	if errors.As(err, &rejection) {
		return rejection, true
	}
	return nil, false
}

// Enqueuer schedules delivery inside the caller's transaction.
//
// It is an interface rather than a concrete river client so that ingest carries
// no dependency on the queue implementation, and so tests can assert on what was
// enqueued without a database round trip through river.
type Enqueuer interface {
	// Enqueue must use tx: a job committed separately from its message row is a
	// message that never sends, or a job for a message that does not exist.
	Enqueue(ctx context.Context, tx pgx.Tx, messageID uuid.UUID) error
}

// Config bounds the pipeline. It mirrors the relevant parts of config.Config,
// kept as its own type so the package is testable without an environment.
type Config struct {
	MaxMessageBytes int64
	MaxHeaderCount  int
	MaxHeaderBytes  int64
	MaxRecipients   int

	DefaultRateLimitRPS    float64
	DefaultRateLimitBurst  int
	RejectedRateLimitRPS   float64
	RejectedRateLimitBurst int

	IdempotencyTTL time.Duration
}

// Service runs the pipeline.
type Service struct {
	store    *store.Store
	enqueuer Enqueuer
	limiter  *ratelimit.Limiter
	cfg      Config
	log      *slog.Logger

	// now and newID are injectable so that tests can assert on generated headers.
	now   func() time.Time
	newID func() string
}

// Options carries the dependencies Service needs.
type Options struct {
	Store    *store.Store
	Enqueuer Enqueuer
	Limiter  *ratelimit.Limiter
	Config   Config
	Log      *slog.Logger

	Now   func() time.Time
	NewID func() string
}

// New builds a Service.
func New(opts Options) (*Service, error) {
	switch {
	case opts.Store == nil:
		return nil, errors.New("ingest: a store is required")
	case opts.Enqueuer == nil:
		return nil, errors.New("ingest: an enqueuer is required")
	}

	if opts.Limiter == nil {
		opts.Limiter = ratelimit.New(ratelimit.Options{})
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.NewID == nil {
		opts.NewID = uuid.NewString
	}
	if opts.Config.MaxRecipients <= 0 {
		opts.Config.MaxRecipients = 50
	}
	if opts.Config.IdempotencyTTL <= 0 {
		opts.Config.IdempotencyTTL = 24 * time.Hour
	}

	return &Service{
		store:    opts.Store,
		enqueuer: opts.Enqueuer,
		limiter:  opts.Limiter,
		cfg:      opts.Config,
		log:      opts.Log,
		now:      opts.Now,
		newID:    opts.NewID,
	}, nil
}

// Facade names which entry point a submission arrived through.
type Facade = string

// Request is a submission. The credential is already authenticated: proving
// identity belongs to the façade, deciding what that identity may do belongs
// here.
type Request struct {
	Credential store.AuthCredential
	Facade     Facade

	// Raw is the complete RFC 5322 message.
	Raw []byte

	// EnvelopeRecipients is the authoritative delivery list. Over SMTP it is the
	// client's RCPT TO commands; over REST it is the union of to, cc and bcc.
	EnvelopeRecipients []string

	// DeclaredBcc lets the REST façade record blind recipients for the audit
	// trail even though no Bcc header is ever written. Left empty by the SMTP
	// façade, which takes them from the header instead.
	DeclaredBcc []string

	IdempotencyKey string
	RemoteIP       netip.Addr
}

// Result describes an accepted submission.
type Result struct {
	// ID is the email_message row, and the id a client uses to poll status.
	ID uuid.UUID
	// Status is "queued" for a fresh submission, or whatever the original
	// submission has reached when Duplicate is true.
	Status string
	// RFCMessageID is the Message-ID header, generated if the client omitted one.
	RFCMessageID string
	// Recipients is the envelope list actually accepted.
	Recipients []string
	// BackendID is the relay this message was pinned to at ingestion.
	BackendID uuid.UUID
	// Duplicate reports that an Idempotency-Key matched an earlier submission and
	// nothing new was enqueued.
	Duplicate bool
}

// Submit runs the pipeline.
//
// A returned *Rejection means the submission was refused for a reason the client
// is entitled to know about. Any other error is an internal failure the client
// should be told nothing about beyond "try again".
func (s *Service) Submit(ctx context.Context, req Request) (Result, error) {
	credential := req.Credential.Credential
	credentialKey := credential.ID.String()

	logger := s.log.With(
		slog.String("credential_id", credentialKey),
		slog.String("credential_name", credential.Name),
		slog.String("facade", req.Facade),
		slog.String("remote_ip", remoteIPString(req.RemoteIP)),
	)

	// A credential that the façade should already have refused. Checking again
	// costs nothing and means no future façade can forget to.
	if !req.Credential.Usable() {
		return Result{}, s.reject(ctx, req, logger, mailnorm.Message{}, &Rejection{
			Reason: ReasonCredentialUnusable,
			Detail: "the credential is disabled or revoked",
		})
	}

	// Rate limiting comes first, before any database write, so that a
	// compromised credential cannot fill the table that records its abuse.
	rps, burst := req.Credential.RateLimit(s.cfg.DefaultRateLimitRPS, s.cfg.DefaultRateLimitBurst)
	if !s.limiter.Allow(credentialKey, rps, burst) {
		logger.Warn("submission rate limited",
			slog.Float64("limit_rps", rps),
			slog.Int("limit_burst", burst),
		)
		// Not persisted: recording it would be the very write the limit exists to
		// prevent, and the log line already carries the signal.
		return Result{}, &Rejection{
			Reason:    ReasonRateLimited,
			Detail:    fmt.Sprintf("rate limit of %g requests per second exceeded", rps),
			Temporary: true,
		}
	}

	if req.IdempotencyKey != "" {
		existing, err := s.store.FindByIdempotencyKey(ctx, credential.ID, req.IdempotencyKey, s.cfg.IdempotencyTTL)
		switch {
		case err == nil:
			logger.Info("idempotent submission replayed",
				slog.String("message_id", existing.ID.String()),
				slog.String("status", existing.Status),
			)
			return Result{
				ID:           existing.ID,
				Status:       existing.Status,
				RFCMessageID: existing.MessageID,
				Recipients:   existing.EnvelopeRecipients,
				BackendID:    derefUUID(existing.SmtpBackendID),
				Duplicate:    true,
			}, nil
		case !errors.Is(err, store.ErrNotFound):
			return Result{}, fmt.Errorf("check idempotency key: %w", err)
		}
	}

	msg, err := mailnorm.Parse(req.Raw, mailnorm.Options{
		MaxBytes:       s.cfg.MaxMessageBytes,
		MaxHeaderCount: s.cfg.MaxHeaderCount,
		MaxHeaderBytes: s.cfg.MaxHeaderBytes,
		Now:            s.now,
		NewID:          s.newID,
	})
	if err != nil {
		// The message could not be understood, so there is no sender to attribute
		// the rejection to beyond the credential.
		return Result{}, s.reject(ctx, req, logger, mailnorm.Message{}, &Rejection{
			Reason: mailnorm.CodeOf(err),
			Detail: err.Error(),
		})
	}

	logger = logger.With(slog.String("from", msg.From.String()))

	// The check the whole service exists for. A sender outside the allow-list is
	// refused outright: no fallback, no override, no environment variable that
	// turns this off.
	pattern, allowed := req.Credential.Patterns.Match(msg.From)
	if !allowed {
		return Result{}, s.reject(ctx, req, logger, msg, &Rejection{
			Reason: ReasonSenderNotAllowed,
			Detail: fmt.Sprintf("the credential is not allowed to send as %s", msg.From),
		})
	}

	recipients, rejection := s.validateRecipients(req, msg)
	if rejection != nil {
		return Result{}, s.reject(ctx, req, logger, msg, rejection)
	}

	route, err := s.store.ResolveSender(ctx, msg.From.Domain)
	switch {
	case errors.Is(err, store.ErrNotFound):
		// The pattern allowed it but no domain row routes it. Almost always an
		// operator who granted "*@*.example.com" without setting
		// include_subdomains, so the message says so.
		return Result{}, s.reject(ctx, req, logger, msg, &Rejection{
			Reason: ReasonDomainNotConfigured,
			Detail: fmt.Sprintf("no enabled sending domain covers %s", msg.From.Domain),
		})
	case err != nil:
		return Result{}, fmt.Errorf("resolve sender domain %q: %w", msg.From.Domain, err)
	}

	bcc := req.DeclaredBcc
	if len(bcc) == 0 {
		bcc = msg.Bcc
	}

	row, err := s.store.InsertQueuedMessage(ctx, store.NewMessageParams{
		CredentialID:       credential.ID,
		Facade:             req.Facade,
		FromAddr:           msg.From.String(),
		FromDomain:         msg.From.Domain,
		To:                 msg.To,
		Cc:                 msg.Cc,
		Bcc:                bcc,
		EnvelopeRecipients: recipients,
		Subject:            msg.Subject,
		MessageID:          msg.MessageID,
		SizeBytes:          msg.Size,
		BackendID:          route.BackendID,
		IdempotencyKey:     req.IdempotencyKey,
		RemoteIP:           req.RemoteIP,
	}, msg.Raw, s.enqueuer.Enqueue)
	if err != nil {
		// A concurrent submission with the same idempotency key won the race.
		// Returning its result is the whole point of the key.
		if req.IdempotencyKey != "" && store.ConstraintName(err) == "email_message_idempotency_key" {
			existing, findErr := s.store.FindByIdempotencyKey(ctx, credential.ID, req.IdempotencyKey, s.cfg.IdempotencyTTL)
			if findErr == nil {
				return Result{
					ID:           existing.ID,
					Status:       existing.Status,
					RFCMessageID: existing.MessageID,
					Recipients:   existing.EnvelopeRecipients,
					BackendID:    derefUUID(existing.SmtpBackendID),
					Duplicate:    true,
				}, nil
			}
		}
		return Result{}, fmt.Errorf("persist message: %w", err)
	}

	// Usage tracking must never fail a legitimate send, so its error is logged
	// and dropped.
	if err := s.store.TouchCredential(ctx, credential.ID); err != nil {
		logger.Debug("could not record credential usage", slog.Any("error", err))
	}

	logger.Info("message accepted",
		slog.String("message_id", row.ID.String()),
		slog.String("rfc_message_id", msg.MessageID),
		slog.String("matched_pattern", pattern.String()),
		slog.String("backend", route.BackendName),
		slog.Int("recipients", len(recipients)),
		slog.Int64("size_bytes", msg.Size),
		slog.Bool("generated_message_id", msg.GeneratedMessageID),
		slog.Bool("stripped_bcc", msg.StrippedBcc),
	)

	return Result{
		ID:           row.ID,
		Status:       row.Status,
		RFCMessageID: msg.MessageID,
		Recipients:   recipients,
		BackendID:    route.BackendID,
	}, nil
}

// validateRecipients checks the envelope list the façade supplied.
func (s *Service) validateRecipients(req Request, msg mailnorm.Message) ([]string, *Rejection) {
	if len(req.EnvelopeRecipients) == 0 {
		return nil, &Rejection{
			Reason: ReasonNoRecipients,
			Detail: "the submission has no recipients",
		}
	}
	if len(req.EnvelopeRecipients) > s.cfg.MaxRecipients {
		// Refusing here yields a clear error, instead of an opaque 5xx from the
		// relay after the message has been queued and attempted.
		return nil, &Rejection{
			Reason: ReasonTooManyRecipients,
			Detail: fmt.Sprintf("%d recipients, over the limit of %d", len(req.EnvelopeRecipients), s.cfg.MaxRecipients),
		}
	}

	seen := make(map[string]struct{}, len(req.EnvelopeRecipients))
	out := make([]string, 0, len(req.EnvelopeRecipients))
	for _, raw := range req.EnvelopeRecipients {
		addr, err := frompattern.ParseAddress(raw)
		if err != nil {
			return nil, &Rejection{
				Reason: ReasonInvalidRecipient,
				Detail: fmt.Sprintf("%q is not a usable recipient address", raw),
			}
		}
		normalized := addr.String()
		if _, dup := seen[normalized]; dup {
			// A duplicate RCPT TO delivers twice and counts twice against the
			// relay's quota.
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out, nil
}

// reject records and logs a refusal, returning the Rejection to the caller.
//
// The log line is the security signal: it carries who tried to send as what,
// from where, and when — and never the message body. The subject is not logged
// either, even though it is stored, because a log pipeline is a much wider
// audience than the admin UI.
func (s *Service) reject(
	ctx context.Context,
	req Request,
	logger *slog.Logger,
	msg mailnorm.Message,
	rejection *Rejection,
) error {
	credential := req.Credential.Credential

	entry := logger.With(
		slog.String("reason", rejection.Reason),
		slog.String("detail", rejection.Detail),
		slog.Int("patterns_configured", req.Credential.Patterns.Len()),
		slog.Int("recipients", len(req.EnvelopeRecipients)),
		slog.Int("size_bytes", len(req.Raw)),
	)

	// A sender that was refused is the whole point of the record, so it is logged
	// at warn rather than info: this is what an alert rule watches.
	if rejection.Reason == ReasonSenderNotAllowed {
		entry.Warn("submission rejected: sender not allowed for this credential")
	} else {
		entry.Info("submission rejected")
	}

	// The rejection row is itself rate limited: a credential in a retry loop
	// against a misconfigured From would otherwise write a row per attempt.
	if !s.limiter.Allow("rejected:"+credential.ID.String(), s.cfg.RejectedRateLimitRPS, s.cfg.RejectedRateLimitBurst) {
		entry.Debug("rejection not persisted: the rejection record rate limit is saturated")
		return rejection
	}

	row, err := s.store.InsertRejectedMessage(ctx, store.RejectedMessageParams{
		CredentialID:       credential.ID,
		Facade:             req.Facade,
		Reason:             rejection.Reason,
		FromAddr:           msg.From.String(),
		FromDomain:         msg.From.Domain,
		To:                 msg.To,
		Cc:                 msg.Cc,
		Bcc:                msg.Bcc,
		EnvelopeRecipients: req.EnvelopeRecipients,
		Subject:            msg.Subject,
		MessageID:          msg.MessageID,
		SizeBytes:          int64(len(req.Raw)),
		RemoteIP:           req.RemoteIP,
	})
	if err != nil {
		// Failing to record a rejection must not turn into a 500: the client is
		// still being refused, which is the outcome that matters.
		entry.Error("could not record the rejection", slog.Any("error", err))
		return rejection
	}

	rejection.MessageID = row.ID
	return rejection
}

func remoteIPString(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	return addr.String()
}

func derefUUID(id *uuid.UUID) uuid.UUID {
	if id == nil {
		return uuid.Nil
	}
	return *id
}
