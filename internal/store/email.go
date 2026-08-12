package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	dbgen "github.com/amenitydev/relais/internal/db/gen"
)

// Message statuses, matching the email_message_status CHECK.
const (
	StatusQueued   = "queued"
	StatusSending  = "sending"
	StatusSent     = "sent"
	StatusFailed   = "failed"
	StatusRejected = "rejected"
)

// Façade names, matching the email_message_facade CHECK.
const (
	FacadeREST = "rest"
	FacadeSMTP = "smtp"
)

// NewMessageParams describes a message to accept.
type NewMessageParams struct {
	CredentialID uuid.UUID
	Facade       string

	FromAddr   string
	FromDomain string

	// To, Cc and Bcc are descriptive: what the submitter declared.
	To  []string
	Cc  []string
	Bcc []string
	// EnvelopeRecipients is the authoritative delivery list.
	EnvelopeRecipients []string

	Subject   string
	MessageID string
	SizeBytes int64

	BackendID      uuid.UUID
	IdempotencyKey string
	RemoteIP       netip.Addr
}

// RejectedMessageParams describes a submission that was refused.
//
// Reason is required by a database constraint, because a rejection with no
// recorded reason is an audit trail that cannot answer the only question anyone
// will ask of it.
type RejectedMessageParams struct {
	CredentialID uuid.UUID
	Facade       string
	Reason       string

	FromAddr   string
	FromDomain string
	To         []string
	Cc         []string
	Bcc        []string
	// EnvelopeRecipients may be empty: a rejection often happens before the
	// recipients are even known.
	EnvelopeRecipients []string

	Subject   string
	MessageID string
	SizeBytes int64
	RemoteIP  netip.Addr
}

// InsertQueuedMessage persists an accepted message, its payload and its delivery
// job atomically.
//
// enqueue runs inside the same transaction, which is the whole reason the job
// queue lives in Postgres: a message row without a job would never be sent and
// nobody would notice, and a job without a row would fail forever on a message
// that does not exist. Either both exist or neither does.
func (s *Store) InsertQueuedMessage(
	ctx context.Context,
	p NewMessageParams,
	payload []byte,
	enqueue func(ctx context.Context, tx pgx.Tx, messageID uuid.UUID) error,
) (dbgen.EmailMessage, error) {
	if len(p.EnvelopeRecipients) == 0 {
		return dbgen.EmailMessage{}, errors.New("insert queued message: no envelope recipients")
	}
	if len(payload) == 0 {
		return dbgen.EmailMessage{}, errors.New("insert queued message: empty payload")
	}

	var row dbgen.EmailMessage
	err := s.withTxRaw(ctx, func(tx pgx.Tx, q *dbgen.Queries) error {
		var err error
		row, err = q.InsertEmailMessage(ctx, dbgen.InsertEmailMessageParams{
			CredentialID:       uuidPtr(p.CredentialID),
			Status:             StatusQueued,
			Facade:             p.Facade,
			FromAddr:           p.FromAddr,
			FromDomain:         p.FromDomain,
			ToAddrs:            nonNilSlice(p.To),
			CcAddrs:            nonNilSlice(p.Cc),
			BccAddrs:           nonNilSlice(p.Bcc),
			EnvelopeRecipients: p.EnvelopeRecipients,
			Subject:            p.Subject,
			MessageID:          p.MessageID,
			SizeBytes:          int32(p.SizeBytes),
			SmtpBackendID:      uuidPtr(p.BackendID),
			IdempotencyKey:     stringPtr(p.IdempotencyKey),
			RemoteIp:           addrPtr(p.RemoteIP),
		})
		if err != nil {
			return err
		}

		if err := q.InsertEmailPayload(ctx, dbgen.InsertEmailPayloadParams{
			EmailMessageID: row.ID,
			Raw:            payload,
		}); err != nil {
			return err
		}

		if enqueue == nil {
			return errors.New("no enqueue function supplied")
		}
		return enqueue(ctx, tx, row.ID)
	})
	if err != nil {
		return dbgen.EmailMessage{}, wrap("insert queued message", err)
	}
	return row, nil
}

// InsertRejectedMessage records a refused submission. No payload is stored: the
// refused content is not retained, only the fact of the attempt.
func (s *Store) InsertRejectedMessage(ctx context.Context, p RejectedMessageParams) (dbgen.EmailMessage, error) {
	if p.Reason == "" {
		return dbgen.EmailMessage{}, errors.New("insert rejected message: a reason is required")
	}

	row, err := s.q.InsertRejectedEmailMessage(ctx, dbgen.InsertRejectedEmailMessageParams{
		CredentialID:       uuidPtr(p.CredentialID),
		Facade:             p.Facade,
		FromAddr:           p.FromAddr,
		FromDomain:         p.FromDomain,
		ToAddrs:            nonNilSlice(p.To),
		CcAddrs:            nonNilSlice(p.Cc),
		BccAddrs:           nonNilSlice(p.Bcc),
		EnvelopeRecipients: nonNilSlice(p.EnvelopeRecipients),
		Subject:            p.Subject,
		MessageID:          p.MessageID,
		SizeBytes:          int32(p.SizeBytes),
		RejectionReason:    &p.Reason,
		RemoteIp:           addrPtr(p.RemoteIP),
	})
	if err != nil {
		return dbgen.EmailMessage{}, wrap("insert rejected message", err)
	}
	return row, nil
}

// GetMessage fetches a message by id.
func (s *Store) GetMessage(ctx context.Context, id uuid.UUID) (dbgen.EmailMessage, error) {
	row, err := s.q.GetEmailMessage(ctx, id)
	if err != nil {
		return dbgen.EmailMessage{}, wrap("get email message", err)
	}
	return row, nil
}

// FindByIdempotencyKey returns a previous submission made with the same key.
//
// ErrNotFound means "no previous submission", which is the normal path.
func (s *Store) FindByIdempotencyKey(ctx context.Context, credentialID uuid.UUID, key string, ttl time.Duration) (dbgen.EmailMessage, error) {
	row, err := s.q.GetEmailMessageByIdempotencyKey(ctx, dbgen.GetEmailMessageByIdempotencyKeyParams{
		CredentialID:   uuidPtr(credentialID),
		IdempotencyKey: &key,
		Ttl:            intervalOf(ttl),
	})
	if err != nil {
		return dbgen.EmailMessage{}, wrap("find message by idempotency key", err)
	}
	return row, nil
}

// GetPayload returns the raw message bytes, or ErrNotFound once retention has
// purged them.
func (s *Store) GetPayload(ctx context.Context, messageID uuid.UUID) ([]byte, error) {
	raw, err := s.q.GetEmailPayload(ctx, messageID)
	if err != nil {
		return nil, wrap("get email payload", err)
	}
	return raw, nil
}

// MarkSending claims a message for a delivery attempt and increments its counter.
//
// It reports false when nothing was updated, which means the message is already
// sent: river delivers at least once, so a duplicate job must be a no-op rather
// than a second send.
func (s *Store) MarkSending(ctx context.Context, id uuid.UUID) (bool, error) {
	affected, err := s.q.MarkEmailSending(ctx, id)
	if err != nil {
		return false, wrap("mark message sending", err)
	}
	return affected > 0, nil
}

// MarkSent records a successful delivery.
func (s *Store) MarkSent(ctx context.Context, id uuid.UUID) error {
	if _, err := s.q.MarkEmailSent(ctx, id); err != nil {
		return wrap("mark message sent", err)
	}
	return nil
}

// MarkSentPartial records a delivery the relay accepted for some recipients while
// refusing others. See the query comment for why the status stays 'sent'.
func (s *Store) MarkSentPartial(ctx context.Context, id uuid.UUID, code, detail string) error {
	if _, err := s.q.MarkEmailSentPartial(ctx, dbgen.MarkEmailSentPartialParams{
		ID:          id,
		ErrorCode:   stringPtr(code),
		ErrorDetail: stringPtr(detail),
	}); err != nil {
		return wrap("mark message partially sent", err)
	}
	return nil
}

// RouteForMessage builds the delivery route for a message from the backend that
// was pinned to it at ingestion.
//
// It deliberately does not re-resolve the sender's domain: an admin re-assigning
// the domain must not silently redirect mail that was already accepted for
// somewhere else. ErrNotFound means the backend was deleted, which is permanent;
// a disabled backend is returned with Enabled false so the caller can treat it as
// transient and wait for the operator to re-enable it.
func (s *Store) RouteForMessage(ctx context.Context, msg dbgen.EmailMessage) (SenderRoute, bool, error) {
	if msg.SmtpBackendID == nil {
		return SenderRoute{}, false, fmt.Errorf("message %s has no pinned backend: %w", msg.ID, ErrNotFound)
	}

	row, err := s.q.GetSenderRouteForBackend(ctx, *msg.SmtpBackendID)
	if err != nil {
		return SenderRoute{}, false, wrap("get route for message", err)
	}

	password, err := s.OpenBackendPassword(row.AuthPasswordSealed)
	if err != nil {
		return SenderRoute{}, false, fmt.Errorf("backend %q: %w", row.BackendName, err)
	}

	return SenderRoute{
		DomainName:     msg.FromDomain,
		BackendID:      row.BackendID,
		BackendName:    row.BackendName,
		Host:           row.Host,
		Port:           row.Port,
		TLSMode:        row.TlsMode,
		AuthUser:       row.AuthUser,
		AuthPassword:   password,
		HeloName:       row.HeloName,
		MaxConcurrency: row.MaxConcurrency,
	}, row.Enabled, nil
}

// MarkFailed records a permanent failure. code is a stable machine token and
// detail is the remote's own response, kept for the operator.
func (s *Store) MarkFailed(ctx context.Context, id uuid.UUID, code, detail string) error {
	if _, err := s.q.MarkEmailFailed(ctx, dbgen.MarkEmailFailedParams{
		ID:          id,
		ErrorCode:   stringPtr(code),
		ErrorDetail: stringPtr(detail),
	}); err != nil {
		return wrap("mark message failed", err)
	}
	return nil
}

// MarkRetrying records a transient failure, leaving the message queued.
func (s *Store) MarkRetrying(ctx context.Context, id uuid.UUID, code, detail string) error {
	if _, err := s.q.MarkEmailRetrying(ctx, dbgen.MarkEmailRetryingParams{
		ID:          id,
		ErrorCode:   stringPtr(code),
		ErrorDetail: stringPtr(detail),
	}); err != nil {
		return wrap("mark message retrying", err)
	}
	return nil
}

// PurgePayloads deletes bodies past their retention window and reports how many
// went.
func (s *Store) PurgePayloads(ctx context.Context, sentRetention, failedRetention time.Duration) (int64, error) {
	deleted, err := s.q.PurgeSentPayloads(ctx, dbgen.PurgeSentPayloadsParams{
		SentRetention:   intervalOf(sentRetention),
		FailedRetention: intervalOf(failedRetention),
	})
	if err != nil {
		return 0, wrap("purge payloads", err)
	}
	return deleted, nil
}

// CountByStatus returns the message count per status, for the admin dashboard.
func (s *Store) CountByStatus(ctx context.Context) (map[string]int64, error) {
	rows, err := s.q.CountEmailsByStatus(ctx)
	if err != nil {
		return nil, wrap("count messages by status", err)
	}
	out := make(map[string]int64, len(rows))
	for _, row := range rows {
		out[row.Status] = row.Total
	}
	return out, nil
}

// withTxRaw runs fn with both the transaction and the bound queries, for the one
// caller that needs to hand the transaction to something else (the job queue).
func (s *Store) withTxRaw(ctx context.Context, fn func(pgx.Tx, *dbgen.Queries) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := fn(tx, s.q.WithTx(tx)); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}

func uuidPtr(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}

func stringPtr(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func addrPtr(addr netip.Addr) *netip.Addr {
	if !addr.IsValid() {
		return nil
	}
	return &addr
}

// nonNilSlice keeps a NOT NULL text[] column happy: pgx sends a nil slice as
// NULL, which the column refuses.
func nonNilSlice(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
