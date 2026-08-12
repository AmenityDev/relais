// Package jobs holds the river job definitions and workers.
//
// Delivery is a background job rather than part of the submission request for two
// reasons: a client should not wait on a relay it does not control, and a relay
// that is briefly unavailable should not turn into a failed API call. river runs
// on Postgres, which is what lets a message row, its payload and its delivery job
// commit in one transaction (see store.InsertQueuedMessage).
package jobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"

	"github.com/amenitydev/relais/internal/sender"
	"github.com/amenitydev/relais/internal/store"
)

// QueueEmailSend carries outbound deliveries. It is separate from the default
// queue so that maintenance work can never sit behind a backlog of mail, and so
// its worker count can be tuned independently.
const QueueEmailSend = "email_send"

// QueueMaintenance carries periodic housekeeping.
const QueueMaintenance = "maintenance"

// SendEmailArgs identifies a message to deliver.
//
// It carries nothing but the id on purpose: the job payload stays tiny, and the
// database remains the single source of truth for what is being sent. A job that
// embedded the recipients would go stale the moment anything changed.
type SendEmailArgs struct {
	MessageID uuid.UUID `json:"message_id"`
}

// Kind implements river.JobArgs.
func (SendEmailArgs) Kind() string { return "send_email" }

// InsertOpts routes the job to the delivery queue.
func (SendEmailArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueEmailSend}
}

// PurgePayloadsArgs triggers the retention sweep.
type PurgePayloadsArgs struct{}

// Kind implements river.JobArgs.
func (PurgePayloadsArgs) Kind() string { return "purge_payloads" }

// InsertOpts keeps housekeeping off the delivery queue.
func (PurgePayloadsArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueMaintenance}
}

// Deliverer is what the send worker needs from the SMTP layer.
type Deliverer interface {
	Send(ctx context.Context, route store.SenderRoute, msg sender.Message) (sender.Result, error)
}

// SendEmailWorker delivers one message.
//
// The status transitions it drives are the contract the admin UI and the REST
// status endpoint read, so each branch below ends with the row in a state that
// says what happened:
//
//	sent      delivered (error_code set when some recipients were refused)
//	failed    permanently refused, or retries exhausted
//	queued    a transient failure; river will try again
type SendEmailWorker struct {
	river.WorkerDefaults[SendEmailArgs]

	store     *store.Store
	deliverer Deliverer
	log       *slog.Logger
}

// NewSendEmailWorker builds the delivery worker.
func NewSendEmailWorker(st *store.Store, deliverer Deliverer, log *slog.Logger) *SendEmailWorker {
	if log == nil {
		log = slog.Default()
	}
	return &SendEmailWorker{store: st, deliverer: deliverer, log: log}
}

// Work delivers the message named by the job.
func (w *SendEmailWorker) Work(ctx context.Context, job *river.Job[SendEmailArgs]) error {
	messageID := job.Args.MessageID
	log := w.log.With(
		slog.String("message_id", messageID.String()),
		slog.Int("attempt", job.Attempt),
		slog.Int("max_attempts", job.MaxAttempts),
	)

	msg, err := w.store.GetMessage(ctx, messageID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// The row is gone. Retrying cannot bring it back, so the job is
			// cancelled rather than left to exhaust its attempts.
			log.Warn("delivery job references a message that no longer exists")
			return river.JobCancel(fmt.Errorf("message %s not found", messageID))
		}
		return fmt.Errorf("load message %s: %w", messageID, err)
	}

	// river guarantees at-least-once delivery, so a job may run twice. Sending
	// twice is the one outcome that cannot be undone.
	if msg.Status == store.StatusSent {
		log.Info("delivery job skipped: the message is already sent")
		return nil
	}

	claimed, err := w.store.MarkSending(ctx, messageID)
	if err != nil {
		return fmt.Errorf("claim message %s: %w", messageID, err)
	}
	if !claimed {
		// Another attempt reached 'sent' between the read above and here.
		log.Info("delivery job skipped: the message was sent concurrently")
		return nil
	}

	payload, err := w.store.GetPayload(ctx, messageID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Retention purged the body. There is nothing left to send, and no
			// amount of retrying will recreate it.
			return w.permanent(ctx, log, messageID, job, "payload_purged",
				"the message body was purged by retention before it could be delivered")
		}
		return fmt.Errorf("load payload for %s: %w", messageID, err)
	}

	route, enabled, err := w.store.RouteForMessage(ctx, msg)
	switch {
	case errors.Is(err, store.ErrNotFound):
		// The backend was deleted. An operator has to point the domain somewhere
		// else and resubmit; retrying this message forever helps nobody.
		return w.permanent(ctx, log, messageID, job, "backend_missing",
			"the backend this message was routed to no longer exists")
	case err != nil:
		// A password that cannot be opened lands here: an operator error worth
		// retrying, because restoring the key fixes it.
		return w.transient(ctx, log, messageID, job, "backend_unavailable", err.Error(), err)
	case !enabled:
		// Disabled is an operator action, and re-enabling is the expected fix, so
		// the message waits rather than failing.
		return w.transient(ctx, log, messageID, job, "backend_disabled",
			fmt.Sprintf("backend %q is disabled", route.BackendName), nil)
	}

	log = log.With(
		slog.String("backend", route.BackendName),
		slog.String("from", msg.FromAddr),
		slog.Int("recipients", len(msg.EnvelopeRecipients)),
	)

	result, err := w.deliverer.Send(ctx, route, sender.Message{
		// The envelope sender is the validated From, per D4.
		From:       msg.FromAddr,
		Recipients: msg.EnvelopeRecipients,
		Raw:        payload,
	})
	if err != nil {
		detail := err.Error()
		code := sender.CodeOf(err)
		if sender.IsPermanent(err) {
			return w.permanent(ctx, log, messageID, job, code, detail)
		}
		return w.transient(ctx, log, messageID, job, code, detail, err)
	}

	if result.Partial() {
		// Delivered, but not to everyone. The status stays 'sent' because the
		// message did go out; error_code is what tells an operator to look.
		if err := w.store.MarkSentPartial(ctx, messageID, sender.CodePartialRecipients, result.RejectedDetail()); err != nil {
			return fmt.Errorf("record a partial delivery for %s: %w", messageID, err)
		}
		log.Warn("message delivered to some recipients only",
			slog.Int("accepted", len(result.Accepted)),
			slog.Int("rejected", len(result.Rejected)),
			slog.String("rejected_detail", result.RejectedDetail()),
			slog.String("relay_response", result.Response),
		)
		return nil
	}

	if err := w.store.MarkSent(ctx, messageID); err != nil {
		// The relay already has the message. Failing the job here would send it
		// again, so the error is reported without retrying.
		log.Error("the message was delivered but its status could not be recorded",
			slog.Any("error", err))
		return river.JobCancel(fmt.Errorf("message %s was delivered but not recorded: %w", messageID, err))
	}

	log.Info("message delivered",
		slog.Bool("over_tls", result.UsedTLS),
		slog.String("relay_response", result.Response),
	)
	return nil
}

// permanent records a failure that must not be retried.
func (w *SendEmailWorker) permanent(
	ctx context.Context,
	log *slog.Logger,
	messageID uuid.UUID,
	job *river.Job[SendEmailArgs],
	code, detail string,
) error {
	if err := w.store.MarkFailed(ctx, messageID, code, detail); err != nil {
		return fmt.Errorf("record the permanent failure of %s: %w", messageID, err)
	}
	log.Warn("delivery failed permanently",
		slog.String("error_code", code),
		slog.String("error_detail", detail),
	)
	// JobCancel stops river from retrying. Hammering a relay over a mailbox that
	// will never exist is how an IP reputation gets ruined.
	return river.JobCancel(errors.New(code + ": " + detail))
}

// transient records a failure worth retrying, or converts it to a permanent one
// when this was the last attempt.
func (w *SendEmailWorker) transient(
	ctx context.Context,
	log *slog.Logger,
	messageID uuid.UUID,
	job *river.Job[SendEmailArgs],
	code, detail string,
	cause error,
) error {
	// The last attempt matters: river discards the job, and without this the row
	// would stay 'queued' forever with nothing left to move it.
	if job.Attempt >= job.MaxAttempts {
		if err := w.store.MarkFailed(ctx, messageID, code, detail); err != nil {
			return fmt.Errorf("record the exhausted retries of %s: %w", messageID, err)
		}
		log.Warn("delivery failed after exhausting retries",
			slog.String("error_code", code),
			slog.String("error_detail", detail),
		)
		return river.JobCancel(errors.New(code + ": " + detail))
	}

	if err := w.store.MarkRetrying(ctx, messageID, code, detail); err != nil {
		return fmt.Errorf("record the transient failure of %s: %w", messageID, err)
	}
	log.Info("delivery failed, will retry",
		slog.String("error_code", code),
		slog.String("error_detail", detail),
	)

	// Returning an error is what makes river schedule the retry with backoff.
	if cause != nil {
		return fmt.Errorf("%s: %w", code, cause)
	}
	return errors.New(code + ": " + detail)
}

// PurgePayloadsWorker enforces payload retention.
type PurgePayloadsWorker struct {
	river.WorkerDefaults[PurgePayloadsArgs]

	store           *store.Store
	sentRetention   time.Duration
	failedRetention time.Duration
	log             *slog.Logger
}

// NewPurgePayloadsWorker builds the retention worker.
func NewPurgePayloadsWorker(st *store.Store, sentRetention, failedRetention time.Duration, log *slog.Logger) *PurgePayloadsWorker {
	if log == nil {
		log = slog.Default()
	}
	return &PurgePayloadsWorker{
		store:           st,
		sentRetention:   sentRetention,
		failedRetention: failedRetention,
		log:             log,
	}
}

// Work deletes message bodies past their retention window.
func (w *PurgePayloadsWorker) Work(ctx context.Context, job *river.Job[PurgePayloadsArgs]) error {
	deleted, err := w.store.PurgePayloads(ctx, w.sentRetention, w.failedRetention)
	if err != nil {
		return fmt.Errorf("purge payloads: %w", err)
	}
	if deleted > 0 {
		w.log.Info("purged message payloads past retention",
			slog.Int64("deleted", deleted),
			slog.Duration("sent_retention", w.sentRetention),
			slog.Duration("failed_retention", w.failedRetention),
		)
	}
	return nil
}

// Enqueuer is the river-backed implementation of ingest.Enqueuer.
type Enqueuer struct {
	client      *river.Client[pgx.Tx]
	maxAttempts int
}

// NewEnqueuer wraps a river client for use by the ingest pipeline.
func NewEnqueuer(client *river.Client[pgx.Tx], maxAttempts int) *Enqueuer {
	if maxAttempts <= 0 {
		maxAttempts = 8
	}
	return &Enqueuer{client: client, maxAttempts: maxAttempts}
}

// Enqueue inserts a delivery job inside the caller's transaction.
func (e *Enqueuer) Enqueue(ctx context.Context, tx pgx.Tx, messageID uuid.UUID) error {
	_, err := e.client.InsertTx(ctx, tx, SendEmailArgs{MessageID: messageID}, &river.InsertOpts{
		Queue:       QueueEmailSend,
		MaxAttempts: e.maxAttempts,
	})
	if err != nil {
		return fmt.Errorf("enqueue delivery for %s: %w", messageID, err)
	}
	return nil
}

// ClientOptions configures the river client.
type ClientOptions struct {
	Store     *store.Store
	Deliverer Deliverer
	Log       *slog.Logger

	// Workers false builds an insert-only client, for a process that accepts mail
	// but does not deliver it (RELAIS_WORKER_ENABLED=false).
	Workers bool
	// Count is the number of concurrent deliveries in this process. The
	// per-backend ceiling is enforced separately, by the sender.
	Count       int
	MaxAttempts int
	JobTimeout  time.Duration

	SentRetention   time.Duration
	FailedRetention time.Duration
	PurgeInterval   time.Duration
}

// NewClient builds the river client.
//
// With Workers false it is insert-only: an API-only instance still needs to
// enqueue, but must not consume. That is what makes splitting the process across
// containers a configuration change rather than a code change.
func NewClient(opts ClientOptions) (*river.Client[pgx.Tx], error) {
	if opts.Store == nil {
		return nil, errors.New("jobs: a store is required")
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}

	config := &river.Config{
		Logger: opts.Log,
	}

	if opts.Workers {
		if opts.Deliverer == nil {
			return nil, errors.New("jobs: a deliverer is required to run workers")
		}
		if opts.Count <= 0 {
			opts.Count = 5
		}
		if opts.MaxAttempts <= 0 {
			opts.MaxAttempts = 8
		}
		if opts.PurgeInterval <= 0 {
			opts.PurgeInterval = time.Hour
		}

		workers := river.NewWorkers()
		river.AddWorker(workers, NewSendEmailWorker(opts.Store, opts.Deliverer, opts.Log))
		river.AddWorker(workers, NewPurgePayloadsWorker(opts.Store, opts.SentRetention, opts.FailedRetention, opts.Log))

		config.Workers = workers
		config.MaxAttempts = opts.MaxAttempts
		config.JobTimeout = opts.JobTimeout
		config.Queues = map[string]river.QueueConfig{
			QueueEmailSend: {MaxWorkers: opts.Count},
			// One worker is plenty: housekeeping is a single DELETE, and running
			// several concurrently would only contend on the same rows.
			QueueMaintenance: {MaxWorkers: 1},
		}
		config.PeriodicJobs = []*river.PeriodicJob{
			river.NewPeriodicJob(
				river.PeriodicInterval(opts.PurgeInterval),
				func() (river.JobArgs, *river.InsertOpts) {
					return PurgePayloadsArgs{}, nil
				},
				// RunOnStart so a long-running deployment does not wait a full
				// interval before its first sweep after a restart.
				&river.PeriodicJobOpts{RunOnStart: true},
			),
		}
	}

	client, err := river.NewClient(riverpgxv5.New(opts.Store.Pool()), config)
	if err != nil {
		return nil, fmt.Errorf("build the river client: %w", err)
	}
	return client, nil
}
