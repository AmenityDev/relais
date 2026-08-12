-- name: InsertEmailMessage :one
INSERT INTO email_message (
    credential_id, status, facade, from_addr, from_domain,
    to_addrs, cc_addrs, bcc_addrs, envelope_recipients,
    subject, message_id, size_bytes, smtp_backend_id,
    idempotency_key, remote_ip
) VALUES (
    @credential_id, @status, @facade, @from_addr, @from_domain,
    @to_addrs, @cc_addrs, @bcc_addrs, @envelope_recipients,
    @subject, @message_id, @size_bytes, @smtp_backend_id,
    @idempotency_key, @remote_ip
)
RETURNING *;

-- InsertRejectedEmailMessage records a submission that was refused.
--
-- Rejections are persisted deliberately: "credential X tried to send as Y" is
-- the signal that matters when a secret leaks. No payload is ever stored for a
-- rejected row, so the refused content is not retained.
-- name: InsertRejectedEmailMessage :one
INSERT INTO email_message (
    credential_id, status, facade, from_addr, from_domain,
    to_addrs, cc_addrs, bcc_addrs, envelope_recipients,
    subject, message_id, size_bytes, rejection_reason, remote_ip
) VALUES (
    @credential_id, 'rejected', @facade, @from_addr, @from_domain,
    @to_addrs, @cc_addrs, @bcc_addrs, @envelope_recipients,
    @subject, @message_id, @size_bytes, @rejection_reason, @remote_ip
)
RETURNING *;

-- name: InsertEmailPayload :exec
INSERT INTO email_payload (email_message_id, raw)
VALUES (@email_message_id, @raw);

-- name: GetEmailMessage :one
SELECT * FROM email_message WHERE id = @id;

-- GetEmailMessageByIdempotencyKey backs the retry-safe submission path: a client
-- that retries after a timeout gets the original message back instead of sending
-- a second copy.
-- name: GetEmailMessageByIdempotencyKey :one
SELECT * FROM email_message
WHERE credential_id = @credential_id
  AND idempotency_key = @idempotency_key
  AND created_at > now() - @ttl::interval;

-- name: GetEmailPayload :one
SELECT raw FROM email_payload WHERE email_message_id = @email_message_id;

-- MarkEmailSending claims a queued message for a delivery attempt.
--
-- The status guard makes the claim idempotent: a job that runs twice (river
-- guarantees at-least-once) updates nothing the second time, and the caller sees
-- zero rows affected.
-- name: MarkEmailSending :execrows
UPDATE email_message
SET status        = 'sending',
    attempt_count = attempt_count + 1,
    error_code    = NULL,
    error_detail  = NULL
WHERE id = @id
  AND status IN ('queued', 'sending');

-- name: MarkEmailSent :execrows
UPDATE email_message
SET status       = 'sent',
    sent_at      = now(),
    error_code   = NULL,
    error_detail = NULL
WHERE id = @id
  AND status <> 'sent';

-- name: MarkEmailFailed :execrows
UPDATE email_message
SET status       = 'failed',
    error_code   = @error_code,
    error_detail = @error_detail
WHERE id = @id
  AND status <> 'sent';

-- MarkEmailRetrying records a transient failure while leaving the message queued
-- for river to retry.
-- name: MarkEmailRetrying :execrows
UPDATE email_message
SET status       = 'queued',
    error_code   = @error_code,
    error_detail = @error_detail
WHERE id = @id
  AND status <> 'sent';

-- ListEmailMessages pages the admin view, newest first.
--
-- Keyset pagination on (created_at, id) rather than OFFSET: the offset cost grows
-- with the table, and a message inserted mid-scroll would shift every later page.
--
-- The optional filters use sqlc.narg, not @named parameters. A plain @name is
-- generated as a non-nullable Go type, so "@filter IS NULL" is never true and an
-- unset filter silently matched nothing — the listing returned zero rows however
-- it was called. sqlc.narg generates a pointer, which is what makes the IS NULL
-- branch reachable.
-- name: ListEmailMessages :many
SELECT
    m.*,
    c.name AS credential_name,
    b.name AS backend_name
FROM email_message m
LEFT JOIN credential c ON c.id = m.credential_id
LEFT JOIN smtp_backend b ON b.id = m.smtp_backend_id
WHERE (sqlc.narg('status')::text IS NULL OR m.status = sqlc.narg('status')::text)
  AND (sqlc.narg('credential_filter')::uuid IS NULL OR m.credential_id = sqlc.narg('credential_filter')::uuid)
  AND (
      sqlc.narg('before_created_at')::timestamptz IS NULL
      OR (m.created_at, m.id) < (sqlc.narg('before_created_at')::timestamptz, sqlc.narg('before_id')::uuid)
  )
ORDER BY m.created_at DESC, m.id DESC
LIMIT @row_limit;

-- PurgeSentPayloads drops bodies that are no longer needed.
--
-- Two retentions, because the two cases have different value: a delivered
-- message's body is dead weight, while a failed one may still be worth replaying.
-- name: PurgeSentPayloads :execrows
DELETE FROM email_payload p
USING email_message m
WHERE p.email_message_id = m.id
  AND (
      (m.status = 'sent' AND m.sent_at < now() - @sent_retention::interval)
      OR (m.status = 'failed' AND m.updated_at < now() - @failed_retention::interval)
  );

-- name: CountEmailsByStatus :many
SELECT status, count(*) AS total
FROM email_message
GROUP BY status;

-- MarkEmailSentPartial records a delivery the relay accepted for some recipients
-- while refusing others.
--
-- The status is 'sent' because the message was delivered; error_code is what
-- tells an operator to look closer. A distinct status would be more expressive
-- and is the obvious v2 change, once per-recipient tracking exists.
-- name: MarkEmailSentPartial :execrows
UPDATE email_message
SET status       = 'sent',
    sent_at      = now(),
    error_code   = @error_code,
    error_detail = @error_detail
WHERE id = @id
  AND status <> 'sent';
