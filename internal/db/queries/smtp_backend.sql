-- name: CreateSMTPBackend :one
INSERT INTO smtp_backend (
    name, host, port, tls_mode, auth_user, auth_password_sealed,
    helo_name, max_concurrency, enabled
) VALUES (
    @name, @host, @port, @tls_mode, @auth_user, @auth_password_sealed,
    @helo_name, @max_concurrency, @enabled
)
RETURNING *;

-- name: GetSMTPBackend :one
SELECT * FROM smtp_backend WHERE id = @id;

-- name: GetSMTPBackendByName :one
SELECT * FROM smtp_backend WHERE lower(name) = lower(@name::text);

-- name: ListSMTPBackends :many
SELECT * FROM smtp_backend ORDER BY name;

-- UpdateSMTPBackend leaves the sealed password untouched when
-- @rotate_password is false, so an admin editing the host does not have to
-- re-enter the credential.
-- name: UpdateSMTPBackend :one
UPDATE smtp_backend
SET name                 = @name,
    host                 = @host,
    port                 = @port,
    tls_mode             = @tls_mode,
    auth_user            = @auth_user,
    auth_password_sealed = CASE WHEN @rotate_password::boolean
                                THEN @auth_password_sealed
                                ELSE auth_password_sealed END,
    helo_name            = @helo_name,
    max_concurrency      = @max_concurrency,
    enabled              = @enabled
WHERE id = @id
RETURNING *;

-- DeleteSMTPBackend fails while a domain still points at it, thanks to the
-- ON DELETE RESTRICT foreign key. That refusal is intentional: silently
-- orphaning a domain would break delivery at send time instead of at edit time.
-- name: DeleteSMTPBackend :execrows
DELETE FROM smtp_backend WHERE id = @id;

-- name: ListSMTPBackendsNeedingRewrap :many
SELECT id, name, auth_password_sealed
FROM smtp_backend
WHERE auth_password_sealed <> ''
ORDER BY name;

-- name: UpdateSMTPBackendSealedPassword :exec
UPDATE smtp_backend
SET auth_password_sealed = @auth_password_sealed
WHERE id = @id;

-- GetSenderRouteForBackend loads the relay a message was pinned to at ingestion.
--
-- The worker deliberately does not re-resolve the sender's domain: the backend
-- was chosen and recorded when the message was accepted (D6), so an admin
-- re-assigning the domain in the meantime must not silently redirect mail that
-- was already queued for somewhere else.
-- name: GetSenderRouteForBackend :one
SELECT
    b.id   AS backend_id,
    b.name AS backend_name,
    b.host,
    b.port,
    b.tls_mode,
    b.auth_user,
    b.auth_password_sealed,
    b.helo_name,
    b.max_concurrency,
    b.enabled
FROM smtp_backend b
WHERE b.id = @backend_id;
