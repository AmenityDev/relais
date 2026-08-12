-- name: CreateCredential :one
INSERT INTO credential (
    name, type, lookup, secret_hmac, enabled,
    rate_limit_rps, rate_limit_burst, created_by
) VALUES (
    @name, @type, @lookup, @secret_hmac, @enabled,
    @rate_limit_rps, @rate_limit_burst, @created_by
)
RETURNING *;

-- GetCredentialByLookup deliberately returns revoked and disabled rows too.
--
-- The caller needs to tell "no such credential" from "revoked credential" in
-- order to log the difference, which is exactly the signal that matters when a
-- key leaks. Clients are told nothing beyond "authentication failed".
-- name: GetCredentialByLookup :one
SELECT * FROM credential WHERE lookup = @lookup;

-- name: GetCredential :one
SELECT * FROM credential WHERE id = @id;

-- name: ListCredentials :many
SELECT
    c.*,
    (
        SELECT count(*)
        FROM credential_from_pattern p
        WHERE p.credential_id = c.id
    ) AS pattern_count
FROM credential c
ORDER BY c.created_at DESC;

-- name: UpdateCredential :one
UPDATE credential
SET name             = @name,
    enabled          = @enabled,
    rate_limit_rps   = @rate_limit_rps,
    rate_limit_burst = @rate_limit_burst
WHERE id = @id
RETURNING *;

-- RevokeCredential is idempotent and irreversible: the first revocation wins,
-- and there is no un-revoke. Restoring access means issuing a new secret.
-- name: RevokeCredential :one
UPDATE credential
SET revoked_at = coalesce(revoked_at, now()),
    enabled    = false
WHERE id = @id
RETURNING *;

-- TouchCredentialLastUsed records usage at most once per interval.
--
-- Writing on every request would add a row update to the hot path for no
-- operational gain; a coarse timestamp is enough to spot a credential nobody
-- uses any more.
-- name: TouchCredentialLastUsed :exec
UPDATE credential
SET last_used_at = now()
WHERE id = @id
  AND (last_used_at IS NULL OR last_used_at < now() - @min_interval::interval);

-- name: DeleteCredential :execrows
DELETE FROM credential WHERE id = @id;

-- AddFromPattern is idempotent: granting a pattern a credential already has is
-- not an error.
--
-- The conflict clause updates the pattern to itself rather than doing nothing,
-- because DO NOTHING suppresses the RETURNING row and the caller would see
-- "no rows" — an error — for what is really a no-op.
-- name: AddFromPattern :one
INSERT INTO credential_from_pattern (credential_id, pattern)
VALUES (@credential_id, @pattern)
ON CONFLICT (credential_id, pattern)
    DO UPDATE SET pattern = EXCLUDED.pattern
RETURNING *;

-- name: ListFromPatterns :many
SELECT * FROM credential_from_pattern
WHERE credential_id = @credential_id
ORDER BY pattern;

-- name: DeleteFromPattern :execrows
DELETE FROM credential_from_pattern
WHERE credential_id = @credential_id AND id = @id;
