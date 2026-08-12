-- name: CreateDomain :one
INSERT INTO domain (name, smtp_backend_id, include_subdomains, enabled)
VALUES (@name, @smtp_backend_id, @include_subdomains, @enabled)
RETURNING *;

-- name: GetDomain :one
SELECT * FROM domain WHERE id = @id;

-- name: GetDomainByName :one
SELECT * FROM domain WHERE name = @name;

-- name: ListDomains :many
SELECT
    d.id,
    d.name,
    d.smtp_backend_id,
    d.include_subdomains,
    d.enabled,
    d.created_at,
    d.updated_at,
    b.name AS backend_name,
    b.enabled AS backend_enabled
FROM domain d
JOIN smtp_backend b ON b.id = d.smtp_backend_id
ORDER BY d.name;

-- ResolveSenderDomain finds the domain row that governs a sender address.
--
-- An exact match wins; otherwise the closest ancestor that opted into
-- include_subdomains is used, so mail from mail.example.com routes through the
-- example.com row. Ordering by name length picks the most specific ancestor.
--
-- The LIKE pattern is safe from wildcard injection because domain.name is
-- constrained by CHECK to [a-z0-9.-], which contains no LIKE metacharacter.
-- name: ResolveSenderDomain :one
SELECT
    d.id                AS domain_id,
    d.name              AS domain_name,
    d.include_subdomains,
    b.id                AS backend_id,
    b.name              AS backend_name,
    b.host,
    b.port,
    b.tls_mode,
    b.auth_user,
    b.auth_password_sealed,
    b.helo_name,
    b.max_concurrency
FROM domain d
JOIN smtp_backend b ON b.id = d.smtp_backend_id
WHERE d.enabled
  AND b.enabled
  AND (
      d.name = @sender_domain::text
      OR (d.include_subdomains AND @sender_domain::text LIKE '%.' || d.name)
  )
ORDER BY length(d.name) DESC
LIMIT 1;

-- name: UpdateDomain :one
UPDATE domain
SET name               = @name,
    smtp_backend_id    = @smtp_backend_id,
    include_subdomains = @include_subdomains,
    enabled            = @enabled
WHERE id = @id
RETURNING *;

-- name: DeleteDomain :execrows
DELETE FROM domain WHERE id = @id;
