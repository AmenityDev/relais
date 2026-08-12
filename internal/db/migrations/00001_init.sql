-- Initial schema for relais.
--
-- Design notes that are load-bearing:
--
--   * Enumerated values are text + CHECK rather than Postgres ENUM types. The
--     guarantee is identical (a typo from any client is refused) but adding a
--     value later is a plain constraint swap instead of ALTER TYPE, and sqlc
--     maps them to ordinary Go strings.
--   * No tenant/organisation column. The service is mono-tenant by decision;
--     adding isolation later deserves a deliberate migration, not a column
--     that is NULL everywhere in the meantime.
--   * Nothing here anticipates bounce/complaint handling. That is out of scope
--     for v1 and pre-building it would be dead weight.

-- +goose Up

-- +goose StatementBegin
CREATE FUNCTION set_updated_at() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

-- ---------------------------------------------------------------------------
-- smtp_backend: an outbound relay (in practice, OCI Email Delivery).
-- ---------------------------------------------------------------------------
-- +goose StatementBegin
CREATE TABLE smtp_backend (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name                 text NOT NULL,
    host                 text NOT NULL,
    port                 integer NOT NULL,
    tls_mode             text NOT NULL,
    auth_user            text NOT NULL DEFAULT '',
    -- Sealed with the AES-256-GCM keyring, format "v1:<key id>:<nonce>:<ct>".
    -- Empty means "no SMTP AUTH", which only makes sense for a local sink.
    auth_password_sealed text NOT NULL DEFAULT '',
    -- helo_name overrides the EHLO name presented to the backend. Empty uses
    -- the configured SMTP domain.
    helo_name            text NOT NULL DEFAULT '',
    -- max_concurrency caps simultaneous deliveries to this backend, because
    -- providers rate-limit connections independently of our worker count.
    max_concurrency      integer NOT NULL DEFAULT 2,
    enabled              boolean NOT NULL DEFAULT true,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT smtp_backend_name_not_blank  CHECK (btrim(name) <> ''),
    CONSTRAINT smtp_backend_host_not_blank  CHECK (btrim(host) <> ''),
    CONSTRAINT smtp_backend_port_range      CHECK (port BETWEEN 1 AND 65535),
    CONSTRAINT smtp_backend_tls_mode        CHECK (tls_mode IN ('starttls', 'tls', 'none')),
    CONSTRAINT smtp_backend_concurrency     CHECK (max_concurrency BETWEEN 1 AND 64),
    -- Refuse to ever send a password over an unencrypted backend connection.
    -- This is an invariant, not a preference, so it lives in the database.
    CONSTRAINT smtp_backend_no_plaintext_auth CHECK (
        tls_mode <> 'none' OR (auth_user = '' AND auth_password_sealed = '')
    )
);
-- +goose StatementEnd

CREATE UNIQUE INDEX smtp_backend_name_key ON smtp_backend (lower(name));

CREATE TRIGGER smtp_backend_set_updated_at
    BEFORE UPDATE ON smtp_backend
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- domain: maps a sending domain to the backend that must carry its mail.
-- No DKIM material: signing happens downstream, in OCI Email Delivery.
-- ---------------------------------------------------------------------------
-- +goose StatementBegin
CREATE TABLE domain (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Stored lowercase and punycode-encoded, so comparison is a plain equality.
    name               text NOT NULL,
    smtp_backend_id    uuid NOT NULL REFERENCES smtp_backend (id) ON DELETE RESTRICT,
    -- include_subdomains lets mail from mail.example.com resolve through the
    -- example.com row. Without it a "*@*.example.com" sender pattern would
    -- match at validation time and then fail to resolve a backend.
    include_subdomains boolean NOT NULL DEFAULT false,
    enabled            boolean NOT NULL DEFAULT true,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT domain_name_lowercase CHECK (name = lower(name)),
    CONSTRAINT domain_name_shape CHECK (
        name ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$'
    ),
    CONSTRAINT domain_name_length CHECK (length(name) <= 253)
);
-- +goose StatementEnd

CREATE UNIQUE INDEX domain_name_key ON domain (name);
CREATE INDEX domain_backend_idx ON domain (smtp_backend_id);

CREATE TRIGGER domain_set_updated_at
    BEFORE UPDATE ON domain
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- credential: a sender identity, either an API key or an SMTP user.
--
-- The secret itself is never stored. `lookup` is the public half used to find
-- the row (token prefix for api_key, username for smtp_user) and `secret_hmac`
-- is HMAC-SHA256(pepper, full secret): a database dump alone cannot even test
-- a candidate secret, since the pepper lives only in the environment.
-- ---------------------------------------------------------------------------
-- +goose StatementBegin
CREATE TABLE credential (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name             text NOT NULL,
    type             text NOT NULL,
    lookup           text NOT NULL,
    secret_hmac      bytea NOT NULL,
    enabled          boolean NOT NULL DEFAULT true,
    -- NULL means "use the process-wide default".
    rate_limit_rps   double precision,
    rate_limit_burst integer,
    -- created_by records the OIDC subject or CLI actor, for auditability.
    created_by       text NOT NULL DEFAULT '',
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    last_used_at     timestamptz,
    revoked_at       timestamptz,

    CONSTRAINT credential_name_not_blank CHECK (btrim(name) <> ''),
    CONSTRAINT credential_type          CHECK (type IN ('api_key', 'smtp_user')),
    CONSTRAINT credential_hmac_length   CHECK (octet_length(secret_hmac) = 32),
    CONSTRAINT credential_lookup_shape  CHECK (lookup ~ '^[A-Za-z0-9_.-]{3,128}$'),
    CONSTRAINT credential_rate_limit    CHECK (
        (rate_limit_rps IS NULL OR rate_limit_rps > 0)
        AND (rate_limit_burst IS NULL OR rate_limit_burst > 0)
    )
);
-- +goose StatementEnd

-- One namespace for both credential types: a single unique index means a single
-- lookup query path shared by the REST and SMTP façades.
CREATE UNIQUE INDEX credential_lookup_key ON credential (lookup);
CREATE UNIQUE INDEX credential_name_key ON credential (lower(name));

-- ---------------------------------------------------------------------------
-- credential_from_pattern: the allow-list of From addresses per credential.
--
-- The grammar is closed (four forms only) and validated in Go before insert.
-- The CHECK below is defence in depth: even a direct psql INSERT cannot store
-- a pattern the matcher would not understand. No user-supplied regex ever
-- reaches a regex engine.
-- ---------------------------------------------------------------------------
-- +goose StatementBegin
CREATE TABLE credential_from_pattern (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    credential_id uuid NOT NULL REFERENCES credential (id) ON DELETE CASCADE,
    pattern       text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),

    -- local@domain, where local is '*' or a literal, and domain is either an
    -- exact name or '*.' followed by an exact name.
    CONSTRAINT credential_from_pattern_shape CHECK (
        pattern ~ '^(\*|[^@[:space:]*]+)@(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$'
    ),
    CONSTRAINT credential_from_pattern_length CHECK (length(pattern) <= 320)
);
-- +goose StatementEnd

CREATE UNIQUE INDEX credential_from_pattern_key ON credential_from_pattern (credential_id, pattern);

-- ---------------------------------------------------------------------------
-- email_message: one row per accepted or rejected submission.
--
-- Rejections are persisted on purpose: "credential X tried to send as Y" is the
-- signal that matters when a credential leaks. The message body is not stored
-- here (see email_payload) and rejected rows never get a payload at all.
-- ---------------------------------------------------------------------------
-- +goose StatementBegin
CREATE TABLE email_message (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- ON DELETE SET NULL: deleting a credential must not erase its history.
    credential_id    uuid REFERENCES credential (id) ON DELETE SET NULL,
    status           text NOT NULL,
    facade           text NOT NULL,
    from_addr        text NOT NULL,
    from_domain      text NOT NULL,
    -- to/cc/bcc are what the submitter declared, and are what a reader of the
    -- message sees. They are descriptive only.
    to_addrs         text[] NOT NULL DEFAULT '{}',
    cc_addrs         text[] NOT NULL DEFAULT '{}',
    bcc_addrs        text[] NOT NULL DEFAULT '{}',
    -- envelope_recipients is the authoritative delivery list: exactly what goes
    -- out as RCPT TO. It is deliberately separate from the headers above,
    -- because the two genuinely differ. Over SMTP submission the envelope comes
    -- from the client's RCPT TO commands and the headers are informational;
    -- over REST the envelope is the union of to+cc+bcc. Conflating them would
    -- make "who actually received this?" unanswerable for one façade or the
    -- other.
    envelope_recipients text[] NOT NULL DEFAULT '{}',
    subject          text NOT NULL DEFAULT '',
    message_id       text NOT NULL DEFAULT '',
    size_bytes       integer NOT NULL DEFAULT 0,
    -- Resolved at ingestion and pinned, so the audit trail survives a later
    -- re-assignment of the domain to another backend.
    smtp_backend_id  uuid REFERENCES smtp_backend (id) ON DELETE SET NULL,
    idempotency_key  text,
    attempt_count    integer NOT NULL DEFAULT 0,
    -- error_code is a stable machine token ("smtp_permanent", "dial_timeout");
    -- error_detail is the human-readable remote response.
    error_code       text,
    error_detail     text,
    rejection_reason text,
    remote_ip        inet,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    sent_at          timestamptz,

    CONSTRAINT email_message_status CHECK (
        status IN ('queued', 'sending', 'sent', 'failed', 'rejected')
    ),
    CONSTRAINT email_message_facade      CHECK (facade IN ('rest', 'smtp')),
    CONSTRAINT email_message_size        CHECK (size_bytes >= 0),
    CONSTRAINT email_message_attempts    CHECK (attempt_count >= 0),
    CONSTRAINT email_message_domain_case CHECK (from_domain = lower(from_domain)),
    -- A 'sent' row without a timestamp, or a 'rejected' row without a reason,
    -- would be a bug that silently degrades the audit trail.
    CONSTRAINT email_message_sent_at CHECK (status <> 'sent' OR sent_at IS NOT NULL),
    CONSTRAINT email_message_rejection CHECK (
        (status = 'rejected') = (rejection_reason IS NOT NULL)
    ),
    CONSTRAINT email_message_idempotency_length CHECK (
        idempotency_key IS NULL OR length(idempotency_key) BETWEEN 1 AND 255
    ),
    -- An accepted message with nowhere to go would sit in the queue forever and
    -- then fail at delivery. A rejected one legitimately has no recipients.
    CONSTRAINT email_message_has_recipients CHECK (
        status = 'rejected' OR cardinality(envelope_recipients) > 0
    )
);
-- +goose StatementEnd

CREATE INDEX email_message_created_at_idx ON email_message (created_at DESC);
CREATE INDEX email_message_credential_idx ON email_message (credential_id, created_at DESC);
CREATE INDEX email_message_status_idx ON email_message (status, created_at DESC);
-- Investigating a leaked credential means listing rejections for an attempted
-- sender; this index keeps that answer cheap.
CREATE INDEX email_message_rejected_from_idx ON email_message (from_addr, created_at DESC)
    WHERE status = 'rejected';
CREATE UNIQUE INDEX email_message_idempotency_key
    ON email_message (credential_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

CREATE TRIGGER email_message_set_updated_at
    BEFORE UPDATE ON email_message
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- email_payload: the raw RFC 5322 bytes, kept only until they are no longer
-- useful. Separated from email_message so that listing messages never drags
-- megabytes of TOAST along, and so retention is a plain DELETE.
-- ---------------------------------------------------------------------------
-- +goose StatementBegin
CREATE TABLE email_payload (
    email_message_id uuid PRIMARY KEY REFERENCES email_message (id) ON DELETE CASCADE,
    raw              bytea NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now()
);
-- +goose StatementEnd

-- +goose Down

DROP TABLE IF EXISTS email_payload;
DROP TABLE IF EXISTS email_message;
DROP TABLE IF EXISTS credential_from_pattern;
DROP TABLE IF EXISTS credential;
DROP TABLE IF EXISTS domain;
DROP TABLE IF EXISTS smtp_backend;
DROP FUNCTION IF EXISTS set_updated_at();
