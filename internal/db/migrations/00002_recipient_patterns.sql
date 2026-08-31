-- Recipient allow-lists: which addresses a credential may send *to*.
--
-- The motivating case is a staging credential that must not be able to mail a
-- real customer by accident. Restricting recipients to the team's own domain
-- turns "we emailed 4000 users from staging" into a refusal recorded against
-- the credential that tried.
--
-- Two decisions are load-bearing here, and both differ from the sender side:
--
--   * A SEPARATE TABLE, not a `kind` column on credential_from_pattern. One
--     table would mean every query needs a discriminator, and the day one is
--     forgotten on the mail path a recipient pattern starts authorizing a
--     sender — a silent widening of the check this whole service exists for.
--     Two tables make that class of mistake impossible to write.
--
--   * AN EMPTY SET MEANS NO RESTRICTION. This is the exact opposite of the
--     sender allow-list, where an empty set matches nothing, and the asymmetry
--     is deliberate: a recipient allow-list is a guardrail an operator opts
--     into, not an authentication primitive. Closed-by-default is also not
--     expressible — the grammar has no "any address" pattern — so it would
--     have meant every existing credential losing the ability to send the
--     moment this migration ran.
--
-- The grammar is the sender grammar, unchanged: same four shapes, same closed
-- form, same matcher (internal/frompattern). The CHECK below is the same
-- defence in depth — a direct psql INSERT cannot store something the matcher
-- would not understand.

-- +goose Up

-- +goose StatementBegin
CREATE TABLE credential_recipient_pattern (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    credential_id uuid NOT NULL REFERENCES credential (id) ON DELETE CASCADE,
    pattern       text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),

    -- Identical to credential_from_pattern_shape. Duplicated rather than shared
    -- through a DOMAIN type so that a future change to one allow-list's grammar
    -- cannot silently change the other's.
    CONSTRAINT credential_recipient_pattern_shape CHECK (
        pattern ~ '^(\*|[^@[:space:]*]+)@(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$'
    ),
    CONSTRAINT credential_recipient_pattern_length CHECK (length(pattern) <= 320)
);
-- +goose StatementEnd

CREATE UNIQUE INDEX credential_recipient_pattern_key
    ON credential_recipient_pattern (credential_id, pattern);

-- +goose Down

DROP TABLE IF EXISTS credential_recipient_pattern;
