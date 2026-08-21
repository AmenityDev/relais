---
name: relais-architecture
description: How relais is built — the ingestion pipeline both façades share, what each internal package owns, the accepted design decisions and their reasoning, the data model and status values, the sender-pattern grammar, and the traps recorded while building it. Use when reading unfamiliar code, deciding where a change belongs, or weighing a design choice.
---

# Architecture

Full reasoning lives in [docs/ARCHITECTURE.md](../../../docs/ARCHITECTURE.md) (decisions
D1–D15 plus the mistakes that produced the constraints). The frontend's own design
record is [docs/FRONTEND.md](../../../docs/FRONTEND.md) (F1–F15). This is the working
summary.

## The pipeline

```text
REST /v1/emails ─┐                                    ┌─ river worker ─→ sender ─→ relay
                 ├─→ ingest.Service.Submit(Request) ──→┤
SMTP submission ─┘   normalize · validate From ·       └─ email_message + email_payload
                     resolve backend · persist            (one transaction)
```

Both façades build an `ingest.Request` and have **no** other route to the database or
the queue. A message row, its payload and its job are created in **one transaction**: a
failing enqueuer leaves no row behind (proved by a test).

## Packages

| Package | Owns |
| --- | --- |
| `config` | env → struct, fail-fast validation. Prefix `RELAIS_`, nested by `envPrefix` (`DB_`, `HTTP_`, `ADMIN_`, `SMTP_`, `TLS_`, `WORKER_`, `SENDER_`, `SECRET_`, `RATELIMIT_`, `RETENTION_`, `OIDC_`, `OBS_`, `LIMITS_`) |
| `obs` | slog JSON, OTLP bridge, traces, `Version` |
| `db` | pgxpool, embedded goose migrations (`db/migrations`), sqlc sources (`db/queries`), generated code (`db/gen`, never hand-edited) |
| `crypto` | AES-GCM keyring, HMAC+pepper, the `Secret` type |
| `tlsconf` | certificate from mounted files or generated self-signed; reload on SIGHUP and by polling |
| `frompattern` | the pattern grammar and matcher — the security core |
| `store` | the only package that touches the tables |
| `mailbuild` | REST JSON → RFC 5322 |
| `mailnorm` | `From` extraction, injection of missing headers |
| `ingest` | ⭐ the shared pipeline |
| `ratelimit` | bounded per-credential token buckets |
| `sender` | SMTP client, 4xx/5xx classification |
| `jobs` | river workers, transactional `Enqueuer`, payload purge |
| `authn` | credential resolution (bearer and SMTP AUTH) |
| `adminauth` | lazy OIDC/JWKS, admin/viewer RBAC |
| `httpapi` | chi routing for `/v1`, `/admin/v1`, health, and the OpenAPI generator |
| `smtpd` | submission server: STARTTLS, AUTH only after TLS |
| `smtptest`, `oidctest`, `dbtest` | test doubles: SMTP sink, throwaway issuer, database access |

## Decisions worth knowing before changing code

- **D2 — HMAC-SHA256(pepper, secret), not argon2id.** These are not human passwords:
  secrets carry 256 bits of entropy, so a slow KDF buys nothing and would cost 50–150 ms
  per REST request and per SMTP connection. The pepper lives only in the environment, so
  a stolen dump cannot even test a candidate. Key layout:
  `relais_sk_<lookup 12><_><secret 43>`, the two halves drawn independently, parsed by
  fixed offset because the secret's alphabet contains `_`.
- **D3/D4** — one `lookup` column for both credential types; the **header `From` is
  authoritative** and `MAIL FROM` is rewritten from it.
- **D6** — the backend is resolved at ingestion and **pinned** to the message, so the
  audit trail survives a later re-assignment of the domain.
- **D9/D10** — one binary with subcommands, migrations **never** implicit; goose for the
  application schema, rivermigrate for river's, sqlc for data access.
- **D13** — rate limiting is in-process per credential; outbound throughput is bounded
  by `smtp_backend.max_concurrency`. Two replicas mean two budgets, deliberately.
- **D15/F11** — the admin API is a **separate listener** (`RELAIS_ADMIN_ADDR`, `:8081`).
  `/admin/v1` on the sending port answers 404, which is what makes exposing 8080
  harmless to the admin surface.
- **OIDC discovery is lazy** — on the first admin request, with a failure remembered for
  a few seconds. A provider outage never stops relais relaying mail; it makes the admin
  API answer 503, not 401.

## The pattern grammar (D5)

| Pattern | Matches | Does not match |
| --- | --- | --- |
| `no-reply@app.example.com` | that exact address | anything else |
| `*@example.com` | any local part, exact domain | `x@mail.example.com` |
| `no-reply@*.example.com` | that local part, any strict subdomain | `no-reply@example.com` |
| `*@*.example.com` | any local part, any strict subdomain | `x@example.com` |

- `*.example.com` does **not** cover `example.com`; covering both takes two patterns.
  Verbose on purpose, so a wildcard never reaches past what the operator wrote.
- `*` is allowed only as a whole local part or as the leading domain label.
- Domains are normalized to lowercase punycode (IDNA); local parts compare
  case-insensitively.
- **An empty set matches nothing** — the most important property in the package.
- Pure string comparison; no operator input ever reaches a regex engine. A database
  `CHECK` replays the grammar as defence in depth, and a test pins the two together.
- The grammar is **never** reimplemented in TypeScript (F5). The UI asks the admin API
  (`POST /admin/v1/patterns:validate`, `POST /admin/v1/credentials/{id}/patterns:test`).

## Data model

`smtp_backend`, `domain`, `credential`, `credential_from_pattern`, `email_message`,
`email_payload` — plus river's own tables. One migration so far:
`internal/db/migrations/00001_init.sql`.

`email_message.status ∈ {queued, sending, sent, failed, rejected}`,
`facade ∈ {rest, smtp}`. Constraints encode the audit guarantees: a `sent` row must
have `sent_at`, a `rejected` row must have a `rejection_reason` (and only those), an
accepted row must have at least one envelope recipient.

`to/cc/bcc_addrs` are what the submitter declared; **`envelope_recipients` is the
authoritative delivery list** — exactly what goes out as `RCPT TO`. They genuinely
differ per façade, and conflating them would make "who actually received this?"
unanswerable. `Bcc` is removed from the relayed bytes and kept in the database.

## Traps recorded in the code

- **Do not re-encode inbound MIME.** Missing headers (`Message-ID`, `Date`) are injected
  on the raw stream; the full parse only extracts the `From` and validates. A
  parse-and-reserialise round trip breaks legacy messages.
- **`sqlc`'s `@name` parameters are non-nullable.** `WHERE (@filter IS NULL OR …)` never
  takes the IS NULL branch, so the filter silently matches nothing. Use `sqlc.narg()`
  for anything optional; this cost the message listing a silent "always empty" bug.
- **Never classify an error by its text.** Guessing 4xx/5xx from substrings answered 503
  to a valid refusal, because "refusing SMTP AUTH over a plaintext backend connection"
  contains "connection". Validation failures carry `store.ErrValidation`.
- **go-smtp is pre-1.0**: its auth API changed between minor versions and it clears
  caller-set deadlines. Pinned, and isolated in `smtpd`/`sender`.
- **The pepper is not rotatable** without re-issuing every credential; the keyring is
  (`relais backend rewrap`).
- **Bind the port before announcing the listener.** `ListenAndServe` binds inside the
  goroutine, so a bind failure raced the shutdown goroutine and surfaced as
  `relais: interrupted`, exit 130. `net.Listen` first, then `server.Serve`.
- **Identical responses for every authentication failure** — unknown key, revoked key
  and wrong secret must stay indistinguishable. Same for the admin surface: forged,
  expired, wrong-issuer and wrong-audience tokens all return the same 401 body. An
  unrecognised group returns 403, and one credential reading another's message gets 404,
  not 403.
