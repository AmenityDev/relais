# relais

An SMTP/API gateway that sits in front of an outbound relay (OCI Email Delivery, or any other SMTP provider). Internal applications submit mail either through a Resend-style REST API or through SMTP submission; relais authenticates the sender, verifies **strictly** that the announced `From` address is one the credential is allowed to use, and relays.

**DKIM is not handled here**: signing happens downstream, in the relay.

## What the service guarantees

- **No anonymous relaying.** Every submission is authenticated, with no exception and no permissive debug mode.
- **No secret in cleartext in the database.** Backend passwords are encrypted (AES-256-GCM, key from the environment, rotation supported); sender credentials are stored only as an HMAC fingerprint, peppered with a key that lives nowhere but the environment.
- **An unauthorised `From` is rejected and logged**, with enough context to investigate a compromised credential — and never with the content of the email.
- **A credential with no configured pattern can send as nobody.**

## Status

M0 through M7 are complete: foundations, data model, sender-pattern grammar,
ingest pipeline, SMTP delivery, REST API, submission server and admin API. Only
the frontend (M8) is left — see [docs/PLAN.md](docs/PLAN.md) for the architecture
decisions and [docs/FRONTEND.md](docs/FRONTEND.md) for the frontend design.

In practice, today: both façades work. `POST /v1/emails` and the SMTP submission
server both accept a message, a worker relays it, and `GET /v1/emails/{id}`
reports its status. The admin API serves the full CRUD on its own listener.

## REST API

```sh
curl -X POST http://localhost:8080/v1/emails \
  -H "Authorization: Bearer relais_sk_..." \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: invoice-42" \
  -d '{
    "from": "My App <no-reply@example.com>",
    "to": "recipient@elsewhere.test",
    "cc": ["copy@elsewhere.test"],
    "bcc": ["hidden@elsewhere.test"],
    "subject": "Invoice #42",
    "text": "Hello,",
    "html": "<p>Hello,</p>",
    "headers": {"X-Entity-Ref-Id": "inv-42"},
    "attachments": [{"filename": "f.pdf", "content_type": "application/pdf", "content": "<base64>"}]
  }'
# → 202 {"id": "...", "status": "queued", "message_id": "<...@example.com>", "recipients": [...]}

curl http://localhost:8080/v1/emails/<id> -H "Authorization: Bearer relais_sk_..."
# → 200 {"status": "sent", "sent_at": "...", ...}
```

The contract follows Resend's for familiarity, without claiming strict
compatibility. `to`, `cc`, `bcc` and `reply_to` each accept either a string or an
array. **No `Bcc` header is ever written**: blind recipients travel in the
envelope only.

| Status | Meaning                                                              |
| ------ | -------------------------------------------------------------------- |
| 202    | accepted and queued                                                  |
| 200    | replay of an `Idempotency-Key` — **nothing was sent again**          |
| 400    | invalid JSON, or an unknown field (a typo is never silently ignored) |
| 401    | authentication failed (no detail: see the logs)                      |
| 403    | the credential may not use that `From`                               |
| 413    | body or message over the configured limit                            |
| 422    | validation: bad recipient, missing body, unconfigured domain…        |
| 429    | rate limit exceeded (with `Retry-After`)                             |

Errors all share one shape, with a stable code — the same vocabulary the logs and
the database use:

```json
{"error": {"code": "sender_not_allowed", "message": "...", "message_id": "..."}}
```

## SMTP submission

For applications that only speak SMTP (WordPress, legacy PHP scripts). Create a
credential of type `smtp_user`:

```sh
relais credential create -name wordpress -type smtp_user -username blog \
  -from 'no-reply@example.com'
# → the SMTP password is printed ONCE
```

Client configuration: host `relais`, port `587`, **STARTTLS**, user `blog`,
password as printed.

Three guarantees, verified by tests and on the wire:

- `AUTH` is **not even advertised** on a plaintext connection, and would be
  refused if a client tried it anyway;
- `MAIL FROM` without authentication is refused `530 5.7.0` — that is what "no
  anonymous relaying" means in protocol terms;
- it is the **header** `From` that gets authorised, not the envelope. A legacy
  client that puts anything in `MAIL FROM` works; a `From` outside the allow-list
  is refused `550 5.7.1` and the attempted address is recorded.

The success reply carries the id, as Postfix does:
`250 2.0.0 OK: queued as <uuid>`, which makes a client's own log correlatable with
a relais message.

## Admin API

`/admin/v1/*` on a **separate listener** (`:8081` by default). Authentication is
an Authentik-issued JWT, validated against the issuer's JWKS; authorisation is
group membership, mapped to `admin` (read/write) or `viewer` (read-only).

Keeping it on its own port means exposing the public API cannot expose the admin
API: exposure becomes a network decision rather than a routing rule nobody must
get wrong.

Beyond CRUD on backends, domains, credentials and patterns, four dry-run
endpoints exist because they are what make the UI useful rather than merely
functional:

| Endpoint                                        | Answers                                                                                 |
| ----------------------------------------------- | --------------------------------------------------------------------------------------- |
| `POST /admin/v1/patterns:validate`              | is this pattern valid, and what is its canonical form?                                  |
| `POST /admin/v1/credentials/{id}/patterns:test` | would this credential be allowed to send as this address, and does any domain route it? |
| `GET /admin/v1/domains:resolve?sender=`         | which backend would carry this sender's mail?                                           |
| `POST /admin/v1/backends/{id}:test`             | do these relay credentials actually work? (connects and authenticates, sends nothing)   |

The first two exist so the frontend never reimplements the pattern grammar. A
TypeScript copy would drift, and the day it drifts the UI misreports what a
credential may send as.

Note that **OIDC discovery is lazy**: it happens on the first admin request, not
at startup. An Authentik outage therefore never stops relais from relaying mail —
it makes the admin API unavailable, with a `503` rather than a `401`.

## Quick start

```sh
task setup                    # creates .env and generates your key material
docker compose up -d          # Postgres and a local SMTP sink (mailpit)
task migrate                  # task loads .env by itself
task build                    # → bin/relais
```

**This repository ships no key material.** `.env.example` leaves the two secret
variables empty, and relais refuses to start without them:

```text
relais: RELAIS_SECRET_CREDENTIAL_PEPPER is required (generate one with `relais keygen pepper`)
        RELAIS_SECRET_ENCRYPTION_KEYS is required (generate one with `relais keygen key`)
```

That refusal is deliberate. A committed default would be a key every reader of
this repository already has, and a service that starts with one is worse than a
service that does not start: the failure is loud, silent exposure is not.
`task setup` generates a fresh pair; it is safe to re-run and never overwrites a
key that is already set.

The binary does **not** read `.env` itself: configuration comes from the
environment and nowhere else. `task` handles it for its own targets, but a command
run by hand needs the variables present, or it fails with
`RELAIS_DB_URL is required`.

The most convenient approach is a wrapper that loads `.env` per invocation,
leaving nothing behind in the shell:

```fish
# fish
function relais
    set -l root ~/Projects/relais
    env (grep -v '^\s*#' $root/.env | grep .) $root/bin/relais $argv
end
funcsave relais    # optional: makes it permanent, usable from anywhere
```

```sh
# bash / zsh
relais() { env $(grep -v '^\s*#' ~/Projects/relais/.env | grep .) \
           ~/Projects/relais/bin/relais "$@"; }
```

Otherwise, load `.env` once into the current shell:

```sh
# bash / zsh
set -a && . ./.env && set +a
```

```fish
# fish: there is no `set -a`, and $var is not split into words
for line in (grep -v '^\s*#' .env | string match -rv '^\s*$')
    set -l parts (string split -m1 '=' -- $line)
    set -gx $parts[1] (string trim -c '"' -- $parts[2])
end
```

Then configure a complete sending path:

```sh
# 1. The outbound relay. The local sink here; OCI Email Delivery in production.
relais backend add -name mailpit-dev -host 127.0.0.1 -port 1025 -tls none

# 2. The sending domain and the backend that carries its mail.
relais domain add -name example.com -backend mailpit-dev -include-subdomains

# 3. A credential and what it is allowed to use as From.
relais credential create -name my-app -from 'no-reply@example.com'
# → the API key is printed ONCE

# Check routing without sending anything:
relais domain resolve mail.example.com
```

Mind `-host`: `127.0.0.1` if relais runs on the host, `mailpit` if it runs inside
the compose network — they are not the same network.

For a real OCI backend:

```sh
relais backend add -name oci-eu-zurich \
  -host smtp.email.eu-zurich-1.oci.oraclecloud.com -port 587 -tls starttls \
  -user 'ocid1.user.oc1..aaaa@ocid1.tenancy.oc1..bbbb.xy.com'
# the password is prompted for without echo, never passed as an argument
```

## Sender patterns

Four shapes, and nothing else:

| Pattern                    | Allows                               |
| -------------------------- | ------------------------------------ |
| `no-reply@app.example.com` | that exact address                   |
| `*@example.com`            | any local part, on that exact domain |
| `no-reply@*.example.com`   | that local part, on any subdomain    |
| `*@*.example.com`          | any local part, on any subdomain     |

`*.example.com` does **not** cover `example.com`. Covering both takes two
patterns, deliberately: a wildcard should never reach further than what was
written.

A partial wildcard (`no-*@example.com`) is refused, and no user-supplied regular
expression is ever evaluated.

## Configuration

Everything comes from environment variables prefixed `RELAIS_`. See
[.env.example](.env.example), which documents each one.

The two secrets to generate for a new environment. `keygen` reads no
configuration and touches no database, so it works before a `.env` exists:

```sh
go run ./cmd/relais keygen key      # RELAIS_SECRET_ENCRYPTION_KEYS
go run ./cmd/relais keygen pepper   # RELAIS_SECRET_CREDENTIAL_PEPPER
```

The keyring is rotatable; the pepper is **not** — changing it invalidates every
existing credential.

### Rotating the encryption key

```sh
RELAIS_SECRET_ENCRYPTION_KEYS="1:<old>,2:<new>"
RELAIS_SECRET_ENCRYPTION_ACTIVE_KEY=2
go run ./cmd/relais backend rewrap     # re-seals everything under key 2
RELAIS_SECRET_ENCRYPTION_KEYS="2:<new>"   # the old one can go
```

### TLS for the SMTP server

Two sources, exactly one at a time:

- `RELAIS_TLS_CERT_FILE` + `RELAIS_TLS_KEY_FILE` — production. Any tool that
  writes a certificate to disk fits (certbot, Caddy, cert-manager, a Coolify
  volume). `SIGHUP` reloads after renewal, with no downtime; a failed reload keeps
  the previous certificate serving.
- `RELAIS_TLS_SELF_SIGNED=true` — tests and development. A certificate is
  generated at startup (its SHA-256 fingerprint is logged so a client can pin it)
  and **refused when `RELAIS_ENV=prod`** unless explicitly overridden.

## Development

```sh
task              # list the tasks
task test         # tests with the race detector
task test:all     # everything, requiring a database (what CI should run)
task fuzz         # fuzz the sender-pattern matcher
task lint         # vet + gofmt + go mod tidy -diff
task generate     # regenerate the sqlc query layer
task dev:reset    # wipe the development database and replay the migrations
```

`task` is not required: every target is a readable sequence of commands in
[Taskfile.yml](Taskfile.yml).

CI runs the same things on every push and pull request
([.github/workflows/ci.yml](.github/workflows/ci.yml)): vet, gofmt, `go mod tidy
-diff`, `sqlc diff`, the full suite with the race detector against a Postgres 18
service, a short fuzz run on the sender-pattern matcher and the message
normalizer, and a multi-arch image build.

Database-backed tests resolve their connection through `internal/dbtest`. Setting
`RELAIS_TEST_DB_URL` makes the database **mandatory** — an unreachable one fails
rather than skips, because a silently skipped integration suite is
indistinguishable from a passing one. With the variable unset, the development
stack is tried and the tests skip if it is not running.

## Deployment

Multi-stage, static (`CGO_ENABLED=0`) image on a distroless non-root base:

```sh
docker buildx build --platform linux/amd64,linux/arm64 \
  -f deploy/Dockerfile -t <registry>/relais:<tag> --push .
```

Notes for Coolify:

- Migrations are **never** implicit. Run `relais migrate up` as a deployment step,
  or once by hand.
- The container listens on 8080 (public HTTP), 8081 (admin) and 2525 (SMTP).
  Publishing `587:2525` avoids granting `CAP_NET_BIND_SERVICE` to a non-root
  process.
- **Never publish port 8081.** The admin API is meant to be reachable only from
  the SvelteKit server on the internal network.
- The `HEALTHCHECK` uses the binary itself (`relais healthcheck`): the image has
  neither a shell nor curl.
- SMTP traffic does not go through the HTTP reverse proxy: it needs an exposed TCP
  port and a mounted certificate.
