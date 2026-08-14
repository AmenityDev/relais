# relais

An SMTP/API gateway that sits in front of an outbound relay — OCI Email Delivery,
Amazon SES, Postmark, or any other SMTP provider. Internal applications submit mail
through a Resend-style REST API or through SMTP submission; relais authenticates the
sender, verifies **strictly** that the announced `From` address is one that credential
is allowed to use, and relays it.

It exists for the situation where several applications share one outbound relay and
you want each of them to be able to send as its own addresses and no others, without
handing every application the relay's own credentials.

**DKIM is not handled here.** Signing happens downstream, in the relay.

## What it guarantees

- **No anonymous relaying.** Every submission is authenticated, with no exception and
  no permissive debug mode.
- **No secret in cleartext in the database.** Relay passwords are sealed with
  AES-256-GCM under a key that lives only in the environment, and the keyring is
  rotatable. Sender credentials are stored as an HMAC fingerprint peppered from the
  environment, and cannot be recovered even with the database.
- **An unauthorised `From` is rejected and recorded**, with enough context to
  investigate a compromised credential and never with the content of the message.
- **A credential with no configured pattern can send as nobody.** The allow-list is
  closed by default.
- **Message content is not kept.** Payloads are held until delivery succeeds and are
  returned by no endpoint.

## What it is not

Deliberately out of scope, so the design stays small:

- **No bounce or complaint handling.** No DSN parsing, no webhooks. The schema
  anticipates none of it.
- **No templates, no open or click tracking.**
- **No multi-tenant isolation.** One deployment serves one organisation. The data
  model is clean enough to grow into it, without pretending to be there.
- **No DKIM, DMARC or SPF management.** That belongs to the relay and to DNS.

If you need those, a hosted sending platform will serve you better.

## Quick start

Requires Go 1.26+, Docker, and Node 22+ for the admin interface.

```sh
task setup                            # generates the keys this repository ships none of
docker compose up -d                  # Postgres + mailpit (a local SMTP sink)
task migrate                          # apply the schema
```

`task setup` creates `.env` from `.env.example` and generates three secrets into it.
**This repository ships no key material**: `.env.example` leaves the secret variables
empty and relais refuses to start without them. That refusal is deliberate — a
committed default would be a key every reader of this repository already has, and a
service that starts with one is worse than a service that does not start.

Then configure a relay, a domain and a credential:

```sh
# The outbound relay. mailpit here; your provider in production.
relais backend add -name mailpit-dev -host 127.0.0.1 -port 1025 -tls none

# Which relay carries which domain's mail.
relais domain add -name example.test -backend mailpit-dev -include-subdomains

# A credential, and what it may use as From.
relais credential create -name my-app -type api_key -from '*@example.test'
# → the API key is printed ONCE
```

Run it, and send something:

```sh
task serve      # :8080 sending API, :8081 admin API, :2525 submission
```

```sh
curl -X POST http://127.0.0.1:8080/v1/emails \
  -H "Authorization: Bearer relais_sk_..." \
  -H "Content-Type: application/json" \
  -d '{"from":"alerts@example.test","to":"someone@elsewhere.test",
       "subject":"It works","text":"Hello."}'
```

It arrives in mailpit at <http://localhost:8025>.

Before sending anything, you can ask relais which relay would carry a domain's mail:

```sh
relais domain resolve example.test
```

The equivalent question about a credential — *would this address be allowed, and does
anything route it?* — is an admin API endpoint rather than a CLI command, because it is
what the interface asks on every keystroke. See [Administration](#administration).

### The admin interface

The interface authenticates through OIDC and has no local bypass, so it needs a
provider. One is included for development, with its realm already imported:

```sh
docker compose --profile auth up -d   # Keycloak on :8180, or: task dev:auth
```

Add the matching settings to `.env` — the issuer must be **the same value** on both
sides, since both deal in the same `iss` claim:

```sh
RELAIS_OIDC_ISSUER=http://localhost:8180/realms/relais
RELAIS_OIDC_AUDIENCE=relais
RELAIS_WEB_API_URL=http://127.0.0.1:8081
RELAIS_WEB_ORIGIN=http://localhost:3000
RELAIS_WEB_OIDC_ISSUER=http://localhost:8180/realms/relais
RELAIS_WEB_OIDC_CLIENT_ID=relais-web
RELAIS_WEB_OIDC_CLIENT_SECRET=dev-only-not-a-production-secret
RELAIS_WEB_INSECURE_COOKIE=true
```

Then `task web:dev` and sign in at <http://localhost:3000> as `ops` / `ops`
(administrator) or `watcher` / `watcher` (read-only).

The interface runs on the host rather than in a container for one reason: an OIDC
issuer URL has to resolve to the same provider from the browser *and* from the server
that exchanges the code, since both deal in the same `iss` value. On a development
machine the only name that satisfies both is `localhost`, which a container cannot
reach. Deployments have a real hostname, so the image itself is unchanged.

The development realm carries a fixed client secret and two throwaway passwords.
Those are fixtures for a loopback-only container in `start-dev` mode: they unlock
that container and nothing else.

## Sending mail

### REST API

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

The contract follows Resend's for familiarity, without claiming strict compatibility.
`to`, `cc`, `bcc` and `reply_to` each accept either a string or an array. **No `Bcc`
header is ever written**: blind recipients travel in the envelope only.

| Status | Meaning |
| --- | --- |
| 202 | accepted and queued |
| 200 | replay of an `Idempotency-Key` — **nothing was sent again** |
| 400 | invalid JSON, or an unknown field (a typo is never silently ignored) |
| 401 | authentication failed (no detail: see the logs) |
| 403 | the credential may not use that `From` |
| 413 | body or message over the configured limit |
| 422 | validation: bad recipient, missing body, unconfigured domain… |
| 429 | rate limit exceeded (with `Retry-After`) |

Errors all share one shape, with a stable code — the same vocabulary the logs and the
database use:

```json
{"error": {"code": "sender_not_allowed", "message": "...", "message_id": "..."}}
```

The full contract is described in [docs/openapi-public.json](docs/openapi-public.json),
generated from the Go types that serve the requests.

### SMTP submission

For applications that only speak SMTP — WordPress, legacy PHP scripts, anything with a
"mail settings" screen. Create a credential of type `smtp_user`:

```sh
relais credential create -name wordpress -type smtp_user -username blog \
  -from 'no-reply@example.com'
# → the SMTP password is printed ONCE
```

Client configuration: host `relais`, port `587`, **STARTTLS**, user `blog`, password as
printed.

Three guarantees, verified by tests and on the wire:

- `AUTH` is **not even advertised** on a plaintext connection, and would be refused if
  a client tried it anyway;
- `MAIL FROM` without authentication is refused `530 5.7.0` — that is what "no
  anonymous relaying" means in protocol terms;
- it is the **header** `From` that gets authorised, not the envelope. A legacy client
  that puts anything in `MAIL FROM` still works; a `From` outside the allow-list is
  refused `550 5.7.1` and the attempted address is recorded.

The success reply carries the id, as Postfix does: `250 2.0.0 OK: queued as <uuid>`,
which makes a client's own log correlatable with a relais message.

### Sender patterns

Four shapes, and nothing else:

| Pattern | Allows |
| --- | --- |
| `no-reply@app.example.com` | that exact address |
| `*@example.com` | any local part, on that exact domain |
| `no-reply@*.example.com` | that local part, on any subdomain |
| `*@*.example.com` | any local part, on any subdomain |

`*.example.com` does **not** cover `example.com`. Covering both takes two patterns,
deliberately: a wildcard should never reach further than what was written.

A partial wildcard (`no-*@example.com`) is refused, and no user-supplied regular
expression is ever evaluated. Domains are normalised to punycode, so `Exemplé.COM` and
`xn--exempl-gva.com` are the same pattern.

## Administration

### Admin API

`/admin/v1/*` on a **separate listener** (`:8081` by default). Authentication is a JWT
from the configured OIDC issuer, validated against its JWKS; authorisation is group
membership, mapped to `admin` (read/write) or `viewer` (read-only).

Keeping it on its own port means exposing the sending API cannot expose the admin API:
exposure becomes a network decision rather than a routing rule nobody must get wrong.

Beyond CRUD on relays, domains, credentials and patterns, four dry-run endpoints exist
because they are what make the interface useful rather than merely functional:

| Endpoint | Answers |
| --- | --- |
| `POST /admin/v1/patterns:validate` | is this pattern valid, and what is its canonical form? |
| `POST /admin/v1/credentials/{id}/patterns:test` | would this credential be allowed to send as this address, and does any domain route it? |
| `GET /admin/v1/domains:resolve?sender=` | which relay would carry this sender's mail? |
| `POST /admin/v1/backends/{id}:test` | do these relay credentials actually work? (connects and authenticates, sends nothing) |

The first two exist so nothing outside Go reimplements the pattern grammar. A copy
would drift, and the day it drifts the interface misreports what a credential may send
as.

**OIDC discovery is lazy**: it happens on the first admin request, not at startup. A
provider outage therefore never stops relais from relaying mail — it makes the admin
API unavailable, with a `503` rather than a `401`.

Described in [docs/openapi-admin.json](docs/openapi-admin.json).

### Admin interface

A SvelteKit application in [web/](web/), served as its own container. It is a
backend-for-frontend: every call to relais is made from its server, so **no token ever
reaches the browser**. Six screens — dashboard, relays, domains, credentials, sender
patterns with the dry runs above, and the message log.

Its design decisions are in [docs/FRONTEND.md](docs/FRONTEND.md).

## Configuration

Everything comes from environment variables prefixed `RELAIS_`. See
[.env.example](.env.example), which documents each one.

### Generating the secrets

`keygen` reads no configuration and touches no database, so it works before a `.env`
exists:

```sh
relais keygen key      # RELAIS_SECRET_ENCRYPTION_KEYS
relais keygen pepper   # RELAIS_SECRET_CREDENTIAL_PEPPER
task web:key           # RELAIS_WEB_SESSION_KEY
```

The keyring is rotatable; the pepper is **not** — changing it invalidates every
existing credential.

### Rotating the encryption key

```sh
RELAIS_SECRET_ENCRYPTION_KEYS="1:<old>,2:<new>"
RELAIS_SECRET_ENCRYPTION_ACTIVE_KEY=2
relais backend rewrap                      # re-seals everything under key 2
RELAIS_SECRET_ENCRYPTION_KEYS="2:<new>"    # the old one can go
```

### TLS for the submission server

Two sources, exactly one at a time:

- `RELAIS_TLS_CERT_FILE` + `RELAIS_TLS_KEY_FILE` — production. Any tool that writes a
  certificate to disk fits (certbot, Caddy, cert-manager, a mounted volume). `SIGHUP`
  reloads after renewal with no downtime, and a failed reload keeps the previous
  certificate serving.
- `RELAIS_TLS_SELF_SIGNED=true` — tests and development. A certificate is generated at
  startup, its SHA-256 fingerprint logged so a client can pin it, and it is **refused
  when `RELAIS_ENV=prod`** unless explicitly overridden.

## Deployment

### Container images

CI publishes two images to GHCR once every check has passed — lint, the suite with the
race detector, the fuzz targets, the frontend checks and both image builds:

| Image | Contents | Ports |
| --- | --- | --- |
| `ghcr.io/amenitydev/relais` | the gateway: sending API, submission server, workers | 8080 sending, 8081 admin, 2525 submission |
| `ghcr.io/amenitydev/relais-web` | the admin interface | 3000 |

Both are `linux/amd64` and `linux/arm64` and run as a non-root user; the gateway image
has no shell.

Tags:

- `sha-<short>` — immutable, one per commit. This is what a rollback pins to.
- `main` — moves with the default branch.
- `1.2.3`, `1.2` and `latest` — only from a `v*` tag. `latest` deliberately does not
  follow `main`: a deployment that tracks it should track releases, not every commit.

`relais version` reports `git describe`, so a running container can be traced back to
its source.

### Running them

There is nothing platform-specific to know. Both images are configured entirely
through the environment and neither reads a config file. Postgres is external; any
standard DSN works, including one pointing at a pooler.

Publish `587:2525` for submission rather than binding 587 in the container, which
avoids needing `CAP_NET_BIND_SERVICE`.

### What to expose

The admin interface needs a public hostname. The admin API on 8081 does not, and
should not — the separate listener exists so that exposure is a network decision. The
sending API and SMTP submission only need exposing if an application lives outside the
network; if everything runs alongside relais, nothing of it needs to be public at all.

### Three things that fail quietly

- **Migrations are never implicit.** Run `relais migrate up` as its own step before
  starting a new version. `serve` will not do it for you.
- **The two issuers must be the same value.** `RELAIS_OIDC_ISSUER` and
  `RELAIS_WEB_OIDC_ISSUER` deal in the same `iss` claim. A mismatch means every token
  the interface obtains is rejected, and the error names neither variable.
- **`RELAIS_WEB_ORIGIN` must be the interface's real public origin.** The image derives
  the CSRF origin and the OIDC redirect URI from it. Get it wrong and navigation works
  while every write is refused.

## Development

```sh
task                # list every task
task test           # Go tests with the race detector (database-backed ones skip)
task test:all       # everything, requiring the relais_test database
task fuzz           # fuzz the sender-pattern matcher
task lint           # vet, gofmt, go mod tidy -diff, OpenAPI freshness
task generate       # regenerate the sqlc query layer
task openapi        # regenerate the OpenAPI documents
task web:check      # frontend: svelte-check, prettier, eslint, vitest
task smoke          # drive the running stack end to end
task dev:reset      # wipe the development database and replay the migrations
task dev:stop       # stop every container, keeping the data
```

`task` is not required: every target is a readable sequence of commands in
[Taskfile.yml](Taskfile.yml).

The database-backed tests run against a **separate** `relais_test` database, created by
the development Postgres on first start. They TRUNCATE every table between cases, so
pointing them at the development database would wipe whatever you were working with —
without an error, and without any obvious cause later.

Setting `RELAIS_TEST_DB_URL` makes the database **mandatory**: an unreachable one fails
rather than skips, because a silently skipped integration suite is indistinguishable
from a passing one. With the variable unset, the development stack is tried and the
tests skip if it is not running.

### The generated API description

The OpenAPI documents in `docs/` are emitted by `relais openapi`, which reflects over
the request and response structs that actually serve the requests. The frontend's
TypeScript types are generated from those documents, and CI diffs both against a fresh
generation. A handler whose response shape changes without a regeneration fails the
build rather than shipping types that describe an API the server no longer has.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — the decisions behind the shape of the
  code, and what was learned building it.
- [docs/FRONTEND.md](docs/FRONTEND.md) — the admin interface's design.
- [docs/openapi-admin.json](docs/openapi-admin.json),
  [docs/openapi-public.json](docs/openapi-public.json) — the generated API descriptions.
- [SECURITY.md](SECURITY.md) — what is in scope, and how to report a vulnerability.
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to propose a change.

## Status

Pre-1.0. The gateway and the admin interface are complete and covered by tests; the
API surface is stable enough that it is described by a generated OpenAPI document, but
nothing is promised across versions yet.

## License

[AGPL-3.0](LICENSE). Running a modified relais as a network service obliges you to
offer its source to the people using it. Deploying it unmodified, which is what most
deployments do, carries no such obligation.
