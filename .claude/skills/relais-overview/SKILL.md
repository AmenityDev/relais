---
name: relais-overview
description: Orientation for the relais repository — what the service does, the guarantees and non-goals that constrain every change, the repository map, and which other relais-* skill to load for development, tests, architecture, the API contract or deployment. Load this at the start of any task in this repository.
---

# relais

An SMTP/API gateway that sits in front of an outbound relay (OCI Email Delivery, SES,
Postmark, any SMTP provider). Internal applications submit mail through a Resend-style
REST API or through SMTP submission; relais authenticates the sender, verifies
**strictly** that the announced `From` is an address that credential is allowed to use,
and relays it.

It exists so several applications can share one relay while each sends only as its own
addresses, without any of them holding the relay's credentials.

Go 1.26 · PostgreSQL 18 · river (queue) · chi · pgx · sqlc · goose ·
SvelteKit + TypeScript in `web/` · OIDC for the admin surface · AGPL-3.0.

**DKIM is not handled here.** Signing belongs to the relay downstream.

## Guarantees that constrain every change

Treat these as invariants, not features. A change that weakens one needs to be raised
before it is written.

- **No anonymous relaying.** Every submission is authenticated. No exception, no
  permissive debug mode, in any environment.
- **No secret in cleartext in the database.** Relay passwords are sealed with
  AES-256-GCM under a key that lives only in the environment (rotatable, see
  `relais backend rewrap`). Sender credentials are stored as `HMAC-SHA256(pepper,
  secret)` and are unrecoverable even with the whole database.
- **An unauthorised `From` is rejected and recorded** with enough context to
  investigate a compromised credential — and **never** with the content of the message.
- **A credential with no pattern can send as nobody.** The allow-list is closed by
  default; an empty set matches nothing.
- **Message content is not kept.** Payloads live until delivery succeeds, then are
  purged, and no endpoint returns them.
- **No email content in logs, ever.** A rejection logs `credential_id`,
  `credential_name`, `from_attempted`, `patterns_count`, `remote_ip`, `facade`,
  `message_id`. Nothing more. The subject is stored in the database but never logged.
- **No user-supplied regex.** The sender-pattern grammar is closed and matched by
  string comparison (see `relais-architecture`).

## Deliberately out of scope

Not oversights — omissions, and the schema anticipates none of them:

- bounce and complaint handling, DSN parsing, webhooks
- templates, open/click tracking
- multi-tenant isolation (one deployment, one organisation)
- DKIM, SPF, DMARC management

## The one contract

```go
ingest.Service.Submit(ctx, ingest.Request) (ingest.Result, error)
```

The REST façade and the SMTP façade each build one `Request` and have **no** other
route to the database or the queue. Validation cannot be duplicated by accident: one
implementation, one set of callers. New submission paths go through it too.

## Repository map

```text
cmd/relais/        subcommands: serve, migrate, keygen, backend, domain,
                   credential, healthcheck, openapi, version
internal/          the service (see relais-architecture for each package)
web/               SvelteKit admin interface (BFF; the browser never holds a token)
docs/              ARCHITECTURE.md, FRONTEND.md, generated openapi-*.json
deploy/            Dockerfiles, Coolify compose, dev Keycloak realm, Postgres init
scripts/           smoke.sh, check-compose-variants.py
Taskfile.yml       every command; readable and runnable by hand
```

## Which skill to load next

| Task | Skill |
| --- | --- |
| Run the stack, ports, dev Keycloak, CLI bootstrap | `relais-dev` |
| Tests, fuzzing, lint, smoke, CI | `relais-testing` |
| Where code lives, decisions, data model, pattern grammar | `relais-architecture` |
| Touching a handler, DTO, route, query or migration | `relais-api-contract` |
| Images, GHCR, Coolify, TLS certificates | `relais-deploy` |

Deeper background lives in [docs/ARCHITECTURE.md](../../../docs/ARCHITECTURE.md) —
including a list of mistakes made while building this, each of which explains a
constraint that looks arbitrary without it. Read it before arguing with a constraint.

## House rules

- **Loud failures.** A configuration that cannot work stops the process; a check that
  cannot run fails rather than skips.
- **Comments explain why**, not what the next line does. Match the density of the file
  you are editing.
- **A test must prove something.** Several tests here passed while asserting nothing.
  If a guard matters, break it on purpose once and watch the test fail.
- **Never classify an error by its text.** Validation failures carry
  `store.ErrValidation`.
