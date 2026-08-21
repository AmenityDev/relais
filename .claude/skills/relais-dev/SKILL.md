---
name: relais-dev
description: Run relais locally — prerequisites, task setup, the Docker development stack (Postgres, mailpit, Keycloak), migrations, the CLI bootstrap sequence, every port, running the SvelteKit admin interface, and the failure modes that waste the most time. Use when starting, configuring or debugging a local run of relais.
---

# Running relais locally

Prerequisites: **Go 1.26+**, **Docker**, and **Node 22+** for the admin interface.

`task` is convenient, not required — every target in `Taskfile.yml` is a readable
command sequence. `Taskfile.yml` loads `.env` (`dotenv:`), so a target sees the
development configuration; a bare `go run` in your shell does not unless you export it.

## First run

```sh
task setup            # creates .env from .env.example and generates the three secrets
docker compose up -d  # Postgres + mailpit
task migrate          # apply the schema
```

The repository **ships no key material**: `.env.example` leaves the secret variables
empty and relais refuses to start without them. `task setup` generates
`RELAIS_SECRET_ENCRYPTION_KEYS`, `RELAIS_SECRET_CREDENTIAL_PEPPER` and
`RELAIS_WEB_SESSION_KEY` into `.env`, and is safe to re-run — it leaves anything already
set alone. `.env` is gitignored.

`RELAIS_ENV=dev` in `.env` is what allows `RELAIS_TLS_SELF_SIGNED=true`; a self-signed
certificate is refused outright when `RELAIS_ENV=prod`.

## Bootstrap: a relay, a domain, a credential

The docs write `relais`; locally that is `go run ./cmd/relais`, or `task build` then
`./bin/relais`.

```sh
relais backend add -name mailpit-dev -host 127.0.0.1 -port 1025 -tls none
relais domain add -name example.test -backend mailpit-dev -include-subdomains
relais credential create -name my-app -type api_key -from '*@example.test'
# → the API key is printed ONCE, and is unrecoverable afterwards
```

`relais domain resolve example.test` answers which relay would carry a domain's mail.
`relais <command> -h` lists flags; `relais help` lists commands.

## Run it

```sh
task serve   # :8080 sending API, :8081 admin API, :2525 submission
curl -X POST http://127.0.0.1:8080/v1/emails \
  -H "Authorization: Bearer relais_sk_..." -H "Content-Type: application/json" \
  -d '{"from":"alerts@example.test","to":"someone@elsewhere.test","subject":"It works","text":"Hello."}'
```

Mail lands in mailpit at <http://localhost:8025>.

## Ports

| Port | What |
| --- | --- |
| 8080 | sending API — `/v1/emails` only, `/admin/v1` answers 404 here |
| 8081 | admin API — `/admin/v1`, never exposed publicly |
| 2525 | SMTP submission in development (`RELAIS_SMTP_ADDR` in `.env`; the config default is `:587`) |
| 5432 | Postgres (`relais` and `relais_test` databases) |
| 1025 / 8025 | mailpit SMTP sink / its web UI |
| 8180 | development Keycloak (console admin/admin) |
| 3000 | the **built** admin interface (`node build/index.js`) |
| 5173 | `vite dev`, i.e. `task web:dev` |

## The admin interface

It authenticates through OIDC with no local bypass, so it needs a provider. One is
included with its realm pre-imported:

```sh
task dev:auth   # Keycloak on :8180, waits for the realm import
```

Users: `ops`/`ops` (administrator), `watcher`/`watcher` (read-only). Issuer:
`http://localhost:8180/realms/relais`. Add to `.env`:

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

The two issuer variables must hold the **same** value: both sides deal in the same
`iss` claim, and a mismatch means every token the interface obtains is rejected, with
an error that names neither side.

**Origin and port must agree — this is the trap.** `RELAIS_WEB_ORIGIN` is what the app
builds the OIDC redirect URI from, and what the container derives adapter-node's
`ORIGIN` from (F15). The development realm allows two callbacks, `:3000` and `:5173`
(`deploy/keycloak/relais-realm.json`), and nothing else:

```sh
task web:start   # the built server, :3000 — what ships, and what task smoke drives
task web:dev     # the Vite dev server with hot reload, :5173
```

Point `RELAIS_WEB_ORIGIN` at whichever one you run. A mismatch loads the interface
normally and refuses **every write** as cross-site, which reads like a broken RBAC check
and is not one. `web:start` derives the listening port from the origin, so those two
cannot drift; it refuses to start when the variable is empty.

The interface runs on the host, not in a container: an issuer URL has to resolve to the
same provider from the browser *and* from the server exchanging the code, and on a dev
machine only `localhost` satisfies both.

The realm's fixed client secret and two passwords are fixtures for a loopback-only
`start-dev` container. They unlock that container and nothing else.

## Everyday targets

```sh
task                # list every task
task dev:up         # Postgres + mailpit (runs setup first)
task dev:auth       # add Keycloak
task dev:stop       # stop everything, keep the data
task dev:reset      # destroy the database and replay the migrations (prompts)
task migrate:status # what has been applied
task web:dev        # the interface, dev server (vite, :5173)
task web:start      # the interface, built and served the way the container does (:3000)
task web:key        # generate a session key
```

`dev:stop` and `dev:reset` name every compose profile on purpose: a plain
`docker compose down` leaves profile-gated containers running, which is how a stale
Keycloak keeps holding :8180.

## Failure modes worth recognising

- **`relais: interrupted`, exit 130, immediately at startup.** Something already holds
  a port. Since the fix in `cmd_serve.go` the message is explicit
  (`http listener on :8080: bind: address already in use`) — if you see the old form,
  look for a stray `go run` or a container from `--profile app`.
- **The interface loads but every write is refused.** A CSRF origin refusal, not RBAC:
  `RELAIS_WEB_ORIGIN` does not match the origin in the browser's address bar.
  Navigation (GET) keeps working, which is what makes it confusing.
- **`admin=false` in the serve log.** The OIDC variables are missing from `.env`; the
  admin listener stays off and the interface has nothing to talk to.
- **The interface 500s on a route right after a rebuild.** adapter-node loads route
  chunks lazily; rebuilding `web/build` under a live process breaks the chunks it had
  not loaded. Restart it. Not a code bug.
- **A Postgres healthcheck loop that never ends** usually means an old volume. `task
  dev:reset` recreates it, including `relais_test`.
