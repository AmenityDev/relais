---
name: relais-testing
description: Run and write tests for relais — the Go suite and its separate relais_test database, fuzzing the sender-pattern matcher, lint and the anti-drift checks, the frontend suite, the end-to-end smoke script, what CI runs, and the rules a test here has to satisfy. Use when running tests, adding tests, or diagnosing a failing check.
---

# Testing relais

```sh
task test        # Go suite, race detector; database-backed tests SKIP if Postgres is down
task test:all    # the same, with the database MANDATORY (what CI runs)
task test:db     # create and migrate relais_test (safe to re-run)
task fuzz        # fuzz the sender-pattern matcher (TIME=60s by default)
task lint        # vet, gofmt, go mod tidy -diff, OpenAPI freshness, compose drift
task web:check   # svelte-check, prettier, eslint, vitest
task smoke       # drive the running stack end to end
```

## The test database, and why it matters

Database-backed packages resolve their connection through `internal/dbtest`:

- **`RELAIS_TEST_DB_URL` set** → the database is mandatory and an unreachable one
  **fails** the run. This is the CI mode: a silently skipped integration suite is
  indistinguishable from a passing one.
- **unset** → the development stack is tried and tests skip if it is not running, so a
  bare `go test ./...` needs no Docker.

**Point it at `relais_test`, never `relais`.** The suite TRUNCATEs every table between
cases. Aimed at the development database it silently wipes the relays, domains and
messages you were working with — no error, just an empty interface later. The
development Postgres creates `relais_test` on first start
(`deploy/postgres/10-create-test-database.sql`); `task test:db` creates and migrates it
on an older volume. `task test:all` defaults to
`postgres://relais:relais@127.0.0.1:5432/relais_test?sslmode=disable`.

A Postgres **advisory lock** serializes these tests. `go test ./...` runs packages in
parallel against one database; without the lock they truncate each other mid-run
(observed: deadlocks and vanishing rows). Keep the lock rather than reaching for `-p 1`.

## Fuzzing

`internal/frompattern` decides what every credential may send as. Changes there are
held to a different standard: they come with fuzzing.

```sh
task fuzz TIME=120s   # FuzzParse and FuzzParseAddressAgainstWildcardPattern
go test ./internal/mailnorm/ -run=XXX -fuzz='^FuzzParse$' -fuzztime=45s
```

CI runs all three at 45s each and uploads any crasher as an artifact. `task fuzz`
covers only the two `frompattern` targets — run the `mailnorm` one by hand when you
touch normalization.

## Lint is also the anti-drift check

`task lint` fails when generated artefacts no longer match their sources:

- `relais openapi -surface admin|public -check docs/openapi-*.json` — a handler whose
  request or response type changed without `task openapi`
- `scripts/check-compose-variants.py` — the two Coolify compose files disagreeing on
  anything but SMTP
- CI additionally re-runs `sqlc generate` and diffs `internal/db/gen`

See `relais-api-contract` for the regeneration sequence.

## The frontend suite

`task web:check` runs `svelte-check`, Prettier, ESLint and Vitest (unit tests next to
what they test, `*.test.ts`). CI also regenerates `web/src/lib/api.generated.d.ts` from
`docs/openapi-admin.json` and diffs it — see `task web:types`.

## The smoke script

`scripts/smoke.sh` drives the **running** servers: a real OIDC login through the
development Keycloak, the six screens, an editor's write reaching the database, and a
viewer being refused. It drives no JavaScript, and covers what broke in practice — the
OIDC handshake, the session cookie, the CSRF origin check, the role split.

It expects the stack from `relais-dev`, with the interface on
`http://localhost:3000` (override with `WEB_URL`, `API_URL`, `ADMIN_URL`,
`KEYCLOAK_URL`, `MAILPIT_URL`). **Rebuild before running it**: rebuilding `web/build`
under a live adapter-node process makes it 500 on route chunks it had not loaded, which
reads exactly like a regression and is not one.

## What CI runs

Jobs `lint`, `test`, `fuzz`, `web`, `image`, then `publish` gated on all five (see
`relais-deploy`). Several jobs begin by asserting the checkout is complete — a
`.gitignore` pattern once excluded `cmd/relais` and three jobs failed with "directory
not found", which says nothing about the cause.

## Rules a test here has to satisfy

Each of these comes from a test that passed while proving nothing:

- **Break the guard on purpose once and watch the test fail.** Two `tlsconf` test
  suites were written, passed, and caught no mutation at all.
- **Assert on a real response, not on names derived from the same source.** Fifteen
  OpenAPI anti-drift tests agreed with each other while the documented error shape was
  wrong, because none compared an actual response body to its schema.
  `TestErrorResponsesMatchTheDocumentedSchema` now does.
- **Grepping rendered HTML for a value proves the data reached the page, not that
  anything renders it.** SvelteKit serialises load data into the document. Assert on
  visible text.
- **A test that reads the ambient environment reports on the shell, not the code.**
  `config.LoadFrom` merged its overlay over `os.Environ()`; the assertion held only
  where the variable happened to be unset — green locally, red in CI.
- **Never truncate test output.** Reporting green from a `tail -4` while another
  package failed has happened here. Read the whole run.
- Four packages deliberately have no tests of their own: `db` and `obs` (exercised by
  everything else / telemetry wiring), and `dbtest`/`smtptest`, which *are* test tooling.
