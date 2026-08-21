# Admin frontend — accepted design

The administration interface for relais: SMTP backends, sending domains,
credentials and their sender patterns, and a message log. Authentication is OIDC
through OIDC; no password is ever handled locally. Any compliant provider works —
the endpoints are discovered from the issuer (F13) — and the development stack ships
a Keycloak with its realm pre-imported.

This document records the decisions. It is updated when a decision changes.

**Prerequisite**: M7 (the Go admin API), which is complete.

---

## Pinned versions

Checked against the npm registry rather than recalled from memory.

| Package | Version | Note |
| --- | --- | --- |
| `svelte` | 5.56.8 | runes |
| `@sveltejs/kit` | 2.70.2 | |
| `@sveltejs/adapter-node` | 5.5.7 | |
| `arctic` | 3.7.0 | `OAuth2Client`, driven by discovery (see F13) |
| `tailwindcss` | 4.3.3 | |
| `typescript` | **6.0.3** | **not** `latest` — see below |
| `vite` | 8.2.1 | |
| `sv` | 0.17.0 | scaffolding: `npx sv create web` |

⚠️ **TypeScript**: npm serves `7.0.2` as `latest` (the compiler rewritten in Go),
but `svelte-check@4.7.5` declares `peerDependencies: typescript ^5.0.0 || ^6.0.0`.
Pin **6.0.3**: stable and supported. Installing `latest` breaks `svelte-check`.

The arctic API in use:

```ts
// Endpoints come from the issuer's discovery document, so this works against any
// provider. arctic's per-vendor classes hardcode vendor paths; see F13.
new OAuth2Client(clientId, clientSecret, redirectURI)
  .createAuthorizationURLWithPKCE(authorizationEndpoint, state, S256, verifier, scopes)
  .validateAuthorizationCode(tokenEndpoint, code, verifier) // → OAuth2Tokens
  .refreshAccessToken(tokenEndpoint, refreshToken, [])
  .revokeToken(revocationEndpoint, token)
```

---

## Decisions

| # | Decision | Status |
| --- | --- | --- |
| F1 | `adapter-node`, not a static SPA | accepted |
| F2 | **BFF pattern**: the browser never holds a token | accepted |
| F3 | Session in a single encrypted cookie — **measured**, see below | accepted |
| F4 | Tailwind 4, hand-rolled components, native `<dialog>`, no component library | accepted |
| F5 | The pattern grammar is **never** reimplemented in TypeScript | accepted |
| F6 | Go is the authority on RBAC; the UI merely reflects it | accepted |
| F7 | The secret is shown once, with an explicit acknowledgement | accepted |
| F8 | Logs stay in HyperDX, deep-linked from the UI | accepted |
| F9 | Two containers; **nothing of relais is exposed to the browser** | accepted |
| F10 | No client-side data fetching: `load` and form actions only | accepted |
| F11 | A separate HTTP listener for the admin API (Go side) | accepted, implemented |
| F12 | The API description is generated from Go, never written | accepted, implemented |
| F13 | OIDC discovery: one issuer, any provider | accepted, implemented |
| F14 | The container refuses to start when misconfigured | accepted, implemented |
| F15 | adapter-node's ORIGIN is derived, never configured twice | accepted, implemented |

### F2 — the browser never holds a token

Every call to the Go API is made from the SvelteKit server (`load` functions and
form actions), which attaches the access token. The browser only ever sees an
`httpOnly` cookie.

An XSS in the admin UI therefore cannot steal a token, there is no CORS, and the
refresh token is never exposed. The cost is one Node container.

The guarantee is **mechanical, not disciplinary**: `src/lib/server/` is a boundary
SvelteKit enforces — an import from client code fails the build.

### F3 — session: measured, not estimated

Prerequisites on the provider side, without which D11 does not hold. Stated for
Authentik because that is the production target; the development Keycloak realm
already satisfies all three:

- the provider must issue a **signed (JWT) access token** — set a *Signing Key*.
  Without one, Authentik issues an opaque token that Go cannot validate against a
  JWKS;
- add `offline_access` to the scopes to obtain a refresh token;
- add a property mapping that exposes only groups prefixed `relais-`. That is the
  only variable that grows the cookie, so it is the only one worth bounding.

Measured against the target instance:

```text
access token   1804 B   (JWT, carries the claims)
refresh token   128 B   (opaque, fixed size)
payload        1984 B
cookie        ~2683 B   (+28 B AES-GCM nonce/tag, then base64 ×1.34)
```

Measured again against the development Keycloak, through the real login flow:

```text
cookie        3075 B   (Set-Cookie in full, name and attributes included)
headroom      1021 B
```

Both providers land in the comfortable band, which is the useful part: the budget
does not depend on which one is in front.

Verdict: **comfortable**. The limit is ~4096 B *including the name and
attributes* (`Path`, `SameSite`, `Secure`, `HttpOnly` account for ~80 B), leaving
roughly 1300 B of headroom.

One encrypted (AEAD) cookie carrying `access_token`, `refresh_token`, `exp`, `sub`
and `groups`. The `id_token` is discarded after login.

**Guard rail to implement**: log a warning when the cookie exceeds 3500 B. The
headroom is not unlimited, and drift must become visible before it breaks.

The measurement recipe, to be repeated if the provider's configuration changes:

```sh
# 1) In a browser, capture the ?code= from the redirect
#    https://auth.example.com/application/o/authorize/?client_id=CLIENT_ID
#      &response_type=code&redirect_uri=http://localhost:5173/auth/callback
#      &scope=openid+profile+email+offline_access&state=test

# 2) Exchange the code
curl -s -X POST https://auth.example.com/application/o/token/ \
  -d grant_type=authorization_code -d code=THE_CODE \
  -d redirect_uri=http://localhost:5173/auth/callback \
  -d client_id=CLIENT_ID -d client_secret=CLIENT_SECRET > tokens.json

# 3) Measure
python3 -c "
import json, math
t = json.load(open('tokens.json'))
payload = json.dumps({'a': t['access_token'], 'r': t.get('refresh_token',''),
                      'e': 0, 's': 'sub', 'g': ['relais-admin']}, separators=(',',':'))
p = len(payload.encode())
print(f'payload {p} B -> cookie ~{math.ceil((p+28)*4/3)} B')
"
```

Thresholds: `< 3000 B` comfortable · `3000–3800 B` fragile · `> 3800 B` a
server-side opaque session is required.

Refreshing happens in `hooks.server.ts` when `exp` approaches, rewriting the
cookie. Access tokens are short-lived on both Authentik and Keycloak, so a
`Set-Cookie` every few
minutes is normal.

### F4 — no component library

About eight hand-rolled components of 20 to 60 lines each: `Table`, `Field`,
`Badge`, `Dialog`, `CopyOnce`, `Pagination`, `EmptyState`, `ConfirmButton`. Markup
and classes, no logic.

What a library would buy is accessibility for the hard components. The only
non-trivial case here is the dialog, and the native **`<dialog>`** element solves
it (focus trap, `Escape`, inert backdrop). There is no combobox and no menu in the
six screens: tables, text inputs, checkboxes and native selects.

Escape hatch if a need appears: **bits-ui** (headless primitives, Svelte 5),
adoptable for one component without rewriting the rest.

### F5 — the pattern grammar lives only in Go

`internal/frompattern` is Go code that is tested, fuzzed, and pinned against a SQL
constraint. A TypeScript copy would drift, and the day it drifts the UI tells an
operator that a pattern covers more, or less, than it does. This is the most
expensive trap in the project.

The API therefore exposes dry runs that call the real code:

- `POST /admin/v1/patterns:validate` — normalizes and validates. The UI calls it
  on blur and shows the canonical form (`Exemplé.COM` → `xn--exempl-gva.com`)
  along with the exact error and a plain-language explanation of what the pattern
  grants.
- `POST /admin/v1/credentials/{id}/patterns:test` — "would this credential be
  allowed to send as this address, and by which pattern?". It also answers whether
  any enabled domain routes that sender, because a pattern can allow an address
  nothing routes, and seeing only "allowed" would send an operator away believing
  the setup works.

On the TypeScript side, only a visual reminder of the four shapes, explicitly
non-normative.

### F9 — what is exposed, and what is not

The browser makes **no** request to `relais`. It only knows `relais-web`, the only
service with a public hostname and Traefik TLS.

| Surface | Called by | Exposure |
| --- | --- | --- |
| `/admin/v1/*` (admin port) | the SvelteKit server only | **never** public |
| `/v1/emails` | internal applications | only if an application lives outside the network |
| SMTP submission (587) | WordPress, PHP scripts | same reasoning |

If every application runs on the same network as relais, **nothing of it
needs to be exposed**.

### F11 — separate admin listener (Go side)

`RELAIS_ADMIN_ADDR`, default `:8081`, distinct from `RELAIS_HTTP_ADDR`.

Without it, exposing `/v1` publicly would make the admin API reachable on the same
hostname, protected by the OIDC check alone. With a distinct port, exposure becomes
a network decision rather than a routing rule nobody must get wrong. Defence in
depth: the OIDC check remains the real protection.

Implemented in M7, and verified: a cross-port request returns `404` on both sides.

---

## Screens, and what they need from the API

| Screen | Contents | Endpoints |
| --- | --- | --- |
| Dashboard | counts per status, latest rejections | `GET /admin/v1/stats`, `GET /admin/v1/messages?status=rejected` |
| Backends | table, creation (write-only password), connection test | `GET/POST/PATCH/DELETE /admin/v1/backends`, `POST .../backends/{id}:test` |
| Domains | table, `include_subdomains` explained, dry-run resolution | `GET/POST/PATCH/DELETE /admin/v1/domains`, `GET /admin/v1/domains:resolve?sender=` |
| Credentials | table, creation → secret shown once, rotation → the same show-once panel, revocation, deletion | `GET/POST /admin/v1/credentials`, `POST .../credentials/{id}:revoke`, `POST .../credentials/{id}:rotate`, `DELETE .../credentials/{id}` |
| Patterns | list, validated-as-you-type add, address test | `POST/DELETE .../credentials/{id}/patterns`, `patterns:validate`, `patterns:test` |
| Messages | paginated list (keyset), filters, detail with the SMTP error | `GET /admin/v1/messages`, `GET /admin/v1/messages/{id}` |

Two states the UI must surface, because they will otherwise generate support
tickets:

- **a domain pointing at a disabled backend** delivers nothing. The list response
  carries `backend_enabled` for exactly this.
- **a credential with no pattern** can send as nobody: a warning badge, not a row
  that looks like every other.

Three of the credential row's four actions are irreversible and they are not
interchangeable, so each states its own consequence in the typed confirmation
rather than sharing a generic "this cannot be undone":

- **Rotate** issues a new secret and keeps the credential — id, name, limits and
  allow-list — so past messages keep their attribution. The old secret stops
  working at once, which is a live application down until it is reconfigured.
- **Revoke** is permanent and keeps the row, so the messages it sent still name
  it. This is the answer to a leak.
- **Delete** removes the row. The messages survive (`ON DELETE SET NULL`) but stop
  naming the credential, so the audit trail loses who submitted them. Offered on a
  revoked credential too, which is where it is mostly wanted.

`GET /admin/v1/identity` tells the frontend who it is acting as, so the UI can
decide whether to render write controls without decoding the token — which is what
the BFF design exists to avoid.

---

## Layout

```text
web/
├── src/
│   ├── lib/
│   │   ├── server/{oidc.ts,session.ts,api.ts,rbac.ts}   # never imported client-side
│   │   ├── components/
│   │   └── types.ts                                     # generated from the OpenAPI
│   ├── routes/
│   │   ├── +layout.server.ts                            # auth guard
│   │   ├── auth/{login,callback,logout}/+server.ts
│   │   ├── backends/  domains/  credentials/  messages/
│   └── hooks.server.ts                                  # session and refresh
└── Dockerfile
```

---

## Prerequisites

- ✅ **OpenAPI emitted by the Go side**, from which the TypeScript types are
  generated. See F12.
- ✅ The cookie-size guard rail described in F3. It refuses rather than warns above
  4096 bytes, because what a browser does with an oversized cookie is discard it
  silently: the operator sees a login loop and the logs say nothing.

### F13 — OIDC discovery, one issuer, any provider

`relais-web` uses arctic's generic `OAuth2Client` with endpoints read from the
issuer's `/.well-known/openid-configuration`, not arctic's per-vendor `Authentik`
class.

The vendor class hardcodes `/application/o/authorize/`, which had two costs. The
application only worked with Authentik. And the configuration had to carry the
provider's *root* URL separately from its *issuer* — two values that look alike,
cannot be swapped, and when confused produce
`…/application/o/<slug>/application/o/authorize/`: a 404 from the provider that
mentions neither variable. That was found by running the container and reading the
redirect it emitted, not by reasoning about it.

Discovery removes both. `RELAIS_WEB_OIDC_ISSUER` is the only value, and it is the
same one the Go side validates the `iss` claim against (`RELAIS_OIDC_ISSUER`).
Discovery is fetched once and kept, so a provider outage does not sit in the path
of every sign-in, and a failure is remembered briefly rather than retried per
request.

The document's own `issuer` is compared against the configured one and a mismatch
is refused, because a mismatch yields tokens relais rejects — a failure that would
otherwise surface a layer away from its cause.

### F14 — the container refuses to start when misconfigured

Configuration is validated as `hooks.server.ts` loads, which is to say as the
server starts, and `/healthz` answers only once that has succeeded.

The first version validated lazily and let the probe answer regardless, with a
comment claiming a liveness probe should not depend on configuration. That was
backwards: an orchestrator would report the container healthy and keep it in
rotation, serving 500s to every request while the probe stayed green. relais itself
refuses to start without its keys, and the two halves should fail the same way.

### F12 — the API description is generated, never written

`relais openapi -surface admin|public` emits an OpenAPI 3.1 document by reflecting
over the request and response structs that actually serve the requests. The
TypeScript types come from that document, so they cannot describe an API the
server does not have.

Two documents, not one: the surfaces sit on separately exposed listeners, and
merging them would blur the boundary F11 exists to draw.

What reflection cannot see is stated explicitly in the route table and then
checked:

- **which fields a create requires.** The same Go struct serves a create and a
  patch, and those are different contracts. Each is published under its own name
  (`BackendInput` demands a host, `BackendPatch` changes only what it mentions), so
  the generated types never tell the UI to resend a value it never displayed.
- **a type whose JSON is not its Go shape.** `addressList` is a `[]string` that
  also accepts a bare string. Described from its Go shape alone, the generated
  types would reject a payload the API accepts. A test fails if any
  `json.Unmarshaler` lacks an explicit schema.

Kept honest by 15 tests, each verified by mutation:

| Guard | What it catches |
| --- | --- |
| `chi.Walk` ≡ route table, both directions | a route served but undocumented, or documented but not served |
| write flags ≡ `requireWrite` group | a control the UI would render for a viewer, or hide from an editor |
| every write refuses a viewer (403) | the flag agreeing with the table but not with reality |
| every operation refuses no token (401) | anonymous access, which has no exception |
| no response schema names a secret | a password, fingerprint or body reaching a payload |
| determinism over 8 renderings | a diff on every run, which would make CI's check noise |
| committed document ≡ fresh one (CI) | a handler changed without regenerating |

The last is `relais openapi -check`, run in CI beside `sqlc diff` for the same
reason.

### F15 — ORIGIN is derived from the origin we already have

`adapter-node` reads `ORIGIN` from the environment before any application code
runs, and uses it for the CSRF origin check on every form POST. Without it, every
write is refused with *"Cross-site POST form submissions are forbidden"* while GET
navigation — and therefore login — keeps working. A deployment looks healthy and
cannot save anything.

The image therefore derives `ORIGIN` from `RELAIS_WEB_ORIGIN` in its entrypoint
rather than asking for it twice. Two variables that must agree are one variable,
and a mismatch here produces that same silent refusal.

Found while testing writes through the interface. It also invalidated an earlier
check: a viewer's write returned 403, which read as the role check when it was the
CSRF check. Both were re-verified once `ORIGIN` was set — the refusal now
carries "read-only access", and an editor's write reaches the database.

## Running the whole stack locally

```sh
task setup                              # generates the keys this repo ships none of
docker compose up -d                    # Postgres + mailpit
docker compose --profile auth up -d     # Keycloak, realm imported, no clicking
task migrate
task web:key                            # put the value in .env as RELAIS_WEB_SESSION_KEY
relais serve                            # or: task serve
task web:start                          # the interface, on the host, at :3000
```

Sign in at <http://localhost:3000> as `ops` / `ops` (admin) or `watcher` /
`watcher` (read-only). Mail lands in mailpit at <http://localhost:8025>.

`task web:dev` runs the Vite dev server instead, with hot reload, on `:5173`. The realm
allows that callback too, but `RELAIS_WEB_ORIGIN` must then name `:5173`: it is what the
redirect URI and adapter-node's CSRF origin are both derived from (F15), and a mismatch
refuses every form POST while navigation keeps working.

The interface runs on the host rather than in a container for one reason: an OIDC
issuer URL has to resolve to the same provider from the browser *and* from the
server that exchanges the code, since both deal in the same `iss` value. On a
development machine the only name that satisfies both is `localhost`, which a
container cannot reach. In a real deployment the provider has a real hostname and
this stops mattering, which is why the image itself is unchanged.

The development realm carries a fixed client secret and two throwaway passwords.
Those are fixtures for a loopback-only container in `start-dev` mode: they unlock
that container and nothing else, and relais itself still ships no keys.
