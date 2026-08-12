# Admin frontend — accepted design

The administration interface for relais: SMTP backends, sending domains,
credentials and their sender patterns, and a message log. Authentication is OIDC
through Authentik; no password is ever handled locally.

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
| `arctic` | 3.7.0 | first-class `Authentik` provider |
| `tailwindcss` | 4.3.3 | |
| `typescript` | **6.0.3** | **not** `latest` — see below |
| `vite` | 8.2.1 | |
| `sv` | 0.17.0 | scaffolding: `npx sv create web` |

⚠️ **TypeScript**: npm serves `7.0.2` as `latest` (the compiler rewritten in Go),
but `svelte-check@4.7.5` declares `peerDependencies: typescript ^5.0.0 || ^6.0.0`.
Pin **6.0.3**: stable and supported. Installing `latest` breaks `svelte-check`.

The arctic API in use:

```ts
new Authentik(baseURL, clientId, clientSecret, redirectURI)
  .createAuthorizationURL(state, codeVerifier, scopes)   // PKCE
  .validateAuthorizationCode(code, codeVerifier)         // → OAuth2Tokens
  .refreshAccessToken(refreshToken)
  .revokeToken(token)
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

### F2 — the browser never holds a token

Every call to the Go API is made from the SvelteKit server (`load` functions and
form actions), which attaches the access token. The browser only ever sees an
`httpOnly` cookie.

An XSS in the admin UI therefore cannot steal a token, there is no CORS, and the
refresh token is never exposed. The cost is one Node container.

The guarantee is **mechanical, not disciplinary**: `src/lib/server/` is a boundary
SvelteKit enforces — an import from client code fails the build.

### F3 — session: measured, not estimated

Prerequisites on the Authentik side, without which D11 does not hold:

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

Verdict: **comfortable**. The limit is ~4096 B *including the name and
attributes* (`Path`, `SameSite`, `Secure`, `HttpOnly` account for ~80 B), leaving
roughly 1300 B of headroom.

One encrypted (AEAD) cookie carrying `access_token`, `refresh_token`, `exp`, `sub`
and `groups`. The `id_token` is discarded after login.

**Guard rail to implement**: log a warning when the cookie exceeds 3500 B. The
headroom is not unlimited, and drift must become visible before it breaks.

The measurement recipe, to be repeated if the Authentik configuration changes:

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
cookie. Authentik access tokens are short-lived, so a `Set-Cookie` every few
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

If every application runs inside the same Coolify network, **nothing of relais
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
| Credentials | table, creation → secret shown once, revocation | `GET/POST /admin/v1/credentials`, `POST .../credentials/{id}:revoke` |
| Patterns | list, validated-as-you-type add, address test | `POST/DELETE .../credentials/{id}/patterns`, `patterns:validate`, `patterns:test` |
| Messages | paginated list (keyset), filters, detail with the SMTP error | `GET /admin/v1/messages`, `GET /admin/v1/messages/{id}` |

Two states the UI must surface, because they will otherwise generate support
tickets:

- **a domain pointing at a disabled backend** delivers nothing. The list response
  carries `backend_enabled` for exactly this.
- **a credential with no pattern** can send as nobody: a warning badge, not a row
  that looks like every other.

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

## Still to do before M8 starts

- An OpenAPI document emitted by the Go side, from which the TypeScript types are
  generated. Written by hand they drift, exactly like the pattern grammar would.
- The cookie-size guard rail described in F3.
