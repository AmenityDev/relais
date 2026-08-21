---
name: relais-deploy
description: Build, publish and deploy relais — the two container images, the GHCR pipeline and its tags, the two Coolify compose files and the drift check that keeps them in step, TLS certificates for SMTP submission over ACME DNS-01, and what to expose. Use when touching deploy/, the CI workflow, or an actual deployment.
---

# Deployment

## Images

| Image | Built from | Notes |
| --- | --- | --- |
| `ghcr.io/amenitydev/relais` | `deploy/Dockerfile` | multi-stage, distroless nonroot (**UID 65532**), no shell — healthcheck is the binary's own `relais healthcheck` |
| `ghcr.io/amenitydev/relais-web` | `deploy/Dockerfile.web` | adapter-node; `deploy/relais-web-entrypoint.sh` derives `ORIGIN` from `RELAIS_WEB_ORIGIN` and **refuses to start without it** |

Locally: `task docker:build`, `task web:docker:build`,
`REGISTRY=ghcr.io/you task docker:buildx` for multi-arch.

## The publish pipeline

CI job `publish` needs `[lint, test, fuzz, web, image]`, runs on `push` only, and takes
`packages: write`. Tags produced by `docker/metadata-action`:

- `sha-<short>` on every push
- `main` on the default branch
- `<version>`, `<major>.<minor>` and `latest` on a `v*` tag

Both images are built for `linux/amd64` and `linux/arm64`. **GHCR creates packages
private even for a public repository** — the first push has to be followed by making
each package public by hand.

## Coolify

Two files in `deploy/coolify/`, the same stack twice:

| File | Contents |
| --- | --- |
| `docker-compose.yaml` | migrate + relais + web, SMTP off, the `certs` service commented out |
| `docker-compose.smtp.yaml` | the same plus submission, `ports: 587:2525`, and a `lego` sidecar |

`scripts/check-compose-variants.py` (in `task lint` and CI) renders both with
`docker compose config` and asserts they differ only in the SMTP parts — service `certs`,
the SMTP/TLS environment variables, and the `ports`/`volumes`/`depends_on` keys. **A
change to the shared parts belongs in both files.** Postgres is external in both:
`RELAIS_DB_URL` points at an existing server.

Conventions these files follow:

- **No `ports:`** except SMTP. Publishing a port bypasses Coolify's proxy, which is what
  terminates TLS and sets the forwarded headers. Submission is the exception because the
  proxy speaks HTTP, not SMTP.
- **Magic variables**, declared as bare list entries: `SERVICE_URL_WEB_3000` and
  `SERVICE_URL_RELAIS_8080` make Coolify generate a domain and point its proxy at that
  port; the value comes back as `${SERVICE_URL_WEB}`. The sending API is exposed through
  the proxy because each application lives in its own stack — and sometimes on another
  server — so `http://relais:8080` is unreachable from where the callers are.
  `${VAR:?}` marks a variable required: Coolify lists those first and refuses to deploy
  while they are empty.
- **`exclude_from_hc: true`** on `migrate` is a Coolify extension that vanilla
  `docker compose config` rejects; the drift script strips it.
- Service names carry **no hyphen**: a magic variable's identifier derives from the
  service name and Coolify does not document how a hyphen is transformed.
- `RELAIS_ADMIN_PORT` is shared between `RELAIS_ADMIN_ADDR` and `RELAIS_WEB_API_URL`, so
  the two cannot disagree. The admin API is never given a domain.
- `RELAIS_HTTP_TRUSTED_PROXY_HEADER=X-Forwarded-For` is required there, because the
  socket peer is Traefik and a rejection recorded against the proxy's address loses
  exactly the context that makes a compromised credential investigable. It is trusted
  only because no port is published to bypass the proxy.

## TLS for submission

Two sources, exactly one at a time: mounted files
(`RELAIS_TLS_CERT_FILE` + `RELAIS_TLS_KEY_FILE`) in production, or
`RELAIS_TLS_SELF_SIGNED=true` for development — refused when `RELAIS_ENV=prod`.

**Renewals need no restart and no signal.** `internal/tlsconf` stats the two files every
`RELAIS_TLS_WATCH_INTERVAL` (30s) and swaps the certificate in for the next handshake;
`SIGHUP` still forces it. Watching rather than signalling is deliberate: signalling
another container would mean handing it the Docker socket. A failed reload keeps the
previous certificate serving and retries, so a half-written renewal resolves itself.

The `certs` sidecar in `docker-compose.smtp.yaml` runs `goacme/lego` in a loop:
`lego run --renew-days 30`, `sleep 12h` on success, retry in **5 minutes** on failure.
DNS-01 because HTTP-01 needs port 80 and TLS-ALPN-01 needs 443, both owned by the proxy —
and because it works for a name that serves no HTTP at all. Notes:

- `LEGO_DNS_RESOLVERS` is **not optional**. Left to the default, lego checks its own
  challenge record through Docker's stub resolver at `127.0.0.11`; the NXDOMAIN it gets
  the instant after creating the record is cached for the zone's negative TTL (1800s on
  Cloudflare), far longer than lego waits, so every attempt fails identically forever.
  Naming public resolvers takes the stub and the host cache out of the path.
  `LEGO_DNS_PROPAGATION_DISABLE_RNS=true` is the fallback: authoritative check only.
- lego writes `$LEGO_PATH/certificates/<domain>.{crt,key}` and both relais paths are
  built from `RELAIS_SMTP_DOMAIN`, so the file relais opens is necessarily the one lego
  renews. The volume also holds the ACME account key.
- The loop `chown`s `/certs` to 65532 because lego writes the key 0600 as root and relais
  runs nonroot; relais mounts the volume `:ro`.
- The image tag is `v`-prefixed (`goacme/lego:v5.3.1`); `5.3.1` does not exist.
- An `accountDoesNotExist` loop means a stored account with no registration, a state that
  never self-heals. Deleting the volume fixes it.

## What to expose

| Surface | Exposure |
| --- | --- |
| sending API 8080 | through the proxy, with a domain |
| admin API 8081 | never — only the interface's container dials it, and no token reaches a browser |
| interface 3000 | through the proxy, with a domain |
| submission 587 | published on the host (`587:2525`, unprivileged inside, no `CAP_NET_BIND_SERVICE`) |
