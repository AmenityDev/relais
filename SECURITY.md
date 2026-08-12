# Security policy

## Reporting a vulnerability

Email **security@amenitydev.com**. Please do not open a public issue for a
vulnerability.

Include whatever you have: the affected version or commit, what an attacker can
do, and a reproduction if you have one. A vague report is still worth sending —
we would rather triage something imprecise than not hear about it.

You will get an acknowledgement, and we will tell you what we found and when a fix
is expected. If we conclude it is not a vulnerability, we will say why.

Please give us a reasonable window to ship a fix before disclosing publicly. If a
report goes unanswered, that is our failure and you should not feel bound by it.

## What is in scope

relais is an SMTP/API gateway that authenticates senders and relays their mail. The
findings that matter most are the ones that break one of these:

- **Sending as an address a credential is not allowed to use.** The sender
  allow-list is the core of the whole design. Any path that bypasses the `From`
  validation, or that makes a pattern match more than it should, is the most
  serious class of bug in this codebase.
- **Relaying without authentication.** Any way to get a message accepted without
  presenting a valid credential, over either façade.
- **Recovering a secret.** Backend passwords are sealed with AES-256-GCM; sender
  credentials are stored only as an HMAC fingerprint peppered from the
  environment. Anything that exposes either — through an API response, a log line,
  an error message, or the database alone — is in scope.
- **Leaking message content.** Bodies are stored only until delivery and are
  returned by no endpoint. Subjects are stored but must never reach a log.
- **Cross-credential access.** One credential reading another's messages, or one
  admin identity acting outside its role.
- **Downgrading transport security.** Anything that gets SMTP AUTH onto an
  unencrypted connection, in either direction, or that makes an untrusted
  certificate acceptable.
- **Admin authentication and authorisation.** Accepting a token that was not
  signed by the configured issuer, was minted for another audience, or carries no
  recognised group; or a `viewer` performing a write.

## What is not in scope

- **The development key material.** There is none: this repository intentionally
  ships no keys, and `.env.example` leaves them empty so relais refuses to start.
  If you find committed key material, that *is* a finding — please report it.
- **`RELAIS_TLS_SELF_SIGNED`.** It generates an untrusted certificate on purpose,
  for tests and local development, and is refused outright when `RELAIS_ENV=prod`
  unless explicitly overridden.
- **`RELAIS_SENDER_INSECURE_VERIFY_EXEMPT_HOSTS`.** It skips certificate
  verification for a named local sink, and the sender additionally refuses to
  honour it for any host that is not loopback or private. A way to make it apply
  to a public host would be a finding.
- **Rate limits being per-process rather than cluster-wide.** This is documented
  and deliberate for a mono-tenant deployment.
- **Bounce and complaint handling.** Out of scope for v1, by design, and the
  schema anticipates none of it.
- Reports produced solely by an automated scanner, with no described impact.

## Supported versions

The project is pre-1.0 and only the latest commit on the default branch is
supported. There are no backports.
