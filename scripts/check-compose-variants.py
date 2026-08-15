#!/usr/bin/env python3
"""Assert the two Coolify compose files agree on everything but SMTP.

deploy/coolify/ holds the same stack twice: once without SMTP submission and once
with it. Duplication is the right shape for a file people deploy and edit — an
override fragment is not deployable on its own, and Coolify takes a single file —
but two files that must agree are exactly the thing this project keeps getting
bitten by. So a change to the shared parts has to land in both, and this says so.

The comparison runs on `docker compose config` output rather than on the text: it
resolves interpolation and normalises shape, so reordering a key or rewrapping a
comment is not reported as drift, while a real difference is.

Exits non-zero and prints what differs. Requires docker compose.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

BASE = Path("deploy/coolify/docker-compose.yaml")
SMTP = Path("deploy/coolify/docker-compose.smtp.yaml")

# Dummy values, only so interpolation resolves. Nothing here is a secret, and
# nothing is deployed: `config` renders and exits.
ENV = {
    "RELAIS_DB_URL": "postgres://relais:pw@db.invalid:5432/relais",
    "RELAIS_SECRET_ENCRYPTION_KEYS": "1:" + "A" * 43 + "=",
    "SERVICE_PASSWORD_64_PEPPER": "pepper",
    "RELAIS_OIDC_ISSUER": "https://auth.invalid/realms/relais",
    "RELAIS_OIDC_AUDIENCE": "relais",
    "SERVICE_URL_WEB": "https://admin.invalid",
    "RELAIS_WEB_OIDC_CLIENT_ID": "relais-web",
    "RELAIS_WEB_OIDC_CLIENT_SECRET": "secret",
    "RELAIS_WEB_SESSION_KEY": "c2Vzc2lvbi1rZXktMzItYnl0ZXMtZm9yLXRlc3RpbmchIQ==",
    "RELAIS_SMTP_DOMAIN": "smtp.invalid",
    "ACME_EMAIL": "ops@invalid",
    "LEGO_DNS_PROVIDER": "cloudflare",
}

# What the SMTP variant is allowed to add or change. Anything else differing is
# drift, and the point of this check.
SMTP_ONLY_SERVICES = {"certs"}
SMTP_ONLY_ENV = {
    "RELAIS_SMTP_ENABLED",
    "RELAIS_SMTP_ADDR",
    "RELAIS_SMTP_DOMAIN",
    "RELAIS_TLS_CERT_FILE",
    "RELAIS_TLS_KEY_FILE",
    # Only meaningful where there are certificate files to watch.
    "RELAIS_TLS_WATCH_INTERVAL",
}
SMTP_ONLY_KEYS = {"ports", "volumes", "depends_on"}


def render(path: Path) -> dict:
    """Resolve a compose file to normalised JSON."""
    # exclude_from_hc is a Coolify extension that vanilla compose rejects. Dropping
    # it here keeps the check honest about everything else.
    text = "\n".join(
        line for line in path.read_text().splitlines() if "exclude_from_hc" not in line
    )
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as tmp:
        tmp.write(text)
        rendered = Path(tmp.name)

    try:
        result = subprocess.run(
            ["docker", "compose", "-f", str(rendered), "config", "--format", "json"],
            capture_output=True,
            text=True,
            env={"PATH": "/usr/bin:/bin:/usr/local/bin", **ENV},
        )
    finally:
        rendered.unlink(missing_ok=True)

    if result.returncode != 0:
        sys.exit(f"{path}: docker compose config failed\n{result.stderr}")
    return json.loads(result.stdout)


def main() -> int:
    base = render(BASE)["services"]
    smtp = render(SMTP)["services"]

    problems: list[str] = []

    extra = set(smtp) - set(base)
    if extra != SMTP_ONLY_SERVICES:
        problems.append(
            f"{SMTP.name} adds {sorted(extra) or 'nothing'}, expected {sorted(SMTP_ONLY_SERVICES)}"
        )
    if missing := set(base) - set(smtp):
        problems.append(f"{SMTP.name} is missing {sorted(missing)}")

    for name in sorted(set(base) & set(smtp)):
        a, b = dict(base[name]), dict(smtp[name])

        for key in SMTP_ONLY_KEYS:
            a.pop(key, None)
            b.pop(key, None)

        for env in (a.get("environment"), b.get("environment")):
            if isinstance(env, dict):
                for key in SMTP_ONLY_ENV:
                    env.pop(key, None)

        if a == b:
            continue

        for key in sorted(set(a) | set(b)):
            if a.get(key) == b.get(key):
                continue

            # Naming the differing variable rather than dumping both environments:
            # a wall of identical keys hides the one that moved.
            if key == "environment":
                left = a.get("environment") or {}
                right = b.get("environment") or {}
                for var in sorted(set(left) | set(right)):
                    if left.get(var) != right.get(var):
                        problems.append(
                            f"service {name}: {var} differs\n"
                            f"      {BASE.name}: {left.get(var, '(absent)')!r}\n"
                            f"      {SMTP.name}: {right.get(var, '(absent)')!r}"
                        )
                continue

            problems.append(
                f"service {name}: {key} differs\n"
                f"      {BASE.name}: {a.get(key)!r}\n"
                f"      {SMTP.name}: {b.get(key)!r}"
            )

    if problems:
        print("The two Coolify compose files have drifted apart.")
        print("They are the same stack twice; a change to the shared parts belongs in both.\n")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    print(f"{BASE.name} and {SMTP.name} agree on everything but SMTP")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
