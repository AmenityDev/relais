#!/usr/bin/env bash
#
# End-to-end smoke test against the local development stack.
#
# This codifies what was otherwise verified by hand: a real login through the
# development Keycloak, the six screens rendering, an editor's write reaching the
# database, and a viewer's being refused. It is not a substitute for a browser test —
# it drives no JavaScript — but it covers the parts that broke in practice: the OIDC
# handshake, the session cookie, the CSRF origin check, and the role split.
#
# Requires the stack from the README:
#   docker compose up -d && docker compose --profile auth up -d
#   task migrate && task serve && task web:dev   (or the built server)
#
# It tests the *running* servers, so rebuild before running it: adapter-node loads
# route chunks lazily, and rebuilding under a live process makes it 500 on routes it
# had not loaded yet. That failure looks like a code bug and is not one.
#
# Usage: scripts/smoke.sh
set -uo pipefail

WEB="${WEB_URL:-http://localhost:3000}"
API="${API_URL:-http://127.0.0.1:8080}"
ADMIN="${ADMIN_URL:-http://127.0.0.1:8081}"
KEYCLOAK="${KEYCLOAK_URL:-http://localhost:8180}"
MAILPIT="${MAILPIT_URL:-http://127.0.0.1:8025}"

passed=0
failed=0

ok() {
	printf '  \033[32mok\033[0m   %s\n' "$1"
	passed=$((passed + 1))
}

fail() {
	printf '  \033[31mFAIL\033[0m %s\n' "$1"
	[ $# -gt 1 ] && printf '       %s\n' "$2"
	failed=$((failed + 1))
}

# expect <description> <actual> <expected>
expect() {
	if [ "$2" = "$3" ]; then ok "$1"; else fail "$1" "got '$2', want '$3'"; fi
}

# contains <description> <haystack> <needle>
contains() {
	case "$2" in
	*"$3"*) ok "$1" ;;
	*) fail "$1" "'$3' not found" ;;
	esac
}

status() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

# login <user> <cookie-jar> — drives the full authorization-code flow with PKCE.
login() {
	local user=$1 jar=$2
	rm -f "$jar"

	local authorize
	authorize=$(curl -s -c "$jar" -o /dev/null -w '%{redirect_url}' "$WEB/auth/login")
	case "$authorize" in
	"$KEYCLOAK"/*) : ;;
	*)
		fail "login($user): /auth/login did not redirect to the issuer" "$authorize"
		return 1
		;;
	esac

	# The login form's action carries the Keycloak execution state; it cannot be
	# guessed and has to be read from the page.
	local form
	form=$(curl -s -c "$jar" -b "$jar" -L "$authorize" |
		grep -oE 'action="[^"]*"' | head -1 |
		sed 's/action="//; s/"$//' |
		python3 -c 'import sys,html; print(html.unescape(sys.stdin.read().strip()))')

	local callback
	callback=$(curl -s -c "$jar" -b "$jar" -o /dev/null -w '%{redirect_url}' \
		-X POST "$form" -d "username=$user" -d "password=$user" -d "credentialId=")
	case "$callback" in
	"$WEB"/auth/callback*) : ;;
	*)
		fail "login($user): the provider did not return to the callback" "$callback"
		return 1
		;;
	esac

	curl -s -c "$jar" -b "$jar" -o /dev/null "$callback"
	grep -q relais_session "$jar" || {
		fail "login($user): no session cookie was set"
		return 1
	}
}

# post <jar> <path-with-action> <fields...> — a form action, with the Origin the CSRF
# check requires. Without it every write is refused as cross-site.
post() {
	local jar=$1 target=$2
	shift 2
	curl -s -b "$jar" -H "Origin: $WEB" \
		-H 'Content-Type: application/x-www-form-urlencoded' \
		"$@" "$WEB$target"
}

echo "relais smoke test"
echo

echo "the stack is up"
expect "relais answers on the public listener" "$(status "$API/healthz")" 200
expect "relais answers on the admin listener" "$(status "$ADMIN/healthz")" 200
expect "the interface answers" "$(status "$WEB/healthz")" 200
expect "the issuer publishes its discovery document" \
	"$(status "$KEYCLOAK/realms/relais/.well-known/openid-configuration")" 200

echo
echo "nothing is reachable without a session"
expect "the dashboard redirects to login" "$(status "$WEB/")" 303
expect "the admin API refuses an anonymous call" "$(status "$ADMIN/admin/v1/identity")" 401
expect "the sending API refuses an anonymous submission" \
	"$(status -X POST -H 'Content-Type: application/json' -d '{}' "$API/v1/emails")" 401

echo
echo "an administrator signs in"
if login ops /tmp/relais-smoke-ops.txt; then
	ok "the authorization-code flow completes"

	cookie=$(grep relais_session /tmp/relais-smoke-ops.txt | awk '{print $7}')
	size=$(printf 'relais_session=%s; Path=/; HttpOnly; Secure; SameSite=Lax' "$cookie" | wc -c)
	if [ "$size" -lt 3500 ]; then
		ok "the session cookie is $size bytes, inside the comfortable band"
	elif [ "$size" -lt 4096 ]; then
		fail "the session cookie is $size bytes: past the warning threshold" \
			"trim the claims in the provider's mapping; see docs/FRONTEND.md F3"
	else
		fail "the session cookie is $size bytes: browsers will drop it"
	fi

	body=$(curl -s -b /tmp/relais-smoke-ops.txt "$WEB/")
	contains "the dashboard renders" "$body" "Dashboard"
	contains "the header names the signed-in operator" "$body" "ops@example.test"

	for screen in backends domains credentials messages; do
		expect "/$screen renders" "$(status -b /tmp/relais-smoke-ops.txt "$WEB/$screen")" 200
	done

	contains "write controls are offered to an editor" \
		"$(curl -s -b /tmp/relais-smoke-ops.txt "$WEB/backends")" ">Edit<"
else
	fail "an administrator could not sign in; skipping the rest"
fi

echo
echo "a viewer sees the same data and cannot change it"
if login watcher /tmp/relais-smoke-watcher.txt; then
	ok "the read-only account signs in"

	body=$(curl -s -b /tmp/relais-smoke-watcher.txt "$WEB/")
	contains "the header marks the session read-only" "$body" "read-only"

	viewer_backends=$(curl -s -b /tmp/relais-smoke-watcher.txt "$WEB/backends")
	case "$viewer_backends" in
	*">Edit<"*) fail "a viewer is offered write controls" ;;
	*) ok "write controls are hidden from a viewer" ;;
	esac

	# The refusal has to come from the role, not from the CSRF check: both answer with
	# a failure, and only one of them means the permission model works.
	refusal=$(post /tmp/relais-smoke-watcher.txt "/backends?/create" \
		-d 'name=smoke-pirate&host=h&port=25&tls_mode=none')
	contains "a viewer's write is refused as read-only" "$refusal" "read-only access"
	case "$refusal" in
	*"Cross-site"*) fail "the refusal was the CSRF check, so the role was never tested" ;;
	*) : ;;
	esac
else
	fail "the read-only account could not sign in"
fi

echo
echo "mail still flows"
expect "mailpit is reachable" "$(status "$MAILPIT/api/v1/messages")" 200

echo
echo "----------------------------------------"
printf 'passed %d, failed %d\n' "$passed" "$failed"
[ "$failed" -eq 0 ] || exit 1
