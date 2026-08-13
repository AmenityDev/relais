#!/bin/sh
# adapter-node reads ORIGIN from the environment before any application code runs,
# and uses it for the CSRF origin check on every form POST. Without it, every write
# in the interface is rejected with "Cross-site POST form submissions are forbidden"
# — while GET navigation, and therefore login, keeps working. A deployment would
# look healthy and be unable to save anything.
#
# ORIGIN is derived from RELAIS_WEB_ORIGIN rather than configured separately,
# because two variables that must agree are one variable: a mismatch would produce
# that same silent refusal, with nothing naming the cause.
set -e

if [ -z "$RELAIS_WEB_ORIGIN" ]; then
	echo "relais-web: RELAIS_WEB_ORIGIN is required (the public origin, e.g. https://mail-admin.example.com)" >&2
	exit 1
fi

export ORIGIN="$RELAIS_WEB_ORIGIN"
exec "$@"
