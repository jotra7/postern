#!/bin/sh
# A gate script that does everything asked of it, and records what it was
# asked so a test can assert on the exact argument vector.
#
# POSTERN_TEST_LOG   appended with one line per invocation: the argv, verbatim.
# POSTERN_TEST_STATE a file whose contents `state` prints. Absent means an
#                    empty admission list (header only).
set -eu

if [ -n "${POSTERN_TEST_LOG:-}" ]; then
	printf '%s\n' "$*" >> "$POSTERN_TEST_LOG"
fi

verb="$1"
case "$verb" in
open | close | health)
	exit 0
	;;
state)
	if [ -n "${POSTERN_TEST_STATE:-}" ] && [ -f "${POSTERN_TEST_STATE}" ]; then
		cat "$POSTERN_TEST_STATE"
	else
		echo postern-state-v1
	fi
	exit 0
	;;
*)
	echo "unknown verb: $verb" >&2
	exit 64
	;;
esac
