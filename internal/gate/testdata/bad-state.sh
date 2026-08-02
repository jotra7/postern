#!/bin/sh
# A gate script whose `state` output cannot be parsed: no version header, and
# a line with the wrong number of fields. Every other verb succeeds, so a test
# can attribute a failure to the parser rather than to the invocation.
set -eu

if [ -n "${POSTERN_TEST_LOG:-}" ]; then
	printf '%s\n' "$*" >> "$POSTERN_TEST_LOG"
fi

if [ "$1" = state ]; then
	echo "203.0.113.5/32"
	exit 0
fi
exit 0
