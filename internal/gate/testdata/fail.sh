#!/bin/sh
# A gate script that fails every verb the way a broken provider call does:
# a diagnostic on stderr and a non-zero exit that is not the refusal code.
set -eu

if [ -n "${POSTERN_TEST_LOG:-}" ]; then
	printf '%s\n' "$*" >> "$POSTERN_TEST_LOG"
fi

echo "the provider API returned 503" >&2
exit 1
