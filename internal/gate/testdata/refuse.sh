#!/bin/sh
# A gate script that understands the request and declines it. Exit code 10 is
# the contract's "refused", distinct from every accidental non-zero exit.
set -eu

if [ -n "${POSTERN_TEST_LOG:-}" ]; then
	printf '%s\n' "$*" >> "$POSTERN_TEST_LOG"
fi

echo "source is outside the ranges this security group will accept" >&2
exit 10
