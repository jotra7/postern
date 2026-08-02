#!/bin/sh
# A gate script that records the environment postern handed it, so a test can
# assert what does and does not reach an operator-supplied executable.
#
# POSTERN_TEST_ENV  appended with this invocation's environment, one
#                   NAME=VALUE per line.
set -eu

if [ -n "${POSTERN_TEST_ENV:-}" ]; then
	env >> "$POSTERN_TEST_ENV"
fi

if [ "$1" = state ]; then
	echo postern-state-v1
fi
exit 0
