#!/bin/sh
# A gate script that never returns. It also spawns a child that outlives the
# shell, so a backend that killed only its direct child would leave this
# holding the pipe past the timeout it was supposed to enforce.
set -eu

if [ -n "${POSTERN_TEST_LOG:-}" ]; then
	printf '%s\n' "$*" >> "$POSTERN_TEST_LOG"
fi

sleep 3600 &
while :; do
	sleep 3600
done
