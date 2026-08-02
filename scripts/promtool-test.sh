#!/usr/bin/env bash
# Evaluate dashboards/rules.yml with the real Prometheus rule evaluator.
#
# "Health is the join" is computed in PromQL, not in Go, because no single
# postern process can hold both halves of it — see dashboards/rules.yml. That
# put the one load-bearing claim in the feature outside everything the Go tests
# can reach: internal/metrics can prove that every metric the rules name is
# exported and that the dashboard reads a rule that is recorded, and it cannot
# prove the expressions mean what they say.
#
# promtool can. `test rules` feeds synthetic series through the same evaluator
# Prometheus runs and asserts what the recording rules and alerts come out as.
# It arrives in a container, the way scripts/linux-test.sh and scripts/e2e.sh
# already get their toolchain, so nothing is added to go.mod and CI runs it the
# same way a laptop does.
#
# Usage: scripts/promtool-test.sh
#   POSTERN_PROMTOOL_IMAGE overrides the image (default: a pinned prometheus).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Pinned. promtool's test-file schema has changed across major versions, and a
# floating tag would turn an upstream release into a failure in this repository
# on a day nobody touched the rules.
IMAGE="${POSTERN_PROMTOOL_IMAGE:-prom/prometheus:v3.1.0}"

promtool() {
    docker run --rm \
        --entrypoint /bin/promtool \
        -v "${REPO_ROOT}/dashboards:/dashboards:ro" \
        -w /dashboards \
        "${IMAGE}" "$@"
}

echo "== promtool check rules =="
promtool check rules rules.yml

echo
echo "== promtool test rules =="
promtool test rules rules_test.yml

echo
echo "rule evaluation complete"
