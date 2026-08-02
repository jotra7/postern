#!/usr/bin/env bash
# The fleet end-to-end pass: sign an inventory into sealed bundles, stand up a
# hub, let an agent pull and arm its own bundle, knock it, stop the hub and
# knock again, redeploy, restart the agent and prove it keeps the confirmed
# policy, replay a stale bundle, and check the always-allow path
# from the always-allow path, against the shipped binaries, real nftables, and
# real systemd, the same discipline scripts/e2e.sh already uses for standalone
# mode.
#
# The last phase is the one that needs this harness rather than a unit test:
# `postern status` has to reach an address `postern open` must not, and the
# only place in this repository where those are two different addresses is
# this container's op0/mesh0 pair.
#
# This is a SEPARATE container and a SEPARATE image from scripts/e2e.sh: Phase
# A adds a plane, it does not alter the standalone one, and running the two
# sequences against the same container name or the same image tag is exactly
# the collision scripts/e2e.sh's own IMAGE_TAG comment warns about — a shared
# tag being rebuilt by two runs at once produces exit 137 mid-phase that reads
# like a container crash rather than like a collision. Both names below are
# derived the identical way, from a distinct default container name, so two
# worktrees — or this script and scripts/e2e.sh — running at once never build
# over each other.
#
# Usage: scripts/fleet-e2e.sh [--keep]
#   --keep leaves the container running for inspection.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GO_IMAGE="${POSTERN_TEST_IMAGE:-golang:1.26-bookworm}"
CONTAINER="${POSTERN_FLEET_E2E_CONTAINER:-postern-fleet-e2e}"
IMAGE_TAG="${POSTERN_FLEET_E2E_IMAGE:-$(printf 'postern-fleet-e2e-%s:%s' \
    "$(printf '%s' "${CONTAINER}" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9_.-' '-')" \
    "$(printf '%s' "${GO_IMAGE}" | tr '/:' '--')")}"
KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

cleanup() {
    if [ "${KEEP}" -eq 0 ]; then
        docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
    else
        echo "container ${CONTAINER} left running (--keep)"
    fi
}
trap cleanup EXIT

docker build \
    --build-arg "GO_IMAGE=${GO_IMAGE}" \
    -t "${IMAGE_TAG}" \
    -f "${REPO_ROOT}/scripts/fleet-e2e.Dockerfile" \
    "${REPO_ROOT}"

docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
docker run -d --name "${CONTAINER}" \
    --privileged \
    --cap-add=NET_ADMIN \
    --network=none \
    --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    --tmpfs /run --tmpfs /run/lock \
    "${IMAGE_TAG}" >/dev/null

phase() {
    echo
    echo "########## phase: $1 ##########"
    docker exec "${CONTAINER}" /opt/postern-fleet-e2e/fleet-e2e.sh "$1"
}

docker exec "${CONTAINER}" timeout 60 bash -c \
    'until systemctl is-system-running --wait >/dev/null 2>&1 || \
        [ "$(systemctl is-system-running)" = degraded ]; do sleep 1; done' || true
docker exec "${CONTAINER}" systemctl --no-pager --failed || true

phase sign
phase hub
phase pull
phase knock
phase hub-down
phase redeploy
phase restart
phase replay
phase status

echo
echo "fleet end-to-end sequence complete"
