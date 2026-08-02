#!/usr/bin/env bash
# The end-to-end pass: enroll, arm, knock, connect, expire, kill, disarm, and
# three reboots, against a real agent, real nftables, and real systemd.
#
# This is the only test in the repository that runs the shipped binary as a
# system service. Everything else drives packages in-process, which cannot
# reach the two mechanisms an operator's recovery actually depends on:
# `systemctl enable/disable` — every revert and disarm calls it — and what
# survives a reboot.
#
# The container boots /sbin/init, so it is privileged and mounts the host
# cgroup tree. --network=none is kept for the same reason
# scripts/linux-test.sh keeps it: the sequence manipulates a firewall, and it
# must not be able to touch anything outside the container. All three
# addresses it uses live in namespaces this script's own image creates.
#
# A reboot is `docker stop` followed by `docker start`: the writable layer
# survives, the network namespace does not, and systemd starts the units that
# are enabled. That is the same set of things a reboot changes on a real
# host, which is what the three reboot phases are asserting about.
#
# The middle one — after-confirm-reboot — is the normal path, and it is the
# one that was missing. The other two reboot from a state where a stopped
# agent looks right (after a revert, after a disarm), so a host that came back
# from an ordinary reboot with the fail-closed drop rules loaded and no agent
# alive to open them passed this whole sequence.
#
# Usage: scripts/e2e.sh [--keep]
#   --keep leaves the container running for inspection.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GO_IMAGE="${POSTERN_TEST_IMAGE:-golang:1.26-bookworm}"
CONTAINER="${POSTERN_E2E_CONTAINER:-postern-e2e}"
# The tag is derived from the container name as well as the base image, so two
# worktrees running this sequence at once do not build over each other.
#
# POSTERN_E2E_CONTAINER already kept the containers apart, and that was not
# enough: `docker build -t` on a shared tag while another run is executing
# against it leaves the second run against a half-swapped image, which surfaces
# as exit 137 partway through a phase and reads exactly like a container crash
# rather than like a collision. Both names are overridable and both defaults
# now vary together.
IMAGE_TAG="${POSTERN_E2E_IMAGE:-$(printf 'postern-e2e-%s:%s' \
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
    -f "${REPO_ROOT}/scripts/e2e.Dockerfile" \
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
    docker exec "${CONTAINER}" /opt/postern-e2e/e2e.sh "$1"
}

reboot_container() {
    echo
    echo "########## reboot ##########"
    docker stop "${CONTAINER}" >/dev/null
    docker start "${CONTAINER}" >/dev/null
    # systemd needs a moment before `systemctl is-system-running --wait` will
    # even answer; the phase script waits properly once it can talk to it.
    sleep 3
}

# Wait for the container's own systemd to finish booting before the first
# phase, so an assertion never races a unit that has not started.
docker exec "${CONTAINER}" timeout 60 bash -c \
    'until systemctl is-system-running --wait >/dev/null 2>&1 || \
        [ "$(systemctl is-system-running)" = degraded ]; do sleep 1; done' || true
docker exec "${CONTAINER}" systemctl --no-pager --failed || true

phase setup
phase arm-revert
reboot_container
phase after-revert-reboot
phase arm-confirm
reboot_container
phase after-confirm-reboot
phase probe
phase knock
phase kill
phase disarm
reboot_container
phase after-disarm-reboot

# The console-recovery scenario is a different enrollment: a host with no
# mesh interface at all, arming through --console-recovery instead of
# --always-allow-iface. It runs last, after the main sequence has disarmed,
# because it writes over the same postern-boot.service and posternd.service
# unit files in /etc/systemd/system that the main sequence used: unit names
# are fixed, so systemctl only ever sees one copy of each, and by this point
# in the sequence the main sequence's copies are disabled and inert, and
# nothing after this phase reads them again. It runs in the same container,
# against the same real systemd and the same real nft(8), so the products
# tested against each other above (fail-closed drops with no accept rule at
# all) are the same products.
phase console-recovery

# The rotating-knock-port testing section's case 3: a fixed-port opt-out
# host is not collateral damage from rotation becoming the default. Runs
# last, for the same reason console-recovery does: it writes over the same
# fixed postern-boot.service/posternd.service unit files, safe only once
# console-recovery's own copies are disabled and inert.
phase fixed-port-optout

echo
echo "end-to-end sequence complete"
