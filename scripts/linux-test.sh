#!/usr/bin/env bash
# Runs Go tests inside a privileged, network-isolated Linux container so
# nftables is real. --network=none is load-bearing, not incidental: this is
# the harness Phase B's gate-layer integration tests run under, and those
# tests manipulate firewall rules — the guarantee that they cannot reach
# anything outside the container, and that the container's own netfilter
# state is all they touch, is the point of running them this way rather than
# on the host or with a live network stack.
#
# nftables itself, and every module go.sum pins (google/nftables included),
# are installed ahead of time into a small local image (see
# linux-test.Dockerfile) rather than fetched inside this --network=none
# container, because both apt-get and `go mod download` need a reachable
# mirror and --network=none is what makes the test run isolated in the first
# place. The image build below uses the Docker daemon's normal network to
# fetch everything once; Docker caches those layers, so it only actually
# hits the network on the first run or after go.mod/go.sum or the
# Dockerfile change. The build context is the repo root because the
# Dockerfile needs to COPY go.mod/go.sum in to prime the module cache.
#
# `-p 1` is not a performance knob, it is a correctness one. postern's tables
# have fixed names on every host by design (postern_boot / postern_open,
# design section 4), so every package whose tests touch real nftables --
# internal/gate and internal/agent both do -- drives the same two tables in
# the container's single netfilter namespace. Without -p 1, `go test ./...`
# runs those two package binaries concurrently and they delete each other's
# tables mid-test, producing ENOENT failures that look like backend bugs and
# are not reproducible on a single-package run. Anything the caller passes
# after this can still override it.
#
# Usage: scripts/linux-test.sh ./internal/gate/... -run TestGate -v
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GO_IMAGE="${POSTERN_TEST_IMAGE:-golang:1.26-bookworm}"
TEST_IMAGE_TAG="postern-linux-test:$(echo "${GO_IMAGE}" | tr '/:' '--')"

docker build \
  --build-arg "GO_IMAGE=${GO_IMAGE}" \
  -t "${TEST_IMAGE_TAG}" \
  -f "${REPO_ROOT}/scripts/linux-test.Dockerfile" \
  "${REPO_ROOT}"

# CGO_ENABLED=0 is postern's build constraint and stays the default here, so
# what the container compiles matches what ships. -race is the one exception:
# the race detector requires cgo, so a run asking for it gets CGO_ENABLED=1
# rather than the confusing "go: -race requires cgo" refusal. The base image
# carries gcc, so nothing extra is needed. This only affects test binaries.
CGO=0
for arg in "$@"; do
  if [ "${arg}" = "-race" ]; then
    CGO=1
    break
  fi
done

exec docker run --rm \
  --privileged \
  --cap-add=NET_ADMIN \
  --network=none \
  -v "${REPO_ROOT}:/src" \
  -w /src \
  -e "CGO_ENABLED=${CGO}" \
  "${TEST_IMAGE_TAG}" \
  go test -p 1 "$@"
