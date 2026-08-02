# Base image for scripts/linux-test.sh's test runs.
#
# nftables is baked in here, at image-build time, specifically so the actual
# test container can run with --network=none: the property that harness
# exists to guarantee is that the code under test cannot reach anything
# outside the container and can only touch the container's own netfilter
# state. `docker build` uses the daemon's normal network to fetch the
# nftables package; that happens once (and is cached by Docker afterward),
# separately from the privileged, network-isolated `docker run` that
# actually executes the tests.
#
# Go module downloads are pre-warmed here for the same reason. Any package
# that imports an external module (google/nftables, for the gate layer
# Phase B will add here) needs that module fetched before `go test` can even
# compile it, and --network=none makes that fetch impossible inside the test
# container. `go mod download` runs once at build time, against exactly the
# versions pinned in go.sum, so the run-time container finds everything
# already in the module cache. If go.mod/go.sum change, this layer's cache
# is invalidated automatically and the new set is downloaded on the next
# build — the test run itself never needs the network.
ARG GO_IMAGE=golang:1.26-bookworm
FROM ${GO_IMAGE}

# iproute2 is here for cmd/postern's demo test: a --network=none container has
# only loopback, and postern refuses to arm without an always-allow interface
# that is not the one the traffic under test arrives on. The demo makes a
# dummy interface for that, which needs ip(8).
RUN apt-get update -qq \
    && apt-get install -y -qq nftables iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
