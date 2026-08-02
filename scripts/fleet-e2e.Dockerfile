# Image for scripts/fleet-e2e.sh: a container that boots real systemd, the
# same discipline scripts/e2e.Dockerfile uses and for the same reason —
# `systemctl enable/disable`, a real reboot's worth of persistence, and a
# real `nft(8)` are none of them things a bare Go-toolchain container (see
# scripts/linux-test.Dockerfile) can exercise.
#
# This is a SEPARATE image from scripts/e2e.Dockerfile, not a variant of it:
# fleet-e2e.sh's own job is the bundle plane (postern sign, postern hub, the
# agent's pull and heartbeat loops) layered on top of what e2e.sh already
# proves standalone, and the two must never build over each other or share a
# container name — see scripts/fleet-e2e.sh's own IMAGE_TAG derivation.
#
# The postern binary is built in a first stage and copied in, so what the
# sequence exercises is the shipped artifact — CGO_ENABLED=0, no toolchain
# present at runtime — exactly like scripts/e2e.Dockerfile.
ARG GO_IMAGE=golang:1.26-bookworm
FROM ${GO_IMAGE} AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/postern ./cmd/postern

FROM debian:bookworm

# nftables and iproute2 are postern's runtime requirements and the harness's
# instruments, identical to e2e.Dockerfile. openssh-server is the service
# behind the ssh gate the inventory grants — a real listener a knock actually
# reaches, rather than a port nothing is behind.
#
# curl is the harness's own HTTP client for talking to the hub: a bundle
# fetch's body is opaque ciphertext, and extracting a binary-safe body plus a
# status code from bash's own /dev/tcp trick (which e2e.sh uses for a
# text-only Prometheus scrape) is not worth reinventing here.
RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends \
        systemd systemd-sysv nftables iproute2 openssh-server openssh-client \
        ca-certificates procps curl \
    && rm -rf /var/lib/apt/lists/* \
    && ssh-keygen -A

# Units that have nothing to manage in a --network=none container and would
# only add failed units and noise to the assertions — the identical set
# e2e.Dockerfile masks, for the identical reason.
RUN systemctl mask systemd-udevd.service systemd-udev-trigger.service \
        systemd-networkd.service systemd-resolved.service \
        systemd-network-generator.service ssh.socket

COPY --from=build /out/postern /usr/local/bin/postern
COPY scripts/fleet-e2e/ /opt/postern-fleet-e2e/
RUN chmod +x /opt/postern-fleet-e2e/*.sh \
    && cp /opt/postern-fleet-e2e/postern-fleet-e2e-net.service /etc/systemd/system/ \
    && systemctl enable postern-fleet-e2e-net.service ssh.service

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
