# Image for scripts/e2e.sh: a container that boots real systemd.
#
# scripts/linux-test.Dockerfile cannot be reused. That image is a Go
# toolchain with no init, which is exactly why two things the design leans on
# have never been executed: `systemctl enable/disable` against real systemd —
# every revert and every disarm depends on it — and a reboot, which is the
# event both "disarm must clear persistence" and "a reverted transaction must
# not re-lock the host" are ultimately claims about. Neither can be faked
# convincingly, so this image runs /sbin/init and the end-to-end script drives
# it the way an operator would: systemctl, journalctl, nft, and real
# connections.
#
# The postern binary is built in a first stage and copied in, so what the
# sequence exercises is the shipped artifact — CGO_ENABLED=0, no toolchain
# present at runtime — rather than `go run`.
ARG GO_IMAGE=golang:1.26-bookworm
FROM ${GO_IMAGE} AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# No git-derived ldflags: .dockerignore excludes .git so the build context
# stays small, and a version string is not what this harness is testing.
RUN CGO_ENABLED=0 go build -o /out/postern ./cmd/postern

FROM debian:bookworm

# nftables and iproute2 are postern's runtime requirements and the harness's
# instruments. openssh-server is the service behind the gate: a real listener
# whose banner proves a connection reached something, rather than a port that
# merely accepted. It is also what `postern enroll --ssh` talks to in phase 0
# — the same sshd, from the operator's own namespace, over a session OpenSSH
# authenticated.
#
# sudo is here for phase 0 alone. --ssh runs init-standalone under `sudo -n`
# for every target that is not root@, and a container where the only login is
# root would leave that path asserted about only by stubs.
# faketime (libfaketime) lets the e2e sequence run one `postern open`
# invocation with its own wall clock skewed, without moving the container's
# real clock — which every other process, including posternd, keeps reading
# unchanged. That is the property the within-overlap-skew case needs: the
# operator's clock is off, the host's is not.
RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends \
        systemd systemd-sysv nftables iproute2 openssh-server openssh-client sudo \
        ca-certificates procps faketime \
    && rm -rf /var/lib/apt/lists/*

# The operator's ssh identity, and root's trust in it. Baked at build time
# rather than generated at boot so that the known_hosts entry below can be
# built from the host key that will actually be presented — phase 0 must
# authenticate for real, not with StrictHostKeyChecking turned off, because
# the host-key check is the thing --ssh's trust rests on.
RUN install -d -m 700 /root/.ssh \
    && ssh-keygen -q -t ed25519 -N '' -C postern-e2e-operator -f /root/.ssh/e2e_ed25519 \
    && cat /root/.ssh/e2e_ed25519.pub >> /root/.ssh/authorized_keys \
    && chmod 600 /root/.ssh/authorized_keys \
    && ssh-keygen -A \
    && for addr in 192.0.2.1 198.51.100.1; do \
        for pub in /etc/ssh/ssh_host_*_key.pub; do \
            printf '%s %s\n' "${addr}" "$(cut -d' ' -f1,2 "${pub}")" >> /root/.ssh/known_hosts; \
        done; \
    done \
    && chmod 600 /root/.ssh/known_hosts

# An unprivileged login for the sudo path. NOPASSWD because `sudo -n` is what
# --ssh runs, deliberately: a sudo that can prompt is a command that hangs on
# a prompt nobody sees.
RUN useradd -m -s /bin/sh ops \
    && install -d -m 700 -o ops -g ops /home/ops/.ssh \
    && cp /root/.ssh/e2e_ed25519.pub /home/ops/.ssh/authorized_keys \
    && cp /root/.ssh/known_hosts /home/ops/.ssh/known_hosts \
    && chown ops:ops /home/ops/.ssh/authorized_keys /home/ops/.ssh/known_hosts \
    && chmod 600 /home/ops/.ssh/authorized_keys /home/ops/.ssh/known_hosts \
    && echo 'ops ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/postern-e2e \
    && chmod 440 /etc/sudoers.d/postern-e2e

# Units that have nothing to manage in a --network=none container and would
# only add failed units and noise to the assertions.
RUN systemctl mask systemd-udevd.service systemd-udev-trigger.service \
        systemd-networkd.service systemd-resolved.service \
        systemd-network-generator.service ssh.socket

COPY --from=build /out/postern /usr/local/bin/postern
COPY scripts/e2e/ /opt/postern-e2e/
RUN chmod +x /opt/postern-e2e/*.sh \
    && cp /opt/postern-e2e/postern-e2e-net.service /etc/systemd/system/ \
    && systemctl enable postern-e2e-net.service ssh.service

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
