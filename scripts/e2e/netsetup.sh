#!/usr/bin/env bash
# Builds the three-way network the end-to-end sequence needs, and rebuilds it
# on every boot (see postern-e2e-net.service).
#
# Three separate namespaces, not one loopback, because loopback would make the
# whole thing prove nothing. The always-allow rule is `iifname "mesh0"
# accept`, so if the operator's packets arrived on the same interface the
# always-allow path uses, every knock would be accepted by that rule and no
# gate would ever be tested. And an operator whose address is the host's own
# address cannot demonstrate that a gate opened for one source rather than for
# everyone.
#
#   root ns (the gated host)   op0  192.0.2.1/24     mesh0 198.51.100.1/24
#   ns "op"  (the operator)    op1  192.0.2.9/24      — the untrusted path
#   ns "mesh" (always-allow)   mesh1 198.51.100.9/24  — the path postern never filters
#
# The interfaces are created AFTER postern-boot.service has already loaded
# boot.nft at boot, which is not incidental: design section 4 requires
# `iifname` rather than `iif` precisely so a ruleset naming an interface that
# does not exist yet still loads. If that were wrong, the boot unit would fail
# here on every boot.
set -euo pipefail

ns_add() {
    ip netns list | grep -qx "$1" || ip netns add "$1"
}

link_pair() {
    local host_if=$1 host_addr=$2 ns=$3 peer_if=$4 peer_addr=$5
    ip link show "${host_if}" >/dev/null 2>&1 && return 0
    ip link add "${host_if}" type veth peer name "${peer_if}"
    ip link set "${peer_if}" netns "${ns}"
    ip addr add "${host_addr}" dev "${host_if}"
    ip link set "${host_if}" up
    ip netns exec "${ns}" ip addr add "${peer_addr}" dev "${peer_if}"
    ip netns exec "${ns}" ip link set "${peer_if}" up
    ip netns exec "${ns}" ip link set lo up
}

ip link set lo up
ns_add op
ns_add mesh
link_pair op0 192.0.2.1/24 op op1 192.0.2.9/24
link_pair mesh0 198.51.100.1/24 mesh mesh1 198.51.100.9/24
