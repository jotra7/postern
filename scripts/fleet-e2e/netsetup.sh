#!/usr/bin/env bash
# Builds the three-way network scripts/fleet-e2e.sh needs, and rebuilds it on
# every boot (see postern-fleet-e2e-net.service). Identical in shape to
# scripts/e2e/netsetup.sh and for the identical reason: loopback would let a
# knock arrive on the same path the always-allow rule trusts, proving
# nothing about the gate it is meant to open.
#
#   root ns (the gated host)   op0  192.0.2.1/24     mesh0 198.51.100.1/24
#   ns "op"  (the operator)    op1  192.0.2.9/24      — the untrusted path
#   ns "mesh" (always-allow)   mesh1 198.51.100.9/24  — the path postern never filters
#
# Created after postern-boot.service has already loaded boot.nft at boot,
# same as e2e's own harness: design section 4 requires `iifname` rather than
# `iif` precisely so a ruleset naming an interface that does not exist yet
# still loads, and this is what proves that rather than merely asserting it.
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
