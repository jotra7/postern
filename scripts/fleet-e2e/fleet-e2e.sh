#!/usr/bin/env bash
# The fleet end-to-end sequence, run inside the systemd container by
# scripts/fleet-e2e.sh. Each phase is a separate invocation, mirroring
# scripts/e2e/e2e.sh's own discipline: postern's report of what it did is
# printed for the record and, except for exit codes, never used as proof —
# every assertion below is made against nft(8), systemctl, real TCP
# connections, and the hub's own HTTP responses.
#
# Phase 5 (hub-down) is why this script exists at all: it stops the real
# postern-hub.service and requires a knock to still open the gate, against
# the shipped binary under real systemd rather than against a test double.
set -uo pipefail

HOST_ADDR=192.0.2.1
OP_ADDR=192.0.2.9
MESH_ADDR=198.51.100.1
SSH_PORT=22
SPA_PORT=62201
METRICS_PORT=9873
HOST_NAME=fleet-host
SECOND_HOST_NAME=second-host

ETC=/etc/postern-fleet
STATE=/var/lib/postern-fleet
CLIENT=/root/.postern-fleet
HUB_STORE=/var/lib/postern-hub
HUB_ADDR=127.0.0.1:8443
HUB_METRICS_ADDR=127.0.0.1:9998
INVENTORY=/root/inventory.yaml
ENTRY=/root/fleet-entry.yaml
V47_BACKUP=/root/bundle-v47.bak

# The second host is enrolled for real — see phase_sign — so it needs its own
# config, state and unit directories. Nothing ever starts an agent from them:
# what this fleet needs from the second host is a genuine host identity in the
# same fleet, which is exactly what --fleet-id is for.
SECOND_ETC=/etc/postern-fleet-second
SECOND_STATE=/var/lib/postern-fleet-second
SECOND_UNITS=/root/second-units
SECOND_ENTRY=/root/second-entry.yaml

failures=0

START=$(date +%s)
elapsed() { printf '%3ds' "$(( $(date +%s) - START ))"; }
say() { printf '\n\033[1m== [%s] %s\033[0m\n' "$(elapsed)" "$*"; }
note() { printf '   %s\n' "$*"; }
run() { printf '\n$ %s\n' "$*"; "$@"; }

must() {
    printf '\n$ %s\n' "$*"
    local rc
    "$@"
    rc=$?
    [ "${rc}" -eq 0 ] && return 0
    fail "command exited ${rc}: $*"
    return "${rc}"
}

capture() {
    local out=$1 rc
    shift
    printf '\n$ %s > %s\n' "$*" "${out}"
    "$@" >"${out}"
    rc=$?
    [ "${rc}" -eq 0 ] && return 0
    fail "command exited ${rc}: $*"
    return "${rc}"
}

fail() {
    failures=$((failures + 1))
    printf '\n\033[31mFAIL: [%s] %s\033[0m\n' "$(elapsed)" "$*"
}

ok() { printf '\033[32mok\033[0m   [%s] %s\n' "$(elapsed)" "$*"; }

# See scripts/e2e/e2e.sh's identical trap for why this exists: an assertion
# that is a shell function call, misspelled, must be a failure rather than a
# silent no-op on stderr.
command_not_found_handle() {
    fail "the harness called \`$1\`, which does not exist: an assertion did not run"
    return 127
}

finish() {
    if [ "${failures}" -ne 0 ]; then
        printf '\n\033[31m%d assertion(s) failed in %s\033[0m\n' "${failures}" "$1"
        exit 1
    fi
    printf '\n\033[32m%s: all assertions passed\033[0m\n' "$1"
}

exec_in() {
    local ns=$1
    shift
    if [ "${ns}" = root ]; then
        "$@"
    else
        ip netns exec "${ns}" "$@"
    fi
}

probe() {
    local ns=$1 addr=$2 port=$3 out rc
    out=$(exec_in "${ns}" timeout 4 bash -c "exec 3<>/dev/tcp/${addr}/${port}" 2>&1)
    rc=$?
    if [ ${rc} -eq 0 ]; then
        echo connected
    elif [ ${rc} -eq 124 ]; then
        echo filtered
    elif [[ ${out} == *"onnection refused"* ]]; then
        echo refused
    else
        echo "unclassified(rc=${rc}) ${out}"
    fi
}

assert_probe() {
    local ns=$1 addr=$2 port=$3 want=$4 why=$5 got
    got=$(probe "${ns}" "${addr}" "${port}")
    if [ "${got}" = "${want}" ]; then
        ok "connect ${ns}:${addr}:${port} = ${got} — ${why}"
    else
        fail "connect ${ns}:${addr}:${port} = ${got}, want ${want} — ${why}"
    fi
}

assert_ssh_banner() {
    local ns=$1 line
    line=$(exec_in "${ns}" timeout 4 bash -c "exec 3<>/dev/tcp/${HOST_ADDR}/${SSH_PORT}; head -c 40 <&3" 2>&1)
    if [[ ${line} == SSH-* ]]; then
        ok "sshd answered with ${line%%$'\r'*}"
    else
        fail "no SSH banner from ${HOST_ADDR}:${SSH_PORT} (got: ${line})"
    fi
}

assert_table() {
    local table=$1 want=$2 why=$3
    if nft list table inet "${table}" >/dev/null 2>&1; then
        if [ "${want}" = present ]; then ok "table inet ${table} is present — ${why}"
        else fail "table inet ${table} is present, want absent — ${why}"; fi
    else
        if [ "${want}" = absent ]; then ok "table inet ${table} is absent — ${why}"
        else fail "table inet ${table} is absent, want present — ${why}"; fi
    fi
}

SSH_SET=gate_ssh_v4_obs

assert_gate_open_for() {
    local table=$1 set=$2 addr=$3 elems
    elems=$(nft list set inet "${table}" "${set}" 2>/dev/null | tr -d '\n')
    if [[ ${elems} == *"${addr}"* ]]; then
        ok "${set} holds ${addr} — the gate is open for the operator's address and nobody else's"
    else
        fail "${set} does not hold ${addr}: ${elems}"
    fi
}

assert_file() {
    local path=$1 want=$2 why=$3
    if [ -e "${path}" ]; then
        if [ "${want}" = present ]; then ok "${path} exists — ${why}"
        else fail "${path} exists, want it gone — ${why}"; fi
    else
        if [ "${want}" = absent ]; then ok "${path} is gone — ${why}"
        else fail "${path} is missing — ${why}"; fi
    fi
}

assert_says() {
    local haystack=$1 needle=$2 why=$3
    if [[ ${haystack} == *"${needle}"* ]]; then
        ok "the output says '${needle}' — ${why}"
    else
        fail "the output does not say '${needle}' — ${why}"
    fi
}

poll() { # poll <seconds> <description> <command...>
    local deadline=$(( $(date +%s) + $1 )) desc=$2
    shift 2
    while [ "$(date +%s)" -lt "${deadline}" ]; do
        if "$@" >/dev/null 2>&1; then
            ok "${desc}"
            return 0
        fi
        sleep 1
    done
    fail "timed out after waiting for: ${desc}"
    return 1
}

pending_field() { # pending_field <json key>
    sed -n "s/.*\"$1\": *\"\{0,1\}\([^\",]*\)\"\{0,1\},\{0,1\}/\1/p" "${STATE}/pending.json" | head -1
}

state_field() { # state_field <json key>
    sed -n "s/.*\"$1\": *\"\{0,1\}\([^\",]*\)\"\{0,1\},\{0,1\}/\1/p" "${STATE}/state.json" | head -1
}

client() { exec_in op postern "$@" --config "${CLIENT}/config.yaml"; }

# confirm_until_recorded waits for a confirm to be RECORDED, and resends if it
# was not. `postern confirm` now puts several copies of the datagram on the
# wire itself (client.DefaultActionSends), so each attempt here is already a
# small burst rather than a single packet — this loop is what turns "the
# datagrams left" into "the agent wrote state.json", which nothing on the SPA
# path can report back.
#
# The budget stays generous rather than the couple of retries e2e.sh's own
# knock loop needs: this container's synthetic op0/mesh0 veth pair, measured
# directly against the real posternd process while writing this script, drops
# the first several UDP datagrams sent over it fairly routinely — sometimes a
# handful, observed as high as nine in a row — in the minute or so after the
# interfaces come up, independent of anything this repository's own code does
# with the packet. --confirm-window is set well above what this budget can
# consume for exactly this reason.
#
# It checks for THIS revision specifically, by content, not merely that
# state.json exists: phase 6 confirms a second time in the same run, and
# state.json already exists from phase 3's confirm of revision 47 by then —
# existence alone would report success before the new confirm ever arrived.
CONFIRM_ATTEMPTS=8

confirm_until_recorded() { # confirm_until_recorded <revision> <nonce>
    local revision=$1 nonce=$2 attempt waited want
    want="\"revision\": ${revision}"
    for attempt in $(seq 1 "${CONFIRM_ATTEMPTS}"); do
        # --force: the operator confirms from op0, which reaches the public
        # knock path but not the always-allow mesh the arm-time liveness
        # pre-check probes (design section 7, I5). A recovery-capable operator
        # would let the check run; here op0 cannot reach the mesh, so the
        # confirm acknowledges it. The dead-man timer remains the safety net.
        client confirm "${HOST_NAME}" --revision "${revision}" --nonce "${nonce}" --force
        waited=0
        while [ "${waited}" -lt 4 ]; do
            grep -qF "${want}" "${STATE}/state.json" 2>/dev/null && return 0
            sleep 1
            waited=$((waited + 1))
        done
        note "confirm not yet recorded after attempt ${attempt}/${CONFIRM_ATTEMPTS}; resending"
    done
    return 1
}

# scrape fetches the agent's exposition text over the always-allow interface,
# the same trick scripts/e2e/e2e.sh uses for the identical reason: nothing
# extra has to be installed in the image for a plain HTTP/1.0 GET whose
# response a shell can read to EOF.
scrape() {
    exec_in mesh timeout 5 bash -c \
        "exec 3<>/dev/tcp/${MESH_ADDR}/${METRICS_PORT}; \
         printf 'GET /metrics HTTP/1.0\r\nHost: postern\r\n\r\n' >&3; cat <&3" 2>&1
}
# Exported so `poll`'s own `bash -c '...'` subshells — a genuinely separate
# bash process, which does not inherit ordinary shell functions — can still
# call scrape (and the exec_in it depends on) rather than failing with
# "scrape: command not found" the instant a poll predicate needs a scrape.
export -f exec_in scrape

assert_metric_at_least() {
    local series=$1 floor=$2 why=$3 body value
    body=$(scrape)
    value=$(printf '%s\n' "${body}" | awk -v s="${series}" '$1 == s { print $2 }' | head -1)
    if [ -z "${value}" ]; then
        fail "/metrics has no sample named ${series} — ${why}"
        printf '%s\n' "${body}" | grep -E '^postern_' || printf '%s\n' "${body}"
    elif [ "${value%%.*}" -ge "${floor}" ] 2>/dev/null; then
        ok "/metrics reports ${series} = ${value} (>= ${floor}) — ${why}"
    else
        fail "/metrics reports ${series} = ${value}, want >= ${floor} — ${why}"
    fi
}

# not_newer_rejections counts the journal lines phase 7 cares about, rather
# than scraping the metric of the same name: not_newer rejections happen
# routinely well before phase 7 even runs (every pull after a bundle is
# already applied re-fetches the same, no-longer-newer, bundle), so what
# matters is the COUNT increasing by the replay's own doing, not merely that
# the reason has ever appeared. journalctl needs no second network namespace
# and no nested ip-netns-exec chain, unlike the scrape() this used to call —
# see phase_hub_down's identical reasoning for switching away from it.
not_newer_rejections() {
    journalctl -u posternd.service --no-pager | grep -c 'bundle pull rejected.*reason=not_newer'
}
export -f not_newer_rejections

# b64_to_hex converts a base64 public key (as identity.PublicIdentity prints
# it, and as `postern enroll`'s printed --operator flag carries it) into the
# hex encoding config.Policy.BundleSigners and internal/config/inventory.go
# both expect for a raw Ed25519 public key. `od`, not `xxd`, because od is
# coreutils and xxd is not installed in this image.
b64_to_hex() {
    base64 -d <<<"$1" | od -An -tx1 | tr -d ' \n'
}

# --- phase 1: sign -----------------------------------------------------

phase_sign() {
    say "phase 1 — an inventory in git compiles to sealed per-host bundles"

    run systemctl is-system-running --wait || true

    say "mint the one operator identity the fleet trusts, the same two-step dance e2e.sh's own phase 1 uses"
    mkdir -p "${CLIENT}"
    capture /root/enroll.txt postern enroll "${HOST_NAME}" --config "${CLIENT}/config.yaml" \
        --operator laptop --no-passphrase
    cat /root/enroll.txt
    local opflag
    opflag=$(sed -n "s/.*--operator '\(.*\)'.*/\1/p" /root/enroll.txt)
    if [ -z "${opflag}" ]; then
        fail "could not read the operator key pair out of the enrollment instructions"
        finish "phase 1" # exits 1: a fatal precondition for the rest of this phase
    fi
    # Parsed with parameter expansion, not `IFS='=,' read`: standard base64
    # padding is '=', which the signing key very often ends in (a 32-byte key
    # encodes to 44 base64 characters with one trailing '=' pad), and IFS-based
    # splitting on '=' would cut that padding off as though it were another
    # field separator. %%=* / #*= only ever look at the FIRST '=', which is the
    # one separating the operator name from its keys; %%,*/ #*, only ever look
    # at the one literal comma the NAME=SIGN,ENC format contains, which base64
    # itself can never produce.
    local opname opsign openc rest
    opname=${opflag%%=*}
    rest=${opflag#*=}
    opsign=${rest%%,*}
    openc=${rest#*,}
    note "operator ${opname}: signing=${opsign} encryption=${openc}"

    # The signer key the fleet trusts, in the hex encoding --bundle-signers
    # and the config's own bundle_signers list both take. Computed BEFORE
    # init-standalone runs, because the whole point of this phase is that
    # every fleet-mode key reaches postern.yaml through a documented flag.
    local signhex
    signhex=$(b64_to_hex "${opsign}")

    say "host: init-standalone in fleet mode, staging a local bootstrap config nothing has armed yet"
    local exec_start="/usr/local/bin/postern agent --config ${ETC}/postern.yaml --state-dir ${STATE}"
    exec_start+=" --confirm-window 180s --debug --metrics-listen :${METRICS_PORT}"
    exec_start+=" --pull-interval 3s --beat-interval 3s"
    capture "${ENTRY}" postern init-standalone \
        --dir "${ETC}" --state-dir "${STATE}" --unit-dir /etc/systemd/system \
        --host-name "${HOST_NAME}" --knock-addr "${HOST_ADDR}" \
        --always-allow-iface mesh0 --recovery-service ssh --revision 1 \
        --exec-start "${exec_start}" \
        --operator "${opflag}" \
        --hub-url "http://${HUB_ADDR}" --bundle-signers "${signhex}" --enrollment-floor 0
    cat "${ENTRY}"
    run systemctl daemon-reload

    # Nothing is appended to postern.yaml anywhere in this script. An earlier
    # version wrote hub_url, bundle_signers and enrollment_floor here with a
    # heredoc, because no command emitted them — which meant the entire bundle
    # plane passed its own end-to-end test while being unreachable by an
    # operator following the documentation. The assertion below is what keeps
    # that gap closed: if the flags stop working, this phase fails rather than
    # the harness quietly writing the file postern would not.
    for key in hub_url bundle_signers enrollment_floor; do
        if grep -q "^${key}:" "${ETC}/postern.yaml"; then
            ok "init-standalone wrote ${key} itself"
        else
            fail "${ETC}/postern.yaml has no ${key}: init-standalone did not produce a fleet-mode config"
        fi
    done

    say "operator: register the host with the identity minted above"
    must postern enroll "${HOST_NAME}" --config "${CLIENT}/config.yaml" --from "${ENTRY}"
    assert_file "${CLIENT}/config.yaml" present "the operator can knock this host from here"

    local fleet_id host_id
    fleet_id=$(sed -n 's/^fleet_id: *"\{0,1\}\([0-9a-f]*\)"\{0,1\}$/\1/p' "${ETC}/postern.yaml" | head -1)
    host_id=$(sed -n 's/^host_id: *"\{0,1\}\([0-9a-f]*\)"\{0,1\}$/\1/p' "${ETC}/postern.yaml" | head -1)
    note "fleet_id=${fleet_id} host_id=${host_id}"
    if [ -z "${fleet_id}" ] || [ -z "${host_id}" ]; then
        fail "could not read fleet_id/host_id back out of ${ETC}/postern.yaml"
        finish "phase 1" # exits 1: a fatal precondition for the rest of this phase
    fi

    # The bundle's host_identity has to be THIS HOST's own public encryption
    # and signing keys — box.SealAnonymous seals to the recipient's real key,
    # not to whichever key happens to be lying around — so these come from
    # entry.yaml (host_encryption/host_signing, printed by init-standalone
    # from the host.key it just minted), never from the operator's opsign/
    # openc. Reusing the operator's keys here was tried first and produced
    # exactly the failure this comment now warns against: postern sign wrote
    # bundles happily, and the agent's own pull rejected every one of them
    # with "cannot unseal for this host", because they had never been sealed
    # to its key at all.
    local host_signing host_encryption
    host_signing=$(sed -n 's/^host_signing: *\(.*\)$/\1/p' "${ENTRY}" | head -1)
    host_encryption=$(sed -n 's/^host_encryption: *\(.*\)$/\1/p' "${ENTRY}" | head -1)
    note "host_signing=${host_signing} host_encryption=${host_encryption}"
    if [ -z "${host_signing}" ] || [ -z "${host_encryption}" ]; then
        fail "could not read host_signing/host_encryption back out of ${ENTRY}"
        finish "phase 1" # exits 1: a fatal precondition for the rest of this phase
    fi

    cat "${ETC}/postern.yaml"

    # The second host is enrolled for real, with --fleet-id naming the fleet
    # the first host minted. That flag is the whole reason this is a fleet at
    # all: init-standalone mints a fresh fleet_id per host, and bundle.Open
    # checks fleet_id, so without it two hosts enrolled the documented way can
    # never be served by one hub. Enrolling it properly also gives the
    # inventory this host's OWN identity keys, rather than reusing the first
    # host's under a second host_id.
    say "second host: init-standalone --fleet-id, joining the fleet the first host minted"
    capture "${SECOND_ENTRY}" postern init-standalone \
        --dir "${SECOND_ETC}" --state-dir "${SECOND_STATE}" --unit-dir "${SECOND_UNITS}" \
        --host-name "${SECOND_HOST_NAME}" --knock-addr 203.0.113.5 \
        --always-allow-iface mesh0 --recovery-service ssh --revision 1 \
        --exec-start "/usr/local/bin/postern agent --config ${SECOND_ETC}/postern.yaml" \
        --operator "${opflag}" \
        --fleet-id "${fleet_id}" \
        --hub-url "http://${HUB_ADDR}" --bundle-signers "${signhex}" --enrollment-floor 0
    cat "${SECOND_ENTRY}"

    local second_fleet_id second_host_id second_signing second_encryption
    second_fleet_id=$(sed -n 's/^fleet_id: *"\{0,1\}\([0-9a-f]*\)"\{0,1\}$/\1/p' "${SECOND_ETC}/postern.yaml" | head -1)
    second_host_id=$(sed -n 's/^host_id: *\(.*\)$/\1/p' "${SECOND_ENTRY}" | head -1)
    second_signing=$(sed -n 's/^host_signing: *\(.*\)$/\1/p' "${SECOND_ENTRY}" | head -1)
    second_encryption=$(sed -n 's/^host_encryption: *\(.*\)$/\1/p' "${SECOND_ENTRY}" | head -1)
    if [ "${second_fleet_id}" = "${fleet_id}" ]; then
        ok "both hosts carry fleet_id ${fleet_id} — one fleet, produced entirely by documented flags"
    else
        fail "second host's fleet_id is ${second_fleet_id}, want ${fleet_id}: the two hosts are in " \
             "different fleets and no hub can serve both"
    fi
    if [ "${second_host_id}" = "${host_id}" ]; then
        fail "both hosts got host_id ${host_id}: --fleet-id must join a fleet, not clone a host"
    else
        ok "the second host minted its own host_id ${second_host_id}"
    fi

    say "the fleet inventory: two hosts, one signer, one operator"
    cat >"${INVENTORY}" <<EOF
fleet_id: "${fleet_id}"
version: 47
bundle_signers: ["${opname}"]

operators:
  - name: "${opname}"
    alg: "ed25519+x25519"
    signing:    "${opsign}"
    encryption: "${openc}"
    grants:
      - hosts: ["*"]
        services: [ssh, confirm, disarm, liveness]
        max_ttl: 300s

services:
  ssh:      { kind: gate, proto: tcp, ports: [${SSH_PORT}], default_ttl: 120s, max_ttl: 300s,
              listener_expectation: present }
  confirm:  { kind: action }
  disarm:   { kind: action }
  liveness: { kind: action }

defaults:
  spa_port: ${SPA_PORT}
  always_allow_iface: "mesh0"
  recovery_service: "ssh"

hosts:
  - name: "${HOST_NAME}"
    host_id: "${host_id}"
    knock_addr: "${HOST_ADDR}"
    host_identity: { alg: "ed25519+x25519", signing: "${host_signing}", encryption: "${host_encryption}" }
    services: [ssh, confirm, disarm, liveness]
  - name: "${SECOND_HOST_NAME}"
    host_id: "${second_host_id}"
    knock_addr: "203.0.113.5"
    host_identity: { alg: "ed25519+x25519", signing: "${second_signing}", encryption: "${second_encryption}" }
    services: [ssh, confirm, disarm, liveness]
EOF
    cat "${INVENTORY}"

    say "postern sign: compile the inventory into sealed bundles"
    must postern sign --inventory "${INVENTORY}" --out "${HUB_STORE}" \
        --key-file "${CLIENT}/identity.json" --as "${opname}"

    for hid in "${host_id}" "${second_host_id}"; do
        assert_file "${HUB_STORE}/${hid}.bundle" present "postern sign wrote a bundle for ${hid}"
    done
    assert_file "${HUB_STORE}/index.json" present "postern sign wrote the signing-key index the hub needs"

    say "the bundles are opaque: no policy text, no key material, readable in the output directory"
    local leaked=0
    for hid in "${host_id}" "${second_host_id}"; do
        if grep -aq -e 'ssh' -e 'operators' -e "${opsign}" "${HUB_STORE}/${hid}.bundle"; then
            fail "bundle for ${hid} contains readable policy text or key material"
            leaked=1
        fi
    done
    [ "${leaked}" -eq 0 ] && ok "neither bundle contains readable policy text"

    # Nothing here survives past this process: every later phase is a
    # separate `docker exec`, so host_id/second_host_id/opname are re-derived
    # from what this phase wrote to disk (load_host_id, and the operator name
    # is a fixed constant — see phase_redeploy) rather than from shell state.
    finish "phase 1"
}

# OPERATOR_NAME is fixed across the whole sequence: phase_sign always mints
# and signs with the identity named "laptop", so later phases that need to
# name it again (postern sign --as) use this rather than passing it through
# shell state that a separate process invocation would not see.
OPERATOR_NAME=laptop

# --- phase 2: hub --------------------------------------------------------

phase_hub() {
    say "phase 2 — a hub serves the sealed bundles, and nothing else"

    cat >/etc/systemd/system/postern-hub.service <<EOF
[Unit]
Description=postern fleet hub
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/postern hub --store ${HUB_STORE} --addr ${HUB_ADDR} --metrics-addr ${HUB_METRICS_ADDR}
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
    run systemctl daemon-reload
    must systemctl enable --now postern-hub.service
    poll 15 "postern-hub is active" systemctl is-active --quiet postern-hub.service
    run journalctl -u postern-hub.service --no-pager -n 20

    local host_id
    host_id=$(load_host_id)
    say "GET /bundle/<host_id> returns the exact opaque ciphertext postern sign wrote"
    local got
    got=$(curl -s -o /root/fetched.bundle -w '%{http_code}' "http://${HUB_ADDR}/bundle/${host_id}")
    if [ "${got}" != "200" ]; then
        fail "GET /bundle/${host_id} = ${got}, want 200"
    elif cmp -s "/root/fetched.bundle" "${HUB_STORE}/${host_id}.bundle"; then
        ok "the hub served exactly the bundle postern sign wrote"
    else
        fail "the hub's response differs from the bundle on disk"
    fi

    say "the public listener has no /metrics route at all — design section 6"
    got=$(curl -s -o /dev/null -w '%{http_code}' "http://${HUB_ADDR}/metrics")
    if [ "${got}" = "404" ]; then
        ok "GET /metrics on the public listener = 404"
    else
        fail "GET /metrics on the public listener = ${got}, want 404"
    fi

    say "the SEPARATE metrics listener is the only place fleet-wide state is published"
    got=$(curl -s -o /dev/null -w '%{http_code}' "http://${HUB_METRICS_ADDR}/metrics")
    if [ "${got}" = "200" ]; then
        ok "GET /metrics on ${HUB_METRICS_ADDR} = 200"
    else
        fail "GET /metrics on ${HUB_METRICS_ADDR} = ${got}, want 200"
    fi
    finish "phase 2"
}

# host_id/second_host_id/operator name do not survive a re-invocation of this
# script (each phase is a separate process, per fleet-e2e.sh's own docker exec),
# so every phase after "sign" re-derives them from what "sign" already wrote to
# disk rather than from shell variables that do not exist any more.
load_host_id() {
    sed -n 's/^host_id: *"\{0,1\}\([0-9a-f]*\)"\{0,1\}$/\1/p' "${ETC}/postern.yaml" | head -1
}

# --- phase 3: pull ---------------------------------------------------------

phase_pull() {
    say "phase 3 — the agent pulls its own bundle, verifies it, and arms"

    must systemctl start posternd.service
    poll 30 "posternd is active" systemctl is-active --quiet posternd.service
    run journalctl -u posternd.service --no-pager -n 40

    # The agent arms TWICE in short order here, and both are correct: once at
    # startup for its own local bootstrap config (revision 1, before the pull
    # loop has ever run), and again — superseding the first, not racing it;
    # BeginTransaction replaces d.pending outright, so the first transaction's
    # dead-man deadline is simply never consulted again — once the pull loop
    # fetches and arms the bundle (revision 47). Polling for revision 47
    # specifically, rather than merely "pending.json exists", is what makes
    # this deterministic rather than an assertion that can catch the
    # transient revision-1 state and report it as a failure.
    poll 30 "the agent published bundle revision 47 as pending" \
        bash -c "test -f ${STATE}/pending.json && grep -q '\"revision\": 47' ${STATE}/pending.json"
    cat "${STATE}/pending.json"
    local rev nonce
    rev=$(pending_field revision)
    nonce=$(pending_field deployment_nonce)
    note "revision=${rev} nonce=${nonce}"
    [ "${rev}" = "47" ] && ok "the agent armed the bundle's version (47), not its own local bootstrap revision (1)"
    # Polled, not a single assert_table: design section 5's ordering publishes
    # pending.json (already checked above) BEFORE Arm loads the ruleset into
    # the kernel, so there is a genuine, if brief, window where the first is
    # already true and the second is not yet.
    poll 10 "the pulled bundle's ruleset is loaded" bash -c "nft list table inet postern_boot >/dev/null 2>&1"

    say "confirm, so the dead-man timer has nothing left to revert while the rest of this sequence runs"
    if confirm_until_recorded "${rev}" "${nonce}"; then
        ok "the confirm was recorded"
    else
        fail "the confirm was never recorded after ${CONFIRM_ATTEMPTS} attempts"
    fi
    cat "${STATE}/state.json"
    assert_file "${STATE}/pending.json" absent "a confirmed configuration is no longer waiting for anything"

    assert_metric_at_least 'postern_bundle_pull_applied_total' 1 "the pull that armed revision 47 is counted"
    finish "phase 3"
}

# --- phase 4: knock ---------------------------------------------------------

phase_knock() {
    say "phase 4 — a real SPA knock opens the gate the pulled bundle armed"

    assert_probe op "${HOST_ADDR}" "${SSH_PORT}" filtered "before the knock, the fleet-armed ssh gate drops"
    # Short TTL, deliberately: phase 5's own knock is only meaningful proof of
    # the split-plane invariant if the gate this knock opens has already
    # closed again by the time phase 5 tests it — otherwise a residual open
    # gate from THIS knock masks phase 5's own knock silently failing. A
    # mutation that broke SPA validation while the hub was down was caught
    # here (task 11, step 6) precisely because this TTL was too long the
    # first time this script was written and phase 5 passed vacuously.
    run client open "${HOST_NAME}" ssh --ttl 20s
    local rc=$?
    [ ${rc} -eq 0 ] || fail "postern open exited ${rc}, want 0"
    assert_gate_open_for postern_open "${SSH_SET}" "${OP_ADDR}"
    assert_ssh_banner op
    finish "phase 4"
}

# --- phase 5: hub-down -------------------------------------------------

phase_hub_down() {
    say "phase 5 — the split-plane invariant: stop the hub, and a knock still opens the gate"

    say "wait for phase 4's own knock to close, so this phase's knock is the one actually under test"
    poll 60 "the ssh gate emptied on its own again" \
        bash -c "! nft list set inet postern_open ${SSH_SET} 2>/dev/null | grep -q elements"

    must systemctl stop postern-hub.service
    poll 15 "postern-hub is inactive" bash -c '! systemctl is-active --quiet postern-hub.service'

    say "with the hub stopped, the next pull and the next heartbeat both fail — and change nothing about SPA"
    # Read from the journal rather than scraping /metrics from the mesh
    # namespace: the same fact (a fetch_failed / send_failed rejection has
    # happened) is right there in the log postern already writes, with none
    # of scrape's own dependency on a second network namespace and a nested
    # ip-netns-exec chain — a chain that, measured directly while writing
    # this script, occasionally never returns a match across a 90-second poll
    # window even while the metric it was scraping for was already sitting
    # in a plain, one-shot scrape run moments later. journalctl has no such
    # dependency and no such flakiness.
    poll 90 "a bundle pull has been rejected while the hub is down" \
        bash -c "journalctl -u posternd.service --no-pager | grep -q 'bundle pull rejected.*reason=fetch_failed'"
    poll 90 "a heartbeat has been rejected while the hub is down" \
        bash -c "journalctl -u posternd.service --no-pager | grep -q 'heartbeat rejected.*reason=send_failed'"

    say "the product, with no hub anywhere: a knock still opens ssh"
    run client open "${HOST_NAME}" ssh --ttl 60s
    local rc=$?
    [ ${rc} -eq 0 ] || fail "postern open exited ${rc} with the hub down, want 0"
    assert_gate_open_for postern_open "${SSH_SET}" "${OP_ADDR}"
    assert_ssh_banner op
    assert_table postern_boot present "the fail-closed posture the bundle armed is untouched by the hub's absence"
    finish "phase 5"
}

# --- phase 6: redeploy ------------------------------------------------------

phase_redeploy() {
    say "phase 6 — bump the inventory, re-sign, restart the hub, and the agent picks it up through confirm-or-revert"

    local host_id
    host_id=$(load_host_id)
    cp "${HUB_STORE}/${host_id}.bundle" "${V47_BACKUP}"
    note "kept a copy of the version-47 bundle for phase 7"

    must sed -i 's/^version: 47$/version: 48/' "${INVENTORY}"
    run grep '^version:' "${INVENTORY}"
    must postern sign --inventory "${INVENTORY}" --out "${HUB_STORE}" \
        --key-file "${CLIENT}/identity.json" --as "${OPERATOR_NAME}"

    # `restart` on a unit phase 5 left stopped is exactly `start` — systemd
    # does not require a unit to already be running — so this is the one
    # command that brings the hub back AND is the literal restart the phase
    # description asks for.
    must systemctl restart postern-hub.service
    poll 15 "postern-hub is active again" systemctl is-active --quiet postern-hub.service

    poll 30 "the agent published revision 48 as pending" \
        bash -c "test -f ${STATE}/pending.json && grep -q '\"revision\": 48' ${STATE}/pending.json"
    cat "${STATE}/pending.json"
    local rev nonce
    rev=$(pending_field revision)
    nonce=$(pending_field deployment_nonce)
    [ "${rev}" = "48" ] || fail "published revision = ${rev}, want 48"

    if confirm_until_recorded "${rev}" "${nonce}"; then
        ok "revision 48 was confirmed"
    else
        fail "revision 48 was never confirmed after ${CONFIRM_ATTEMPTS} attempts"
    fi
    cat "${STATE}/state.json"

    # #47: a fleet host regenerates posternd.service's per-set flush drop-in as
    # bundles change the catalogue, then reloads systemd, so the teardown flush
    # lines track the live ruleset rather than a frozen enrollment enumeration.
    # Three things prove it end to end on a real host.
    #
    # 1. The fleet ExecStart hands the agent its drop-in path — appended even to
    #    this phase's operator-supplied --exec-start, because without it the
    #    daemon never regenerates and the frozen enumeration is exactly the bug.
    run bash -c "systemctl cat posternd.service | grep -- '--flush-dropin' || true"
    if systemctl cat posternd.service | grep -q -- "--flush-dropin /etc/systemd/system/posternd.service.d/flush.conf"; then
        ok "the fleet ExecStart points the agent at its flush drop-in"
    else
        fail "the fleet posternd.service ExecStart carries no --flush-dropin, so the daemon would never regenerate the teardown flush lines"
    fi
    # 2. The main unit's revision-independent half is intact: it still deletes
    #    postern_open on any exit.
    effective_teardown=$(systemctl show posternd.service --property=ExecStopPost)
    if grep -q "delete table inet postern_open" <<<"${effective_teardown}"; then
        ok "the main unit still deletes postern_open on teardown"
    else
        fail "the fleet host's effective ExecStopPost lost the postern_open delete:
${effective_teardown}"
    fi
    # 3. The regenerated drop-in flushes EXACTLY the fail-closed gate sets that
    #    are live in postern_boot at revision 48 — the invariant-6 property #47
    #    restores. The daemon reloaded systemd after applying, so the effective
    #    ExecStopPost reflects the new catalogue. Revision 48's inventory has
    #    ssh fail-open, so it has no fail-closed gate sets; the enrollment
    #    bootstrap had a fail-closed canary, so a frozen drop-in would still name
    #    gate_canary_* here and this comparison would fail. That mismatch is the
    #    regression, caught on real systemd.
    flush_named=$(systemctl show posternd.service --property=ExecStopPost \
        | tr ';' '\n' | sed -n 's/.*flush set inet postern_boot \([a-z0-9_]*\).*/\1/p' | sort -u)
    live_gate_sets=$(nft list table inet postern_boot 2>/dev/null \
        | sed -n 's/^[[:space:]]*set \(gate_[a-z0-9_]*\) {.*/\1/p' | sort -u)
    run bash -c "printf 'flush-named: [%s]\nlive gate sets: [%s]\n' \"\$(systemctl show posternd.service --property=ExecStopPost | tr ';' '\n' | sed -n 's/.*flush set inet postern_boot \([a-z0-9_]*\).*/\1/p' | sort -u | tr '\n' ' ')\" \"\$(nft list table inet postern_boot 2>/dev/null | sed -n 's/^[[:space:]]*set \(gate_[a-z0-9_]*\) {.*/\1/p' | sort -u | tr '\n' ' ')\""
    if [ "${flush_named}" = "${live_gate_sets}" ]; then
        ok "the regenerated drop-in flushes exactly the fail-closed gate sets live in postern_boot at revision 48"
    else
        fail "the drop-in's flush sets do not match the live catalogue; a frozen enrollment enumeration would name sets revision 48 does not have:
flush-named:
${flush_named}
live gate sets:
${live_gate_sets}"
    fi

    say "the change went through confirm-or-revert, not a silent in-place swap"
    assert_table postern_boot present "revision 48 is armed"
    # Deliberately not asserting the gate is closed here first: phase 5's own
    # knock (--ttl 60s) may still have time left on its lease depending on how
    # long this phase's confirm retries took, and a gate still open from a
    # PRIOR phase's knock is not evidence about anything the redeploy did.
    # What matters is proven below instead — a fresh knock against the
    # redeployed policy still opens the gate.
    run client open "${HOST_NAME}" ssh --ttl 60s
    assert_gate_open_for postern_open "${SSH_SET}" "${OP_ADDR}"
    finish "phase 6"
}

# --- phase 6.5: restart -----------------------------------------------------

phase_restart() {
    say "phase 6.5 — a posternd restart keeps the confirmed fetched policy, not the enrollment bootstrap (#52)"

    # Phase 6's confirm of revision 48 persisted the running policy beside
    # bundle.json. This file is what a restart loads instead of postern.yaml.
    assert_file "${STATE}/policy.yaml" present "the confirmed policy was persisted for a restart to load"
    # The standalone policy names its revision `revision:`; `version:` is the
    # inventory's field, not the compiled policy's.
    poll 5 "the persisted policy names the confirmed revision 48" \
        bash -c "grep -q '^revision: 48$' ${STATE}/policy.yaml"

    # Restart the agent process, the event #52 is about. Before the fix this
    # reloaded /etc/postern/postern.yaml — revision 1, the enrollment bootstrap —
    # and re-armed it, reverting the host to a configuration a bundle had since
    # replaced, with the hub unable to correct it because its version-48 bundle
    # is refused as not-newer. postern-boot.service holds boot.nft loaded across
    # the restart, so the host stays fail-closed the whole way through.
    must systemctl restart posternd.service
    poll 30 "posternd is active again after the restart" systemctl is-active --quiet posternd.service
    run journalctl -u posternd.service --no-pager -n 20

    # Running the confirmed policy (revision 48), the daemon's effective revision
    # already equals the recorded one, so it arms nothing. Reverting to the
    # bootstrap (revision 1) instead would differ from the recorded 48 and
    # publish a pending.json to re-arm it — the symptom this asserts is absent.
    sleep 2
    assert_file "${STATE}/pending.json" absent "the restart armed nothing; it did not revert to the enrollment revision"
    cat "${STATE}/state.json"
    local recorded
    recorded=$(state_field revision)
    [ "${recorded}" = "48" ] || fail "recorded revision after restart = ${recorded}, want 48"
    assert_table postern_boot present "the host is still armed after the restart"

    # And still functional on the fetched policy: a fresh knock opens the gate.
    run client open "${HOST_NAME}" ssh --ttl 30s
    assert_gate_open_for postern_open "${SSH_SET}" "${OP_ADDR}"
    ok "the host restarted on its confirmed revision-48 policy and still serves knocks"
    finish "phase 6.5"
}

# --- phase 7: replay ---------------------------------------------------------

phase_replay() {
    say "phase 7 — a captured version-47 bundle is rejected, and the host stays on 48"

    local host_id
    host_id=$(load_host_id)
    if [ ! -f "${V47_BACKUP}" ]; then
        fail "no version-47 bundle backup from phase 6; cannot test replay"
        finish "phase 7" # exits 1: a fatal precondition for the rest of this phase
    fi

    local before_count
    before_count=$(not_newer_rejections)
    [ -z "${before_count}" ] && before_count=0
    note "not_newer rejections before the replay: ${before_count}"

    must cp "${V47_BACKUP}" "${HUB_STORE}/${host_id}.bundle"
    note "the hub is now serving the OLD, validly-signed version-47 ciphertext again"

    # The window is sized against the LOG THROTTLE, not against the pull
    # interval. Rejections happen every --pull-interval (3s here) and the
    # counter moves on every one of them, but the journal line an operator —
    # and this assertion — reads is throttled to a multiple of that interval
    # (agent.rejectLogWindowFactor, 20, so 60s here). A poll shorter than one
    # window is a coin flip on where in the rhythm this phase happens to
    # start — it timed out at 31s with one line on record and the next one due
    # — so this one spans two windows.
    NOT_NEWER_WANT=$((before_count + 1))
    export NOT_NEWER_WANT
    poll 150 "the replayed version-47 bundle was rejected as not_newer" \
        bash -c 'got=$(not_newer_rejections); [ -n "${got}" ] && [ "${got%%.*}" -ge "${NOT_NEWER_WANT}" ]'

    cat "${STATE}/state.json"
    local recorded
    recorded=$(state_field revision)
    if [ "${recorded}" = "48" ]; then
        ok "the recorded revision is still 48 — the replayed bundle changed nothing"
    else
        fail "the recorded revision is ${recorded}, want 48 — a replayed bundle must never be applied"
    fi
    assert_table postern_boot present "the host is still armed at 48, not reverted by a rejected replay"
    finish "phase 7"
}

# --- phase 8: status ----------------------------------------------------------

# STATUS_ATTEMPTS budgets the same veth packet loss confirm_until_recorded
# documents at length: `postern status` puts ONE ping on the wire per run and
# waits, so a single dropped datagram is a red report about a healthy host.
# Fewer attempts than the confirm loop needs, because by this phase the
# interfaces have been up for the whole sequence.
STATUS_ATTEMPTS=4

# This is the only phase in either end-to-end sequence where the two addresses
# a host is reached at are genuinely different addresses, and it is the axis a
# green unit suite and a green standalone e2e both passed over: `open` knocks
# op0's 192.0.2.1 from the operator's namespace, while the agent answers a
# liveness ping only on mesh0, at 198.51.100.1, from the mesh namespace. On one
# machine, or on a host whose mesh and public addresses are the same address,
# an implementation that pings knock_addr and an implementation that pings the
# always-allow address are indistinguishable, which is how a client that
# pinged the wrong one shipped and was found on live hardware instead.
phase_status() {
    say "phase 8: status reaches the always-allow address, which is not the address open knocks"

    # Asserted before anything is built on it: a phase whose two addresses had
    # quietly become one address would keep passing while proving nothing.
    local knock always
    knock=$(sed -n 's/^knock_addr: *\(.*\)$/\1/p' "${ENTRY}" | head -1)
    always=$(sed -n 's/^always_allow_addr: *\(.*\)$/\1/p' "${ENTRY}" | head -1)
    note "knock_addr=${knock} always_allow_addr=${always}"
    if [ "${knock}" != "${HOST_ADDR}" ]; then
        fail "the entry's knock_addr is ${knock}, want the public ${HOST_ADDR}"
        finish "phase 8" # exits 1: nothing below distinguishes anything without it
    fi
    if [ "${always}" != "${MESH_ADDR}" ]; then
        fail "the entry's always_allow_addr is '${always}', want mesh0's own ${MESH_ADDR}: " \
             "init-standalone did not record the address of the interface it verified"
        finish "phase 8" # exits 1: nothing below distinguishes anything without it
    fi
    ok "the entry carries two different addresses: public ${knock}, always-allow ${always}"

    say "from the always-allow path: the pong verifies and the recovery service answers on the same address"
    local out rc attempt
    for attempt in $(seq 1 "${STATUS_ATTEMPTS}"); do
        out=$(exec_in mesh postern status "${HOST_NAME}" --config "${CLIENT}/config.yaml" --wait 3s 2>&1)
        rc=$?
        [ "${rc}" -eq 0 ] && break
        note "status attempt ${attempt}/${STATUS_ATTEMPTS} exited ${rc}; resending"
    done
    printf '%s\n' "${out}"
    if [ "${rc}" -eq 0 ]; then
        ok "status is green over the always-allow path"
    else
        fail "status exited ${rc} over the always-allow path after ${STATUS_ATTEMPTS} attempts, against " \
             "an agent this sequence has already proven armed and knockable"
    fi
    assert_says "${out}" "host ${HOST_NAME} (${MESH_ADDR}:${SPA_PORT})" \
        "the report names the address it actually checked, not knock_addr"
    assert_says "${out}" "liveness  ok" "the agent signed a pong for a ping that arrived on mesh0"
    # The address, not just the verdict: the two assertions have to traverse
    # one path, and a recovery connect that reached ssh at 192.0.2.1 while the
    # ping reached the agent at 198.51.100.1 would be green here and would be
    # a report about two different paths.
    assert_says "${out}" "recovery  ok    ssh reachable at ${MESH_ADDR}" \
        "the recovery connect went to the same address as the ping, and ssh answered there"

    say "the same check aimed at the public address: refused in silence, on a host that is healthy"
    # --via, from the operator's own namespace, so the datagram genuinely
    # reaches the agent over op0 rather than merely failing to route. What
    # comes back is nothing: a liveness ping that arrives anywhere but the
    # always-allow interface gets no reply, which is exactly why knock_addr
    # cannot serve this command and why the recorded always_allow_addr exists.
    out=$(exec_in op postern status "${HOST_NAME}" --config "${CLIENT}/config.yaml" \
        --via "${HOST_ADDR}" --wait 3s --timeout 2s 2>&1)
    rc=$?
    printf '%s\n' "${out}"
    if [ "${rc}" -ne 0 ]; then
        ok "status against the public address exited ${rc}"
    else
        fail "status against the public address passed; the agent is answering liveness on an untrusted " \
             "interface, or this phase's two addresses are not distinct"
    fi
    assert_says "${out}" "liveness  FAIL" "no pong is emitted for a ping that arrived on op0"
    finish "phase 8"
}

case "${1:-}" in
sign) phase_sign ;;
hub) phase_hub ;;
pull) phase_pull ;;
knock) phase_knock ;;
hub-down) phase_hub_down ;;
redeploy) phase_redeploy ;;
restart) phase_restart ;;
replay) phase_replay ;;
status) phase_status ;;
*)
    echo "usage: fleet-e2e.sh <phase>" >&2
    exit 2
    ;;
esac
