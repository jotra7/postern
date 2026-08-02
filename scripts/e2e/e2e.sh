#!/usr/bin/env bash
# The end-to-end sequence, run inside the systemd container by
# scripts/e2e.sh. Each phase is a separate invocation because two of the
# transitions being tested are reboots, and a reboot ends the process.
#
# Everything here asserts on evidence postern does not produce: `nft list
# ruleset`, `systemctl is-enabled`, and real TCP connections from a separate
# network namespace. postern's own report of what it did is printed for the
# record and, except for exit codes — which are themselves a documented
# interface — never used as proof. A harness that believed the tool under
# test would pass just as happily against a tool that only claimed to work.
set -uo pipefail

HOST_ADDR=192.0.2.1
OP_ADDR=192.0.2.9
MESH_ADDR=198.51.100.1
SSH_PORT=22
CANARY_PORT=62202
# SPA_PORT is no longer what the main sequence's host binds: init-standalone
# is called with no --spa-port at all there (phase_setup, phase_console_
# recovery), so rotation is on by default and the agent binds somewhere in
# ROTATION_RANGE_LO..ROTATION_RANGE_HI instead. SPA_PORT survives as the
# literal port the dedicated fixed-port opt-out phase asks for with
# --no-port-rotation --spa-port, so that phase reads the same as every other
# phase's fixed-value assertions.
SPA_PORT=62201
# ROTATION_RANGE_LO/HI match internal/knockport's DefaultRangeLo/DefaultRangeHi.
ROTATION_RANGE_LO=20000
ROTATION_RANGE_HI=30000
METRICS_PORT=9873
# The probe's own exposition port. It is a second scrape target on purpose:
# the probe runs in the operator's namespace, not on the host, which is the
# whole reason "health is the join" is a join and not a metric.
PROBE_METRICS_PORT=9874
HOST_NAME=demo-host
ETC=/etc/postern
STATE=/var/lib/postern
CLIENT=/root/.postern
INTRUDER=/root/.intruder
# The probe holds its own identity, granted the canary service and nothing
# else. That split is design section 9's probe-theft claim made real rather
# than asserted: a stolen probe key must open only a port with nothing behind
# it, which is false the moment the probe reuses the operator's key.
PROBE=/root/.probe

failures=0

START=$(date +%s)
elapsed() { printf '%3ds' "$(( $(date +%s) - START ))"; }
say() { printf '\n\033[1m== [%s] %s\033[0m\n' "$(elapsed)" "$*"; }
note() { printf '   %s\n' "$*"; }
run() { printf '\n$ %s\n' "$*"; "$@"; }

# must is run() for a step the rest of the phase depends on. The first
# version of this harness used run() everywhere and reported a phase green
# while `postern enroll` had failed and written no client config at all —
# the phases that needed it were three phases later, and the ones in between
# never touched it. A command whose failure invalidates everything after it
# has to be checked where it runs.
must() {
    printf '\n$ %s\n' "$*"
    local rc
    "$@"
    rc=$?
    # Captured immediately. `if "$@"; then ...; fi` followed by `$?` reads the
    # status of the *if*, which is zero when the condition failed and there is
    # no else — so the first version of this reported "command exited 0" while
    # failing the phase.
    [ "${rc}" -eq 0 ] && return 0
    fail "command exited ${rc}: $*"
    return "${rc}"
}

# capture runs a command whose stdout is the artifact rather than commentary,
# so the echoed command line cannot end up inside it. That is not
# hypothetical either: `run cmd > file` put run's own "$ cmd" banner into the
# file, and the YAML it was supposed to hold no longer parsed.
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

# capture2 is capture for a command whose stderr is also an artifact rather
# than commentary: --go-live prints the confirm line an operator runs next on
# stderr, separately from the host entry init-standalone prints on stdout, and
# an assertion against that line needs it captured rather than left to scroll
# past in the log.
capture2() {
    local out=$1 errout=$2 rc
    shift 2
    printf '\n$ %s > %s 2> %s\n' "$*" "${out}" "${errout}"
    "$@" >"${out}" 2>"${errout}"
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

# bash calls this for any command it cannot find, which in a script whose
# assertions ARE commands is the difference between an assertion that failed
# and one that never ran. A phase called assert_ruleset_has after that helper
# had been renamed: bash printed "command not found" on stderr, carried on,
# and the phase reported all assertions passed with its most important one —
# that a dead agent leaves the fail-closed drop rules standing — never
# executed. Silence is not a pass.
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

# probe classifies one TCP connect the way an operator's own tooling would:
# a completed handshake, a refusal (the packet reached the host and nothing
# was listening, or nothing was dropping it), or a timeout (something is
# dropping it silently — which is what a postern gate looks like from
# outside). The distinction is the entire product, so it is drawn from the
# connection itself rather than from anything postern says.
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

# scrape fetches the agent's exposition text over the always-allow interface.
# bash's /dev/tcp is used rather than curl for the same reason probe() uses
# it: nothing else has to be installed in the image, and the request is a
# plain HTTP/1.0 GET whose response the shell can read to EOF.
scrape() {
    exec_in mesh timeout 5 bash -c \
        "exec 3<>/dev/tcp/${MESH_ADDR}/${METRICS_PORT}; \
         printf 'GET /metrics HTTP/1.0\r\nHost: postern\r\n\r\n' >&3; cat <&3" 2>&1
}

# scrape_probe fetches the probe's own exposition text from the operator's
# namespace. Deliberately a separate function from scrape(): they are separate
# targets, in separate namespaces, and the point of the assertions below is
# that the two halves of the join come from two places.
scrape_probe() {
    exec_in op timeout 5 bash -c \
        "exec 3<>/dev/tcp/${OP_ADDR}/${PROBE_METRICS_PORT}; \
         printf 'GET /metrics HTTP/1.0\r\nHost: postern\r\n\r\n' >&3; cat <&3" 2>&1
}

# assert_metric asserts one exposition line. The agent's own report of what it
# did is not proof of anything else in this script, and it is not used as
# proof here either: the claim under test is that the metric moved, which the
# surrounding assertions have already established independently from nft(8).
assert_metric() {
    local want=$1 why=$2 body
    body=$(scrape)
    if [[ ${body} == *"${want}"* ]]; then
        ok "/metrics reports ${want} — ${why}"
    else
        fail "/metrics does not report ${want} — ${why}"
        printf '%s\n' "${body}" | grep -E '^postern_' || printf '%s\n' "${body}"
    fi
}

# assert_metric_at_least asserts a counter's value, for the samples whose
# absolute value is a function of how far into the sequence we are.
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

# banner reads the first line the service sends, which is what makes
# "connected" mean "reached the real sshd" rather than "something accepted a
# TCP handshake".
assert_ssh_banner() {
    local ns=$1 line
    line=$(exec_in "${ns}" timeout 4 bash -c "exec 3<>/dev/tcp/${HOST_ADDR}/${SSH_PORT}; head -c 40 <&3" 2>&1)
    if [[ ${line} == SSH-* ]]; then
        ok "sshd answered with ${line%%$'\r'*}"
    else
        fail "no SSH banner from ${HOST_ADDR}:${SSH_PORT} (got: ${line})"
    fi
}

# stable_ruleset strips the live expiry countdowns, which tick between any
# two reads and would make every before/after comparison report a change.
# Everything else survives: an element the unauthorised knock had opened
# would still appear, because what is stripped is how long an element has
# left, never which elements exist.
stable_ruleset() {
    nft list ruleset | sed -E 's/ expires [0-9a-z]+//g'
}

nft_dump() {
    printf '\n$ nft list ruleset\n'
    nft list ruleset
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

# The armed-state assertions are made against ONE dump taken at one instant,
# not against a fresh `nft list ruleset` per assertion. The state under test
# here is time-limited by construction — a dead-man timer is counting down
# while the assertions run — so a series of independent reads can straddle the
# very transition being asserted about, and report a mixture of two states as
# though it were one. That is not a hypothetical: it is what the first run of
# this harness did.
SNAPSHOT=""

snapshot_ruleset() {
    SNAPSHOT=$(nft list ruleset)
    printf '\n$ nft list ruleset   # snapshot taken at %s\n%s\n' "$(elapsed)" "${SNAPSHOT}"
}

assert_snapshot_has() {
    local pattern=$1 why=$2
    if [[ ${SNAPSHOT} == *"${pattern}"* ]]; then
        ok "ruleset contains '${pattern}' — ${why}"
    else
        fail "ruleset does not contain '${pattern}' — ${why}"
    fi
}

# assert_live_has reads the ruleset now rather than from a snapshot, for the
# phases where nothing is counting down and a fresh read is the honest one.
assert_live_has() {
    local pattern=$1 why=$2 live
    live=$(nft list ruleset)
    if [[ ${live} == *"${pattern}"* ]]; then
        ok "ruleset contains '${pattern}' — ${why}"
    else
        fail "ruleset does not contain '${pattern}' — ${why}"
    fi
}

# assert_live_lacks is assert_live_has's complement, for the one scenario in
# this harness that needs to assert a pattern is absent from the live
# ruleset rather than present: console-recovery mode's whole premise is that
# no iifname accept rule exists anywhere, because there is no always-allow
# interface to write one for.
assert_live_lacks() {
    local pattern=$1 why=$2 live
    live=$(nft list ruleset)
    if [[ ${live} == *"${pattern}"* ]]; then
        fail "ruleset contains '${pattern}', want it absent: ${why}"
    else
        ok "ruleset does not contain '${pattern}': ${why}"
    fi
}

assert_snapshot_table() {
    local table=$1 want=$2 why=$3
    if [[ ${SNAPSHOT} == *"table inet ${table} {"* ]]; then
        if [ "${want}" = present ]; then ok "table inet ${table} is present — ${why}"
        else fail "table inet ${table} is present, want absent — ${why}"; fi
    else
        if [ "${want}" = absent ]; then ok "table inet ${table} is absent — ${why}"
        else fail "table inet ${table} is absent, want present — ${why}"; fi
    fi
}

assert_unit_enabled() {
    local unit=$1 want=$2 why=$3 got
    got=$(systemctl is-enabled "${unit}" 2>&1)
    if [ "${got}" = "${want}" ]; then
        ok "systemctl is-enabled ${unit} = ${got} — ${why}"
    else
        fail "systemctl is-enabled ${unit} = ${got}, want ${want} — ${why}"
    fi
}

assert_enabled() { assert_unit_enabled postern-boot.service "$1" "$2"; }

assert_unit_active() {
    local unit=$1 want=$2 why=$3 got
    got=$(systemctl is-active "${unit}" 2>&1)
    if [ "${got}" = "${want}" ]; then
        ok "systemctl is-active ${unit} = ${got} — ${why}"
    else
        fail "systemctl is-active ${unit} = ${got}, want ${want} — ${why}"
    fi
}

# assert_agent_up_holds_the_lease reads the dead-man element that makes the
# SPA port reachable at all. postern-boot.service's ruleset accepts on the SPA
# port only while agent_up holds it and drops otherwise, so an empty agent_up
# on an armed host is a host that cannot be knocked — which is the whole
# failure, and is invisible to every assertion about the ruleset's shape.
#
# expected_port, the second argument, is optional. A fixed-port host (this
# harness's console-recovery scenario before rotation became the default, and
# the dedicated fixed-port opt-out phase now) has exactly one port to look
# for, so a caller that knows it passes SPA_PORT and gets the old exact-match
# behaviour back unchanged. Every other caller in this sequence now enrolls a
# rotation host: the agent binds a port the arm step picked from
# ROTATION_RANGE_LO..ROTATION_RANGE_HI, not a value this script ever sees in
# advance, so the only thing worth asserting is that SOME element of the live
# set falls in that band — which is also what RefreshAgentUpPorts' own
# contract promises (Tasks 4-6): the current window and both neighbors, always
# at least one of which is live.
assert_agent_up_holds_the_lease() {
    local why=$1 expected_port=${2:-} elems
    elems=$(nft list set inet postern_boot agent_up 2>&1 | tr -d '\n')
    if [ -n "${expected_port}" ]; then
        if [[ ${elems} == *"${expected_port}"* ]]; then
            ok "agent_up holds ${expected_port} — ${why}"
        else
            fail "agent_up does not hold ${expected_port}: ${elems} — ${why}"
        fi
        return
    fi
    local port
    for port in $(printf '%s' "${elems}" | grep -oE '[0-9]+'); do
        if [ "${port}" -ge "${ROTATION_RANGE_LO}" ] && [ "${port}" -le "${ROTATION_RANGE_HI}" ]; then
            ok "agent_up holds ${port}, in ${ROTATION_RANGE_LO}-${ROTATION_RANGE_HI} — ${why}"
            return
        fi
    done
    fail "agent_up holds no port in ${ROTATION_RANGE_LO}-${ROTATION_RANGE_HI}: ${elems} — ${why}"
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

# ssh_gate_set is the observed-address set the ssh gate opens into. The name
# comes from internal/gate's one naming function; spelling it here rather
# than asking postern for it keeps the assertion independent.
SSH_SET=gate_ssh_v4_obs
CANARY_SET=gate_canary_v4_obs

gate_elements() {
    nft list set inet "$1" "$2" 2>/dev/null | sed -n 's/.*elements = {\(.*\)}.*/\1/p'
}

assert_gate_open_for() {
    local table=$1 set=$2 addr=$3 elems
    elems=$(nft list set inet "${table}" "${set}" 2>/dev/null | tr -d '\n')
    if [[ ${elems} == *"${addr}"* ]]; then
        ok "${set} holds ${addr} — the gate is open for the operator's address and nobody else's"
    else
        fail "${set} does not hold ${addr}: ${elems}"
    fi
}

assert_gate_empty() {
    local table=$1 set=$2 elems
    elems=$(nft list set inet "${table}" "${set}" 2>/dev/null | tr -d '\n')
    if [[ ${elems} == *elements* ]]; then
        fail "${set} still holds elements: ${elems}"
    else
        ok "${set} is empty"
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
        sleep 2
    done
    fail "timed out after waiting for: ${desc}"
    return 1
}

pending_field() { # pending_field <json key>
    sed -n "s/.*\"$1\": *\"\{0,1\}\([^\",]*\)\"\{0,1\},\{0,1\}/\1/p" "${STATE}/pending.json" | head -1
}

client() { exec_in op postern "$@" --config "${CLIENT}/config.yaml"; }

# --- phases ------------------------------------------------------------

# assert_says is a substring assertion on output that was captured rather than
# streamed, for the refusals whose exact wording is the product.
assert_says() {
    local haystack=$1 needle=$2 why=$3
    if [[ ${haystack} == *"${needle}"* ]]; then
        ok "the output says '${needle}' — ${why}"
    else
        fail "the output does not say '${needle}' — ${why}"
    fi
}

phase_setup() {
    say "phase 1 — enrollment, with nothing armed"

    run systemctl is-system-running --wait || true
    run ip -brief addr
    run exec_in op ip -brief addr

    say "the host before postern: sshd is reachable from the operator's network"
    assert_ssh_banner op
    assert_probe op "${HOST_ADDR}" "${CANARY_PORT}" refused "nothing listens on the canary port and nothing filters it yet"
    assert_table postern_boot absent "postern has not been installed yet"
    assert_table postern_open absent "postern has not been installed yet"

    say "operator: mint an identity"
    mkdir -p "${CLIENT}"
    capture /root/enroll.txt postern enroll "${HOST_NAME}" --config "${CLIENT}/config.yaml" \
        --operator laptop --no-passphrase
    cat /root/enroll.txt
    local opflag
    opflag=$(sed -n "s/.*--operator '\(.*\)'.*/\1/p" /root/enroll.txt)
    if [ -z "${opflag}" ]; then
        fail "could not read the operator key pair out of the enrollment instructions"
        return
    fi
    note "operator flag: ${opflag}"

    say "probe: mint a separate identity, granted the canary and nothing else"
    mkdir -p "${PROBE}"
    capture /root/enroll-probe.txt postern enroll "${HOST_NAME}" --config "${PROBE}/config.yaml" \
        --operator probe-local --no-passphrase
    local probeflag
    probeflag=$(sed -n "s/.*--operator '\(.*\)'.*/\1/p" /root/enroll-probe.txt)
    if [ -z "${probeflag}" ]; then
        fail "could not read the probe key pair out of the enrollment instructions"
        return
    fi
    note "probe flag: ${probeflag}:canary"

    say "host: init-standalone (gates staged, NOT armed)"
    capture /root/entry.yaml postern init-standalone \
        --dir "${ETC}" --state-dir "${STATE}" --unit-dir /etc/systemd/system \
        --host-name "${HOST_NAME}" --knock-addr "${HOST_ADDR}" \
        --always-allow-iface mesh0 --recovery-service ssh \
        --ssh-host "${HOST_ADDR}" --ssh-user root \
        --revision 1 \
        --exec-start "/usr/local/bin/postern agent --config ${ETC}/postern.yaml --state-dir ${STATE} --confirm-window 60s --debug --metrics-listen :${METRICS_PORT}" \
        --operator "${opflag}" \
        --operator "${probeflag}:canary" \
        --max-ttl probe-local=30s
    cat /root/entry.yaml
    run systemctl daemon-reload

    say "operator: register the host"
    must postern enroll "${HOST_NAME}" --config "${CLIENT}/config.yaml" --from /root/entry.yaml
    assert_file "${CLIENT}/config.yaml" present "the operator can knock this host from here"
    cat "${CLIENT}/config.yaml"
    must postern enroll "${HOST_NAME}" --config "${PROBE}/config.yaml" --from /root/entry.yaml
    assert_file "${PROBE}/config.yaml" present "the probe can knock this host from here"

    assert_enabled disabled "enrollment stages the boot unit inert; nothing may drop traffic until a configuration is armed"
    assert_unit_enabled posternd.service disabled "enrollment stages the agent inert too; the arm step is what enables it"
    assert_table postern_boot absent "init-standalone writes boot.nft but loads nothing"
    assert_ssh_banner op
    nft_dump
    finish "phase 1"
}

phase_arm_revert() {
    say "phase 2 — first arm, never confirmed, reverts on the dead-man timer"

    # Started, deliberately NOT enabled. `systemctl enable posternd.service`
    # here would have made every later reboot bring the agent back for a
    # reason that has nothing to do with postern, and that is exactly what hid
    # the defect this phase and phase 5 now cover: for the whole of this
    # sequence's history the harness enabled the agent itself, so no phase
    # could tell whether postern ever did. Nothing but the arm step may enable
    # it from here on.
    must systemctl start posternd.service
    poll 30 "posternd is active" systemctl is-active --quiet posternd.service
    run journalctl -u posternd.service --no-pager -n 30

    say "the pair the agent published BEFORE it armed"
    assert_file "${STATE}/pending.json" present "the arm step publishes the revision and nonce a confirm must carry"
    cat "${STATE}/pending.json"
    local rev nonce outcome
    rev=$(pending_field revision); nonce=$(pending_field deployment_nonce); outcome=$(pending_field outcome)
    note "revision=${rev} nonce=${nonce} outcome=${outcome}"
    [ "${rev}" = "1" ] || fail "published revision = ${rev}, want 1"
    [ "${outcome}" = "pending" ] || fail "published outcome = ${outcome}, want pending"
    [ ${#nonce} -eq 32 ] || fail "published nonce ${nonce} is not 32 hex characters"

    say "what the arm did to the host"
    snapshot_ruleset
    assert_snapshot_table postern_boot present "the arm step loaded the generated ruleset"
    assert_snapshot_table postern_open present "the agent creates its own table at startup"
    assert_enabled enabled "the arm step enables the boot unit through real systemd, so the posture survives a reboot"
    assert_unit_enabled posternd.service enabled \
        "the arm step enables the agent too; a boot unit enabled without it drops the SPA port at every boot with nothing alive to open it"
    assert_snapshot_has "tcp dport 22 drop" "the break-glass service is gated"
    assert_snapshot_has "tcp dport ${CANARY_PORT} drop" "the fail-closed service is gated"
    assert_probe op "${HOST_ADDR}" "${SSH_PORT}" filtered "an armed host drops ssh from an unknocked source"
    assert_probe op "${HOST_ADDR}" "${CANARY_PORT}" filtered "the canary port drops rather than refusing (I2)"

    say "nobody confirms; the dead-man timer must roll all of it back"
    poll 150 "postern_boot is gone — the unconfirmed configuration reverted" \
        bash -c '! nft list table inet postern_boot >/dev/null 2>&1'
    run journalctl -u posternd.service --no-pager -n 20
    nft_dump
    assert_enabled disabled "the revert restored the boot unit's enabled state, or the host re-locks at the next reboot"
    assert_unit_enabled posternd.service disabled \
        "and the agent's, to the disabled state the transaction found: an unconfirmed first arm returns the host to as-found"
    assert_file "${STATE}/state.json" absent "nothing was confirmed, so no revision may be recorded"
    assert_file "${ETC}/boot.nft" present "the generated ruleset is restored, not deleted: it existed before the transaction"
    cat "${STATE}/pending.json"
    [ "$(pending_field outcome)" = "reverted" ] || fail "the pending record does not say the revision was reverted"
    assert_probe op "${HOST_ADDR}" "${CANARY_PORT}" refused "the fail-closed drop rule is gone with the table"
    finish "phase 2"
}

phase_after_revert_reboot() {
    say "phase 3 — after a reboot, a reverted transaction has not re-locked the host"
    run systemctl is-system-running --wait || true
    nft_dump
    assert_table postern_boot absent "the boot unit is disabled, so nothing loaded the fail-closed drops"
    assert_table postern_open absent "posternd cannot arm anything without postern_boot"
    assert_enabled disabled "a reverted transaction leaves the boot unit as it found it"
    assert_unit_enabled posternd.service disabled "and the agent unit, which the transaction also found disabled"
    assert_unit_active posternd.service inactive \
        "nothing started the agent at this boot, because the revert returned the host to as-found"
    assert_ssh_banner op
    assert_probe op "${HOST_ADDR}" "${CANARY_PORT}" refused "nothing is dropping anything"

    say "and when it is started by hand it says why it is not arming, rather than re-arming the reverted revision"
    # Not `must`: the agent exits inert here on purpose, so the start job
    # fails. What is being asserted is the exit code and the reason.
    run systemctl start posternd.service || true
    poll 60 "posternd exited 3 (inert) — the documented exit code systemd retries" \
        bash -c '[ "$(systemctl show posternd.service -p ExecMainStatus --value)" = 3 ]'
    run journalctl -u posternd.service --no-pager -n 40
    local journal
    journal=$(journalctl -u posternd.service --no-pager)
    if [[ ${journal} == *"refusing to re-arm"* ]]; then
        ok "the agent refused to re-arm the reverted revision"
    else
        fail "nothing in the journal says why the agent did not arm"
    fi
    # Restart=always is cycling it every RestartSec; stop it so the next phase
    # starts from a known state rather than from wherever the loop happens to be.
    run systemctl stop posternd.service
    finish "phase 3"
}

phase_arm_confirm() {
    say "phase 4 — a new revision, armed and confirmed"
    note "the operator's documented way forward after a revert: bump the revision"
    must sed -i 's/^revision: 1$/revision: 2/' "${ETC}/postern.yaml"
    run grep '^revision:' "${ETC}/postern.yaml"
    must systemctl restart posternd.service
    poll 30 "posternd is active" systemctl is-active --quiet posternd.service

    # Sampled here, immediately after start, so the watchdog check below has
    # a genuine baseline: systemd arms WatchdogTimestampMonotonic to a
    # non-zero value the instant a Type=notify service with WatchdogSec
    # starts, whether or not anything ever pings it. A single later read
    # that only checks "non-zero" would pass on that one-time arming alone —
    # this mutation-checked assertion caught exactly that on the first draft
    # (task-1 step 6) — so what is asserted below is that the timestamp
    # ADVANCES from this baseline, which only a real WATCHDOG=1 can do.
    local wd_start
    wd_start=$(systemctl show posternd.service -p WatchdogTimestampMonotonic --value)
    note "WatchdogTimestampMonotonic at start: ${wd_start}"

    cat "${STATE}/pending.json"
    local rev nonce
    rev=$(pending_field revision); nonce=$(pending_field deployment_nonce)
    [ "${rev}" = "2" ] || fail "published revision = ${rev}, want 2"
    assert_table postern_boot present "revision 2 is armed"
    assert_enabled enabled "the boot unit is enabled again"
    assert_unit_enabled posternd.service enabled "and the agent unit with it; phase 5 reboots to see whether it holds"

    say "confirm, from the operator's namespace, carrying the published binding"
    # --force: the operator confirms from op0, which reaches the public knock
    # path but not the always-allow mesh the arm-time liveness pre-check probes
    # (design section 7, I5). A real operator on a recovery-capable machine
    # would let the check run; here it cannot reach the mesh, so the confirm
    # explicitly acknowledges it -- the dead-man timer is still the safety net.
    must client confirm "${HOST_NAME}" --revision "${rev}" --nonce "${nonce}" --force
    poll 30 "the confirm was recorded" test -f "${STATE}/state.json"
    cat "${STATE}/state.json"
    assert_file "${STATE}/pending.json" absent "a confirmed configuration is no longer waiting for anything"

    say "and the dead-man timer no longer has anything to revert"
    sleep 45
    assert_table postern_boot present "a confirmed configuration is not rolled back when the window elapses"
    assert_enabled enabled "and neither is the boot unit"
    nft_dump

    # The watchdog is only meaningful if systemd is accepting the
    # notifications, and "non-zero" alone does not show that: systemd sets
    # WatchdogTimestampMonotonic once at service start regardless of whether
    # anything ever pings it, so a discarded sd_notify still leaves a
    # non-zero, merely stale, timestamp — Type=notify with a discarded
    # READY=1 still starts the service, so nothing else in this sequence
    # would catch it either. What proves systemd is actually accepting
    # ongoing pings is the timestamp ADVANCING past its start-of-service
    # value across the 45s (more than one 30s heartbeat) this phase has
    # already waited. This reads systemd's own record of what it received
    # rather than anything postern reports about itself, the same rule that
    # made RefreshAgentUp's silent no-op visible.
    say "the watchdog: systemd's own record of what it actually received"
    local wd_now
    wd_now=$(systemctl show posternd.service -p WatchdogTimestampMonotonic --value)
    if [ -z "${wd_now}" ] || [ "${wd_now}" = "0" ]; then
        fail "systemd has never accepted a watchdog ping from posternd"
        journalctl -u posternd.service --no-pager | grep -i 'notification message' || true
    elif [ "${wd_now}" = "${wd_start}" ]; then
        fail "WatchdogTimestampMonotonic has not moved since service start (still ${wd_start});" \
            "the timer was armed at start but no ping has been accepted since"
        journalctl -u posternd.service --no-pager | grep -i 'notification message' || true
    else
        ok "watchdog pings are being accepted (start=${wd_start} now=${wd_now})"
    fi
    finish "phase 4"
}

# The normal path, which is the one that was broken. Every reboot assertion in
# this sequence used to be made from a state where a stopped agent looked
# right — after a revert, after a disarm — so a host that came back from an
# ordinary reboot with the drop rules loaded and the agent dead passed the
# whole suite. It also passed two review rounds and shipped, and was found by
# typing `systemctl reboot` on a real VM.
#
# There is no way to reach this state except by rebooting a confirmed, armed
# host and looking at what systemd started. So that is what this does.
phase_after_confirm_reboot() {
    say "phase 5 — after a reboot, a confirmed host is still armed AND still reachable by a knock"
    run systemctl is-system-running --wait || true
    nft_dump

    say "the fail-closed posture came back, with no help from the agent"
    assert_table postern_boot present "the enabled boot unit loaded the confirmed ruleset before the network came up"
    assert_live_has "tcp dport ${CANARY_PORT} drop" "the fail-closed service is gated by postern_boot alone"
    assert_probe op "${HOST_ADDR}" "${CANARY_PORT}" filtered "and drops rather than refusing"

    say "and so did the agent, which is the only thing that can open any of it"
    assert_unit_enabled posternd.service enabled \
        "an armed host with a disabled agent is design section 7's failure row, reached on the normal path"
    poll 60 "posternd is active after the reboot" systemctl is-active --quiet posternd.service
    assert_unit_active posternd.service active "nothing but the agent can open a gate"
    run systemctl status posternd.service --no-pager || true
    assert_table postern_open present "the agent recreated its own table at this boot"
    assert_live_has "tcp dport ${SSH_PORT} drop" "the break-glass gate is standing again, which only the agent builds"
    assert_probe op "${HOST_ADDR}" "${SSH_PORT}" filtered "an unknocked source still gets nothing"

    # Rotation is the default enrollment now (phase_setup passes no
    # --spa-port and no --no-port-rotation), so this host's boot.nft was
    # built from the range drop rather than a single-port drop, and the
    # SPA port agent_up holds is whichever one the arm step picked from the
    # band, not a fixed value. Both of those are new truths, not
    # implementation detail: a reviewer reading only the ruleset dump above
    # this point would otherwise have no way to tell this host apart from a
    # fixed-port one.
    assert_live_has "udp dport ${ROTATION_RANGE_LO}-${ROTATION_RANGE_HI} drop" \
        "rotation is the default: the fail-closed drop covers the whole knock-port band, not one fixed port"
    assert_agent_up_holds_the_lease "without the lease no port in the rotating band is reachable and the host cannot be knocked at all"

    say "case 1: a rotated knock opens the gate, exactly the way a fixed-port knock always has"
    run client open "${HOST_NAME}" ssh --ttl 60s
    local open_rc=$?
    [ ${open_rc} -eq 0 ] || fail "postern open exited ${open_rc}, want 0"
    assert_gate_open_for postern_open "${SSH_SET}" "${OP_ADDR}"
    assert_ssh_banner op

    # Let the lease close before the skew case knocks again, so that case's
    # own open is what proves the gate opened rather than riding on this
    # one's still-live lease.
    poll 120 "the ssh gate set emptied on its own again, before the skew case" \
        bash -c "! nft list set inet postern_open ${SSH_SET} | grep -q ${OP_ADDR}"

    say "case 2: a client clock skewed within the overlap still opens it"
    # The agent holds the current window and both neighbors live at all
    # times (knockport.LiveSet, Tasks 4-6), so a client whose clock has
    # drifted into the neighbor window still lands on a port the agent
    # already accepts. What proves that is a knock built under a clock this
    # host's agent never had: the operator's clock is wrong, not the host's.
    #
    # libfaketime cannot be used for this: it intercepts libc's time calls,
    # and the shipped postern binary is a CGO_ENABLED=0 Go binary that reads
    # CLOCK_REALTIME through the vDSO directly, bypassing libc (and
    # therefore LD_PRELOAD) entirely. Verified directly against this image
    # before writing this: `faketime '+10 minutes' postern ...` produced a
    # datagram timestamped with the real clock, byte for byte. So this skews
    # the container's real wall clock instead, for exactly the one `client
    # open` call below, and restores it immediately after.
    #
    # Only the client's process needs to be wrong, not the host's — a
    # system-wide clock move takes the host's clock with it, which sounds
    # like it would undermine the whole case. It does not, for two reasons.
    # First, the fact under test — that the neighbor port is already open —
    # was decided by the agent's periodic RefreshAgentUpPorts loop before
    # this block ever runs, off the real, unmoved clock; the kernel's
    # agent_up set does not get asked again until that loop's next tick, and
    # this block is in and out in well under that. Second, KindGate packets
    # (what `open` sends) are admitted by EITHER a fresh timestamp OR a
    # counter above the high-water mark (internal/agent/validate.go); a
    # brand-new counter value clears that bar regardless of what either
    # clock reads, so nothing here depends on the freshness window at all.
    # What this case actually exercises — the only thing a system-wide clock
    # move could not fake — is the destination port: CurrentKnockPort has to
    # compute w+1 from a clock that, at the moment `client open` builds the
    # datagram, genuinely reads a time in the next window, not a value this
    # script hands it directly.
    #
    # The skew is computed rather than a flat +5m: a flat offset added to
    # whatever moment this phase happens to run at only crosses into the
    # next window when the real time is already past the current window's
    # midpoint, which makes the case flaky by construction. Landing just
    # past the next boundary, whatever the current offset is, always lands
    # in the immediate neighbor window (never two windows out) and always
    # counts as "within the overlap".
    local window_s=600 real_before uptime_before offset skew_s skewed_epoch
    real_before=$(date +%s)
    uptime_before=$(cut -d' ' -f1 /proc/uptime)
    offset=$(( real_before % window_s ))
    skew_s=$(( window_s - offset + 30 ))
    skewed_epoch=$(( real_before + skew_s ))
    note "real epoch ${real_before} (offset ${offset}s into the window), skewing the client's view ${skew_s}s forward to ${skewed_epoch} (window w+1)"
    must date -s "@${skewed_epoch}"
    run client open "${HOST_NAME}" ssh --ttl 60s
    local skew_open_rc=$?
    local uptime_after elapsed_s restore_epoch
    uptime_after=$(cut -d' ' -f1 /proc/uptime)
    # /proc/uptime is monotonic and unaffected by date -s (checked above the
    # date -s line never touched it), so it is what measures real elapsed
    # time across a block that just moved the wall clock out from under
    # itself. +1 rounds the fractional remainder up rather than down, so the
    # restore never lands slightly in the past relative to where a
    # wall-clock read would have been without any of this.
    elapsed_s=$(awk -v a="${uptime_before}" -v b="${uptime_after}" 'BEGIN{d=b-a; if (d<0) d=0; printf "%d", d+1}')
    restore_epoch=$(( real_before + elapsed_s ))
    must date -s "@${restore_epoch}"
    note "restored the clock to ${restore_epoch} (${elapsed_s}s of real time elapsed while it was skewed)"
    [ ${skew_open_rc} -eq 0 ] || fail "postern open (skewed) exited ${skew_open_rc}, want 0"
    assert_gate_open_for postern_open "${SSH_SET}" "${OP_ADDR}"
    assert_ssh_banner op

    # Hand the next phase the state it asserts on: a closed gate. The lease
    # opened above expires on its own, which is also the only thing that ever
    # closes it.
    poll 120 "the ssh gate set emptied on its own again" \
        bash -c "! nft list set inet postern_open ${SSH_SET} | grep -q ${OP_ADDR}"
    finish "phase 5"
}

# phase_probe is the evidence postern's own reports cannot supply.
#
# `postern open` reports what its connect found, and says plainly that a
# successful connect does not establish that postern did it: a fail-open
# service whose agent has died looks identical from there, and so does a host
# with no firewall tables at all. The probe closes that gap by asserting the
# CLOSED state first — and the second half of this phase is what makes that
# assertion worth anything, because it deletes the canary drop rule and
# requires the very same command to fail. A probe that reported green there
# would be worse than no probe: it would manufacture confidence about
# precisely the state it exists to catch.
phase_probe() {
    say "phase 6 — the external probe: both phases asserted, every sweep (I2)"

    prober() { exec_in op postern probe "${HOST_NAME}" --config "${PROBE}/config.yaml" "$@"; }

    poll 90 "the canary gate set is empty, so phase 1 has a closed gate to measure" \
        bash -c "! nft list set inet postern_boot ${CANARY_SET} 2>/dev/null | grep -q elements"
    assert_probe op "${HOST_ADDR}" "${CANARY_PORT}" filtered "phase 1's premise: the canary port drops rather than answering"

    say "a full sweep against a healthy armed host"
    local rc
    run prober --once --closed-timeout 4s --open-timeout 4s
    rc=$?
    if [ "${rc}" -eq 0 ]; then
        ok "the sweep passed: the gate was shut, the knock opened it, and it answered only after the knock"
    else
        fail "postern probe --once exited ${rc} against a healthy armed host"
    fi
    assert_gate_open_for postern_boot "${CANARY_SET}" "${OP_ADDR}"

    say "the probe's key opens the canary and nothing else (design section 9)"
    exec_in op postern open "${HOST_NAME}" ssh --config "${PROBE}/config.yaml" --timeout 2s --attempts 1
    rc=$?
    if [ "${rc}" -ne 0 ]; then
        ok "the probe identity could not open ssh (exit ${rc}) — its grant covers the canary alone"
    else
        fail "the probe identity opened ssh; a stolen probe key would reach a real service"
    fi
    assert_probe op "${HOST_ADDR}" "${SSH_PORT}" filtered "ssh stayed shut against the probe's key"

    say "now delete the canary drop rule — the state postern's own reports cannot see"
    poll 90 "the canary lease expired, so the next phase 1 measures the drop rule and not a live gate" \
        bash -c "! nft list set inet postern_boot ${CANARY_SET} 2>/dev/null | grep -q elements"
    local handle
    handle=$(nft -a list chain inet postern_boot input |
        sed -n "s/.*tcp dport ${CANARY_PORT} drop # handle \([0-9]*\).*/\1/p" | head -1)
    if [ -z "${handle}" ]; then
        fail "could not find the canary drop rule to delete, so the falsifiability check never ran"
        return
    fi
    must nft delete rule inet postern_boot input handle "${handle}"
    assert_probe op "${HOST_ADDR}" "${CANARY_PORT}" refused \
        "with no drop rule the port answers with no gate open — the host that looks healthy to \`postern open\`"

    local out
    printf '\n$ prober --once   # with the drop rule gone\n'
    out=$(prober --once --closed-timeout 4s --open-timeout 4s 2>&1)
    rc=$?
    printf '%s\n' "${out}"
    if [ "${rc}" -ne 0 ]; then
        ok "the sweep FAILED (exit ${rc}) with no drop rule in front of the canary — phase 1 is load-bearing"
    else
        fail "the sweep passed against a canary port nothing filters: the probe reports green on a host with no gate"
    fi
    if [[ ${out} == *"gate not closed"* ]]; then
        ok "the failure names the reason rather than only the verdict"
    else
        fail "the failure does not say 'gate not closed': ${out}"
    fi
    if [[ ${out} == *"knock    sent"* ]]; then
        fail "the sweep knocked after phase 1 had already failed"
    else
        ok "the sweep stopped at phase 1 and did not spend a gate lease on a host already known to be wrong"
    fi

    say "restore the drop rule for the phases that follow"
    must nft add rule inet postern_boot input tcp dport "${CANARY_PORT}" drop
    assert_probe op "${HOST_ADDR}" "${CANARY_PORT}" filtered "the fail-closed posture is back"
    run prober --once --closed-timeout 4s --open-timeout 4s
    rc=$?
    [ "${rc}" -eq 0 ] || fail "the sweep did not recover after the drop rule was restored (exit ${rc})"

    phase_probe_join

    poll 90 "the canary lease expired again, leaving the next phase the closed gate it asserts on" \
        bash -c "! nft list set inet postern_boot ${CANARY_SET} 2>/dev/null | grep -q elements"
    finish "phase 6"
}

# health is the join, on real hardware, from two namespaces.
#
# Design section 8: "an agent reporting itself healthy while the probe cannot
# reach it is the most valuable state the system surfaces, because it is
# exactly the condition that makes a break-glass door useless on the day it is
# needed."
#
# No process can hold both halves at the instant they disagree — that is what
# the state is — so what is asserted here is what postern actually owes the
# monitoring system: two scrape targets, simultaneously readable, disagreeing,
# and carrying a key that joins them. The PromQL that turns those into one
# alertable series lives in dashboards/rules.yml, and it is evaluated by
# scripts/promtool-test.sh rather than here.
#
# The unreachability is manufactured on the operator's side, by asking for a
# gate that expires before the sweep connects to it. Nothing on the host
# changes: the agent is genuinely healthy and genuinely says so, it authorizes
# and opens the gate exactly as it should, phase 1 still measures the real drop
# rule, and the ruleset the later phases assert on is untouched.
phase_probe_join() {
    say "health is the join: the agent says healthy, the probe cannot reach it"

    # Without this the previous sweep's own 30s lease is still live, phase 1
    # finds the canary port answering, and the sweep goes red for the wrong
    # reason — a red that says nothing about the path and would make this whole
    # phase a demonstration of the probe poisoning its own evidence.
    poll 90 "the last sweep's canary lease expired, so phase 1 has a closed gate to measure" \
        bash -c "! nft list set inet postern_boot ${CANARY_SET} 2>/dev/null | grep -q elements"

    # The unreachability is manufactured by asking for a gate that expires
    # before the sweep connects to it: --ttl 1s with --settle 3s. The knock is
    # ordinary, well-formed SPA to the real port, the agent authorizes it and
    # opens a real gate, and the gate is gone by the time phase 2 dials — so
    # the sweep reports gate_not_opened through the path a genuinely broken
    # host would use.
    #
    # The first version pointed the probe at a UDP port the agent does not bind
    # and that was a worse test twice over. It exercised a path no deployment
    # has, and "unreachable" meant "the harness aimed somewhere else" rather
    # than anything about the host. It also perturbed the phase that follows:
    # with it in place the knock phase's re-knock lost its datagram on five of
    # seven runs, with postern_spa_datagrams_total unchanged, and with this
    # block disabled that phase passed. Whatever the mechanism was, sending
    # traffic to a port nothing binds was not worth finding out.
    #
    # --failure-threshold 1 rather than the default 3, so this takes one sweep
    # instead of seven minutes. The threshold itself is asserted by unit tests;
    # what is being established here is that the two targets exist and
    # disagree.
    exec_in op postern probe "${HOST_NAME}" --config "${PROBE}/config.yaml" \
        --metrics-listen "${OP_ADDR}:${PROBE_METRICS_PORT}" \
        --failure-threshold 1 --ttl 1s --settle 3s \
        --closed-timeout 4s --open-timeout 2s --open-attempts 1 \
        >/root/probe-metrics.log 2>&1 &
    local probe_pid=$!

    probe_reports_red() {
        scrape_probe | grep -q "postern_probe_health{host=\"${HOST_NAME}\",state=\"red\"} 1"
    }
    if ! poll 60 "the probe's own /metrics is up and reports ${HOST_NAME} red" probe_reports_red; then
        cat /root/probe-metrics.log || true
    fi

    local probe_body agent_body
    probe_body=$(scrape_probe)
    agent_body=$(scrape)
    printf '%s\n' "${probe_body}" | grep -E '^postern_probe' || true

    # Half one: the probe, from the operator's namespace, says it cannot reach
    # the host.
    if [[ ${probe_body} == *"postern_probe_health{host=\"${HOST_NAME}\",state=\"red\"} 1"* ]]; then
        ok "the probe's /metrics reports ${HOST_NAME} red"
    else
        fail "the probe's /metrics does not report ${HOST_NAME} red: ${probe_body}"
    fi
    # The reason has to be one that says the *path* is broken. gate_not_closed
    # would mean phase 1 met a live lease rather than the drop rule, which is
    # the probe poisoning its own evidence — red, but red about nothing, and
    # this phase would be asserting on a coincidence.
    local reason
    reason=$(printf '%s\n' "${probe_body}" |
        sed -n 's/^postern_probe_sweeps_total{.*reason="\([a-z_]*\)".*/\1/p' | head -1)
    case "${reason}" in
    gate_not_opened | knock_not_sent)
        ok "the failed sweep is counted as ${reason} — phase 1 held and the knock did not arrive"
        ;;
    "")
        fail "no failed sweep is counted in the probe's /metrics"
        ;;
    *)
        fail "the sweep failed as ${reason}, not because the knock could not reach the host; this is not the join's red state"
        ;;
    esac

    # Half two: the agent, scraped over the mesh at the same moment, says it is
    # fine. This is the half that makes the state dangerous rather than merely
    # bad — an alert on the agent alone would be green right now.
    if [[ ${agent_body} == *'postern_agent_health_red{source="agent_up"} 0'* ]] &&
        [[ ${agent_body} == *'postern_agent_health_red{source="standing"} 0'* ]]; then
        ok "the agent's /metrics reports itself healthy at the same moment"
    else
        fail "the agent does not report itself healthy, so this is not the join's red state"
        printf '%s\n' "${agent_body}" | grep -E '^postern_agent' || true
    fi

    # And the key. Without a shared identifier the two halves above are two
    # unrelated facts, and "health is the join" would need an operator to
    # hand-write a matching label into their scrape config — a join that is
    # documented and never wired.
    local probe_hostid agent_hostid
    probe_hostid=$(printf '%s\n' "${probe_body}" |
        sed -n 's/^postern_probe_target_info{.*host_id="\([0-9a-f]*\)".*/\1/p' | head -1)
    agent_hostid=$(printf '%s\n' "${agent_body}" |
        sed -n 's/^postern_agent_info{.*host_id="\([0-9a-f]*\)".*/\1/p' | head -1)
    if [ -z "${probe_hostid}" ] || [ -z "${agent_hostid}" ]; then
        fail "one of the two targets publishes no host_id (probe=${probe_hostid:-none} agent=${agent_hostid:-none}); nothing joins them"
    elif [ "${probe_hostid}" = "${agent_hostid}" ]; then
        ok "both targets publish host_id ${agent_hostid} — the join key needs no operator configuration"
    else
        fail "host_id differs across the two targets: probe=${probe_hostid} agent=${agent_hostid}"
    fi

    # The exposition is a list of hosts and how reachable each one is. It must
    # not also be a list of the addresses reaching them.
    if [[ ${probe_body} == *"${OP_ADDR}"* ]]; then
        fail "the probe's own address appears in its /metrics"
    else
        ok "no source address appears in the probe's /metrics"
    fi

    # Both, because exec_in runs the probe under `ip netns exec`: killing the
    # job leaves the grandchild, and a probe still holding the metrics port
    # would make a re-run of this phase look like a bind failure.
    kill "${probe_pid}" 2>/dev/null || true
    pkill -f "postern probe ${HOST_NAME}" 2>/dev/null || true
    wait "${probe_pid}" 2>/dev/null || true
}

phase_knock() {
    say "phase 7 — the product: a knock opens the port, and the TTL closes it again"

    assert_probe op "${HOST_ADDR}" "${SSH_PORT}" filtered "before the knock"
    assert_gate_empty postern_open "${SSH_SET}"

    say "postern open, from the operator's namespace"
    run client open "${HOST_NAME}" ssh --ttl 60s
    local open_rc=$?
    [ ${open_rc} -eq 0 ] || fail "postern open exited ${open_rc}, want 0"
    run nft list set inet postern_open "${SSH_SET}"
    assert_gate_open_for postern_open "${SSH_SET}" "${OP_ADDR}"
    assert_ssh_banner op
    assert_probe op "${HOST_ADDR}" "${CANARY_PORT}" filtered "only the knocked service opened"

    # Design section 8: "the agent's endpoint binds to the always-allow
    # interface or localhost". These two probes are that sentence, asserted
    # against the shipped binary run by systemd rather than against a helper
    # function. The endpoint was asked for as ":${METRICS_PORT}", with no
    # host, which the agent resolves to the always-allow interface — so it
    # answers on mesh0 and there is nothing on the untrusted interface to
    # answer at all. A wildcard bind would make the second probe "connected",
    # and neither the ruleset nor any postern output would say so.
    say "the metrics endpoint is on the always-allow interface and nowhere else"
    assert_probe mesh "${MESH_ADDR}" "${METRICS_PORT}" connected \
        "/metrics answers over the always-allow path"
    assert_probe op "${HOST_ADDR}" "${METRICS_PORT}" refused \
        "nothing is listening on ${METRICS_PORT} on the untrusted interface, so the endpoint did not bind the wildcard"
    # At least one, not exactly one: the agent has been up since phase 2 and
    # earlier phases knocked ssh too, so a count pinned to this phase's opens
    # would assert the sequence's history rather than the wiring.
    assert_metric_at_least 'postern_gate_opens_total{service="ssh"}' 1 \
        "the opens nft(8) has been showing are the ones the agent counted"
    assert_metric 'postern_gate_open_sources{service="ssh",source_kind="observed"} 1' \
        "gate state is published as a count, and the admitted address is not in it"
    if [[ $(scrape) == *"${OP_ADDR}"* ]]; then
        fail "the admitted source ${OP_ADDR} appears in /metrics; which addresses are admitted is close to who is logged in from where"
    else
        ok "no admitted source address appears anywhere in /metrics"
    fi

    say "a second knock while the gate is live refreshes the TTL rather than stacking"
    sleep 12
    local before after count
    before=$(nft list set inet postern_open "${SSH_SET}" | grep -o 'expires [0-9]*s' | head -1)
    note "expires before the second knock: ${before}"
    local before_s
    before_s=${before#expires }; before_s=${before_s%s}
    run client open "${HOST_NAME}" ssh --ttl 60s

    # Two mechanisms protect this assertion, and the next person to see it
    # flake needs both, or they will simplify it back into a race.
    #
    # POLLED rather than read once. `postern open` returns when its own confirm
    # connect succeeds, and that connect succeeds against the gate the *first*
    # knock opened — so the command returning says nothing about whether the
    # agent's packet loop has applied the second datagram yet. A single read
    # here races that loop and reports a refresh that landed a few milliseconds
    # later as a refresh that never happened: a harness bug wearing the costume
    # of a product bug. Observed failing exactly that way.
    ttl_went_back_up() {
        local now
        now=$(nft list set inet postern_open "${SSH_SET}" | grep -o 'expires [0-9]*s' | head -1)
        now=${now#expires }
        now=${now%s}
        [ -n "${now}" ] && [ -n "${before_s}" ] && [ "${now}" -gt "${before_s}" ]
    }
    # And RETRIED, which is the second mechanism. A knock is one UDP datagram
    # and UDP does not guarantee delivery, so "the TTL went up after exactly
    # one knock" asserts a property the transport does not have. This failed on
    # five of seven runs doing exactly that — and the counters printed below
    # are how that was established rather than guessed: on every failure
    # postern_spa_datagrams_total was unchanged, so the datagram never reached
    # the agent's socket at all and no amount of waiting would have helped.
    #
    # What is under test here is that a knock against a live gate refreshes it
    # rather than stacking a second element, so the knock is retried, bounded,
    # and the count is reported. A gate that never refreshes still fails. A
    # datagram that went missing shows up as a retry in the output instead of
    # as a red assertion about the wrong thing.
    local knocks=1 attempt
    for attempt in 1 2 3; do
        local waited=0
        while [ "${waited}" -lt 8 ]; do
            ttl_went_back_up && break 2
            sleep 2
            waited=$((waited + 2))
        done
        ttl_went_back_up && break
        note "no refresh after ${knocks} knock(s); knocking again"
        run client open "${HOST_NAME}" ssh --ttl 60s
        knocks=$((knocks + 1))
    done

    if ttl_went_back_up; then
        ok "the remaining TTL went back up from ${before_s}s after ${knocks} knock(s) — a knock against a live gate refreshes it"
        if [ "${knocks}" -gt 1 ]; then
            note "NOTE: ${knocks} knocks were needed. Each knock is a single UDP datagram; check postern_spa_datagrams_total below to see whether the lost one reached the agent at all."
            scrape | grep -E '^postern_spa_datagrams_total|^postern_spa_rejections_total' || true
        fi
    else
        fail "the TTL did not increase after ${knocks} knocks; a knock against a live gate is not refreshing it"
        # A knock that changed nothing is either a datagram that never reached
        # the agent or one it rejected, and those call for completely different
        # investigations. The counters separate them.
        note "SPA counters at the moment of the failure:"
        scrape | grep -E '^postern_spa|^postern_agent_health_red|^postern_gate_opens_total' || true
        journalctl -u posternd.service --no-pager -n 20 || true
    fi

    run nft list set inet postern_open "${SSH_SET}"
    count=$(nft list set inet postern_open "${SSH_SET}" | grep -c "${OP_ADDR}")
    after=$(nft list set inet postern_open "${SSH_SET}" | grep -o 'expires [0-9]*s' | head -1)
    note "expires after the second knock: ${after}"
    if [ "${count}" -eq 1 ]; then
        ok "the set holds exactly one element for ${OP_ADDR} — the knock refreshed rather than stacked"
    else
        fail "the set holds ${count} elements for ${OP_ADDR}; a second knock stacked instead of refreshing"
    fi

    say "an unauthorised key produces silence and changes nothing"
    mkdir -p "${INTRUDER}"
    must postern enroll "${HOST_NAME}" --config "${INTRUDER}/config.yaml" --operator intruder --no-passphrase
    must postern enroll "${HOST_NAME}" --config "${INTRUDER}/config.yaml" --from /root/entry.yaml
    local ruleset_before ruleset_after
    ruleset_before=$(stable_ruleset)
    exec_in op postern open "${HOST_NAME}" canary --config "${INTRUDER}/config.yaml" --timeout 2s --attempts 1
    local intruder_rc=$?
    if [ ${intruder_rc} -ne 0 ]; then
        ok "the intruder's open reported failure (exit ${intruder_rc}) — no port became reachable"
    else
        fail "the intruder's open reported success"
    fi
    ruleset_after=$(stable_ruleset)
    if [ "${ruleset_before}" = "${ruleset_after}" ]; then
        ok "the ruleset is byte-for-byte unchanged after the unauthorised knock"
    else
        fail "the ruleset changed after an unauthorised knock:"
        diff <(printf '%s' "${ruleset_before}") <(printf '%s' "${ruleset_after}") || true
    fi
    assert_probe op "${HOST_ADDR}" "${CANARY_PORT}" filtered "the canary gate did not open for an unknown key"
    run journalctl -u posternd.service --no-pager -n 5

    say "the TTL lapses and the port closes again, with no help from anything"
    poll 120 "the ssh gate set emptied on its own" \
        bash -c "! nft list set inet postern_open ${SSH_SET} | grep -q ${OP_ADDR}"
    run nft list set inet postern_open "${SSH_SET}"
    assert_probe op "${HOST_ADDR}" "${SSH_PORT}" filtered "the gate closed when the kernel expired the element"
    finish "phase 7"
}

phase_kill() {
    say "phase 8 — the agent killed with a corrupt binary on disk"
    note "fail-open must stay open and fail-closed must stay shut, without the postern binary being runnable"

    # #47: the per-set flush lines live in a drop-in the agent owns
    # (posternd.service.d/flush.conf), not in the main unit, so a bundle that
    # changes the catalogue can regenerate them. This SIGKILL teardown only
    # empties a bundle-added gate's grant if systemd actually MERGED that
    # drop-in into the unit — so prove it did before relying on it below. The
    # effective ExecStopPost must carry BOTH the revision-independent
    # postern_open delete (from the unit) and a per-set flush (from the
    # drop-in). A drop-in systemd never loaded would show only the delete.
    assert_file /etc/systemd/system/posternd.service.d/flush.conf present \
        "the flush drop-in was installed at enrollment"
    effective_teardown=$(systemctl show posternd.service --property=ExecStopPost)
    run bash -c "systemctl show posternd.service --property=ExecStopPost | tr ';' '\n' | grep -E 'delete table|flush set' || true"
    if grep -q "delete table inet postern_open" <<<"${effective_teardown}" \
        && grep -q "flush set inet postern_boot" <<<"${effective_teardown}"; then
        ok "systemd merged the unit's postern_open delete and the drop-in's per-set flush into one teardown"
    else
        fail "systemd's effective ExecStopPost is missing the unit delete or the drop-in flush, so a SIGKILL would not empty a fail-closed gate:
${effective_teardown}"
    fi

    run client open "${HOST_NAME}" ssh --ttl 300s
    assert_gate_open_for postern_open "${SSH_SET}" "${OP_ADDR}"

    # Unlink and replace, rather than write over it: the kernel refuses to
    # write to a running executable (ETXTBSY), so the first version of this
    # left the binary perfectly intact and the phase went on to "prove"
    # something about a corrupt binary that was never corrupted. Replacing the
    # inode is also what a bad package upgrade actually does.
    cp /usr/local/bin/postern /root/postern.good
    rm -f /usr/local/bin/postern
    head -c 4096 /dev/urandom >/usr/local/bin/postern
    chmod +x /usr/local/bin/postern
    if cmp -s /root/postern.good /usr/local/bin/postern; then
        fail "the binary on disk is unchanged, so nothing here says anything about a corrupt one"
    else
        ok "the binary on disk has been replaced with 4096 random bytes"
    fi
    # --help is a real subcommand that exits 0 on a working binary, so a
    # non-zero exit here is the kernel refusing to run this file rather than
    # postern refusing a name it does not know. The first version probed with
    # `postern version`, which does not exist, and would have reported an
    # intact binary as unrunnable.
    if /usr/local/bin/postern --help >/dev/null 2>&1; then
        fail "the binary still runs, so this proves nothing about a teardown that does not depend on it"
    else
        ok "the postern binary on disk can no longer be executed"
    fi

    run systemctl kill -s SIGKILL posternd.service
    sleep 3
    run systemctl stop posternd.service
    sleep 2
    nft_dump

    assert_table postern_open absent "ExecStopPost deleted the agent's table with nft(8), not with postern"
    assert_table postern_boot present "the fail-closed posture does not depend on the agent"
    assert_live_has "tcp dport ${CANARY_PORT} drop" "flush set, never flush table: the drop rules are still standing"
    assert_gate_empty postern_boot "${CANARY_SET}"
    assert_ssh_banner op
    assert_probe op "${HOST_ADDR}" "${CANARY_PORT}" filtered "a fail-closed service stays shut when the agent dies"

    say "restore the binary and bring the agent back"
    cp /root/postern.good /usr/local/bin/postern
    must systemctl start posternd.service
    poll 30 "posternd is active again" systemctl is-active --quiet posternd.service
    assert_table postern_open present "the agent recreated its own table"
    assert_file "${STATE}/pending.json" absent "a confirmed revision arms nothing on restart, so no transaction was started"
    finish "phase 8"
}

phase_disarm() {
    say "phase 9 — disarm over SPA"
    must client disarm "${HOST_NAME}"
    poll 30 "postern_boot is gone" bash -c '! nft list table inet postern_boot >/dev/null 2>&1'
    sleep 2
    nft_dump
    assert_table postern_boot absent "disarm removes both tables"
    assert_table postern_open absent "disarm removes both tables"
    assert_file "${ETC}/boot.nft" absent "disarm must clear persistence, or the host re-locks at the next reboot"
    assert_file "${STATE}/state.json" absent "disarm clears the recorded revision"
    assert_enabled disabled "disarm disables the boot unit"
    assert_unit_enabled posternd.service disabled \
        "and the agent unit: a disarmed host must boot as though postern were not installed"
    assert_ssh_banner op
    assert_probe op "${HOST_ADDR}" "${CANARY_PORT}" refused "nothing is gated any more"
    finish "phase 9"
}

phase_after_disarm_reboot() {
    say "phase 10 — after a reboot, the disarm held"
    run systemctl is-system-running --wait || true
    nft_dump
    assert_table postern_boot absent "a disarmed host does not re-lock at the next boot"
    assert_table postern_open absent "a disarmed host does not re-lock at the next boot"
    assert_enabled disabled "the boot unit is still disabled"
    assert_unit_enabled posternd.service disabled "and the agent unit"
    assert_unit_active posternd.service inactive "nothing started postern at this boot"
    assert_ssh_banner op
    assert_probe op "${HOST_ADDR}" "${CANARY_PORT}" refused "no drop rule came back"
    run systemctl status postern-boot.service --no-pager || true
    finish "phase 10"
}

# CR_* are the console-recovery scenario's own paths: a console-recovery host
# is a different enrollment, with no mesh interface at all, so it gets its own
# client identity and its own /etc and /var/lib directories beside the main
# sequence's rather than on top of them. Only the systemd unit directory
# cannot be isolated the same way: postern-boot.service and posternd.service
# are fixed unit names, and systemctl only ever looks in the real unit
# directory, so arming this host through real systemd means writing over the
# main sequence's copies of both units rather than beside them. That is safe
# only because this scenario runs at the tail, after the main sequence has
# disarmed: by then both units are disabled and inert, and nothing after this
# phase reads them again.
CR_CLIENT=/root/.console-recovery
CR_ETC=/etc/postern-console
CR_STATE=/var/lib/postern-console
CR_HOST_NAME=demo-host-console
CONSOLE_URL="https://provider.example/console"

# phase_console_recovery is the whole feature end to end, on a host that
# never had a mesh interface to begin with: init-standalone with
# --console-recovery and no --always-allow-iface, an arm with nothing to run
# the always-allow liveness pre-check against, a live ruleset with the
# fail-closed drops and no iifname accept rule anywhere, a knock over the
# public path, a confirm that ratifies with no --force and no liveness
# pre-check because there is no always-allow address on record to check
# against, and postern disarm --local tearing it back down.
phase_console_recovery() {
    say "phase 11 - a console-recovery host arms with no mesh interface at all"

    say "operator: mint an identity for the console-recovery host"
    mkdir -p "${CR_CLIENT}"
    capture /root/cr-enroll.txt postern enroll "${CR_HOST_NAME}" --config "${CR_CLIENT}/config.yaml" \
        --operator laptop-console --no-passphrase
    cat /root/cr-enroll.txt
    local opflag
    opflag=$(sed -n "s/.*--operator '\(.*\)'.*/\1/p" /root/cr-enroll.txt)
    if [ -z "${opflag}" ]; then
        fail "could not read the operator key pair out of the console-recovery enrollment instructions"
        return
    fi

    say "host: init-standalone with --console-recovery and no --always-allow-iface at all, arming immediately via --go-live"
    capture2 /root/cr-entry.yaml /root/cr-init.stderr postern init-standalone \
        --dir "${CR_ETC}" --state-dir "${CR_STATE}" --unit-dir /etc/systemd/system \
        --host-name "${CR_HOST_NAME}" --knock-addr "${HOST_ADDR}" \
        --console-recovery "${CONSOLE_URL}" \
        --revision 1 \
        --exec-start "/usr/local/bin/postern agent --config ${CR_ETC}/postern.yaml --state-dir ${CR_STATE} --confirm-window 60s --debug" \
        --operator "${opflag}" \
        --go-live
    cat /root/cr-entry.yaml
    cat /root/cr-init.stderr
    run systemctl daemon-reload

    say "the config validated with no always-allow path recorded anywhere"
    if grep -q 'console_recovery: true' "${CR_ETC}/postern.yaml" && grep -q "console: \"${CONSOLE_URL}\"" "${CR_ETC}/postern.yaml"; then
        ok "postern.yaml records console_recovery: true and the console URL"
    else
        fail "postern.yaml does not record console_recovery: true and the console URL"
    fi
    if grep -q 'always_allow_iface' "${CR_ETC}/postern.yaml"; then
        fail "the config carries always_allow_iface; this scenario has no mesh interface at all"
    else
        ok "the config carries no always_allow_iface: there is no mesh path here to fall back on"
    fi
    assert_file "${CR_ETC}/boot.nft" present \
        "init-standalone validated the ruleset with the real nft(8), with no always-allow accept rule to add"

    say "operator: register the host"
    must postern enroll "${CR_HOST_NAME}" --config "${CR_CLIENT}/config.yaml" --from /root/cr-entry.yaml
    assert_file "${CR_CLIENT}/config.yaml" present "the operator can knock this host from here"
    cat "${CR_CLIENT}/config.yaml"
    if grep -q 'always_allow_addr' "${CR_CLIENT}/config.yaml"; then
        fail "the client entry records an always_allow_addr; there is no mesh address here to record"
    else
        ok "the client entry records no always_allow_addr: confirm's liveness pre-check will find nothing to check and skip itself"
    fi

    say "--go-live printed the confirm line the operator runs next"
    local go_live_stderr
    go_live_stderr=$(cat /root/cr-init.stderr)
    assert_says "${go_live_stderr}" "postern confirm ${CR_HOST_NAME} --revision" \
        "the emitted guidance carries the exact command an operator runs to ratify this arm"

    say "the arm --go-live already performed: posternd is active, with no always-allow path for a pre-arm check to fail over"
    poll 30 "posternd is active" systemctl is-active --quiet posternd.service
    run journalctl -u posternd.service --no-pager -n 30
    assert_unit_active posternd.service active \
        "the agent armed rather than going inert; console-recovery is exactly the case where there is no always-allow path to verify"

    local journal
    journal=$(journalctl -u posternd.service --no-pager)
    if [[ ${journal} == *"console_recovery is set"* ]]; then
        ok "the agent logged the console-recovery warning on this load"
    else
        fail "the agent did not log the console-recovery warning on load"
    fi

    say "the pair the agent published before it armed"
    cr_pending_field() { # cr_pending_field <json key>
        sed -n "s/.*\"$1\": *\"\{0,1\}\([^\",]*\)\"\{0,1\},\{0,1\}/\1/p" "${CR_STATE}/pending.json" | head -1
    }
    assert_file "${CR_STATE}/pending.json" present "the arm step publishes the revision and nonce a confirm must carry"
    cat "${CR_STATE}/pending.json"
    local rev nonce outcome
    rev=$(cr_pending_field revision); nonce=$(cr_pending_field deployment_nonce); outcome=$(cr_pending_field outcome)
    note "revision=${rev} nonce=${nonce} outcome=${outcome}"
    [ "${rev}" = "1" ] || fail "published revision = ${rev}, want 1"
    [ "${outcome}" = "pending" ] || fail "published outcome = ${outcome}, want pending"
    [ ${#nonce} -eq 32 ] || fail "published nonce ${nonce} is not 32 hex characters"

    say "what arming did to the host: the live boot.nft has the fail-closed drops and no always-allow accept rule anywhere"
    assert_table postern_boot present "the arm step loaded the generated ruleset"
    assert_table postern_open present "the agent creates its own table at startup"
    assert_enabled enabled "the arm step enables the boot unit, so the posture survives a reboot"
    assert_unit_enabled posternd.service enabled "the arm step enables the agent too"
    assert_live_has "tcp dport ${SSH_PORT} drop" "the break-glass service is gated, the same as the mesh host"
    assert_live_lacks "iifname" "there is no always-allow interface to accept from: that is the entire point of console-recovery mode"
    assert_agent_up_holds_the_lease "without the lease the SPA port drops and this host cannot be knocked at all"
    assert_probe op "${HOST_ADDR}" "${SSH_PORT}" filtered "an armed console-recovery host drops ssh from an unknocked source"
    nft_dump

    say "the product: a knock over the public path opens the gate, with no mesh anywhere on this host"
    cr_client() { exec_in op postern "$@" --config "${CR_CLIENT}/config.yaml"; }
    assert_probe op "${HOST_ADDR}" "${SSH_PORT}" filtered "before the knock"
    assert_gate_empty postern_open "${SSH_SET}"
    run cr_client open "${CR_HOST_NAME}" ssh --ttl 60s
    local open_rc=$?
    [ ${open_rc} -eq 0 ] || fail "postern open exited ${open_rc}, want 0"
    assert_gate_open_for postern_open "${SSH_SET}" "${OP_ADDR}"
    assert_ssh_banner op

    say "confirm ratifies with no --force and no liveness pre-check: there is no always-allow address to check against"
    must cr_client confirm "${CR_HOST_NAME}" --revision "${rev}" --nonce "${nonce}"
    poll 30 "the confirm was recorded" test -f "${CR_STATE}/state.json"
    cat "${CR_STATE}/state.json"
    assert_file "${CR_STATE}/pending.json" absent "a confirmed configuration is no longer waiting for anything"

    say "postern disarm --local on the host tears it down, with no agent involved"
    must postern disarm --local --dir "${CR_ETC}" --state-dir "${CR_STATE}"
    # disarm --local's own output documents that posternd may still be
    # running and may recreate postern_open before the next boot; stopping
    # it here is the follow-up the tool names, and it is what makes the
    # absence assertions below honest rather than a race against the agent
    # that is still alive underneath them.
    run systemctl stop posternd.service
    poll 30 "postern_boot is gone" bash -c '! nft list table inet postern_boot >/dev/null 2>&1'
    sleep 2
    nft_dump
    assert_table postern_boot absent "disarm --local removes both tables"
    assert_table postern_open absent "disarm --local removes both tables"
    assert_file "${CR_ETC}/boot.nft" absent "disarm --local clears persistence, or the host re-locks at the next reboot"
    assert_file "${CR_STATE}/state.json" absent "disarm --local clears the recorded revision"
    assert_enabled disabled "disarm --local disables the boot unit"
    assert_unit_enabled posternd.service disabled "and the agent unit: a disarmed host must boot as though postern were not installed"
    assert_ssh_banner op
    assert_probe op "${HOST_ADDR}" "${CANARY_PORT}" refused "nothing is gated any more"
    finish "phase 11"
}

# FP_* are the fixed-port opt-out scenario's own paths, isolated the same way
# CR_* is above and for the same reason: its own client identity and its own
# /etc and /var/lib directories, but the same fixed postern-boot.service and
# posternd.service unit names, so it can only run at the tail, after
# console-recovery has disarmed and left both units disabled and inert.
FP_CLIENT=/root/.fixed-port
FP_ETC=/etc/postern-fixed
FP_STATE=/var/lib/postern-fixed
FP_HOST_NAME=demo-host-fixed

# phase_fixed_port_optout is case 3 of the rotating-knock-port testing
# section: --no-port-rotation is not collateral damage from rotation becoming
# the default. Every other host in this sequence enrolls with rotation on
# (phase_setup and phase_console_recovery pass neither --spa-port nor
# --no-port-rotation); this one explicitly opts out and has to come out the
# other side with the pre-rotation ruleset shape, byte for byte, and a knock
# that still opens ssh.
phase_fixed_port_optout() {
    say "phase 12 - a fixed-port opt-out host is not collateral damage from rotation-by-default"

    say "operator: mint an identity for the fixed-port host"
    mkdir -p "${FP_CLIENT}"
    capture /root/fp-enroll.txt postern enroll "${FP_HOST_NAME}" --config "${FP_CLIENT}/config.yaml" \
        --operator laptop-fixed --no-passphrase
    cat /root/fp-enroll.txt
    local opflag
    opflag=$(sed -n "s/.*--operator '\(.*\)'.*/\1/p" /root/fp-enroll.txt)
    if [ -z "${opflag}" ]; then
        fail "could not read the operator key pair out of the fixed-port enrollment instructions"
        return
    fi

    say "host: init-standalone --no-port-rotation --spa-port ${SPA_PORT}, arming immediately via --go-live"
    capture2 /root/fp-entry.yaml /root/fp-init.stderr postern init-standalone \
        --dir "${FP_ETC}" --state-dir "${FP_STATE}" --unit-dir /etc/systemd/system \
        --host-name "${FP_HOST_NAME}" --knock-addr "${HOST_ADDR}" \
        --always-allow-iface mesh0 --recovery-service ssh \
        --ssh-host "${HOST_ADDR}" --ssh-user root \
        --revision 1 \
        --exec-start "/usr/local/bin/postern agent --config ${FP_ETC}/postern.yaml --state-dir ${FP_STATE} --confirm-window 60s --debug" \
        --operator "${opflag}" \
        --no-port-rotation --spa-port "${SPA_PORT}" \
        --go-live
    cat /root/fp-entry.yaml
    cat /root/fp-init.stderr
    run systemctl daemon-reload

    say "operator: register the host"
    must postern enroll "${FP_HOST_NAME}" --config "${FP_CLIENT}/config.yaml" --from /root/fp-entry.yaml
    assert_file "${FP_CLIENT}/config.yaml" present "the operator can knock this host from here"
    cat "${FP_CLIENT}/config.yaml"
    if grep -q 'port_rotation' "${FP_CLIENT}/config.yaml"; then
        fail "the fixed-port host entry carries a port_rotation block; --no-port-rotation must not emit one"
    else
        ok "the fixed-port host entry carries no port_rotation block"
    fi

    say "what arming did to the host: the single fixed-port drop, not the range"
    poll 30 "posternd is active" systemctl is-active --quiet posternd.service
    run journalctl -u posternd.service --no-pager -n 30
    assert_table postern_boot present "the arm step loaded the generated ruleset"
    assert_table postern_open present "the agent creates its own table at startup"
    assert_live_has "udp dport ${SPA_PORT} drop" "the single fixed port is gated, exactly as every host was before rotation existed"
    assert_live_lacks "udp dport ${ROTATION_RANGE_LO}-${ROTATION_RANGE_HI} drop" \
        "no range drop anywhere: --no-port-rotation must not leave rotation's rule behind alongside its own"
    assert_agent_up_holds_the_lease "without the lease the SPA port drops and the host cannot be knocked at all" "${SPA_PORT}"
    assert_probe op "${HOST_ADDR}" "${SSH_PORT}" filtered "an armed fixed-port host drops ssh from an unknocked source"

    say "confirm ratifies the arm, over the public path, the same as the main sequence's phase 4"
    fp_client() { exec_in op postern "$@" --config "${FP_CLIENT}/config.yaml"; }
    fp_pending_field() { # fp_pending_field <json key>
        sed -n "s/.*\"$1\": *\"\{0,1\}\([^\",]*\)\"\{0,1\},\{0,1\}/\1/p" "${FP_STATE}/pending.json" | head -1
    }
    assert_file "${FP_STATE}/pending.json" present "the arm step publishes the revision and nonce a confirm must carry"
    cat "${FP_STATE}/pending.json"
    local rev nonce
    rev=$(fp_pending_field revision); nonce=$(fp_pending_field deployment_nonce)
    [ "${rev}" = "1" ] || fail "published revision = ${rev}, want 1"
    must fp_client confirm "${FP_HOST_NAME}" --revision "${rev}" --nonce "${nonce}" --force
    poll 30 "the confirm was recorded" test -f "${FP_STATE}/state.json"
    cat "${FP_STATE}/state.json"
    assert_file "${FP_STATE}/pending.json" absent "a confirmed configuration is no longer waiting for anything"

    say "the product: a fixed-port knock opens ssh, opt-out is not collateral damage"
    assert_probe op "${HOST_ADDR}" "${SSH_PORT}" filtered "before the knock"
    assert_gate_empty postern_open "${SSH_SET}"
    run fp_client open "${FP_HOST_NAME}" ssh --ttl 60s
    local open_rc=$?
    [ ${open_rc} -eq 0 ] || fail "postern open exited ${open_rc}, want 0"
    assert_gate_open_for postern_open "${SSH_SET}" "${OP_ADDR}"
    assert_ssh_banner op
    finish "phase 12"
}

case "${1:-}" in
setup) phase_setup ;;
arm-revert) phase_arm_revert ;;
after-revert-reboot) phase_after_revert_reboot ;;
arm-confirm) phase_arm_confirm ;;
after-confirm-reboot) phase_after_confirm_reboot ;;
probe) phase_probe ;;
knock) phase_knock ;;
kill) phase_kill ;;
disarm) phase_disarm ;;
after-disarm-reboot) phase_after_disarm_reboot ;;
console-recovery) phase_console_recovery ;;
fixed-port-optout) phase_fixed_port_optout ;;
*)
    echo "usage: e2e.sh <phase>" >&2
    exit 2
    ;;
esac
