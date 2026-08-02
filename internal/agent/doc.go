// Package agent is postern's daemon and the packet-validation pipeline it
// runs on.
//
// # The pipeline
//
// Validate assembles Phase A's independently-tested packages (internal/spa,
// internal/config, internal/replay) into the validation order design section
// 5 describes: the function that decides whether one attacker-controlled
// datagram, arriving as root on a port that never replies, is allowed to
// open a port or run a command. It performs no I/O beyond the replay store —
// it does not touch the network and it does not touch the firewall — and
// returns a Decision the daemon applies through internal/gate.
//
// The three security properties the pipeline owns, carried forward from
// Phase A's whole-branch review because no package before it could exercise
// the seam where each lives, are documented at
// docs/phase-b-carry-forward.md: the replay retention formula (read live off
// Policy on every call, never cached), packet-kind versus service-kind
// agreement (checked before any kind-specific payload is read), and
// asserted-source validation (Grant.AllowsSource, wired in at last).
//
// # The daemon
//
// Daemon is the long-running process. Three things about its shape are load
// bearing, and each of them is a property rather than an implementation
// detail:
//
// Pre-arm degrades per service. Global preconditions keep the agent inert
// because nothing works without them. A per-service precondition — a
// listener_expectation mismatch, ports that cannot be armed — disables that
// service and nothing else. An all-or-nothing gate would let a postgres
// daemon that failed to restart silence SPA for ssh, so a database outage
// would remove the door built for outages.
//
// agent_up is renewed by the packet loop itself, from the same beat that
// feeds the systemd watchdog. A renewal goroutine independent of packet
// processing would keep the lease alive while the loop is wedged, leaving
// the SPA port open and accepting into an agent that does nothing with what
// it receives — worse than being silent, because the operator's client
// reports the packet sent and then times out on connect. A failed renewal is
// its own immediate red transition and does not feed the watchdog.
//
// Confirm-or-revert is transactional over four artifacts: the live
// postern_boot table, boot.nft, the two units' enabled states, and the
// recorded hashes. Both units, not the boot unit alone: a revert that
// re-enabled the boot unit while leaving the agent unit disabled is the
// fail-closed-drops-load-but-nothing-opens-them lockout row (see
// transaction.go). A revert that restores the live table alone looks
// successful and re-locks the host at the next reboot. Prepare snapshots and
// mints the deployment nonce without changing anything, so the nonce reaches
// the client before the ruleset that might break the channel it travels on.
//
// # What the daemon deliberately does not own
//
// postern_boot. It is loaded at boot by a oneshot unit running nft(8),
// before the agent runs and independently of it. The agent creates only
// postern_open, which has no on-disk form and no boot persistence. Teardown
// is likewise not the agent's alone: the unit's ExecStopPost lines
// (rendered by internal/gate) perform the same teardown from outside the
// process, so a crash lands in the same firewall state as a clean stop.
//
// Nothing here is a binary. New and Run are the entry points; cmd/postern
// wires them to flags and a config file.
package agent
