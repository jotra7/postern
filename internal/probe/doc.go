// Package probe is postern's external evidence: the canary sweep that
// establishes, from outside the host, that a knock still opens a gate.
//
// It is a client role. It holds an operator identity granted the canary
// service, knocks, and measures; it never runs on the gated host, never
// touches nftables, and must build and run on macOS.
//
// # Why the probe exists at all
//
// Everything else postern reports about itself is self-attestation. The
// agent's heartbeat says the ruleset it installed hashes to what it
// planned; `postern open` says a connect succeeded. Neither establishes
// that UDP reaches the host, that the provider firewall permits the path,
// that the agent processes SPA, that the rule installs, or that the service
// becomes reachable — and those are the five things that rot. Design
// section 8 puts the probe in M1 for exactly that reason.
//
// The point is sharper than "a second opinion". `postern open` against a
// host with no agent and no firewall tables at all reports the port
// reachable, because the service was never filtered. The client says so
// honestly — Advise sets GateUnproven — but the client cannot supply the
// missing evidence from where it stands. The probe can, because it asserts
// on the *closed* state first.
//
// # The contract
//
//	phase 1  gate closed → connect to canary port → timeout   (packet DROPped)
//	         send SPA for service "canary"
//	phase 2  gate open   → connect to canary port → RST       (accepted, nothing listening)
//
// Both phases are asserted every sweep (invariant I2). Checking only phase
// 2 cannot distinguish a working gate from a missing drop rule where every
// connect returns RST — which is to say, from a host with no firewall at
// all. A sweep whose phase 1 returns RST is a failure, not a pass. A probe
// that got this wrong would report green on precisely the state it exists
// to catch, which is worse than shipping no probe: it manufactures
// confidence.
//
// # What a failed sweep does and does not distinguish
//
// Sweep records a Reason, and each one rules a different set of things in
// and out. The honest boundaries are in Sweep.Detail and are worth stating
// here too, because a category an operator cannot trust is worse than an
// unfamiliar error string (the same reasoning as client.Classify):
//
//   - ReasonGateNotClosed — phase 1 answered. The canary port is reachable
//     with no gate open. Consistent with a missing drop rule, a flushed
//     postern_boot, a host that was never armed, and a host where postern
//     was uninstalled without disarming. Not consistent with a working
//     gate, which is the whole point.
//   - ReasonListenerPresent — phase 1 answered by *connecting*. Everything
//     above, plus something is listening on a port declared
//     listener_expectation: absent, which design section 4 calls red on its
//     own: it converts the probe identity from "can open a port with
//     nothing behind it" into "can open a reachable service".
//   - ReasonGateNotOpened — phase 1 was correct and phase 2 timed out. This
//     is the same three-way ambiguity client.Advise names for a timed-out
//     open, and the probe cannot resolve it either: the datagram was
//     dropped upstream, the agent is not running, or the probe's own egress
//     address differs between UDP and TCP.
//   - ReasonNoRoute — the network rejected the connect before it left. The
//     knock cannot have arrived either; this is connectivity, not
//     authorization.
//
// # Cadence
//
// DefaultInterval is deliberately not a multiple of the 60-second
// heartbeat, and is jittered, so the two do not phase-lock and sample the
// same moment forever. Three consecutive failures turn a host red.
//
// # Reporting
//
// Hub-less in M1. The probe emits through a Metrics interface it owns —
// see metrics.go for what it expects to be wired to — and optionally posts
// each sweep to a webhook. The hub aggregates from M2; nothing here knows
// about a hub.
package probe
