// Package hub is the fleet control plane: a bundle store and a heartbeat
// sink, served over one public listener that carries exactly those two
// routes, plus an optional private listener for the operator running it.
//
// # Two listeners, and which fact goes on which
//
// The public listener answers anyone. What it will tell a stranger is bounded
// by what a stranger already had to know to ask: a bundle fetch confirms that
// some host_id exists, and only for a host_id the caller could already name.
// Everything that is a fact about the fleet rather than about one host the
// caller already knew of belongs on the private listener Config.MetricsAddr
// opens: fleet size on /metrics, and on BeatsPath which hosts have gone quiet.
// Serve refuses to start if the two addresses are the same, since a hub that
// collapsed them would be publishing the second set to everyone who could ask
// for the first.
//
// # The hub is not in the path of a knock
//
// This is the load-bearing property of the whole package, not a preference.
// The hub is a management convenience — design section 2's split-plane
// invariant is that a knock succeeds whether the hub is up, down,
// unreachable, or actively hostile. Nothing in this package is imported by
// internal/agent's SPA path, and internal/agent must never import
// internal/hub at all: an agent that waited on this package, or that failed
// closed because it could not reach it, would have put the control plane
// back in the one path this project exists to keep it out of.
//
// # The store holds ciphertext it cannot read
//
// Store.Bundle returns exactly the bytes bundle.Seal produced: opaque to
// the hub, opaque to anyone who fetches it without the target host's
// private key. A compromised hub can tell an observer who is asking for
// what, how often, and how large the answer was — request sources, timing,
// fetch frequency, ciphertext size, and so fleet size and rough policy size
// (design section 6) — but not a single byte of the policy itself. That is
// the bound: contents are protected, metadata is not, and nothing in this
// package narrows or widens it.
//
// The one place an operator-controlled string reaches the filesystem is the
// host_id path element on a bundle fetch. ParseHostID rejects anything that
// is not a clean 16-byte value before it is used for anything, and every
// exported Store method past that point takes hostID [16]byte rather than a
// string — so there is no code path left where a request's raw text could
// be concatenated into a filename.
//
// # Heartbeats are not persisted
//
// Beats keeps only the latest (epoch, sequence) per host, in memory, lost on
// restart. That is a deliberate choice, not an omission: a restarted hub
// that starts accepting a lower sequence than it saw before is a smaller
// problem than the hub becoming a durable database, which the dependency cap
// (no database, ever) and the hub's whole "management convenience" framing
// both argue against. It is also a problem this design already tolerates
// structurally — absence is a signal (design section 8): a host that has
// sent nothing since a hub restart looks exactly like a host that has sent
// nothing at all, and both read as "not fresh" to anything that checks
// Beats.Latest's age against a max. A hub outage does not make a dead host
// look alive; it makes a live host look briefly unmonitored, which is the
// gap this project accepts here in exchange for not shipping a database.
//
// # Signature before sequence, always
//
// A beat that fails attest.Verify must never reach Beats.Accept. The two
// checks guard different attacks and neither substitutes for the other:
// Verify stops forgery, and Accept's epoch-then-sequence ordering stops a
// captured, genuinely signed beat from being replayed to hold a dead host
// green forever. But letting an unverified beat's claimed (epoch, sequence)
// into the sequence store at all would let an attacker who cannot forge a
// signature still park a host's recorded epoch at its maximum — locking out
// every legitimately signed beat that host sends afterward, since none of
// them could ever claim a higher epoch. server.go verifies before it ever
// calls Accept, and never the other way around.
package hub
