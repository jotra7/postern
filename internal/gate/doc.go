// Package gate is postern's firewall backend: it opens a source address for
// a named service with a kernel-managed TTL, and it renders the boot-time
// ruleset that keeps fail-closed services shut when the agent is not
// running.
//
// # Two sets per gated service
//
// docs/spikes/2026-07-27-nft-interval-timeout.md measured the nftables
// property this package is built around: inserting a prefix whose range
// overlaps one already live in a set fails with EEXIST, in either insertion
// order, regardless of whether the two prefixes share a boundary. Only an
// insert of an *identical* element while it is live is safe unconditionally
// — that re-insert succeeds with no error and refreshes the timeout in
// place (confirmed by an unchanged raw element-record count, not just
// boolean membership, since a silent duplicate would read as "still a
// member" too).
//
// Those two facts push in opposite directions for the two shapes of source
// this package ever inserts:
//
//   - An observed source (the SPA packet's UDP source address) is always a
//     single address, /32 or /128. The dominant write against its set is an
//     operator's retry of the same knock — the identical-key re-insert path,
//     which the spike shows is always safe. Distinct observed addresses
//     never overlap by construction, since single-address ranges cannot
//     partially overlap without being equal.
//   - An asserted source (an operator-supplied CIDR inside the signed
//     packet) is a prefix that can genuinely overlap another live prefix —
//     two operators asserting adjacent or nested ranges, or the same
//     operator re-knocking with a differently-sized assertion. That path
//     needs interval semantics to hold a range at all, and needs to expect
//     and handle EEXIST as a real, occasional outcome rather than a
//     surprise.
//
// Putting both shapes in one set would make the common case (an identical
// re-insert refreshing cleanly) share failure modes with the rare case (a
// genuine overlap collision), and a set that must handle both correctly
// needs interval semantics it does not need for its dominant write. So each
// gated service gets two sets per address family instead of one:
//
//   - a plain set, flags timeout only, for observed addresses — no interval
//     support needed, because every element is a /32 or /128 and overlap
//     cannot arise between two single addresses;
//   - an interval,timeout set for asserted CIDRs — the only path that
//     actually needs interval semantics, and where the spike's overlap
//     behaviour is expected and handled rather than treated as anomalous.
//
// # Re-adding a live element does not refresh it
//
// Read this before writing anything that keeps an element alive on a
// schedule. Getting it wrong has now cost two bugs in this package, both
// silent, and the second one took break-glass access away intermittently for
// a week without moving a single counter.
//
// On this kernel, NFT_MSG_NEWSETELEM for a key that is already present
// returns success and leaves the original expiry in place — **when the
// timeout value in the request is identical to the live element's**. Passing
// a *different* timeout value does reset the timer. Measured directly:
//
//	add    62201 timeout 90s  → after 10s: expires 1m19s985ms
//	re-add 62201 timeout 90s  → expires 1m19s975ms   (ignored)
//	re-add 62201 timeout 91s  → expires 1m30s997ms   (reset)
//
// The spike in docs/spikes/2026-07-27-nft-interval-timeout.md concluded that
// an identical-key re-insert refreshes cleanly. That conclusion is wrong, and
// wrong in a way that reads as thorough: its identical-key case re-inserted
// with ttl 3s and then 9s, so it only ever exercised the branch that works.
// Open was fixed for this once the real behaviour surfaced; RefreshAgentUp
// was not, and RefreshAgentUp is the one caller that always passes the same
// constant, so it is where the bug always bit rather than occasionally.
//
// So: every write that must extend a live lease deletes the element and adds
// it back in the same batch, guarded by a read that the element is actually
// there (deleting an absent key aborts the batch). Both current writers —
// Open and RefreshAgentUp — do this. A third one must too, and must not rely
// on the caller happening to vary the ttl.
//
// # The script backend, and what it cannot promise
//
// A `kind: gate` service may set `backend: script` and hand its admissions to
// an operator-supplied executable — a cloud provider's firewall, a load
// balancer, an appliance. See script.go for the contract and dispatch.go for
// how a host runs both backends at once.
//
// nftables does not become optional. It keeps agent_up, the SPA port's
// concealment, boot.nft, and every fail-posture drop rule, on every host,
// whatever the services declare. What moves is one service's admissions, and
// that service gets no nftables sets and no nftables rules at all — including
// no drop rule, which would otherwise be the only rule that ever matched.
//
// **Read this part before deploying one.** Everything above rests on the
// kernel expiring set elements: no reaper can fail, and a crashed agent
// cannot leave a gate wedged open. A script backend cannot offer that. Most
// targets have no per-entry TTL at all — a security group rule has no expiry
// field — so the deadline lives in a durable lease store beside the replay
// store, and a goroutine inside the agent acts on it.
//
// The consequence, stated plainly rather than left to be discovered:
//
//   - A clean stop withdraws the admissions. Script.Close invokes the close
//     verb for every outstanding lease.
//   - A crash — SIGKILL, an OOM kill, power loss — leaves them. The next
//     start recovers the schedule from the lease file and its reaper catches
//     up.
//   - An agent that never comes back leaves them indefinitely.
//
// That is strictly weaker than either documented fail posture, and it is why
// the config loader warns on every script-backed service (config.Service.
// Warnings) and the README's posture table carries its own row for it.
//
// `fail_posture: closed` is refused outright on a script-backed service
// rather than warned about. The distinction is that "open" is a description
// this backend can honour — the local kernel really does drop nothing for
// that service when the agent is absent — while "closed" is a promise kept by
// boot.nft loading a drop rule before the agent exists, and a script has no
// boot-time form. There is no state in which a script-backed service is shut
// and the agent is absent. Accepting the word while delivering none of the
// mechanism is how a posture silently inverts, which is what every other
// control in this package exists to prevent.
//
// The intended deployment is both: an nftables gate on the port and a
// script-backed gate on the same port, which port-ownership validation
// permits because it is enforced per backend. The kernel then holds the local
// bolt with a real timeout on it while the script handles the perimeter, so a
// crashed agent leaves a provider rule pointing at a port the kernel has
// already shut.
//
// That is two accept rules per service per address family (one per set)
// instead of one, and RulesetPlan (plan.go) is the single place that
// decides their names and shape — the netlink writer, the boot.nft text
// renderer, and the systemd unit's flush-line renderer all consume the same
// plan, which is what makes renderer equivalence (invariant 6) a testable
// property instead of an assumption. See task-1-brief.md for the contract
// this package implements and docs/superpowers/specs/2026-07-27-postern-design.md
// section 4 for the surrounding table layout.
package gate
