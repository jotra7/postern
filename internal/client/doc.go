// Package client is the operator's half of postern: the code behind open,
// status, confirm, and disarm.
//
// It is the only package in this project that must build and run on a
// laptop. An operator knocks from macOS, so nothing here may import
// internal/gate's netlink writer or anything else that is Linux-only, and
// nothing here touches a firewall. The agent's half of every exchange lives
// in internal/agent.
//
// # Nothing resolves a name
//
// LoadConfig refuses a knock_addr that is not an IP literal. That looks
// severe for a configuration field until you notice when this code runs: the
// mesh is down, the operator is locked out, and DNS is one of the things
// that may be down with it. Design section 6 makes the same point from the
// other direction — knock_addr exists so a CDN-fronted host can be knocked
// at its origin rather than at whatever edge its name resolves to. A
// hostname in that field would put a resolver on the critical path of an
// emergency open and silently send the packet somewhere else on a proxied
// domain. Both the knock and the confirmation connect therefore go to
// knock_addr.
//
// # status goes somewhere else, and both of its assertions go there together
//
// The one exception to "everything goes to knock_addr" is `status`. A liveness
// pong is emitted only for a ping that arrived on the host's always-allow
// interface, so a ping sent to the public address is refused in silence, which
// is the same silence a dead agent produces. The host entry records the host's
// address on that interface as always_allow_addr, and Status sends its ping
// and its recovery connect to that one address; on a host where the two
// collapse to the same address, or on an entry that predates the field, it
// falls back to knock_addr. That field is an IP literal too, and for the extra
// reason that `status` is what answers whether the always-allow path still
// carries anyone.
//
// # The confirmation is a diagnosis, not a status line
//
// The SPA path never replies (design section 5), so the only evidence a
// gate opened is that the target service became reachable. Confirm draws
// the three distinctions that evidence supports — no route, timeout,
// refused — and Advise turns them into the sentence an operator needs at
// the moment they are locked out. The timeout case is the one that earns
// its length: on cellular and hotel wifi some carrier NATs egress UDP and
// TCP from different pool addresses, so the gate opens for the address the
// knock arrived from while the TCP connect arrives from another. The client
// cannot discover its own pool, so the mitigation is the --source-cidr
// hint and nothing else. See design section 5, "Source address".
package client
