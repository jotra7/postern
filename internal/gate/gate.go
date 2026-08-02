package gate

import (
	"context"
	"fmt"
	"net/netip"
	"time"
)

// SourceKind distinguishes an address observed from a packet's UDP source
// from one an operator explicitly asserted inside the signed payload. See
// the package doc: the two land in different nftables sets so that the
// dominant write (an identical observed-address re-insert) never shares a
// set, and therefore never shares a failure mode, with the rarer asserted
// CIDR path where overlap is a real outcome.
type SourceKind int

const (
	// SourceObserved is the packet's UDP source address, always a single
	// address (Prefix.Bits() == Prefix.Addr().BitLen()).
	SourceObserved SourceKind = iota
	// SourceAsserted is an operator-supplied CIDR from the signed payload.
	SourceAsserted
)

func (k SourceKind) String() string {
	switch k {
	case SourceObserved:
		return "observed"
	case SourceAsserted:
		return "asserted"
	default:
		return "unknown"
	}
}

// Source is one address or CIDR to admit through a gate.
type Source struct {
	Kind   SourceKind
	Prefix netip.Prefix
}

// normalizeSource unmaps an IPv4-mapped IPv6 address and reports the
// address family the source belongs in, the same unmapping
// config.Grant.AllowsSource performs and for the identical reason: an
// unmapped ::ffff:0.0.0.0/96-shaped prefix must be measured, and stored,
// as IPv4, not as a /96-or-narrower slice of the IPv6 space.
//
// It lives here, untagged, rather than beside the netlink writer that first
// needed it: the script backend hands the same prefix to a subprocess and
// must hand it over in the same normalized form, and a second copy of this
// unmapping is exactly how one backend would come to admit ::ffff:10.0.0.1/104
// while the other admitted 10.0.0.1/8.
func normalizeSource(src Source) (Source, AddrFamily, error) {
	if !src.Prefix.IsValid() {
		return Source{}, 0, fmt.Errorf("gate: source prefix is invalid")
	}
	addr := src.Prefix.Addr()
	bits := src.Prefix.Bits()
	if addr.Is4In6() {
		addr = addr.Unmap()
		bits -= 96
	}
	norm := Source{Kind: src.Kind, Prefix: netip.PrefixFrom(addr, bits)}
	if addr.Is4() {
		return norm, FamilyIPv4, nil
	}
	if addr.Is6() {
		return norm, FamilyIPv6, nil
	}
	return Source{}, 0, fmt.Errorf("gate: source prefix %s has no recognized address family", src.Prefix)
}

// ElementState is one live element read back from a gate's sets.
type ElementState struct {
	Source  Source
	Expires time.Duration
}

// ServiceState is a gate service's currently open sources.
type ServiceState struct {
	Service  string
	Elements []ElementState
}

// Health reports whether the backend can currently enforce the policy it
// was given, including the pre-arm CIDR capability check design section 4
// requires: IPv4 asserted CIDRs have a fallback (expansion into individual
// elements, out of scope for this task's netlink writer) if interval sets
// prove unreliable on a given kernel; IPv6 assertions have none; a false
// here on IPv6 means asserted IPv6 CIDRs must be refused outright rather
// than degraded.
type Health struct {
	Healthy         bool
	IPv4CIDRCapable bool
	IPv6CIDRCapable bool
	Detail          string
}

// Gate opens time-limited holes in a host firewall for named services and
// reports on them. This package's nftables implementation is the only
// backend in v1; the interface exists so a future pf backend (design
// section 13) and the agent's validation pipeline (Task 2/3) both have one
// contract to hold, per the brief.
type Gate interface {
	// Open admits src into service's gate for ttl. Re-opening an identical
	// live Source is not an error: it refreshes the timeout in place (see
	// the package doc's identical-key-reinsert finding). Open returns an
	// error if service does not name a known kind:gate service, or ttl is
	// non-positive.
	Open(ctx context.Context, service string, src Source, ttl time.Duration) error

	// State reports the live elements currently admitted for service.
	State(ctx context.Context, service string) (ServiceState, error)

	// Health reports whether the backend can currently enforce policy.
	Health(ctx context.Context) (Health, error)

	// Close tears down everything this Gate created for the agent's
	// lifetime: postern_open is deleted outright (design section 7's
	// ExecStopPost contract for fail-open enforcement), and every
	// fail-closed gate set in postern_boot is flushed empty while its drop
	// rules are left standing (I3: a dead agent must not leave an
	// already-open fail-closed gate wedged open until its TTL happens to
	// expire). Close does not remove /etc/postern/boot.nft, the boot unit,
	// or the postern_boot table itself.
	Close(ctx context.Context) error

	// RefreshAgentUp adds or refreshes the agent_up dead-man element
	// (design section 4, invariant 1): the SPA port is reachable only
	// while agent_up holds it, so refreshing it is what keeps the SPA
	// port open, and letting it lapse is what makes the port silent again
	// without any other component acting. This package owns only the
	// single insert-or-refresh operation each call needs — mirroring the
	// same identical-key-reinsert-refresh behavior Open relies on for
	// observed gate sources — and does not own the schedule. The caller
	// (the agent's packet loop, per design section 7's "agent_up renewal
	// and the watchdog must share one definition of health") owns when to
	// call this, at what cadence, and what ttl to pass: design section 4
	// specifies a 90s ttl refreshed every 30s, but that policy belongs to
	// the agent, not to this interface. RefreshAgentUp returns an error if
	// ttl is non-positive.
	RefreshAgentUp(ctx context.Context, ttl time.Duration) error

	// AgentUpExpiry reports how long the agent_up element has left, read back
	// from the backend rather than computed from the last refresh. A zero
	// duration means the element is not there, which means the SPA port is
	// closed right now.
	//
	// It exists because RefreshAgentUp returning nil turned out not to mean
	// the lease had moved. For a year of wall-clock time it meant the opposite
	// on the most common path: a re-add of a live element with an identical
	// ttl is silently ignored by the kernel (see the package doc), so the call
	// succeeded, changed nothing, and the port went silent on the first add's
	// clock while the agent reported itself healthy. Nothing observed the
	// effect of the write, only its return code.
	//
	// So the caller checks what the kernel actually holds. That is the same
	// distinction the rest of postern already draws — the last-open timestamp
	// moves only after the backend confirmed, and the external probe exists at
	// all because self-attestation is not evidence.
	AgentUpExpiry(ctx context.Context) (time.Duration, error)

	// SilenceAgentUp removes the agent_up element immediately, rather than
	// waiting for its ttl to lapse. Design section 6 requires this on the
	// replay-store-unavailable path: the agent declares itself incapable
	// and must silence the SPA port immediately, before it tears down the
	// rest of its state, not at lease expiry. SilenceAgentUp is a no-op,
	// not an error, if the element or the set holding it is already
	// absent.
	SilenceAgentUp(ctx context.Context) error

	// RefreshAgentUpPorts refreshes agent_up to hold the rotating live set:
	// each port in ports, plus the fixed HTTP carrier port when configured,
	// added with ttl in one atomic batch. This is rotation mode's
	// counterpart to RefreshAgentUp: a fixed-port host calls RefreshAgentUp
	// with the one SPA port design section 4 assigns it, and a rotating-port
	// host calls this with the knock port library's current live set instead.
	// A port that was live last window and is not in ports is deliberately
	// not refreshed here — it ages out on its own timeout, which is how the
	// expired window's ports leave the set. RefreshAgentUpPorts returns an
	// error if ttl is non-positive.
	RefreshAgentUpPorts(ctx context.Context, ports []uint16, ttl time.Duration) error

	// AgentUpExpiryFor reports how long agent_up holds a specific port, read
	// back from the backend rather than computed from the last refresh, for
	// the same reason AgentUpExpiry does. Zero means the port is not
	// currently live. The rotation loop checks the current window's port so
	// a live-signal red means "the port an operator would knock right now is
	// closed", the same thing AgentUpExpiry means for a fixed-port host.
	AgentUpExpiryFor(ctx context.Context, port uint16) (time.Duration, error)
}
