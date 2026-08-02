//go:build linux

package gate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"github.com/jotra7/postern/internal/config"
)

// ErrOverlap distinguishes a genuine asserted-CIDR overlap collision
// (docs/spikes/2026-07-27-nft-interval-timeout.md: EEXIST from a range that
// partially overlaps something already live) from every other failure Open
// can return. It is deliberately NOT auto-resolved by a delete-then-add
// here: the spike's own writeup calls that workaround "settled by neither
// this spike nor Phase B's design" and notes it silently drops the other
// range's coverage, which is not a decision this package's Open should make
// on a caller's behalf. Callers that want the workaround can drive it
// themselves once they see this error.
var ErrOverlap = errors.New("gate: asserted source overlaps a live element")

// NFTables is the nftables-backed Gate. It holds one netlink connection and
// the RulesetPlan resolved from the policy it was built from, per the
// package doc: this is the piece invariant 6 requires stay in lockstep with
// the boot.nft and systemd-flush-lines renderers in render.go, and it is
// why every method below drives itself from g.plan rather than
// re-deriving set names.
type NFTables struct {
	mu     sync.Mutex
	conn   *nftables.Conn
	policy *config.Policy
	plan   *RulesetPlan
}

// var _ Gate keeps NFTables honest against the interface at compile time —
// nothing else in this module asserted that until now, so an interface
// change that NFTables silently stopped satisfying would otherwise only
// surface wherever a future caller first tried to use it as a Gate.
var _ Gate = (*NFTables)(nil)

// NewNFTables opens a netlink connection and resolves policy into a
// RulesetPlan. It performs no kernel writes; call Apply to create the
// tables.
func NewNFTables(policy *config.Policy, opts ...nftables.ConnOption) (*NFTables, error) {
	plan, err := BuildRulesetPlan(policy)
	if err != nil {
		return nil, err
	}
	conn, err := nftables.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("gate: open netlink: %w", err)
	}
	return &NFTables{conn: conn, policy: policy, plan: plan}, nil
}

// Plan exposes the RulesetPlan this Gate was built from, for tests that
// need to compare it against the text renderers in render.go.
func (g *NFTables) Plan() *RulesetPlan {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.plan
}

// SetPolicy rebuilds this Gate's view of the service catalogue from a new
// policy, without touching the kernel.
//
// It exists for M2 fleet mode, where a fetched bundle can add or remove a
// gate service after the Gate was constructed. Without it, Open answers
// "%q is not a known gate service" for a service the running policy declares
// and the live ruleset already carries — from the catalogue this type was
// built with — after validation has already passed and after the packet's
// replay slot has already been consumed.
//
// It writes nothing to the kernel on purpose. The sets and rules for a new
// catalogue arrive through the arm step (boot.nft reloaded into postern_boot)
// and through ApplyOpen (postern_open recreated), both of which the agent
// drives around this call. A method that quietly re-applied would be additive
// — see Apply — and would leave the previous revision's rules standing beside
// this one's.
//
// A plan that cannot be built leaves this Gate exactly as it was, so a
// refusal here is never a Gate that half-adopted a policy.
func (g *NFTables) SetPolicy(policy *config.Policy) error {
	plan, err := BuildRulesetPlan(policy)
	if err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.policy = policy
	g.plan = plan
	return nil
}

// Apply creates both tables — postern_boot and postern_open — with every
// set, chain, and rule the plan describes, and flushes the batch to the
// kernel. It is idempotent-from-empty (AddTable/AddSet/AddChain/AddRule are
// additive; calling Apply twice without deleting first will duplicate
// rules), so callers that need to reapply should delete first.
//
// Production posternd adopts an existing postern_boot rather than
// recreating it (design section 7) — that reconciliation lives in the
// agent layer, out of scope for this package. Apply exists so this
// package's own tests, including renderer equivalence, can drive a
// complete, known-good application of a policy via netlink alone.
func (g *NFTables) Apply(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if err := g.applyTable(TableBoot, true, g.plan.BootServices()); err != nil {
		return err
	}
	if err := g.applyTable(TableOpen, false, g.plan.OpenServices()); err != nil {
		return err
	}
	return nil
}

func (g *NFTables) applyTable(name string, includeAgentUp bool, services []ServicePlan) error {
	table := g.conn.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: name})

	if includeAgentUp {
		agentUp := &nftables.Set{
			Table:      table,
			Name:       AgentUpSet,
			KeyType:    nftables.TypeInetService,
			HasTimeout: true,
		}
		if err := g.conn.AddSet(agentUp, nil); err != nil {
			return fmt.Errorf("gate: add set %s: %w", AgentUpSet, err)
		}
	}

	for _, svc := range services {
		for _, s := range svc.Sets {
			nftSet := &nftables.Set{
				Table:      table,
				Name:       s.Name,
				KeyType:    addrKeyType(s.Family),
				Interval:   s.Interval(),
				HasTimeout: true,
			}
			if err := g.conn.AddSet(nftSet, nil); err != nil {
				return fmt.Errorf("gate: add set %s: %w", s.Name, err)
			}
		}
	}

	accept := nftables.ChainPolicyAccept
	chain := g.conn.AddChain(&nftables.Chain{
		Name:     ChainInput,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &accept,
	})

	// Always-allow and established/related are duplicated into every table
	// on the hook (invariant 2, design section 4): with multiple base
	// chains on one hook, an accept in one table cannot save a packet from
	// a drop in another, so both properties must hold independently in
	// each.
	g.conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: establishedRelatedAcceptExprs()})
	if g.plan.AlwaysAllowIface != "" {
		g.conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: iifnameAcceptExprs(g.plan.AlwaysAllowIface)})
	}

	if includeAgentUp {
		g.conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: agentUpAcceptExprs("udp")})
		if g.plan.PortRotation != nil {
			g.conn.AddRule(&nftables.Rule{Table: table, Chain: chain,
				Exprs: dportRangeDropExprs("udp", g.plan.PortRotation.RangeLo, g.plan.PortRotation.RangeHi)})
		} else {
			g.conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: dportDropExprs("udp", g.plan.SPAPort)})
		}
		// Same order as RenderBootNFT's writeSPAHTTPRules, and emitted only
		// when the carrier is configured, for the same reason: renderer
		// equivalence (invariant 6) hashes rule count and order, so a rule
		// this writer emits unconditionally would not appear in the text.
		if g.plan.SPAHTTPPort != 0 {
			g.conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: agentUpAcceptExprs("tcp")})
			g.conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: dportDropExprs("tcp", g.plan.SPAHTTPPort)})
		}
	}

	for _, svc := range services {
		for _, port := range svc.Ports {
			// A forward gets the drop and no accept, the same asymmetry
			// writeServiceRules renders and for the same reason: nothing
			// listens on the external port here, and an admitted source has
			// already been translated in prerouting and is not on this hook.
			if svc.Forward == nil {
				for _, s := range svc.Sets {
					g.conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: gateAcceptExprs(svc.Proto, port, s)})
				}
			}
			g.conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: dportDropExprs(svc.Proto, port)})
		}
	}

	g.applyForwardChains(table, &accept, services)

	return g.conn.Flush()
}

// applyForwardChains builds the netlink half of writeNATChain and
// writeForwardChain. Chain order, rule order, and the emit-nothing-when-empty
// rule all mirror the text renderer exactly, because renderer equivalence
// (invariant 6) hashes the loaded ruleset rather than the source text.
func (g *NFTables) applyForwardChains(table *nftables.Table, accept *nftables.ChainPolicy, services []ServicePlan) {
	var forwards []ServicePlan
	for _, svc := range services {
		if svc.Forward != nil {
			forwards = append(forwards, svc)
		}
	}
	if len(forwards) == 0 {
		return
	}

	natChain := g.conn.AddChain(&nftables.Chain{
		Name:     ChainPrerouting,
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
		Policy:   accept,
	})
	for _, svc := range forwards {
		for _, port := range svc.Ports {
			for _, s := range svc.Sets {
				g.conn.AddRule(&nftables.Rule{Table: table, Chain: natChain, Exprs: dnatExprs(svc.Proto, port, s, *svc.Forward)})
			}
		}
	}

	fwdChain := g.conn.AddChain(&nftables.Chain{
		Name:     ChainForward,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
		Policy:   accept,
	})
	g.conn.AddRule(&nftables.Rule{Table: table, Chain: fwdChain, Exprs: establishedRelatedAcceptExprs()})
	if g.plan.AlwaysAllowIface != "" {
		g.conn.AddRule(&nftables.Rule{Table: table, Chain: fwdChain, Exprs: iifnameAcceptExprs(g.plan.AlwaysAllowIface)})
	}
	for _, svc := range forwards {
		for _, s := range svc.Sets {
			g.conn.AddRule(&nftables.Rule{Table: table, Chain: fwdChain, Exprs: forwardAcceptExprs(svc.Proto, s, *svc.Forward)})
		}
		g.conn.AddRule(&nftables.Rule{Table: table, Chain: fwdChain, Exprs: forwardDropExprs(svc.Proto, *svc.Forward)})
	}
}

// ApplyOpen creates postern_open alone, deleting any table already carrying
// that name first.
//
// This is the agent's startup path (design section 4: postern_open is
// "created by the agent at startup, removed when it exits"). postern_boot is
// deliberately not touched: it is loaded at boot by the oneshot unit,
// before the agent runs and independently of it, and Apply is additive — an
// agent that reapplied it would duplicate every rule it found, and would
// make the fail-closed posture depend on the agent starting, which is what
// that posture exists to avoid.
//
// The delete-first is not defensive tidying. postern_open has no on-disk
// form and ExecStopPost removes it on any exit, so a table present here is a
// leftover from a teardown that did not run; recreating over it would
// duplicate every rule for the same additive reason.
func (g *NFTables) ApplyOpen(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.conn.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: TableOpen})
	if err := g.conn.Flush(); err != nil && !errors.Is(err, syscall.ENOENT) {
		return fmt.Errorf("gate: apply open: delete stale %s: %w", TableOpen, err)
	}
	return g.applyTable(TableOpen, false, g.plan.OpenServices())
}

// Open admits src into service's gate. See the package doc and ErrOverlap's
// comment for why a genuine asserted-CIDR overlap is returned as a
// distinguishable error rather than silently resolved.
func (g *NFTables) Open(ctx context.Context, service string, src Source, ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("gate: ttl must be positive, got %s", ttl)
	}

	// The lock covers the catalogue reads as well as the netlink batch. It
	// used to start below them, which was safe only while the catalogue was
	// immutable after construction; SetPolicy makes it a live field, and a
	// packet resolving against a half-swapped policy and plan would open a
	// service against another revision's set names.
	g.mu.Lock()
	defer g.mu.Unlock()

	svcCfg, ok := g.policy.Services[service]
	if !ok || svcCfg.Kind != config.KindGate {
		return fmt.Errorf("gate: %q is not a known gate service", service)
	}
	plan, ok := g.plan.ServiceByName(service)
	if !ok {
		return fmt.Errorf("gate: %q has no ruleset plan", service)
	}

	norm, family, err := normalizeSource(src)
	if err != nil {
		return err
	}
	setKind := SetObserved
	if norm.Kind == SourceAsserted {
		setKind = SetAsserted
	}
	setPlan, ok := plan.SetByFamilyKind(family, setKind)
	if !ok {
		// Reachable, and only for a forward: its target address fixes one
		// family, so nothing in the ruleset would ever read a set of the other
		// one. Refusing here is what keeps a knock from the wrong family out of
		// the "reported open, opened nothing" class, which is what inserting
		// into an unread set would have been.
		return fmt.Errorf("gate: service %q has no %s/%s set; a forward's target address fixes the one "+
			"address family a translated packet can carry", service, family, setKind)
	}

	elems, err := buildElements(norm, ttl)
	if err != nil {
		return err
	}

	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: plan.Table}
	kset, err := g.conn.GetSetByName(table, setPlan.Name)
	if err != nil {
		return fmt.Errorf("gate: look up set %s: %w", setPlan.Name, err)
	}

	// A knock for a source that is already open must extend its lease, and on
	// this kernel a bare re-insert does not: NFT_MSG_NEWSETELEM for a key that
	// already exists returns success and leaves the original expiry in place,
	// for hash sets and interval sets alike (checked against nft(8) itself on
	// 6.12, both set flavours). The spike's identical-key-reinsert-refreshes
	// case reported a refresh and this method's earlier comment repeated that
	// claim, so nothing here deleted first.
	//
	// The consequence is worse than it sounds because it is silent. An
	// operator whose session is about to lapse re-knocks, the client reports
	// the port reachable — it is, for the moment — and the gate shuts on the
	// original schedule anyway, in the middle of whatever they were doing. It
	// is exactly the moment postern exists for.
	//
	// So an existing element is deleted and re-added, both in the same batch,
	// which nftables applies atomically: there is no instant in which the
	// source is not permitted. The delete is issued ONLY when this set already
	// holds this exact source, because a delete of a key that is not there
	// aborts the whole batch — and for an asserted prefix that is not
	// identical but merely overlapping, the batch must reach the kernel
	// unmodified so the EEXIST classified below is the kernel's own verdict on
	// the overlap rather than an ENOENT this method invented.
	if g.holdsExactly(kset, setPlan, norm) {
		if err := g.conn.SetDeleteElements(kset, elems); err != nil {
			return fmt.Errorf("gate: encode refresh of %s in %s: %w", norm.Prefix, setPlan.Name, err)
		}
	}

	// SetAddElements only marshals the request into conn's local batch; it
	// talks to no socket and returns non-nil only for a local encoding
	// failure (e.g. a key of the wrong length for the set's type), never
	// for a kernel-side rejection. The real EEXIST from a genuine overlap
	// — or any other kernel-side outcome — surfaces from Flush, which is
	// what actually sends the batch and reads the kernel's reply. An
	// earlier version of this method classified SetAddElements' return
	// instead of Flush's, so ErrOverlap was dead code: every real overlap
	// error arrived already wrapped as an opaque Flush failure two lines
	// below where the classification ran. See
	// TestGate_Open_AssertedOverlapReturnsErrOverlap, which reproduces
	// that exact miswrap against the kernel before asserting the fix.
	if err := g.conn.SetAddElements(kset, elems); err != nil {
		return fmt.Errorf("gate: encode open of %s into %s: %w", src.Kind, setPlan.Name, err)
	}

	flushErr := g.conn.Flush()
	if flushErr == nil {
		return nil
	}

	if norm.Kind == SourceObserved {
		// An observed /32 or /128 either is not there — a plain insert — or
		// is, in which case it was deleted in this same batch above. Neither
		// path can collide, so any error here is a real failure rather than
		// the expected overlap. (The spike's identical-key-reinsert-refreshes
		// case was cited here for the same conclusion; it is no longer the
		// reason, because re-inserting without deleting turned out not to
		// refresh the lease at all.)
		return fmt.Errorf("gate: insert observed source into %s: %w", setPlan.Name, flushErr)
	}
	if !errors.Is(flushErr, syscall.EEXIST) {
		return fmt.Errorf("gate: insert asserted source into %s: %w", setPlan.Name, flushErr)
	}
	return fmt.Errorf("%w: %s in %s: %v", ErrOverlap, norm.Prefix, setPlan.Name, flushErr)
}

// holdsExactly reports whether set already holds this exact source, which is
// the only case in which Open deletes before it adds.
//
// "Exactly" is doing real work here: an interval set holding 203.0.113.0/24
// does not hold 203.0.113.5/32, and deleting the /24 to make room for it
// would silently withdraw permission from every other address in that
// prefix. Only an identical prefix is a refresh; anything else is an overlap
// and belongs on the EEXIST path.
//
// A read failure answers false. The cost of being wrong that way is one
// unrefreshed lease reported through the ordinary EEXIST path; the cost of
// answering true on a failed read is a delete of an element that may not
// exist, which aborts a batch that would otherwise have opened the gate.
func (g *NFTables) holdsExactly(set *nftables.Set, plan GateSet, src Source) bool {
	live, err := g.conn.GetSetElements(set)
	if err != nil {
		return false
	}
	for _, e := range decodeElements(live, plan) {
		if e.Source.Prefix == src.Prefix {
			return true
		}
	}
	return false
}

// State reads back the live elements of every set backing service.
func (g *NFTables) State(ctx context.Context, service string) (ServiceState, error) {
	// Locked before the plan is read, for the same reason Open is: SetPolicy
	// can replace the catalogue at any time.
	g.mu.Lock()
	defer g.mu.Unlock()

	plan, ok := g.plan.ServiceByName(service)
	if !ok {
		return ServiceState{}, fmt.Errorf("gate: %q has no ruleset plan", service)
	}

	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: plan.Table}
	out := ServiceState{Service: service}

	for _, s := range plan.Sets {
		kset, err := g.conn.GetSetByName(table, s.Name)
		if err != nil {
			return ServiceState{}, fmt.Errorf("gate: look up set %s: %w", s.Name, err)
		}
		elems, err := g.conn.GetSetElements(kset)
		if err != nil {
			return ServiceState{}, fmt.Errorf("gate: read elements of %s: %w", s.Name, err)
		}
		out.Elements = append(out.Elements, decodeElements(elems, s)...)
	}
	return out, nil
}

// Health probes whether this kernel and library combination still supports
// interval+timeout sets for each address family, independently — the
// pre-arm capability check design section 4 requires, using a throwaway
// table so the probe never touches live gate state.
func (g *NFTables) Health(ctx context.Context) (Health, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	v4, v4Err := g.probeIntervalTimeout(nftables.TypeIPAddr)
	v6, v6Err := g.probeIntervalTimeout(nftables.TypeIP6Addr)

	h := Health{IPv4CIDRCapable: v4, IPv6CIDRCapable: v6, Healthy: v4 && v6}
	if h.Healthy {
		h.Detail = "interval+timeout capability confirmed for ipv4 and ipv6"
	} else {
		h.Detail = fmt.Sprintf("interval+timeout capability check: ipv4=%v (%v) ipv6=%v (%v)", v4, v4Err, v6, v6Err)
	}
	return h, nil
}

func (g *NFTables) probeIntervalTimeout(dt nftables.SetDatatype) (bool, error) {
	table := g.conn.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: "postern_capability_probe"})
	defer func() {
		g.conn.DelTable(table)
		_ = g.conn.Flush()
	}()

	set := &nftables.Set{Table: table, Name: "probe", KeyType: dt, Interval: true, HasTimeout: true}
	if err := g.conn.AddSet(set, nil); err != nil {
		return false, err
	}
	if err := g.conn.Flush(); err != nil {
		return false, err
	}
	return true, nil
}

// Close deletes postern_open outright and flushes (empties, without
// touching drop rules) every fail-closed gate set in postern_boot — the
// same operation the systemd unit's ExecStopPost lines perform from
// outside the process (render.go's RenderSystemdFlushLines), so a crash
// that never reaches this method still lands in the same state via the
// unit file, and a clean stop that does reach this method does not depend
// on systemd running the ExecStopPost lines at all.
func (g *NFTables) Close(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.conn.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: TableOpen})
	if err := g.conn.Flush(); err != nil && !errors.Is(err, syscall.ENOENT) {
		return fmt.Errorf("gate: close: delete %s: %w", TableOpen, err)
	}

	bootTable := &nftables.Table{Family: nftables.TableFamilyINet, Name: TableBoot}
	for _, svc := range g.plan.BootServices() {
		for _, s := range svc.Sets {
			kset, err := g.conn.GetSetByName(bootTable, s.Name)
			if err != nil {
				if errors.Is(err, syscall.ENOENT) {
					continue
				}
				return fmt.Errorf("gate: close: look up set %s: %w", s.Name, err)
			}
			g.conn.FlushSet(kset)
		}
	}
	if err := g.conn.Flush(); err != nil {
		return fmt.Errorf("gate: close: flush gate sets: %w", err)
	}
	return nil
}

// agentUpElement is the one element agent_up ever holds: the SPA port
// number itself, encoded the same big-endian way every port comparison in
// this package uses (dportDropExprs, gateAcceptExprs). agent_up's presence,
// not its value, is what the accept rule tests via set membership — but
// the port number is the only value design section 4 ever describes it
// holding, and using anything else here would insert an element the
// generated accept rule's lookup against @agent_up still matches (nftables
// set membership does not care what the value "means"), while a reader
// checking `nft list set inet postern_boot agent_up` would see a number
// that does not name the thing it is a dead-man switch for.
func (g *NFTables) agentUpElement() []byte {
	return binaryutil.BigEndian.PutUint16(g.plan.SPAPort)
}

// agentUpElements is every port the dead-man set holds: the SPA UDP port
// always, and the HTTP carrier's TCP port when that carrier is configured.
//
// One set rather than one per carrier, because agent_up is a statement about
// the agent, not about a socket. Two sets would be two leases, refreshed by
// two writes that can fail independently — and a host whose UDP port went
// silent while its TCP port stayed open would be advertising break-glass
// access through a carrier whose liveness nothing had established. On one set
// the two carriers cannot disagree: the same beat refreshes both keys in the
// same batch, and the same failure silences both.
func (g *NFTables) agentUpElements() [][]byte {
	out := [][]byte{g.agentUpElement()}
	if g.plan.SPAHTTPPort != 0 {
		out = append(out, binaryutil.BigEndian.PutUint16(g.plan.SPAHTTPPort))
	}
	return out
}

// RefreshAgentUp adds or refreshes the agent_up element. See the Gate
// interface doc comment: this performs one insert-or-refresh operation:
// the schedule, the ttl policy, and the "share one definition of health
// with the watchdog" requirement (design section 7) all belong to the
// caller.
//
// The delete before the add is the same workaround Open carries, and this
// method needed it more: see the package doc on re-adding a live element.
// Open's callers pass whatever ttl the operator asked for, so the value often
// differs between knocks and the bug is intermittent there. This method is
// called every beat with one constant — Daemon.agentUpTTL — so *every* refresh
// after the first was a no-op that returned nil, and the dead-man ran on the
// clock of the first add for the life of the process.
//
// What that cost: agent_up is invariant 1. The SPA port is reachable only
// while this element holds it, so the element lapsing takes break-glass access
// away, and it lapsed on a schedule nothing was watching. The kernel dropped
// the knocks before the socket, so no counter moved and no log line was
// written; the agent went on reporting itself healthy, because the refresh it
// had just performed returned no error. It was found from outside, by the
// canary probe reporting a host red that said it was fine — which is design
// section 8's "health is the join" catching the exact class of failure it was
// put in M1 to catch.
func (g *NFTables) RefreshAgentUp(ctx context.Context, ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("gate: ttl must be positive, got %s", ttl)
	}
	return g.refreshAgentUpKeys(ctx, g.agentUpElements(), ttl)
}

// RefreshAgentUpPorts refreshes agent_up to hold the rotating live set: each
// port in ports, plus the fixed http carrier port when configured, added with
// ttl in one atomic batch. A port that was live last window and is not in
// ports is deliberately not refreshed here — it ages out on its own timeout,
// which is how the expired window's ports leave the set (design "let the
// expired window's ports age out"). It shares the same delete-then-add-live
// workaround RefreshAgentUp uses, so a re-add of a still-live port extends
// rather than no-ops.
func (g *NFTables) RefreshAgentUpPorts(ctx context.Context, ports []uint16, ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("gate: ttl must be positive, got %s", ttl)
	}
	keys := make([][]byte, 0, len(ports)+1)
	for _, p := range ports {
		keys = append(keys, binaryutil.BigEndian.PutUint16(p))
	}
	if g.plan.SPAHTTPPort != 0 {
		keys = append(keys, binaryutil.BigEndian.PutUint16(g.plan.SPAHTTPPort))
	}
	return g.refreshAgentUpKeys(ctx, keys, ttl)
}

// refreshAgentUpKeys is the insert-or-refresh batch RefreshAgentUp and
// RefreshAgentUpPorts share: delete-present-then-add-all-live, in one flush,
// for whatever key list the caller passes.
//
// The delete before the add is the same workaround Open carries, and this
// method needed it more: see the package doc on re-adding a live element.
// Open's callers pass whatever ttl the operator asked for, so the value often
// differs between knocks and the bug is intermittent there. RefreshAgentUp is
// called every beat with one constant — Daemon.agentUpTTL — so *every*
// refresh after the first was a no-op that returned nil, and the dead-man ran
// on the clock of the first add for the life of the process.
//
// What that cost: agent_up is invariant 1. The SPA port is reachable only
// while this element holds it, so the element lapsing takes break-glass access
// away, and it lapsed on a schedule nothing was watching. The kernel dropped
// the knocks before the socket, so no counter moved and no log line was
// written; the agent went on reporting itself healthy, because the refresh it
// had just performed returned no error. It was found from outside, by the
// canary probe reporting a host red that said it was fine — which is design
// section 8's "health is the join" catching the exact class of failure it was
// put in M1 to catch.
func (g *NFTables) refreshAgentUpKeys(ctx context.Context, keys [][]byte, ttl time.Duration) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: TableBoot}
	kset, err := g.conn.GetSetByName(table, AgentUpSet)
	if err != nil {
		return fmt.Errorf("gate: look up set %s: %w", AgentUpSet, err)
	}

	// Every key, in one batch, which nftables applies atomically: there is no
	// instant in which any key is unreachable, and no instant in which one key
	// holds a lease another does not. The delete is issued only for keys
	// actually present, because deleting a key that is not there aborts the
	// whole batch — and an aborted batch here would leave the ports silent,
	// which is the failure this is fixing.
	live := g.liveAgentUpKeys(kset)
	var del, add []nftables.SetElement
	for _, key := range keys {
		if live[string(key)] {
			del = append(del, nftables.SetElement{Key: key})
		}
		add = append(add, nftables.SetElement{Key: key, Timeout: ttl})
	}
	if len(del) > 0 {
		if err := g.conn.SetDeleteElements(kset, del); err != nil {
			return fmt.Errorf("gate: encode agent_up refresh delete: %w", err)
		}
	}
	if err := g.conn.SetAddElements(kset, add); err != nil {
		return fmt.Errorf("gate: encode agent_up refresh: %w", err)
	}
	if err := g.conn.Flush(); err != nil {
		return fmt.Errorf("gate: flush agent_up refresh: %w", err)
	}
	return nil
}

// liveAgentUpKeys reports which keys the set currently holds, so a refresh
// deletes only what is there.
//
// A read failure answers "none", so the batch degrades to a bare add. That is
// the pre-fix behaviour for one beat — the lease is not extended — rather than
// a delete of an absent key, which would abort the batch and leave the ports
// silent. Wrong in the direction that keeps the door open.
func (g *NFTables) liveAgentUpKeys(set *nftables.Set) map[string]bool {
	out := map[string]bool{}
	live, err := g.conn.GetSetElements(set)
	if err != nil {
		return out
	}
	for _, e := range live {
		out[string(e.Key)] = true
	}
	return out
}

// SilenceAgentUp removes the agent_up element immediately. See the Gate
// interface doc comment for why this exists as its own method rather than
// waiting on ttl expiry (design section 6, the replay-store-unavailable
// path).
func (g *NFTables) SilenceAgentUp(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: TableBoot}
	kset, err := g.conn.GetSetByName(table, AgentUpSet)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return nil
		}
		return fmt.Errorf("gate: look up set %s: %w", AgentUpSet, err)
	}

	// One batch per key rather than one batch for all of them. Deleting an
	// absent key aborts the whole batch, so a single batch covering both
	// carriers would leave the other carrier's port OPEN whenever one of them
	// had already lapsed — the exact inversion this method exists to prevent.
	// Per-key batches make each removal independent, and the ENOENT tolerance
	// below is what makes an already-absent key a success rather than a
	// failure that stops the loop before it reaches the key that is present.
	for _, key := range g.agentUpElements() {
		if err := g.conn.SetDeleteElements(kset, []nftables.SetElement{{Key: key}}); err != nil {
			return fmt.Errorf("gate: encode agent_up removal: %w", err)
		}
		if err := g.conn.Flush(); err != nil && !errors.Is(err, syscall.ENOENT) {
			return fmt.Errorf("gate: flush agent_up removal: %w", err)
		}
	}
	return nil
}

// --- element encode/decode --------------------------------------------

func buildElements(src Source, ttl time.Duration) ([]nftables.SetElement, error) {
	addr := src.Prefix.Addr()
	if src.Kind == SourceObserved {
		if src.Prefix.Bits() != addr.BitLen() {
			return nil, fmt.Errorf("gate: observed source %s is not a single address", src.Prefix)
		}
		return []nftables.SetElement{{Key: addr.AsSlice(), Timeout: ttl}}, nil
	}
	start, end, err := prefixBounds(src.Prefix)
	if err != nil {
		return nil, err
	}
	return []nftables.SetElement{
		{Key: start, Timeout: ttl},
		{Key: end, IntervalEnd: true},
	}, nil
}

// prefixBounds returns the interval [start, end) nftables expects for an
// interval set element pair: start is the prefix's network address, end is
// one address past its last usable address. Implemented with big.Int so
// the same code handles both 4-byte and 16-byte keys.
func prefixBounds(pfx netip.Prefix) (start, end []byte, err error) {
	pfx = pfx.Masked()
	addr := pfx.Addr()
	raw := addr.AsSlice()
	totalBits := len(raw) * 8
	hostBits := totalBits - pfx.Bits()

	// hostBits is len(raw)*8 - pfx.Bits(): at most 128 (an IPv6 /0, which
	// grant validation never permits in practice, but this function does
	// not assume that), always non-negative since pfx.Bits() cannot exceed
	// the address's own bit length. The int -> uint conversion below can
	// therefore never wrap.
	startInt := new(big.Int).SetBytes(raw)
	hostMask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(hostBits)), big.NewInt(1)) //nolint:gosec // hostBits bounded to [0,128], see comment above
	endInt := new(big.Int).Or(startInt, hostMask)
	endInt.Add(endInt, big.NewInt(1))

	endBytes := endInt.Bytes()
	if len(endBytes) > len(raw) {
		return nil, nil, fmt.Errorf("gate: prefix %s spans the entire address space; cannot express an interval end", pfx)
	}
	padded := make([]byte, len(raw))
	copy(padded[len(padded)-len(endBytes):], endBytes)
	return raw, padded, nil
}

// decodeElements pairs raw element records back into ElementState values.
// Non-interval (SetObserved) sets hold bare addresses. Interval
// (SetAsserted) sets hold a start record and a separate end record.
//
// The pairing is by VALUE — each start is matched with the lowest end above
// it — rather than by position. An earlier version paired each start with
// the record that happened to follow it, on the grounds that buildElements
// writes the two adjacently. The kernel does not return them that way: on
// 6.12 a single /24 comes back as [end(203.0.114.0), start(203.0.113.0)],
// end first, so the start had no following record and every asserted prefix
// decoded as a /32 — a /24 grant reported by State() as one address. That is
// wrong in the direction that understates what is open, and it silently
// disabled the identical-prefix refresh in Open, which asks State's decoder
// whether this exact source is already live.
func decodeElements(elems []nftables.SetElement, s GateSet) []ElementState {
	family := s.Family
	bits := 32
	if family == FamilyIPv6 {
		bits = 128
	}

	if s.Kind == SetObserved {
		out := make([]ElementState, 0, len(elems))
		for _, e := range elems {
			addr, ok := addrFromBytes(e.Key, family)
			if !ok {
				continue
			}
			out = append(out, ElementState{
				Source:  Source{Kind: SourceObserved, Prefix: netip.PrefixFrom(addr, bits)},
				Expires: e.Expires,
			})
		}
		return out
	}

	var ends [][]byte
	for _, e := range elems {
		if e.IntervalEnd {
			ends = append(ends, e.Key)
		}
	}
	sort.Slice(ends, func(i, j int) bool { return bytes.Compare(ends[i], ends[j]) < 0 })

	var out []ElementState
	for _, e := range elems {
		if e.IntervalEnd {
			continue
		}
		startAddr, ok := addrFromBytes(e.Key, family)
		if !ok {
			continue
		}
		prefixBits := bits
		if end, ok := lowestEndAbove(ends, e.Key); ok {
			if pfx, ok := prefixFromBounds(e.Key, end, bits); ok {
				prefixBits = pfx
			}
		}
		out = append(out, ElementState{
			Source:  Source{Kind: SourceAsserted, Prefix: netip.PrefixFrom(startAddr, prefixBits)},
			Expires: e.Expires,
		})
	}
	return out
}

// lowestEndAbove finds the end bound belonging to a start: the smallest end
// key strictly greater than it. ends must be sorted.
func lowestEndAbove(ends [][]byte, start []byte) ([]byte, bool) {
	for _, e := range ends {
		if bytes.Compare(e, start) > 0 {
			return e, true
		}
	}
	return nil, false
}

func addrFromBytes(b []byte, family AddrFamily) (netip.Addr, bool) {
	switch {
	case family == FamilyIPv4 && len(b) == 4:
		return netip.AddrFrom4([4]byte(b)), true
	case family == FamilyIPv6 && len(b) == 16:
		return netip.AddrFrom16([16]byte(b)), true
	default:
		return netip.Addr{}, false
	}
}

// prefixFromBounds recovers a prefix length from a well-formed [start, end)
// pair this package produced. It assumes the range size is a power of two,
// true for every interval buildElements constructs; it is a best-effort
// display value for State(), not something correctness depends on.
func prefixFromBounds(startKey, endKey []byte, totalBits int) (int, bool) {
	s := new(big.Int).SetBytes(startKey)
	e := new(big.Int).SetBytes(endKey)
	size := new(big.Int).Sub(e, s)
	if size.Sign() <= 0 {
		return 0, false
	}
	hostBits := size.BitLen() - 1
	if hostBits < 0 || hostBits > totalBits {
		return 0, false
	}
	return totalBits - hostBits, true
}

// --- rule expression builders -------------------------------------------

func addrKeyType(f AddrFamily) nftables.SetDatatype {
	if f == FamilyIPv4 {
		return nftables.TypeIPAddr
	}
	return nftables.TypeIP6Addr
}

func protoNum(proto string) byte {
	if proto == "udp" {
		return unix.IPPROTO_UDP
	}
	return unix.IPPROTO_TCP
}

func nfprotoByte(f AddrFamily) byte {
	if f == FamilyIPv4 {
		return unix.NFPROTO_IPV4
	}
	return unix.NFPROTO_IPV6
}

// ifname pads an interface name to IFNAMSIZ (16 bytes), the fixed width
// nftables' meta iifname comparison expects.
func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, n)
	return b
}

// establishedRelatedAcceptExprs builds "ct state established,related
// accept" — present in every table on the hook (invariant 2).
func establishedRelatedAcceptExprs() []expr.Any {
	return []expr.Any{
		&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
			Xor:            binaryutil.NativeEndian.PutUint32(0),
		},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}

// iifnameAcceptExprs builds "iifname <iface> accept" using meta iifname —
// never meta iif, which resolves an interface index at ruleset-load time
// and fails the whole load if the interface does not exist yet (the task
// brief's central invariant: the boot ruleset loads before the mesh
// interface appears).
func iifnameAcceptExprs(iface string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(iface)},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}

// agentUpAcceptExprs builds "<proto> dport @agent_up limit rate N/second
// accept" — a SPA carrier's port is reachable only while the agent_up set
// holds that port number (invariant 1's dead-man switch). proto is "udp" for
// the datagram carrier and "tcp" for the HTTP one; both look up the same set,
// so one lease governs both.
func agentUpAcceptExprs(proto string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protoNum(proto)}},
		&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Lookup{SourceRegister: 1, SetName: AgentUpSet},
		&expr.Limit{Type: expr.LimitTypePkts, Rate: AgentUpRateLimitPerSecond, Unit: expr.LimitTimeSecond},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}

// dportDropExprs builds "<proto> dport <port> drop" — the unconditional
// drop for the SPA port when agent_up is empty, and the per-service drop
// invariant 4 requires on every gated port including canary.
func dportDropExprs(proto string, port uint16) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protoNum(proto)}},
		&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(port)},
		&expr.Verdict{Kind: expr.VerdictDrop},
	}
}

// dportRangeDropExprs builds "<proto> dport lo-hi drop": the whole rotating band
// is dark unless agent_up currently holds the live port. nftables expresses an
// inclusive range as two comparisons on the loaded dport, so the netlink form
// and the "dport lo-hi" text `nft -f` compiles to the same range expression.
func dportRangeDropExprs(proto string, lo, hi uint16) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protoNum(proto)}},
		&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Range{Op: expr.CmpOpEq, Register: 1,
			FromData: binaryutil.BigEndian.PutUint16(lo),
			ToData:   binaryutil.BigEndian.PutUint16(hi)},
		&expr.Verdict{Kind: expr.VerdictDrop},
	}
}

// saddrPayload and daddrPayload are the network-header offsets of a packet's
// source and destination address for each family, kept in one place so the
// three rule builders that load them cannot disagree about which end of the
// header they are reading.
func saddrPayload(f AddrFamily) (offset, length uint32) {
	if f == FamilyIPv4 {
		return 12, 4
	}
	return 8, 16
}

func daddrPayload(f AddrFamily) (offset, length uint32) {
	if f == FamilyIPv4 {
		return 16, 4
	}
	return 24, 16
}

// dnatExprs builds "<proto> dport <external> ip[6] saddr @<set> dnat to
// <target>" for the prerouting chain.
//
// The two immediates hold the target address and port. They are literals from
// the plan, which came from the host's configuration; there is no register
// here loaded from the packet that reaches the NAT expression. A packet's only
// influence is the set lookup above them, which decides whether the rule
// matches at all.
func dnatExprs(proto string, port uint16, set GateSet, f ForwardPlan) []expr.Any {
	saddrOffset, saddrLen := saddrPayload(set.Family)
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{nfprotoByte(set.Family)}},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protoNum(proto)}},
		&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(port)},
		&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: saddrOffset, Len: saddrLen},
		&expr.Lookup{SourceRegister: 1, SetName: set.Name},
		&expr.Immediate{Register: 1, Data: f.To.AsSlice()},
		&expr.Immediate{Register: 2, Data: binaryutil.BigEndian.PutUint16(f.Port)},
		&expr.NAT{
			Type:        expr.NATTypeDestNAT,
			Family:      uint32(nfprotoByte(f.Family)),
			RegAddrMin:  1,
			RegProtoMin: 2,
		},
	}
}

// forwardAcceptExprs builds "ip[6] daddr <target> <proto> dport <target port>
// ip[6] saddr @<set> accept" for the forward chain. The match is on the
// internal target because prerouting has already rewritten the packet.
func forwardAcceptExprs(proto string, set GateSet, f ForwardPlan) []expr.Any {
	saddrOffset, saddrLen := saddrPayload(set.Family)
	e := forwardMatchExprs(proto, f)
	e = append(e,
		&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: saddrOffset, Len: saddrLen},
		&expr.Lookup{SourceRegister: 1, SetName: set.Name},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)
	return e
}

// forwardDropExprs builds "ip[6] daddr <target> <proto> dport <target port>
// drop": the rule that carries a forwarded path's fail-closed posture, and the
// one that the boot unit puts in place before the agent exists.
func forwardDropExprs(proto string, f ForwardPlan) []expr.Any {
	return append(forwardMatchExprs(proto, f), &expr.Verdict{Kind: expr.VerdictDrop})
}

func forwardMatchExprs(proto string, f ForwardPlan) []expr.Any {
	daddrOffset, daddrLen := daddrPayload(f.Family)
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{nfprotoByte(f.Family)}},
		&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: daddrOffset, Len: daddrLen},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: f.To.AsSlice()},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protoNum(proto)}},
		&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(f.Port)},
	}
}

// gateAcceptExprs builds "<proto> dport <port> ip[6] saddr @<set> accept".
// The explicit nfproto match is what keeps an inet-family chain from
// reading IPv6 header bytes off a v4 packet (or vice versa) for the
// network-header payload load below it.
func gateAcceptExprs(proto string, port uint16, set GateSet) []expr.Any {
	addrOffset, addrLen := saddrPayload(set.Family)
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{nfprotoByte(set.Family)}},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protoNum(proto)}},
		&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(port)},
		&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: addrOffset, Len: addrLen},
		&expr.Lookup{SourceRegister: 1, SetName: set.Name},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}

// AgentUpExpiry reports the agent_up element's remaining lifetime, or zero if
// the element is absent. See the Gate interface for why the agent reads this
// back rather than trusting RefreshAgentUp's return.
func (g *NFTables) AgentUpExpiry(ctx context.Context) (time.Duration, error) {
	return g.agentUpExpiryOfKey(g.agentUpElement())
}

// AgentUpExpiryFor reports how long agent_up holds a specific port, read back
// from the kernel. Zero means the port is not currently live. The rotation
// loop checks the current window's port so a live-signal red means "the port
// an operator would knock right now is closed", the same thing AgentUpExpiry
// means for a fixed-port host.
func (g *NFTables) AgentUpExpiryFor(ctx context.Context, port uint16) (time.Duration, error) {
	return g.agentUpExpiryOfKey(binaryutil.BigEndian.PutUint16(port))
}

// agentUpExpiryOfKey is the read-back AgentUpExpiry and AgentUpExpiryFor
// share: look up the set, read its live elements, and report the ttl left on
// the one matching key, or zero if the set or the key is absent.
func (g *NFTables) agentUpExpiryOfKey(want []byte) (time.Duration, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: TableBoot}
	kset, err := g.conn.GetSetByName(table, AgentUpSet)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) {
			// No set at all: the table is gone, which is a bigger problem than
			// this method's, and every other signal already reports it. Zero
			// is the honest answer to "how long is the port open for".
			return 0, nil
		}
		return 0, fmt.Errorf("gate: look up set %s: %w", AgentUpSet, err)
	}
	live, err := g.conn.GetSetElements(kset)
	if err != nil {
		return 0, fmt.Errorf("gate: read elements of %s: %w", AgentUpSet, err)
	}
	for _, e := range live {
		if bytes.Equal(e.Key, want) {
			return e.Expires, nil
		}
	}
	return 0, nil
}
