package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/jotra7/postern/internal/config"
	"github.com/jotra7/postern/internal/gate"
)

// Pre-arm is split in two, and the split is the whole point (design section
// 7, "Pre-arm degrades per service").
//
// An all-or-nothing gate would let an unrelated outage take down
// break-glass: if listener_expectation were checked globally, a postgres
// daemon that failed to come back after a reboot would fail pre-arm, keep
// the agent inert, leave agent_up unset, and silence the SPA port for every
// service including ssh. A database outage would have removed the door built
// for outages.
//
// So: global preconditions keep the agent inert, because nothing works
// without them. Per-service preconditions disable exactly their own service
// and leave the SPA listener, agent_up, and every other gate alone.

// PreArmChecks are pre-arm's probes, injected so the decision logic in
// RunPreArm is testable without a kernel, a network, or a filesystem. Any
// nil field is filled from ProductionChecks by Daemon construction; a
// hand-built PreArmChecks with nil fields treats those checks as passing,
// which is why New never passes one through unfilled.
type PreArmChecks struct {
	// --- global: failure keeps the agent inert ---

	// NFTBinary reports whether nft(8) is present. It is a runtime
	// requirement on every host, for the boot path and for fail-open
	// teardown, neither of which may depend on the postern binary.
	NFTBinary func() error
	// FirewallReady is the gate backend's own capability check (design
	// section 4): nftables present, writable, and able to hold the interval
	// plus timeout sets asserted CIDRs need.
	FirewallReady func(ctx context.Context) error
	// StoreWritable reports whether the replay store can still be durably
	// written. An agent that cannot record a reservation cannot reason about
	// replay at all.
	StoreWritable func() error
	// OperatorKeys reports whether at least one operator key is loaded.
	// Without one, nothing can ever authenticate and the SPA port would be
	// an open UDP socket serving no purpose.
	OperatorKeys func(policy *config.Policy) error
	// AlwaysAllow reports whether the always-allow interface or CIDR
	// resolves. Under fail-closed it is the only route in (I5).
	//
	// An error wrapping ErrAlwaysAllowDegraded is recorded as a warning
	// rather than a global failure; see that sentinel for where the line
	// sits and why.
	AlwaysAllow func(policy *config.Policy) error
	// ForeignFirewall probes for foreign nftables base chains that could
	// override postern's own gate (invariant 2, ErrForeignFirewall's own
	// doc comment). Unlike AlwaysAllow this has exactly one verdict, not
	// two: any error it returns is recorded as a warning, never as a
	// global failure — a foreign firewall is routinely intentional and
	// correctly configured, and the alternative (going inert because
	// something else on the host also filters traffic) would brick hosts
	// that run ufw or firewalld deliberately alongside postern. A nil
	// field, like every other optional probe here, is treated as passing;
	// ProductionChecks leaves it nil on any Gate this probe cannot run
	// against.
	ForeignFirewall func() error

	// --- per-service: failure disables only that service ---

	// ListenerUp reports whether something is listening on a gate service's
	// ports. Consulted only when the service declares an expectation other
	// than "unchecked".
	ListenerUp func(ctx context.Context, svc config.Service) (bool, error)
	// PortsArmable reports whether this service's ports and sets can be
	// bound into the ruleset.
	PortsArmable func(ctx context.Context, svc config.Service) error
}

// ErrAlwaysAllowDegraded marks an always-allow finding that must be reported
// loudly and must NOT keep the agent inert.
//
// The line it draws is "the configured name resolves to nothing on this
// host" (global, inert) versus "it resolves, and what it resolves to is
// currently no use" (warning, still armed). Both are bad. They are not
// symmetric, and treating them the same locks hosts out:
//
// Inert on a fail-closed host means boot.nft's drop rules are live, nothing
// can open them, and the SPA port is silent (design section 7). An agent
// that arms with a dead always-allow path leaves the same drops live but
// keeps SPA answering — strictly more recoverable. So refusing to arm
// *because the backup path is dead* removes the primary path too, at the
// exact moment the backup is known not to cover for it. That is the shape
// of failure the global/per-service split already exists to prevent: "a
// database outage would have removed the door built for outages."
//
// A down or address-less interface is also the ordinary shape of a
// transient — a mesh flap, `tailscale down`, a DHCP renegotiation, a link
// renegotiating after a reboot — and it self-heals with no operator. An
// unresolvable name does not: something has to be edited. That asymmetry,
// not the severity, is what puts them in different buckets.
//
// Design section 7 also settles what is lost by not gating on it: "checking
// that the interface is up with an address is not sufficient", because
// expired mesh credentials leave the interface up, addressed, and routing
// nothing. The proof that the path works is the arm-time liveness challenge
// on the deploy path, not this probe: `postern confirm` runs client.Status
// (an authenticated liveness pong plus a recovery-service connect) before it
// ratifies an arm and refuses on a dead recovery path, which is the I5
// interlock this probe deliberately is not. Gating the agent's existence on a
// signal the design already calls insufficient buys very little and costs
// the host its last door.
var ErrAlwaysAllowDegraded = errors.New("always-allow path is degraded but present")

// ErrForeignFirewall marks a foreign nftables base chain finding: a chain
// this host did not get from postern, sharing a hook postern's own ruleset
// also registers a chain on, whose policy or rules carry a drop or reject.
//
// nftables runs every base chain registered on a hook, and a drop verdict
// in any one of them is terminal regardless of an accept in another
// (design section 4, invariant 2 — see internal/gate/nft_linux.go's
// applyTable, which duplicates postern's own always-allow and
// established/related rules into both its tables for exactly this reason).
// postern can enforce that duplication inside its own two tables. It
// cannot reach into a table iptables-nft, ufw, firewalld, or a hand-rolled
// ruleset owns, and a drop sitting there is invisible from the knock's
// point of view: the gate really did open (Open returned no error, the set
// really holds the source), and the SYN still dies, because something else
// on the same hook killed it first. That is the exact silent-failure shape
// this whole feature exists to surface — see the motivating bug: a host
// running `table ip filter` with an IP allowlist and its own "tcp dport 22
// ... drop" alongside postern's gate, where postern opened for the knocker
// and the foreign drop killed the SYN anyway.
//
// Unlike ErrAlwaysAllowDegraded this sentinel has exactly one verdict.
// There is no global-failure branch for it: a foreign firewall on the same
// hook is routinely intentional and correctly configured (an operator's
// own IP allowlist, a distro's default ufw policy, firewalld zones), and
// going inert because some other component also filters traffic on this
// host would be a much worse failure than the one this warning reports —
// it would silence the SPA port over a firewall that is probably fine and
// certainly none of postern's business to override. So every error
// RunPreArm gets back from ForeignFirewall lands in Warnings, always,
// regardless of what wraps this sentinel; naming the specific chains and
// explaining the override risk is the wiring's job (ProductionChecks), not
// this sentinel's.
var ErrForeignFirewall = errors.New("a foreign nftables base chain could override postern's gate")

// PreArm is what pre-arm decided. The zero value arms nothing.
type PreArm struct {
	// Global holds the failed global preconditions. Non-empty means inert.
	Global []error
	// Warnings holds findings that are reported but do not keep the agent
	// inert. Today that is exactly the degraded always-allow path (see
	// ErrAlwaysAllowDegraded): loud, visible in Summary and in the journal,
	// and deliberately not an interlock.
	Warnings []error
	// Disabled maps a gate service's name to why it is not armed. A service
	// absent from this map, on a non-inert result, is armed.
	Disabled map[string]error
	// FailClosedDropsLive records that this host has at least one
	// fail-closed gate, so boot.nft's drop rules are live independently of
	// the agent. It matters most when Inert() is true: "inert" on such a
	// host does not mean nothing is dropping traffic, it means the drops are
	// enforced with nothing able to open them and no SPA to knock with
	// (design section 7).
	FailClosedDropsLive bool
}

// Inert reports whether a global precondition failed. An inert agent arms no
// gate, creates no postern_open, never sets agent_up, and therefore never
// makes the SPA port reachable.
func (r PreArm) Inert() bool { return len(r.Global) > 0 }

// SPAEnabled reports whether the SPA listener may come up and agent_up may
// be refreshed. This is deliberately not a function of any per-service
// outcome: that coupling is the exact bug the global/per-service split
// exists to prevent.
func (r PreArm) SPAEnabled() bool { return !r.Inert() }

// ServiceEnabled reports whether a named service may be acted on. Actions
// (confirm, disarm, liveness) own no ports and no listener, so they are
// never disabled per-service — only by the agent being inert.
func (r PreArm) ServiceEnabled(name string) bool {
	if r.Inert() {
		return false
	}
	_, disabled := r.Disabled[name]
	return !disabled
}

// Summary is one line an operator can act on. On an inert fail-closed host
// it states the position plainly rather than leaving "inert" to be read as
// "nothing is happening".
func (r PreArm) Summary() string {
	if !r.Inert() {
		msg := "pre-arm: all preconditions satisfied"
		if len(r.Disabled) > 0 {
			names := make([]string, 0, len(r.Disabled))
			for name := range r.Disabled {
				names = append(names, name)
			}
			sort.Strings(names)
			msg = fmt.Sprintf("pre-arm: armed, with %d service(s) disabled: %s", len(names), strings.Join(names, ", "))
		}
		return msg + r.warningSuffix()
	}

	reasons := make([]string, 0, len(r.Global))
	for _, err := range r.Global {
		reasons = append(reasons, err.Error())
	}
	msg := "pre-arm: INERT, no gate can be opened and the SPA port is silent: " + strings.Join(reasons, "; ")
	if r.FailClosedDropsLive {
		msg += "; this host has fail-closed services, so boot.nft's drop rules are already live " +
			"and nothing can open them — reachable only via the always-allow path or console"
	}
	return msg + r.warningSuffix()
}

// warningSuffix appends the non-interlocking findings. They ride on Summary
// rather than living somewhere only a debugger looks because a warning
// nobody is shown is the same as no warning — which is how an always-allow
// interface that protects nobody stayed invisible in the first place.
func (r PreArm) warningSuffix() string {
	if len(r.Warnings) == 0 {
		return ""
	}
	reasons := make([]string, 0, len(r.Warnings))
	for _, err := range r.Warnings {
		reasons = append(reasons, err.Error())
	}
	return fmt.Sprintf("; WARNING (armed anyway): %s", strings.Join(reasons, "; "))
}

// RunPreArm evaluates every precondition and reports what may be armed. It
// runs every check rather than stopping at the first failure, so an operator
// sees the whole picture in one pass instead of fixing one precondition at a
// time.
func RunPreArm(ctx context.Context, policy *config.Policy, checks PreArmChecks) PreArm {
	res := PreArm{Disabled: map[string]error{}, FailClosedDropsLive: policy.HasFailClosed()}

	if checks.NFTBinary != nil {
		if err := checks.NFTBinary(); err != nil {
			res.Global = append(res.Global, fmt.Errorf("nft(8) is a runtime requirement for the boot path and fail-open teardown: %w", err))
		}
	}
	if checks.FirewallReady != nil {
		if err := checks.FirewallReady(ctx); err != nil {
			res.Global = append(res.Global, fmt.Errorf("firewall backend cannot enforce policy: %w", err))
		}
	}
	if checks.StoreWritable != nil {
		if err := checks.StoreWritable(); err != nil {
			res.Global = append(res.Global, fmt.Errorf("replay store is not writable: %w", err))
		}
	}
	if checks.OperatorKeys != nil {
		if err := checks.OperatorKeys(policy); err != nil {
			res.Global = append(res.Global, fmt.Errorf("no operator key is loaded: %w", err))
		}
	}
	if checks.AlwaysAllow != nil && policy.AlwaysAllowIface != "" {
		// Keyed on the interface being present, not on the console-recovery
		// flag: pure console-recovery has no interface and nothing to verify,
		// but an interface named alongside --console-recovery is a real path
		// and is verified like any other. Skipping on the flag would leave a
		// dead mesh wired into the ruleset (render emits its accept on
		// interface presence) and never checked.
		if err := checks.AlwaysAllow(policy); err != nil {
			// The one precondition with two verdicts. See
			// ErrAlwaysAllowDegraded: an unresolvable name is a
			// configuration nothing but an edit will fix, while a resolvable
			// name pointing at a currently-useless interface is usually a
			// transient — and going inert over a transient takes the SPA
			// port down with it on a fail-closed host.
			if errors.Is(err, ErrAlwaysAllowDegraded) {
				res.Warnings = append(res.Warnings, err)
			} else {
				res.Global = append(res.Global, fmt.Errorf("always-allow path does not resolve: %w", err))
			}
		}
	}
	if checks.ForeignFirewall != nil {
		// Always a warning, never a global failure — see ErrForeignFirewall's
		// doc for why this probe has only one verdict, unlike AlwaysAllow's
		// two. There is deliberately no errors.Is branch here: whatever
		// ForeignFirewall returns lands in Warnings regardless of what it
		// wraps, though the wiring in ProductionChecks always wraps
		// ErrForeignFirewall so a caller that wants to distinguish this
		// finding from other warnings still can.
		if err := checks.ForeignFirewall(); err != nil {
			res.Warnings = append(res.Warnings, err)
		}
	}

	// Per-service checks run even when a global precondition already failed:
	// the result is inert either way, and an operator fixing the global
	// problem should not then discover a second, per-service one on the next
	// start.
	names := make([]string, 0, len(policy.Services))
	for name := range policy.Services {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		svc := policy.Services[name]
		if svc.Kind != config.KindGate {
			continue // actions own no ports and no listener
		}
		if err := checkService(ctx, svc, checks); err != nil {
			res.Disabled[name] = err
		}
	}
	return res
}

func checkService(ctx context.Context, svc config.Service, checks PreArmChecks) error {
	if checks.PortsArmable != nil {
		if err := checks.PortsArmable(ctx, svc); err != nil {
			return fmt.Errorf("ports cannot be armed into the ruleset: %w", err)
		}
	}
	if checks.ListenerUp == nil || svc.ListenerExpectation == config.ListenerUnchecked || svc.ListenerExpectation == "" {
		return nil
	}

	up, err := checks.ListenerUp(ctx, svc)
	if err != nil {
		return fmt.Errorf("listener probe failed: %w", err)
	}
	switch svc.ListenerExpectation {
	case config.ListenerPresent:
		if !up {
			return fmt.Errorf("listener_expectation is %q but nothing is listening on %s/%v",
				config.ListenerPresent, svc.Proto, svc.Ports)
		}
	case config.ListenerAbsent:
		if up {
			// I2: a listener behind an absent-expectation gate makes the
			// canary's post-knock RST come from something real rather than
			// from the gate, so the proof it exists to give is worthless.
			return fmt.Errorf("listener_expectation is %q but something is listening on %s/%v; "+
				"its verification would report green from the listener rather than from the gate",
				config.ListenerAbsent, svc.Proto, svc.Ports)
		}
	}
	return nil
}

// --- production probes ------------------------------------------------

// ProductionChecks builds the real probes. Any field the caller already set
// on base is left alone, so a test can replace one probe without stubbing
// the rest.
//
// g and storePath are what the production probes need beyond the policy: the
// gate backend answers the capability check, and the replay store's own
// directory is what "writable" is asked about (the store itself is already
// open and holding an exclusive lock by this point, so probing it by writing
// a record would consume a request_id to answer a health question).
func ProductionChecks(base PreArmChecks, g gate.Gate, storePath string, nftPath string) PreArmChecks {
	if nftPath == "" {
		nftPath = gate.DefaultNFTPath
	}
	if base.NFTBinary == nil {
		base.NFTBinary = func() error {
			if _, err := os.Stat(nftPath); err == nil {
				return nil
			}
			if _, err := exec.LookPath("nft"); err != nil {
				return fmt.Errorf("nft not found at %s and not on PATH: %w", nftPath, err)
			}
			return nil
		}
	}
	if base.FirewallReady == nil {
		base.FirewallReady = func(ctx context.Context) error {
			h, err := g.Health(ctx)
			if err != nil {
				return err
			}
			if !h.Healthy {
				return errors.New(h.Detail)
			}
			return nil
		}
	}
	if base.StoreWritable == nil {
		base.StoreWritable = func() error {
			// Guarded rather than trusted. filepath.Dir("") is ".", so an
			// unset storePath would silently probe the working directory —
			// "/" under systemd, which is writable as root on every host —
			// and report a global precondition satisfied about a filesystem
			// that is not the one the store lives on. A read-only
			// /var/lib/postern would sail straight through. Daemon
			// construction refuses an empty StorePath for this reason; this
			// is the second lock on the same door, for a caller that built
			// PreArmChecks directly.
			if storePath == "" {
				return errors.New("no replay store path was configured, so writability cannot be established")
			}
			return dirWritable(filepath.Dir(storePath))
		}
	}
	if base.OperatorKeys == nil {
		base.OperatorKeys = func(policy *config.Policy) error {
			if len(policy.Operators) == 0 {
				return errors.New("policy declares no operators")
			}
			return nil
		}
	}
	if base.AlwaysAllow == nil {
		base.AlwaysAllow = alwaysAllowResolvable
	}
	if base.ForeignFirewall == nil {
		// A type assertion, not a build-tag split. gate.Gate has other
		// implementations — test fakes in this package, and eventually a
		// non-nftables backend (design section 13) — that have no chains
		// to enumerate at all, and *gate.NFTables itself only exists on
		// Linux (internal/gate/nft_linux.go). foreignFirewallProbe asks for
		// exactly the one method this wiring needs; a Gate that does not
		// implement it is simply not probed, the same "absent means
		// passing" contract every other nil PreArmChecks field already
		// carries, and this file itself never has to name a Linux-only
		// type to say so.
		if probe, ok := g.(foreignFirewallProbe); ok {
			base.ForeignFirewall = func() error {
				findings := probe.ForeignFirewallFindings()
				if len(findings) == 0 {
					return nil
				}
				return foreignFirewallFindingsError(findings)
			}
		}
	}
	if base.ListenerUp == nil {
		base.ListenerUp = listenerUp
	}
	if base.PortsArmable == nil {
		base.PortsArmable = func(ctx context.Context, svc config.Service) error {
			// Only fail-closed services are checkable here, and the
			// asymmetry is real rather than a shortcut. Their sets live in
			// postern_boot, which the boot unit loaded from boot.nft before
			// the agent started — so a boot.nft that predates this service
			// leaves it with accept rules referring to sets that do not
			// exist, and every knock for it would fail at Open time with the
			// service looking armed. State() is exactly the probe for that:
			// it resolves each of the service's sets by name and errors if
			// one is missing.
			//
			// A fail-open service's sets live in postern_open, which the
			// agent creates itself from the same plan, after pre-arm has
			// run. There is nothing to reconcile against at this point, and
			// the question is instead answered by ApplyOpen succeeding,
			// which Run already treats as fatal.
			if svc.FailPosture != config.PostureClosed {
				return nil
			}
			if _, err := g.State(ctx, svc.Name); err != nil {
				return err
			}
			return nil
		}
	}
	return base
}

// foreignFirewallProbe is the minimal surface ProductionChecks needs from a
// Gate to run the foreign-chain probe: today only *gate.NFTables implements
// it (internal/gate/nft_foreign_linux.go's ForeignFirewallFindings). It is
// declared as an interface, rather than a type assertion straight to
// *gate.NFTables, so that this file — which has to build on every GOOS
// postern targets, unlike the Linux-only gate file that satisfies it —
// never has to name a type that only exists under //go:build linux.
type foreignFirewallProbe interface {
	// ForeignFirewallFindings returns one rendered line per foreign base
	// chain flagged, or nil if none were found or the probe itself could
	// not run (see ForeignFirewallChains' best-effort doc in package gate).
	ForeignFirewallFindings() []string
}

// foreignFirewallFindingsError turns a non-empty findings slice into the
// error ForeignFirewall returns, wrapping ErrForeignFirewall so a caller can
// still errors.Is this specific warning out of res.Warnings, and naming
// every chain plus the override risk in the text an operator actually
// reads (Summary's "WARNING (armed anyway): ..." suffix).
func foreignFirewallFindingsError(findings []string) error {
	return fmt.Errorf("%w — nftables runs every base chain on a hook, and a drop verdict in any of "+
		"them is terminal regardless of an accept in another (design section 4, invariant 2); confirm "+
		"these chains permit the gated ports or your source: %s",
		ErrForeignFirewall, strings.Join(findings, "; "))
}

// alwaysAllowResolvable is design section 7's global precondition
// "always-allow interface or CIDR resolvable", which until now was only a
// non-emptiness check in two places — so `always_allow_iface: lo` satisfied
// every gate postern had and protected nobody. That is a real lockout: the
// rail was present in the ruleset, never touched, and never useful.
//
// It answers two different questions and returns two different classes of
// error for them. See ErrAlwaysAllowDegraded.
func alwaysAllowResolvable(policy *config.Policy) error {
	name := policy.AlwaysAllowIface
	if name == "" {
		return errors.New("always_allow_iface is unset")
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		// Global. The rail named in postern's own ruleset matches no
		// interface on this host, so rail 1 is a string in a file. Nothing
		// but an edit — or the interface finally appearing — changes that,
		// and the second case costs one RestartSec: Run returns ErrInert,
		// the unit is Restart=always/RestartSec=5s, so a mesh daemon that
		// creates its interface after posternd starts heals in seconds
		// rather than locking the host out.
		return fmt.Errorf("interface %q: %w", name, err)
	}
	addrs, addrErr := iface.Addrs()
	return classifyAlwaysAllowIface(name, iface.Flags, len(addrs), addrErr)
}

// classifyAlwaysAllowIface holds the verdict for an interface that exists,
// separated from the lookup so every branch is reachable in a test without
// root, netlink, or a machine that happens to have a down interface on it.
//
// Every finding here is degraded rather than global. A loopback rail is a
// configuration error as surely as a typo is, but the refusal for it belongs
// at enrollment (postern init-standalone), where the operator still has a
// working way in and nothing has been written yet. Making it inert here
// would turn every host already enrolled with `lo` into a console-only host
// at its next agent restart — manufacturing the lockout this check exists to
// prevent, on a host that was reachable a moment earlier.
func classifyAlwaysAllowIface(name string, flags net.Flags, addrs int, addrErr error) error {
	switch {
	case flags&net.FlagLoopback != 0:
		return fmt.Errorf("%w: interface %q is loopback, which no remote operator can arrive on, so "+
			"the always-allow rule above every gate protects nobody; re-enroll with the interface an "+
			"operator would actually reach this host over", ErrAlwaysAllowDegraded, name)
	case flags&net.FlagUp == 0:
		return fmt.Errorf("%w: interface %q is down, so the only route into this host under fail-closed "+
			"is not carrying traffic right now", ErrAlwaysAllowDegraded, name)
	case addrErr != nil:
		return fmt.Errorf("%w: interface %q addresses could not be read: %v", ErrAlwaysAllowDegraded, name, addrErr)
	case addrs == 0:
		return fmt.Errorf("%w: interface %q is up but has no address, so nothing can be routed to it",
			ErrAlwaysAllowDegraded, name)
	}
	return nil
}

// dirWritable probes a directory by creating and removing a file in it,
// rather than by inspecting mode bits — which say nothing about a read-only
// mount, a full filesystem, or a restrictive MAC policy, all of which are
// the actual ways this precondition fails in production.
func dirWritable(dir string) error {
	f, err := os.CreateTemp(dir, ".postern-writable-*")
	if err != nil {
		return err
	}
	name := f.Name()
	closeErr := f.Close()
	rmErr := os.Remove(name)
	return errors.Join(closeErr, rmErr)
}

// listenerUp reports whether a gate service's ports are already bound, by
// attempting to bind them itself: a bind that fails with "address in use"
// means something is listening. This is asked rather than a loopback dial
// because a daemon bound only to a public address answers no loopback
// connection, and would read as absent.
//
// The probe binds and immediately closes, so there is a sub-millisecond
// window in which the port is held by postern. It runs once, at startup,
// before anything is armed.
func listenerUp(ctx context.Context, svc config.Service) (bool, error) {
	network := svc.Proto
	if network == "" {
		network = "tcp"
	}
	var lc net.ListenConfig
	for _, port := range svc.Ports {
		addr := net.JoinHostPort("", strconv.Itoa(int(port)))
		ln, err := lc.Listen(ctx, network, addr)
		if err != nil {
			// Any bind failure means the port is not available to postern,
			// which for this probe's purpose is indistinguishable from — and
			// operationally equivalent to — something already holding it.
			return true, nil //nolint:nilerr // see comment: a failed bind is the positive answer here
		}
		if err := ln.Close(); err != nil {
			return false, err
		}
	}
	return false, nil
}
