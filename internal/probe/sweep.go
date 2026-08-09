package probe

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/jotra7/postern/internal/client"
)

// DefaultService is the gate the sweep drives. It is an ordinary service
// name, not a special case anywhere in the codebase: what makes it a canary
// is its configuration (listener_expectation: absent, verification:
// tcp_rst, fail_posture closed), which is why this is a field on Prober
// rather than a constant nothing can change.
const DefaultService = "canary"

// DefaultClosedTimeout bounds phase 1. Phase 1 expects silence, so this is
// paid in full on every passing sweep — that is what makes it short. It is
// long enough that a slow path is not mistaken for a drop and short enough
// that the whole sweep fits inside the canary's 30-second default TTL with
// room for the knock and phase 2.
const DefaultClosedTimeout = 2 * time.Second

// DefaultOpenTimeout bounds one phase-2 attempt. It matches the client's
// confirmation timeout: this is the same connect, against the same gate,
// for the same reason.
const DefaultOpenTimeout = client.DefaultConnectTimeout

// DefaultOpenAttempts is how many times phase 2 retries a timeout. A
// refusal is definitive and stops the loop immediately (see client.Confirm),
// so this costs nothing on a passing sweep and covers the case where the
// gate element lands microseconds after the first connect left.
const DefaultOpenAttempts = 2

// DefaultSettle is the pause between the knock and phase 2. The agent has
// to receive the datagram, validate it, and commit a netlink transaction;
// connecting before that is a race the probe would lose intermittently and
// report as a red host.
const DefaultSettle = 250 * time.Millisecond

// Verdict is whether a sweep supplied the evidence it exists to supply.
type Verdict string

const (
	// Pass: phase 1 timed out and phase 2 was refused. Both halves of I2.
	Pass Verdict = "pass"
	// Fail: anything else. See Reason.
	Fail Verdict = "fail"
)

// Reason names which of the several distinguishable failures happened. It
// is a separate field from the verdict because "the host is red" and "the
// host has no firewall at all" call for different people to be woken up.
type Reason string

const (
	// ReasonNone accompanies a pass.
	ReasonNone Reason = ""

	// ReasonGateNotClosed: phase 1 answered with a reset. The canary port is
	// reachable with no gate open, so a connect there proves nothing about
	// postern and a phase-2-only probe would have reported this host green
	// forever. This is the failure the phase-1 assertion exists to catch.
	ReasonGateNotClosed Reason = "gate not closed"

	// ReasonListenerPresent: phase 1 answered by connecting. Everything
	// ReasonGateNotClosed means, and additionally something is listening on
	// a port whose listener_expectation is absent — which design section 4
	// calls red on its own, because it converts a stolen probe key from "can
	// open a port with nothing behind it" into "can open a reachable
	// service".
	ReasonListenerPresent Reason = "listener present on the canary port"

	// ReasonKnockNotSent: the datagram never left this machine, so the agent
	// has seen nothing and phase 2 could not mean anything.
	ReasonKnockNotSent Reason = "knock not sent"

	// ReasonGateNotOpened: phase 1 was correct and phase 2 timed out. The
	// host is unreachable end to end. This is the ordinary red.
	ReasonGateNotOpened Reason = "gate did not open"

	// ReasonNoRoute: the network rejected a connect before it left. This is
	// connectivity, not authorization; the knock cannot have arrived either.
	ReasonNoRoute Reason = "no route"

	// ReasonUnclassified: a connect failed in a way client.Classify does not
	// categorize. Reported as itself rather than folded into a neighbour.
	ReasonUnclassified Reason = "unclassified connect error"

	// ReasonInternal: the sweep could not be performed — no identity, no
	// such service, a counter file that will not write. Not evidence about
	// the host.
	ReasonInternal Reason = "probe error"
)

// Reasons is every value Sweep.Reason can carry. It is exported so a metrics
// implementation can pre-declare its label values — the set is closed, so
// `reason` costs one series per host per entry and nothing derived from the
// network ever becomes a label.
//
// The list is maintained by hand alongside the constants above; what a test
// enforces is that every entry has its own diagnosis, so a reason added
// without one is a failure rather than a sweep that reports "nothing is
// ruled in or out" about a cause the code knew perfectly well.
var Reasons = []Reason{
	ReasonNone,
	ReasonGateNotClosed,
	ReasonListenerPresent,
	ReasonKnockNotSent,
	ReasonGateNotOpened,
	ReasonNoRoute,
	ReasonUnclassified,
	ReasonInternal,
}

// Sweep is one complete two-phase measurement, and the only thing this
// package asks anyone to believe. Every field is an observation; none of it
// is postern's report of what postern did.
type Sweep struct {
	// Host and Service name what was measured.
	Host    string
	Service string
	// KnockAddr is where the datagram went; ConnectAddr is what both phases
	// dialled. They differ by port, and neither is ever a hostname.
	KnockAddr   netip.AddrPort
	ConnectAddr netip.AddrPort

	// Start is when the sweep began and Duration how long it took, both from
	// the injected clock.
	Start    time.Time
	Duration time.Duration

	// Closed is phase 1: the connect made while the gate should be shut. A
	// passing sweep has Closed.Outcome == client.TimedOut and nothing else.
	Closed client.Result
	// Knocked reports whether the SPA datagram left this machine, and
	// KnockErr why it did not.
	Knocked  bool
	KnockErr error
	// Open is phase 2: the connect made after the knock. A passing sweep has
	// Open.Outcome == client.Refused and nothing else.
	Open client.Result

	Verdict Verdict
	Reason  Reason
	// Summary is one line. Detail says what this outcome rules in and out,
	// including what it cannot distinguish.
	Summary string
	Detail  string
	// Err carries a ReasonInternal failure's cause.
	Err error
}

// Passed reports whether both phases held.
func (s Sweep) Passed() bool { return s.Verdict == Pass }

// Prober performs one sweep against one host. Every timing bound and every
// external dependency is a field, so a test can drive the whole state
// machine without a socket and without waiting.
type Prober struct {
	// Builder seals the canary knock. Its Signer must hold an identity the
	// host grants the canary service — and, per design section 9, ideally
	// nothing else.
	Builder client.Builder
	// Host is the target, from the probe's own client config.
	Host *client.Host
	// Service names the canary gate. Empty selects DefaultService.
	Service string
	// TTL of zero asks the host for the service's configured default.
	TTL time.Duration
	// Counter persists the monotonic SPA counter. Nil sends counter 0, which
	// leaves only the timestamp freshness path — usable, but it gives up the
	// tolerance the counter path exists to provide.
	Counter *client.Counter

	// Send, Dial, NowMS, Now, and Sleep default to the production
	// implementations.
	Send  client.Sender
	Dial  client.Dialer
	NowMS func() uint64
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error

	ClosedTimeout time.Duration
	OpenTimeout   time.Duration
	OpenAttempts  int
	Settle        time.Duration
}

func (p *Prober) service() string {
	if p.Service == "" {
		return DefaultService
	}
	return p.Service
}

// Validate checks everything that can be checked before any packet moves,
// so a misconfigured probe fails at startup rather than reporting a red
// host every 137 seconds forever.
func (p *Prober) Validate() error {
	if p == nil || p.Host == nil {
		return fmt.Errorf("probe: no host")
	}
	if p.Builder.Signer == nil {
		return fmt.Errorf("probe: no operator identity is loaded")
	}
	if _, err := p.Host.Service(p.service()); err != nil {
		// Named rather than wrapped bare, because the fix is a grant and a
		// config line rather than anything the probe can do.
		return fmt.Errorf("probe: %w — the probe drives a gate service whose "+
			"listener_expectation is absent; see `postern init-standalone`, which generates one called %q",
			err, DefaultService)
	}
	return nil
}

// CanaryTTL is the TTL this prober will ask for, resolved against the
// host's configured default. The runner needs it to refuse a sweep interval
// short enough that one sweep's own gate would still be open when the next
// sweep's phase 1 runs — which would report a permanently red host with a
// perfectly healthy gate.
func (p *Prober) CanaryTTL() time.Duration {
	if p.TTL > 0 {
		return p.TTL
	}
	if p.Host == nil {
		return 0
	}
	svc, err := p.Host.Service(p.service())
	if err != nil {
		return 0
	}
	return svc.TTL
}

// Sweep runs both phases and reports what it observed.
//
// Phase 1 runs first and, when it fails, the sweep stops there without
// knocking. That is deliberate: a canary port that already answers cannot
// be made to say anything new by opening a gate to it, and knocking anyway
// would spend a real gate lease on a host whose posture is already known to
// be wrong.
func (p *Prober) Sweep(ctx context.Context) Sweep {
	now := p.Now
	if now == nil {
		now = time.Now
	}
	sw := Sweep{Host: hostName(p.Host), Service: p.service(), Start: now()}

	if err := p.Validate(); err != nil {
		return p.finish(sw, now, Fail, ReasonInternal, err)
	}
	svc, err := p.Host.Service(p.service())
	if err != nil {
		return p.finish(sw, now, Fail, ReasonInternal, err)
	}
	sw.KnockAddr = p.Host.KnockAddrPort()
	sw.ConnectAddr = p.Host.ConnectAddr(svc)

	dial := p.Dial
	if dial == nil {
		dial = client.DialTCP
	}
	send := p.Send
	if send == nil {
		send = client.UDPSend
	}
	sleep := p.Sleep
	if sleep == nil {
		sleep = SleepContext
	}

	// Phase 1. One attempt, never more: client.Confirm retries a
	// non-definitive outcome, and here the non-definitive outcome is the one
	// we are hoping for. Retrying it would multiply the cost of every passing
	// sweep by the attempt count for no information at all.
	sw.Closed = client.Confirm(ctx, dial, sw.ConnectAddr, orDuration(p.ClosedTimeout, DefaultClosedTimeout), 1)
	if r, ok := closedFailure(sw.Closed.Outcome); ok {
		return p.finish(sw, now, Fail, r, nil)
	}

	// The knock.
	nowMS := p.NowMS
	if nowMS == nil {
		nowMS = func() uint64 { return uint64(time.Now().UnixMilli()) } //nolint:gosec // a unix-millisecond clock is non-negative for any real time
	}
	ms := nowMS()
	// Under rotation, the canary knock goes to the current-window port too:
	// the agent does not bind the fixed port at all once rotation is on, so
	// a probe sent to KnockAddrPort's fixed default reports every rotation
	// host permanently red (ReasonGateNotOpened) whether or not the agent is
	// healthy. Task 7 changed `open` this way; the probe is the same SPA
	// carrier and missed the same change, exactly like confirm and disarm.
	// Computed here, right before the datagram that carries the same
	// timestamp is built, rather than at the top of Sweep: phase 1 above can
	// wait up to ClosedTimeout, and a port picked before that wait is a port
	// that may no longer be the current window's by the time this actually
	// goes on the wire.
	//nolint:gosec // G115: a millisecond wall-clock timestamp divided by 1000 is far within int64.
	if port, ok := p.Host.CurrentKnockPort(int64(ms / 1000)); ok {
		sw.KnockAddr = netip.AddrPortFrom(p.Host.KnockAddr, port)
	}
	datagram, err := p.seal(ms)
	if err != nil {
		return p.finish(sw, now, Fail, ReasonInternal, err)
	}
	if err := send(ctx, sw.KnockAddr, datagram); err != nil {
		sw.KnockErr = err
		return p.finish(sw, now, Fail, ReasonKnockNotSent, err)
	}
	sw.Knocked = true

	if err := sleep(ctx, orDuration(p.Settle, DefaultSettle)); err != nil {
		return p.finish(sw, now, Fail, ReasonInternal, err)
	}

	// Phase 2.
	sw.Open = client.Confirm(ctx, dial, sw.ConnectAddr,
		orDuration(p.OpenTimeout, DefaultOpenTimeout), orInt(p.OpenAttempts, DefaultOpenAttempts))
	if r, ok := openFailure(sw.Open.Outcome); ok {
		return p.finish(sw, now, Fail, r, nil)
	}
	return p.finish(sw, now, Pass, ReasonNone, nil)
}

// closedFailure maps a phase-1 outcome onto the reason it fails, and
// reports whether it fails at all.
//
// Only client.TimedOut passes, and that judgement is client.PriorFrom's
// rather than a second copy of it: `postern open` now makes the same connect
// before its own knock and asks the same question of the same outcomes, and
// two allow-lists that could disagree about what "shut" means is one more
// than this project can defend. It stays an allow-list of one wherever it
// lives, because this is the entire difference between a probe and a
// reassurance machine, and a list of rejections is what a later outcome value
// quietly slips past.
//
// The switch below maps the rejections onto probe's own vocabulary, which is
// where the two callers legitimately differ: a sweep needs to say which
// failure it was, and `open` needs only to know that the port was not shut.
func closedFailure(o client.Outcome) (Reason, bool) {
	if client.PriorFrom(o) == client.PriorShut {
		return ReasonNone, false
	}
	switch o {
	case client.Connected:
		return ReasonListenerPresent, true
	case client.Refused:
		return ReasonGateNotClosed, true
	case client.NoRoute:
		return ReasonNoRoute, true
	default:
		return ReasonUnclassified, true
	}
}

// openFailure is the same allow-list for phase 2, where the one passing
// outcome is a reset: nothing listens behind the canary port, so a gate that
// admitted the packet produces RST and a gate that did not produces silence.
func openFailure(o client.Outcome) (Reason, bool) {
	switch o {
	case client.Refused:
		return ReasonNone, false
	case client.Connected:
		return ReasonListenerPresent, true
	case client.TimedOut:
		return ReasonGateNotOpened, true
	case client.NoRoute:
		return ReasonNoRoute, true
	default:
		return ReasonUnclassified, true
	}
}

// seal builds and seals the canary knock. ms comes from the caller rather
// than from p.NowMS directly, so it is the exact same reading Sweep used to
// pick sw.KnockAddr under rotation — the packet and the port it goes to
// describing two different moments would be a harmless drift in practice
// (the window is ten minutes) but not one this function has any reason to
// introduce on its own.
func (p *Prober) seal(ms uint64) ([]byte, error) {
	var counter uint64
	if p.Counter != nil {
		var err error
		if counter, err = p.Counter.Next(ms); err != nil {
			return nil, err
		}
	}
	// No asserted source. The probe is not the CGNAT mitigation path: a
	// probe whose UDP and TCP egress differ is reporting a real fact about
	// the path it measures, and papering over it with a wide asserted prefix
	// would hand the canary grant a much larger blast radius to buy a green
	// light.
	req, err := p.Builder.Gate(p.Host, p.service(), p.TTL, nil, counter, ms)
	if err != nil {
		return nil, err
	}
	return p.Builder.Seal(req, p.Host)
}

func (p *Prober) finish(sw Sweep, now func() time.Time, v Verdict, r Reason, err error) Sweep {
	sw.Duration = now().Sub(sw.Start)
	sw.Verdict = v
	sw.Reason = r
	sw.Err = err
	sw.Summary, sw.Detail = describe(sw)
	return sw
}

// describe is the probe's half of client.Advise: the sentence a human reads,
// and the honest boundary on what it establishes.
func describe(sw Sweep) (summary, detail string) {
	target := sw.ConnectAddr.String()
	switch sw.Reason {
	case ReasonNone:
		return fmt.Sprintf("%s/%s: the gate was shut, the knock opened it, and it accepted only after the knock",
				sw.Host, sw.Service),
			"phase 1 timed out and phase 2 was refused. Both halves are required: a refusal in phase 1 " +
				"would mean the port answers with no gate open, which is what a host with no firewall at " +
				"all looks like, and checking only phase 2 cannot tell the two apart."

	case ReasonGateNotClosed:
		return fmt.Sprintf("%s/%s: %s answered before the knock", sw.Host, sw.Service, target),
			"phase 1 was refused rather than timing out, so the canary port is reachable with no gate " +
				"open. This is consistent with a missing drop rule, a flushed postern_boot, a host that " +
				"was never armed, and postern removed without disarming — and it is not consistent with " +
				"a working gate. Nothing measured after this point would mean anything, so the sweep did " +
				"not knock."

	case ReasonListenerPresent:
		return fmt.Sprintf("%s/%s: something is listening on %s", sw.Host, sw.Service, target),
			"the connect succeeded, so a real service is behind a port declared listener_expectation: " +
				"absent. That is red on its own (design section 4): it turns the probe identity from one " +
				"that can open a port with nothing behind it into one that can open a reachable service, " +
				"which is the claim the probe-theft analysis rests on."

	case ReasonKnockNotSent:
		return fmt.Sprintf("%s/%s: the knock never left this machine", sw.Host, sw.Service),
			"phase 1 was correct, but the datagram was not sent, so the agent has seen nothing and " +
				"phase 2 would measure the closed gate again. This is a fault on the probe host, not on " +
				"the target."

	case ReasonGateNotOpened:
		return fmt.Sprintf("%s/%s: %s did not answer after the knock", sw.Host, sw.Service, target),
			"phase 1 was correct — the gate is shut, and postern is doing something — but the knock did " +
				"not open it. Silence here is consistent with three things and cannot distinguish them: " +
				"the datagram was dropped upstream (a provider firewall in front of the host is the usual " +
				"one), the agent is not running, or this probe's UDP and TCP traffic egresses from " +
				"different addresses, so the gate opened for one and the connect arrived from the other."

	case ReasonNoRoute:
		return fmt.Sprintf("%s/%s: no route to %s", sw.Host, sw.Service, target),
			"the network rejected a connect before it left, so the knock cannot have arrived either. " +
				"This is connectivity, not authorization, and says nothing about the gate."

	case ReasonInternal:
		s := fmt.Sprintf("%s/%s: the sweep could not run", sw.Host, sw.Service)
		d := "this is a fault in the probe's own configuration or state, not an observation about the host"
		if sw.Err != nil {
			d += ": " + sw.Err.Error()
		}
		return s, d

	default:
		return fmt.Sprintf("%s/%s: a connect failed in a way postern does not classify", sw.Host, sw.Service),
			"nothing is ruled in or out" + errSuffix(sw)
	}
}

func errSuffix(sw Sweep) string {
	for _, e := range []error{sw.Closed.LastErr, sw.Open.LastErr, sw.Err} {
		if e != nil {
			return ": " + e.Error()
		}
	}
	return ""
}

// SleepContext waits for d or until ctx is done, whichever is first. It is
// the production Prober.Sleep and Runner.Sleep, exported so a caller
// building either by hand gets the bounded implementation rather than
// time.Sleep.
func SleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func hostName(h *client.Host) string {
	if h == nil {
		return ""
	}
	return h.Name
}

func orDuration(v, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return v
}

func orInt(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}
