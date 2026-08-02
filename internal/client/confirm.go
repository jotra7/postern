package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"time"
)

// DefaultActionSends and DefaultActionResendDelay are how many copies of one
// action datagram SendAction puts on the wire, and how long it waits between
// them.
//
// A confirm is one UDP datagram like any other knock, and UDP does not
// guarantee delivery. On a live two-host fleet the first confirm to one host
// was lost and the second landed; the other host took four attempts. The
// consequence of a lost confirm is not a retry an operator can make — it is
// an automatic revert ten minutes later, which is the expensive failure this
// command exists to prevent.
//
// Resending is safe because an action packet is idempotent at the agent: a
// confirm names one transaction by revision and nonce, so a second copy
// either ratifies the same transaction again or is refused as a replay by the
// store. Nothing here can observe delivery — the SPA path never answers — so
// every copy is sent unconditionally rather than until something acknowledges.
//
// Three, with 300ms between them, is sized against what it costs: three
// datagrams is nothing to the host and the whole sequence finishes inside a
// second, well under any confirmation window.
const (
	DefaultActionSends       = 3
	DefaultActionResendDelay = 300 * time.Millisecond
)

// Outcome is what the confirmation connect established. The SPA path never
// replies (design section 5), so these four are the entire evidence base an
// operator has, and each one points at a different next action.
type Outcome string

const (
	// Connected: the gate is open and the service answered. Nothing else to
	// diagnose.
	Connected Outcome = "connected"
	// Refused: a TCP RST came back, so packets reach the host and the gate
	// let this one through. Postern's job is done and the service is down.
	Refused Outcome = "refused"
	// NoRoute: the kernel had no route, or the network declared the host
	// unreachable. The knock cannot have arrived either.
	NoRoute Outcome = "no route"
	// TimedOut: nothing came back at all. Three causes are indistinguishable
	// from here — dropped upstream, agent dead, or a CGNAT split egress —
	// and Advise names all three rather than guessing.
	TimedOut Outcome = "timeout"
	// Unclassified: a dial error that is none of the above. Reported with
	// its error text rather than forced into a category, because a category
	// an operator cannot trust is worse than an unfamiliar error string.
	Unclassified Outcome = "unclassified"
)

// definitive reports whether this outcome ends the confirmation: the packet
// demonstrably reached the host, so a retry would only cost the operator
// time.
func (o Outcome) definitive() bool { return o == Connected || o == Refused }

// Prior is what a connect made before the knock established about the target
// port. It is the half of the evidence a post-knock connect cannot supply on
// its own: "the port answers" and "the port answers now and did not a moment
// ago" are very different claims, and only the second one is about postern.
type Prior string

const (
	// PriorUnmeasured: no connect was made before the knock. This is the zero
	// value, so a caller that does not pre-connect gets it without saying
	// anything, and every claim downstream stays exactly as strong as it was
	// before there was a pre-connect at all.
	PriorUnmeasured Prior = ""
	// PriorShut: the pre-knock connect timed out. Nothing answered on that
	// port before the knock.
	PriorShut Prior = "shut"
	// PriorAnswering: the pre-knock connect was answered, by the service or by
	// a reset. The port was already reachable, which three unrelated states
	// produce and which a second connect cannot tell apart.
	PriorAnswering Prior = "answering"
	// PriorUnclear: the pre-knock connect failed in a way that says nothing
	// about the gate, no route being the ordinary one. Advise treats it
	// exactly as PriorUnmeasured, because a measurement that established
	// nothing supports the same claims as one that was never made.
	PriorUnclear Prior = "unclear"
)

// PriorFrom maps a pre-knock connect's outcome onto what it established.
//
// Only a timeout means the port was shut. That is written as an allow-list of
// one rather than as a list of rejections, so an Outcome value added later
// cannot slip into the branch that licenses the strongest thing `open` says.
// internal/probe's phase 1 asks this same question of these same outcomes and
// calls this rather than keeping a second copy of the answer.
func PriorFrom(o Outcome) Prior {
	switch o {
	case TimedOut:
		return PriorShut
	case Connected, Refused:
		return PriorAnswering
	default:
		return PriorUnclear
	}
}

// Prior reports what this Result establishes when it is the connect made
// before the knock. A Result with no attempts was never made, and reports
// PriorUnmeasured rather than being classified as though it had been.
func (r Result) Prior() Prior {
	if r.Attempts == 0 {
		return PriorUnmeasured
	}
	return PriorFrom(r.Outcome)
}

// Dialer is the confirmation's only network dependency, injected so the
// state machine is testable without a socket. It matches net.Dialer's
// DialContext.
type Dialer func(ctx context.Context, network, address string) (net.Conn, error)

// Result is the confirmation's finding.
type Result struct {
	Outcome  Outcome
	Attempts int
	// LastErr is the dial error the outcome was classified from, kept so an
	// Unclassified outcome can still show the operator what happened.
	LastErr error
}

// Confirm connects to addr, up to attempts times with timeout per attempt,
// and reports what it could distinguish.
//
// It never waits for a reply from the agent, because there is none: a gate
// request is confirmed by the service becoming reachable and by nothing
// else.
//
// Retries stop early on a definitive outcome. A refusal is as conclusive as
// a connection — both prove the packet reached the host and the gate
// admitted it — and retrying either would add seconds to an incident for no
// new information.
func Confirm(ctx context.Context, dial Dialer, addr netip.AddrPort, timeout time.Duration, attempts int) Result {
	if attempts < 1 {
		attempts = 1
	}
	if timeout <= 0 {
		timeout = DefaultConnectTimeout
	}
	res := Result{Outcome: Unclassified}

	for i := 0; i < attempts; i++ {
		res.Attempts = i + 1
		attemptCtx, cancel := context.WithTimeout(ctx, timeout)
		conn, err := dial(attemptCtx, "tcp", addr.String())
		cancel()
		if conn != nil {
			_ = conn.Close()
		}
		res.Outcome = Classify(err)
		res.LastErr = err
		if res.Outcome.definitive() {
			return res
		}
		if ctx.Err() != nil {
			return res
		}
	}
	return res
}

// Classify maps a dial error onto the distinction it supports.
//
// The comparisons are against errno values rather than error strings: a
// net.OpError's text is not an interface, and matching on it would break
// silently on a Go release or a different libc. errors.Is walks the wrapping
// chain, so a *net.OpError wrapping an *os.SyscallError wrapping
// syscall.ECONNREFUSED matches.
func Classify(err error) Outcome {
	if err == nil {
		return Connected
	}
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return Refused
	case errors.Is(err, syscall.EHOSTUNREACH),
		errors.Is(err, syscall.ENETUNREACH),
		errors.Is(err, syscall.EHOSTDOWN),
		errors.Is(err, syscall.ENETDOWN):
		return NoRoute
	}
	// A deadline that fired is a timeout however it is spelled: the context's
	// own sentinel, os.ErrDeadlineExceeded from a socket deadline, or a
	// net.Error that reports Timeout.
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return TimedOut
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return TimedOut
	}
	return Unclassified
}

// AssertedSourceGrant is what the operator's own host entry records about
// whether the host will accept an asserted source prefix from them. It is a
// record of what enrollment wrote, never an observation: the SPA path never
// replies, so nothing the client does can discover the host's grants.
type AssertedSourceGrant int

const (
	// AssertedSourceUnknown: the entry says nothing. A hand-written entry, an
	// entry from a host enrolled before this was recorded, or one issued to
	// several operators whose grants differ.
	AssertedSourceUnknown AssertedSourceGrant = iota
	// AssertedSourceGranted: the host was enrolled to permit an asserted
	// source prefix from this operator.
	AssertedSourceGranted
	// AssertedSourceNotGranted: it was not, so `open --source-cidr` is
	// refused by the agent — and refused in silence, like every other SPA
	// rejection. This is the state a default enrollment produces.
	AssertedSourceNotGranted
)

// Sent describes the knock a confirmation is diagnosing. Advise needs it
// because the advice differs by what was actually sent: a timeout after a
// packet that never left is a local problem, and a timeout after an asserted
// source is not the CGNAT case.
type Sent struct {
	Host    string
	Service string
	Addr    netip.AddrPort
	// Delivered reports whether the datagram left this machine.
	Delivered bool
	// AssertedSource is the prefix the packet asserted, if any. Nil means the
	// packet used the observed source, which is the mode CGNAT can split.
	AssertedSource *netip.Prefix
	// SourceGrant is the host entry's record of whether asserting one is
	// permitted at all. The zero value is AssertedSourceUnknown, which is the
	// right default for any caller that does not know.
	SourceGrant AssertedSourceGrant
	// TTL is what the packet requested, for the "the gate may already have
	// expired" case.
	TTL time.Duration
	// Prior is what a connect made to Addr before the knock established. The
	// zero value, PriorUnmeasured, is what a caller that made no such connect
	// passes, and it leaves every claim Advise makes exactly as strong as it
	// was before there was one.
	Prior Prior
}

// Advice is the sentence an operator reads at the worst moment of their day.
type Advice struct {
	Outcome Outcome
	Summary string
	// Detail explains what the outcome rules in and out.
	Detail string
	// Hint is the next command to run, empty when there is nothing useful to
	// suggest. The CGNAT retry lives here.
	Hint string
	// SourceCIDRHint reports whether Hint is the --source-cidr retry. Exposed
	// so a test can assert on the property rather than on prose.
	SourceCIDRHint bool
	// SourceGrant is what the host entry claimed, carried through so a test
	// can assert on the property that decided the hint rather than on prose.
	SourceGrant AssertedSourceGrant
	// GateUnproven marks an outcome that says nothing about whether postern
	// did anything. See Advise.
	GateUnproven bool
	// GateOpened marks the one pair of observations that does establish it:
	// a port that did not answer before the knock and did answer after. It is
	// never set without a pre-knock connect, because nothing else can supply
	// the first half. Exposed so a test can assert on the property rather than
	// on prose.
	GateOpened bool
	// Verify is the command that would establish what this outcome cannot.
	Verify string
}

// answeredBefore is what a port that was already reachable before the knock
// leaves undecided. Three states produce it, they call for three different
// next moves, and the connect that just succeeded cannot pick between them,
// so this ends by naming the instrument that can rather than by guessing.
const answeredBefore = "the port was reachable before the knock as well. Three things look like " +
	"this and they are not the same emergency: a lease from an earlier knock is still live, this " +
	"port is not gated at all because the agent has died and the service is fail-open, or this host " +
	"was never armed. An authenticated liveness pong is what separates a live agent from a dead one."

// Advise turns a Result into that sentence.
//
// The timeout branch is the runbook's signature (design section 5, "Source
// address"): on a sent packet followed by a connect timeout the client emits
// the specific hint to retry with --source-cidr, and says why. The client
// cannot discover its own carrier NAT pool, so a diagnostic is the entire
// mitigation available — which is exactly why it must not be buried among
// the other two causes, and why it is not emitted for the cases it cannot
// explain.
//
// One of those cases is a host enrolled without the grant. The retry is
// refused by the agent, and refused in silence, so an operator following the
// hint gets a byte-identical timeout a second time while still locked out.
// Sent.SourceGrant is what lets this tell the difference, and it is a record
// rather than an observation — so an entry that says nothing gets the hint
// plus the fact that it may not apply, not a confident claim either way.
//
// Sent.Prior is the one input that can make a claim here stronger. It is
// consulted on Connected and Refused and on nothing else, because those are
// the two outcomes where something came back: a pre-knock connect changes what
// an answer means and cannot change what silence means, so no route, a
// timeout, and an unclassified error read the same whether one was made or
// not. Where no pre-knock connect was made, every branch says exactly what it
// said before there was one.
func Advise(res Result, sent Sent) Advice {
	a := Advice{Outcome: res.Outcome, SourceGrant: sent.SourceGrant}
	target := sent.Addr.String()

	switch res.Outcome {
	case Connected:
		a.Summary = fmt.Sprintf("%s is reachable at %s", sent.Service, target)
		switch sent.Prior {
		case PriorShut:
			// The one place `open` may attribute the change to postern. The
			// pre-knock connect is what earns it: a fail-open service whose
			// agent has died leaves the port unfiltered, and an unfiltered
			// port answers a connect made before a knock as readily as one
			// made after, so a target that was silent first is not that host.
			a.Detail = "the port did not answer before the knock and answers now, so something opened " +
				"it between the two connects and the knock is the only thing this command did in " +
				"between. That is the distinction one connect cannot draw: a fail-open service whose " +
				"agent has died leaves the port unfiltered, and an unfiltered port answers before a " +
				"knock as readily as after one. What two connects seconds apart still cannot rule out " +
				"is a path that was dropping packets for the first and was not for the second."
			a.GateOpened = true
		case PriorAnswering:
			a.Detail = "the connect succeeded, which is what you needed, and it establishes nothing " +
				"beyond that: " + answeredBefore
			a.GateUnproven = true
			a.Verify = verifyCommand(sent.Host)
		default:
			// Deliberately not "the gate admitted this source". Nothing here can
			// know that: the SPA path never replies, so a successful connect is
			// equally consistent with a fail-open service on a host whose agent
			// has died — where design section 7 says the port "behaves as it
			// would without postern", i.e. exposed with no gate at all. Claiming
			// the gate worked in exactly that case would make this tool the
			// source of the reassurance that hides the outage.
			a.Detail = "the connect succeeded, which is what you needed. It does not establish that " +
				"postern did it: the SPA path never replies, so nothing observable here separates an " +
				"open gate from a fail-open service whose agent has died and left the port unfiltered."
			a.GateUnproven = true
			a.Verify = verifyCommand(sent.Host)
		}

	case Refused:
		a.Summary = fmt.Sprintf("%s refused the connection at %s", sent.Service, target)
		a.Hint = "check the service on the host"
		switch sent.Prior {
		case PriorShut:
			// Silence, then a reset. That is the shape internal/probe calls a
			// passing sweep, and it is worth more to an operator than a
			// connection would be: it separates the gate from the service and
			// says which of the two is still broken.
			a.Detail = "the port was silent before the knock and refused after it, so the packet now " +
				"reaches the host and something opened the path between the two connects. A refusal " +
				"comes from the host itself with nothing listening behind that port, which leaves the " +
				"service as the thing still to fix."
			a.GateOpened = true
		case PriorAnswering:
			a.Detail = "a refusal comes from the host itself and nothing is listening on that port, so " +
				"this is not a filter dropping you. It is also not the knock that let it through: " +
				answeredBefore
			a.GateUnproven = true
			a.Verify = verifyCommand(sent.Host)
		default:
			// The useful half of this is still worth stating plainly: an operator
			// staring at "connection refused" during an outage will otherwise
			// spend ten minutes on the firewall. What changed is the attribution
			// — "something on the path let it through" is knowable, "postern's
			// part worked" is not.
			a.Detail = "the packet reached the host and something on the path let it through, so this is " +
				"not a filter dropping you: a refusal comes from the host itself and nothing is listening " +
				"on that port. Whether postern's gate is what let it through is not observable from here."
			a.GateUnproven = true
			a.Verify = verifyCommand(sent.Host)
		}

	case NoRoute:
		a.Summary = fmt.Sprintf("no route to %s", target)
		a.Detail = "the network rejected the connect before it left, so the knock cannot have arrived " +
			"either. This is connectivity, not authorization — nothing on the host has seen anything yet."
		a.Hint = "check the path to the host before suspecting postern"

	case TimedOut:
		a.Summary = fmt.Sprintf("%s did not answer on %s", sent.Service, target)
		a.Detail = timeoutDetail(sent)
		switch {
		case !sent.Delivered:
			a.Hint = "the knock never left this machine; fix that first"
		case sent.AssertedSource != nil:
			a.Hint = "the source assertion did not help: check that the agent is running and that " +
				"UDP reaches the host (a provider firewall in front of the host is the usual cause)"
		case sent.SourceGrant == AssertedSourceNotGranted:
			// Deliberately not a command. Printing the --source-cidr retry
			// here is worse than printing nothing: the operator runs it, waits
			// out the same timeout, and learns nothing, because the agent
			// refuses an asserted source it has no grant for without replying.
			a.Hint = fmt.Sprintf("a source assertion will not help: your entry for %s records that it "+
				"permits none, so the agent refuses that knock silently. Granting it means re-running "+
				"init-standalone on the host with --allow-source-cidr <your operator name>.", sent.Host)
		default:
			a.Hint = fmt.Sprintf("postern open %s %s --source-cidr <your-public-prefix>", sent.Host, sent.Service)
			a.SourceCIDRHint = true
		}

	default:
		a.Summary = fmt.Sprintf("could not confirm %s on %s", sent.Service, target)
		a.Detail = "the connect failed in a way postern does not classify, so nothing is ruled in or out"
		if res.LastErr != nil {
			a.Detail += ": " + res.LastErr.Error()
		}
	}
	return a
}

// timeoutDetail names all three causes a timeout is consistent with, in the
// order an operator can act on them, and explains the third — it is the one
// nobody guesses.
func timeoutDetail(sent Sent) string {
	if !sent.Delivered {
		return "the datagram was never sent, so the agent has seen nothing"
	}
	var b strings.Builder
	b.WriteString("the knock was sent and nothing came back. Silence here is consistent with three things " +
		"and cannot distinguish them: the datagram was dropped upstream (a provider firewall in front of " +
		"the host is the usual one), the agent is not running, or ")
	if sent.AssertedSource != nil {
		fmt.Fprintf(&b, "the asserted source %s is not the address your TCP connect actually egresses from.",
			sent.AssertedSource.String())
		return b.String()
	}
	b.WriteString("your carrier NAT egresses UDP and TCP from different pool addresses — so the gate " +
		"opened for the address the knock arrived from, and the connect arrived from another one. That last " +
		"case is common on cellular and hotel wifi, which is where break-glass happens, and the client " +
		"cannot discover its own pool. Asserting a prefix wide enough to cover it is the only fix, ")
	// What the client may say about whether that fix is available to it. The
	// grant lives on the host and the SPA path never replies, so all three
	// endings are about the entry rather than about the host's current state.
	switch sent.SourceGrant {
	case AssertedSourceGranted:
		b.WriteString("and your entry for this host records that it was enrolled to accept one.")
	case AssertedSourceNotGranted:
		b.WriteString("and your entry for this host records that it was enrolled to accept none.")
	default:
		b.WriteString("and your entry for this host does not record whether it will accept one.")
	}
	return b.String()
}

// verifyCommand names the one instrument that does establish agent liveness:
// the liveness pong is signed by the host key and arrives only from a
// running agent that authenticated the ping, which is proof of a kind no
// TCP connect can supply.
func verifyCommand(host string) string {
	if host == "" {
		return "postern status <host>"
	}
	return "postern status " + host
}
