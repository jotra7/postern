package client

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/jotra7/postern/internal/spa"
)

// Sender puts one datagram on the wire and returns. It never reads: the
// public SPA path produces silence by design, so a client that waited for a
// reply would wait forever on a knock that worked.
type Sender func(ctx context.Context, to netip.AddrPort, payload []byte) error

// UDPSend is the production Sender.
func UDPSend(ctx context.Context, to netip.AddrPort, payload []byte) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", to.String())
	if err != nil {
		return fmt.Errorf("dial %s: %w", to, err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write(payload); err != nil {
		return fmt.Errorf("send to %s: %w", to, err)
	}
	return nil
}

// DialTCP is the production Dialer.
func DialTCP(ctx context.Context, network, address string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

// OpenOptions is one invocation of `postern open`.
type OpenOptions struct {
	Builder Builder
	Host    *Host
	Service string
	// TTL of zero asks the host for its configured default.
	TTL time.Duration
	// SourceCIDR asserts a source prefix instead of letting the agent use
	// the address it observed. This is the CGNAT mitigation.
	SourceCIDR *netip.Prefix
	Counter    *Counter

	// Carrier chooses how the knock leaves this machine. Empty selects
	// CarrierUDP.
	//
	// It is explicit, and there is deliberately no fallback: a failed UDP
	// knock does not silently retry over HTTP. A silent fallback would mean an
	// operator's UDP path could be broken for months without them ever finding
	// out, because every knock kept working — and they would find out on the
	// day they are somewhere that has neither. Worse, "the UDP send failed" is
	// not even a signal postern has: a UDP send to a black hole succeeds
	// locally, so the only thing a fallback could trigger on is the
	// confirmation connect failing, which has a dozen other causes (the gate
	// opened for the wrong address under CGNAT, the service is down, pre-arm
	// disabled it). Falling back on that would fire the fallback for reasons
	// that are not the carrier, and mask the real diagnosis Advise exists to
	// give.
	//
	// So: the operator says which carrier, once, and learns which one works.
	Carrier Carrier

	// Send and Dial default to the carrier's own sender and to DialTCP.
	Send Sender
	Dial Dialer
	// NowMS defaults to the wall clock.
	NowMS func() uint64

	ConnectTimeout  time.Duration
	ConnectAttempts int

	// PreConnectTimeout bounds the connect made to the service before the
	// knock, which is what lets a successful open report shut-then-open rather
	// than merely open. Zero selects DefaultPreConnectTimeout; a negative
	// value makes no pre-knock connect at all, which leaves every claim in the
	// report exactly as strong as it was before there was one.
	//
	// Whatever it resolves to, it is capped at one confirmation attempt: see
	// preConnectTimeout.
	PreConnectTimeout time.Duration
}

// DefaultPreConnectTimeout bounds the connect `open` makes before it knocks.
//
// It is paid in full on the good path, because a shut gate answers with
// silence, so this is a tax on the successful open of an operator who is
// already having a bad day. Two seconds buys the one distinction the rest of
// the report cannot make; more than that would buy nothing, since the pre-knock
// connect is not waiting for an answer it expects. It is deliberately not
// DefaultConnectTimeout: that number is how long to wait for a reply, and this
// one is how long to wait for the absence of one.
//
// internal/probe bounds its own phase 1 separately, against a limit this one
// does not answer to: a sweep's closed-gate connect has to fit inside the
// canary's TTL alongside the knock and phase 2.
const DefaultPreConnectTimeout = 2 * time.Second

// OpenReport is everything `postern open` learned.
type OpenReport struct {
	// KnockAddr is where the datagram went. Recorded because the whole point
	// of knock_addr is that it is not the SSH hostname.
	KnockAddr netip.AddrPort
	// Carrier is which envelope carried it. Reported because "the knock was
	// sent" means something different per carrier — a UDP send succeeds
	// locally even into a black hole, an HTTP one at least proves a TCP
	// handshake completed — and an operator reading a failed open needs to
	// know which of those they are looking at.
	Carrier Carrier
	// Before is the connect made before the knock, when one was made. Its
	// Attempts is zero when none was, which is what Result.Prior reads to
	// distinguish "measured and inconclusive" from "never measured".
	Before Result
	Sent   Sent
	Result Result
	Advice Advice
}

// Open builds a gate request, seals it to the host, sends exactly one
// datagram, and confirms by connecting.
//
// A send failure is not fatal to the confirmation. It is reported through
// Sent.Delivered and the connect still runs, because a gate opened by an
// earlier knock may well still be live — and telling an operator "the send
// failed" while the port is in fact open would send them chasing the wrong
// thing.
//
// # The connect before the knock
//
// By default it connects once before knocking too, and that connect is the
// difference between reporting that a port answers and reporting that it
// answers now and did not a moment ago. Only the second is evidence about
// postern, and it cannot be recovered afterwards: once the knock has landed,
// the pre-knock state of the port is gone for the length of the lease. That is
// why it is on by default rather than behind a flag an operator would have to
// think of in advance, at the moment they are least able to.
//
// It never stops the knock, whatever it finds. internal/probe does stop, and
// is right to, because a sweep's product is evidence and there is no evidence
// left to gather once phase 1 has failed. This command's product is access.
// An operator who runs `open` twice inside one lease finds the port already
// answering both times, and refusing to knock on that reading would let the
// lease they were extending expire under them.
func Open(ctx context.Context, o OpenOptions) (OpenReport, error) {
	var rep OpenReport
	if o.Host == nil {
		return rep, fmt.Errorf("client: open needs a host")
	}
	svc, err := o.Host.Service(o.Service)
	if err != nil {
		return rep, err
	}
	ttl := o.TTL
	if ttl == 0 {
		ttl = svc.TTL
	}

	nowMS := o.NowMS
	if nowMS == nil {
		nowMS = func() uint64 { return uint64(time.Now().UnixMilli()) } //nolint:gosec // a unix-millisecond clock is non-negative for any real time
	}
	carrier, err := ParseCarrier(string(o.Carrier))
	if err != nil {
		return rep, err
	}
	// Resolved before anything is built or signed, so an `open --carrier http`
	// against a host entry with no http port fails saying that, rather than
	// minting a request_id and burning a counter on a knock with nowhere to go.
	knockAddr, err := o.Host.CarrierAddrPort(carrier)
	if err != nil {
		return rep, err
	}
	send := o.Send
	if send == nil {
		send = SenderFor(carrier)
	}
	dial := o.Dial
	if dial == nil {
		dial = DialTCP
	}
	connectAddr := o.Host.ConnectAddr(svc)

	// Before the counter is burned and before anything is sealed, so the
	// datagram's timestamp and counter describe when it went on the wire
	// rather than when the command started. One attempt, never more:
	// Confirm retries a non-definitive outcome, and here the non-definitive
	// outcome is the one a healthy host is supposed to give.
	if pre, ok := preConnectTimeout(o.PreConnectTimeout, o.ConnectTimeout); ok {
		rep.Before = Confirm(ctx, dial, connectAddr, pre, 1)
	}

	now := nowMS()
	var counter uint64
	if o.Counter != nil {
		if counter, err = o.Counter.Next(now); err != nil {
			return rep, err
		}
	}

	req, err := o.Builder.Gate(o.Host, o.Service, ttl, o.SourceCIDR, counter, now)
	if err != nil {
		return rep, err
	}
	datagram, err := o.Builder.Seal(req, o.Host)
	if err != nil {
		return rep, err
	}
	// Padded once, before the send, so both carriers inherit it: the UDP
	// datagram and the HTTP body are the same bytes, and padding here varies
	// the on-wire length (and the HTTP Content-Length) so the datagram's size
	// is no longer a fingerprint.
	datagram, err = spa.Pad(datagram)
	if err != nil {
		return rep, err
	}

	rep.KnockAddr = knockAddr
	rep.Carrier = carrier
	// Under rotation, one datagram to the current-window port. The HTTP carrier
	// port is fixed, so this only applies to the UDP carrier; --carrier http keeps
	// the resolved knockAddr from CarrierAddrPort above.
	if port, ok := o.Host.CurrentKnockPort(int64(now / 1000)); ok && carrier == CarrierUDP {
		rep.KnockAddr = netip.AddrPortFrom(o.Host.KnockAddr, port)
	}
	sendErr := send(ctx, rep.KnockAddr, datagram)

	rep.Sent = Sent{
		Host:           o.Host.Name,
		Service:        o.Service,
		Addr:           connectAddr,
		Delivered:      sendErr == nil,
		AssertedSource: o.SourceCIDR,
		SourceGrant:    o.Host.AssertedSourceGrant(),
		TTL:            ttl,
		Prior:          rep.Before.Prior(),
	}
	rep.Result = Confirm(ctx, dial, rep.Sent.Addr, o.ConnectTimeout, orInt(o.ConnectAttempts, DefaultConnectAttempts))
	rep.Advice = Advise(rep.Result, rep.Sent)
	if sendErr != nil {
		return rep, fmt.Errorf("client: the knock was not sent: %w", sendErr)
	}
	return rep, nil
}

// ActionOptions is one invocation of confirm or disarm: build, seal, send,
// and stop. Neither action produces a reply, so there is nothing to wait
// for and nothing to confirm beyond the send itself.
type ActionOptions struct {
	Builder Builder
	Host    *Host
	Send    Sender
	NowMS   func() uint64

	// Sends is how many copies of the datagram to put on the wire. Zero or
	// one sends exactly one. See DefaultActionSends for why more than one is
	// the right default for a confirm: UDP does not guarantee delivery, the
	// SPA path never answers, and the cost of a lost confirm is an automatic
	// revert nobody asked for.
	Sends int
	// ResendDelay is the wait between copies. Zero selects
	// DefaultActionResendDelay, and it is only consulted when Sends > 1.
	ResendDelay time.Duration
	// Sleep replaces the wait between copies. Nil selects a real timer;
	// tests use it to keep a multi-send deterministic and instant.
	Sleep func(ctx context.Context, d time.Duration)
}

// ActionReport is what SendAction did: where the datagram went, and how many
// copies actually left this machine.
type ActionReport struct {
	To netip.AddrPort
	// Sent counts the copies the Sender accepted. It is not evidence of
	// delivery — nothing on this path is — but a Sent below Attempted means
	// this machine itself could not put every copy on the wire.
	Sent int
	// Attempted is how many copies were tried.
	Attempted int
}

// SendAction seals one already-built action request and sends it, by default
// more than once.
//
// Each copy is built fresh, so every datagram carries its own request_id and
// its own timestamp: resending the identical bytes would be a replay of one
// packet rather than several sends of one instruction, and the agent's replay
// store would reject every copy after the first before it ever reached the
// action. That is the difference between a retry that works and one that
// guarantees only the first attempt can ever land.
//
// It returns the first send error only if NO copy left the machine. A partial
// failure is not a failure of the command: one datagram on the wire is all a
// confirm has ever needed.
func SendAction(ctx context.Context, o ActionOptions, build func(nowMS uint64) (*spa.Request, error)) (ActionReport, error) {
	nowMS := o.NowMS
	if nowMS == nil {
		nowMS = func() uint64 { return uint64(time.Now().UnixMilli()) } //nolint:gosec // a unix-millisecond clock is non-negative for any real time
	}
	send := o.Send
	if send == nil {
		send = UDPSend
	}
	sleep := o.Sleep
	if sleep == nil {
		sleep = sleepCtx
	}
	sends := o.Sends
	if sends < 1 {
		sends = 1
	}
	delay := o.ResendDelay
	if delay <= 0 {
		delay = DefaultActionResendDelay
	}

	rep := ActionReport{To: o.Host.KnockAddrPort()}
	// Under rotation, an action targets the current-window port too: the
	// agent no longer binds the fixed port at all (Task 7 changed `open`
	// the same way; confirm and disarm are the same carrier and missed the
	// same change). Computed once, before the loop, exactly as Open does for
	// its single send: every copy in this loop is a resend of the same
	// action, not a fresh one, so they all belong on the one port a fresh
	// send would have chosen.
	if port, ok := o.Host.CurrentKnockPort(int64(nowMS() / 1000)); ok {
		rep.To = netip.AddrPortFrom(o.Host.KnockAddr, port)
	}
	var firstErr error
	for i := 0; i < sends; i++ {
		if i > 0 {
			sleep(ctx, delay)
			if ctx.Err() != nil {
				break
			}
		}
		req, err := build(nowMS())
		if err != nil {
			return rep, err
		}
		datagram, err := o.Builder.Seal(req, o.Host)
		if err != nil {
			return rep, err
		}
		// Padded per copy: each resend already carries its own request_id and
		// timestamp, and now its own random length too, so the copies do not
		// share one constant size on the wire.
		datagram, err = spa.Pad(datagram)
		if err != nil {
			return rep, err
		}
		rep.Attempted++
		if err := send(ctx, rep.To, datagram); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		rep.Sent++
	}
	if rep.Sent == 0 {
		return rep, firstErr
	}
	return rep, nil
}

// sleepCtx waits for d, or until ctx is done.
func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

func orInt(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

// preConnectTimeout resolves the pre-knock connect's budget, and reports
// whether there is to be one at all.
//
// Whether to connect is decided here and nowhere else, which is why it is a
// second return value rather than a zero the caller is expected to recognise.
// Zero does not mean "skip" anywhere else in this package: Confirm reads a
// non-positive timeout as a request for the default, so a caller that guarded
// on the duration alone would connect for four seconds on the one path that
// asked for no connect at all.
//
// The cap is the other half. An operator who passes a short --timeout has said
// how long they are willing to wait on this port at all, and a pre-knock
// connect that outlasted that would spend more of an incident establishing
// that the gate was shut than establishing that it opened. So the pre-knock
// connect is never the longest thing `open` waits on: it cannot exceed a
// single confirmation attempt, and the confirmation makes more than one.
func preConnectTimeout(want, confirm time.Duration) (time.Duration, bool) {
	if want < 0 {
		return 0, false
	}
	if want == 0 {
		want = DefaultPreConnectTimeout
	}
	if confirm <= 0 {
		confirm = DefaultConnectTimeout
	}
	if want > confirm {
		return confirm, true
	}
	return want, true
}
