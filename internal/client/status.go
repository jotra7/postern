package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/jotra7/postern/internal/spa"
)

// DefaultPongWait is how long the client waits for a liveness pong. The pong
// travels only over the always-allow path, so this is a mesh round trip, not
// an internet one.
const DefaultPongWait = 3 * time.Second

// DefaultPongFreshness bounds how far the host's clock may be from the
// client's before a pong is refused. It mirrors the agent's own
// freshness_window default.
const DefaultPongFreshness = 60 * time.Second

// Exchanger sends one datagram and waits for one reply. It exists only for
// liveness: every other path postern uses is send-only.
type Exchanger func(ctx context.Context, to netip.AddrPort, payload []byte, wait time.Duration) ([]byte, error)

// UDPExchange is the production Exchanger.
func UDPExchange(ctx context.Context, to netip.AddrPort, payload []byte, wait time.Duration) ([]byte, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", to.String())
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", to, err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write(payload); err != nil {
		return nil, fmt.Errorf("send to %s: %w", to, err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(wait)); err != nil {
		return nil, fmt.Errorf("set read deadline: %w", err)
	}
	// Sized to MaxDatagram (plus one, to catch an oversized reply rather than
	// silently truncating it into an in-range one): a pong is padded to a
	// random length up to MaxDatagram, and ParsePong slices off the PongSize
	// prefix.
	buf := make([]byte, spa.MaxDatagram+1)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// StatusOptions is one invocation of `postern status`.
type StatusOptions struct {
	Builder Builder
	Host    *Host
	// RecoveryService overrides the host's configured recovery_service.
	RecoveryService string
	// Via overrides the address both assertions use, for a host whose
	// always-allow address has moved since it was enrolled. An invalid Addr
	// takes the host entry's own answer.
	Via netip.Addr

	Exchange Exchanger
	Dial     Dialer
	NowMS    func() uint64

	PongWait       time.Duration
	PongFreshness  time.Duration
	ConnectTimeout time.Duration
}

// StatusReport is the pair of assertions design section 7 requires before a
// fail-closed service may be armed, and the pair an operator wants when they
// are deciding whether the always-allow path still works.
//
// Two assertions rather than one, deliberately. A pong proves mesh routing
// works inbound, the agent is alive, and authentication succeeds — on UDP
// 62201. Mesh ACLs are routinely written per port, so a rule permitting UDP
// 62201 while dropping TCP 22 leaves the pong green with no shell available.
// The recovery connect is the other port that matters.
type StatusReport struct {
	// Addr is the address both assertions were sent to. One field, because
	// two would be two things to keep equal.
	Addr netip.Addr

	// Pong is whether the authenticated liveness pong came back and verified.
	Pong bool
	// PongErr is why it did not.
	PongErr error
	// PongRTT is how long the exchange took.
	PongRTT time.Duration
	// ClockSkew is the host's clock minus the client's, from the pong's
	// timestamp. Reported rather than enforced beyond the freshness window:
	// design section 5 wants a timestamp preceding the agent's build date
	// reported red rather than silently rejecting everything.
	ClockSkew time.Duration

	// RecoveryService is the service the second assertion targeted.
	RecoveryService string
	// Recovery is the outcome of the TCP connect to it.
	Recovery Result
}

// Healthy reports whether both assertions passed. A fail-closed service may
// be armed only when this is true (or an explicit override is recorded).
func (r StatusReport) Healthy() bool {
	return r.Pong && r.Recovery.Outcome == Connected
}

// ErrNoHostSigningKey means the client cannot verify a pong from this host
// because the config carries no host_signing key for it. Refused rather than
// skipped: an unverified pong proves nothing at all, and reporting it as
// liveness would be exactly the false green design section 7 spends a page
// on.
var ErrNoHostSigningKey = errors.New("client: host has no host_signing key configured, so a pong cannot be verified")

// ErrHostKeyIsOperatorKey means the host entry's host_signing key is this
// operator's own signing key. One key would then sign in both roles, over SPA
// requests as an operator and over pongs as a host. spa.RequestDomain and
// spa.PongDomain are what stop either signature standing in for the other;
// this is the operator-side half of keeping the roles disjoint, the agent-side
// half being spa.NewOpenerFromSigner. Refused rather than warned about,
// because a pong the operator could have produced themselves is not evidence
// that anything is alive at the far end.
var ErrHostKeyIsOperatorKey = errors.New("client: this host's host_signing key is the operator's own signing key")

// Status runs both liveness assertions against a host over the always-allow
// path.
//
// Both go to one address, resolved once here. The design requires them to
// traverse the same path: the pong proves the agent is alive and reachable on
// UDP 62201, the connect proves the port an operator would actually recover
// with is reachable too, and a pair of assertions that reached the host by two
// different routes would be evidence about neither.
func Status(ctx context.Context, o StatusOptions) (StatusReport, error) {
	var rep StatusReport
	if o.Host == nil {
		return rep, fmt.Errorf("client: status needs a host")
	}
	rep.Addr = o.Via.Unmap()
	if !rep.Addr.IsValid() {
		rep.Addr = o.Host.StatusAddr()
	}
	nowMS := o.NowMS
	if nowMS == nil {
		nowMS = func() uint64 { return uint64(time.Now().UnixMilli()) } //nolint:gosec // a unix-millisecond clock is non-negative for any real time
	}
	exchange := o.Exchange
	if exchange == nil {
		exchange = UDPExchange
	}
	dial := o.Dial
	if dial == nil {
		dial = DialTCP
	}
	wait := o.PongWait
	if wait <= 0 {
		wait = DefaultPongWait
	}
	freshness := o.PongFreshness
	if freshness <= 0 {
		freshness = DefaultPongFreshness
	}

	rep.PongErr = pingOnce(ctx, o, exchange, nowMS, wait, freshness, &rep)
	rep.Pong = rep.PongErr == nil

	name := o.RecoveryService
	if name == "" {
		name = o.Host.RecoveryService
	}
	rep.RecoveryService = name
	if name == "" {
		// Not an error here — `status` is also run on hosts with no
		// fail-closed service, where there is nothing to recover into. Arming
		// is where an unset recovery_service is refused (config.Policy).
		return rep, nil
	}
	svc, err := o.Host.Service(name)
	if err != nil {
		return rep, err
	}
	rep.Recovery = Confirm(ctx, dial, netip.AddrPortFrom(rep.Addr, svc.Port), o.ConnectTimeout, 1)
	return rep, nil
}

func pingOnce(
	ctx context.Context,
	o StatusOptions,
	exchange Exchanger,
	nowMS func() uint64,
	wait, freshness time.Duration,
	rep *StatusReport,
) error {
	var zero [32]byte
	if o.Host.HostSign == zero {
		return ErrNoHostSigningKey
	}
	if o.Builder.Signer != nil && o.Host.HostSign == o.Builder.Signer.Public().Signing {
		return ErrHostKeyIsOperatorKey
	}

	sentAt := nowMS()
	req, challenge, err := o.Builder.Liveness(o.Host, sentAt)
	if err != nil {
		return err
	}
	requestID := req.RequestID
	datagram, err := o.Builder.Seal(req, o.Host)
	if err != nil {
		return err
	}

	// Under rotation, the liveness ping goes to the current-window port too:
	// the agent does not bind the fixed port at all once rotation is on, so
	// a ping sent to SPAPort's fixed default times out on a perfectly
	// healthy host. This is the fourth site with the same gap Task 7 left in
	// three others (open, confirm/disarm, the probe): `postern status` runs
	// this directly, and confirm's own liveness pre-check
	// (confirmLivenessPrecheck) runs it as the very check I5 exists for, so
	// an operator confirming a rotation host without --force from a
	// genuinely healthy mesh path would have failed here.
	pingPort := o.Host.SPAPort()
	if port, ok := o.Host.CurrentKnockPort(int64(sentAt / 1000)); ok {
		pingPort = port
	}
	reply, err := exchange(ctx, netip.AddrPortFrom(rep.Addr, pingPort), datagram, wait)
	if err != nil {
		return fmt.Errorf("liveness ping: %w", err)
	}
	rep.PongRTT = millis(nowMS() - sentAt)

	pong, err := spa.ParsePong(reply)
	if err != nil {
		return fmt.Errorf("parse pong: %w", err)
	}
	now := nowMS()
	// Every field, and the challenge this exchange minted rather than one
	// recovered from the reply: echoing request_id and challenge_nonce
	// together is what stops a captured pong answering a later ping.
	if err := pong.Verify(o.Host.HostSign, o.Host.HostID, requestID, challenge, now, uint64(freshness.Milliseconds())); err != nil { //nolint:gosec // freshness is a positive duration
		return err
	}
	rep.ClockSkew = skew(pong.TimestampMS, now)
	return nil
}

// millis converts an elapsed count of milliseconds into a Duration without
// the int64 conversion tripping an overflow check. An RTT beyond a few
// seconds is a timeout, not a number worth preserving.
func millis(ms uint64) time.Duration {
	const maxMS = uint64(1 << 40) // ~34 years; anything larger is a broken clock
	if ms > maxMS {
		return time.Duration(maxMS) * time.Millisecond
	}
	return time.Duration(ms) * time.Millisecond //nolint:gosec // bounded immediately above
}

// skew is the host's clock minus the client's, as a signed Duration.
func skew(hostMS, clientMS uint64) time.Duration {
	if hostMS >= clientMS {
		return millis(hostMS - clientMS)
	}
	return -millis(clientMS - hostMS)
}
