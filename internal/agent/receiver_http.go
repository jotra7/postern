package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

// This file adds a second carrier for the SPA packet and nothing else. The
// bytes are the same padded datagram over the same 224-byte record, signed the
// same way, sealed the same way, and handed to the same Validate; the body's
// length varies with the padding just as the UDP datagram's does. An
// HTTP-carried request that validated
// differently from a UDP-carried one would be a bug, not a feature. Postern
// binds a socket rather than sniffing the wire (fwknop's HTTP mode does the
// latter), so "a second carrier" means literally a second listener whose
// output is a Datagram indistinguishable from the UDP receiver's.
//
// The hard part is not the transport. It is that an HTTP listener is a
// response-shaped thing by construction, and the SPA port's entire security
// property is that it answers nothing distinguishable: a valid knock, random
// garbage, and a host with no postern on it all look the same. Everything
// below that looks over-careful is that property being defended.

const (
	// httpCarrierMaxBody caps the request body at the same size the UDP
	// receive buffer uses, and for the same reason (see receiveBufferSize):
	// deliberately larger than a full padded datagram, so a body past
	// MaxDatagram reaches TrialOpen's bounded-length check and is rejected
	// THERE, by the shared pipeline, rather than by a length test this file
	// invented. A cap at MaxDatagram would truncate an over-long body down
	// into the accepted range and the cheapest rejection in the system would
	// never fire.
	httpCarrierMaxBody = receiveBufferSize

	// httpCarrierMaxHeaderBytes bounds the request head. A knock needs a
	// request line and almost nothing else; a megabyte of headers (net/http's
	// own default) is a memory cost an unauthenticated peer should not be able
	// to impose on a root daemon.
	httpCarrierMaxHeaderBytes = 4096

	// The timeouts below bound a peer that connects and then stalls. The
	// write timeout matters least — the response is 204 with no body — and is
	// set anyway so no combination of stalls leaves a connection owned by a
	// handler goroutine indefinitely.
	httpCarrierReadHeaderTimeout = 5 * time.Second
	httpCarrierReadTimeout       = 10 * time.Second
	httpCarrierWriteTimeout      = 10 * time.Second
	httpCarrierIdleTimeout       = 10 * time.Second
)

// ErrHTTPCarrierCannotReply is what Reply returns on the HTTP carrier.
//
// The liveness pong is the only thing postern ever transmits, and it is bound
// to the always-allow path — which this carrier, by construction, never
// reports a packet as having arrived on (see the OnAlwaysAllowPath comment in
// serveKnock). So this is unreachable through the daemon's own logic, and it
// is an error rather than a silent no-op precisely because reaching it would
// mean that logic had changed underneath the assumption.
var ErrHTTPCarrierCannotReply = errors.New("agent: the http carrier never replies")

// httpReceiver is the HTTP carrier: one TCP listener whose every response is
// identical, feeding the same Datagram channel shape the UDP receiver feeds.
type httpReceiver struct {
	ln  net.Listener
	srv *http.Server
	in  chan Datagram

	closeOnce sync.Once
	// done is closed by Close and is the only thing that unblocks a handler
	// parked on the channel send, so a Close cannot be held up by a queue
	// nobody is draining.
	done chan struct{}
}

// NewHTTPReceiver binds the HTTP carrier's TCP port.
//
// The listener is bound here and nowhere else, so an agent whose policy does
// not configure the carrier never calls this and therefore never opens the
// port at all. "Off unless configured" is the absence of this call, not a
// flag checked inside it.
func NewHTTPReceiver(port uint16) (Receiver, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}
	return newHTTPReceiverOn(ln), nil
}

// newHTTPReceiverOn serves the carrier on an already-bound listener. Tests use
// it to get a real net/http server on an ephemeral port without racing for one.
func newHTTPReceiverOn(ln net.Listener) *httpReceiver {
	r := &httpReceiver{
		ln:   ln,
		in:   make(chan Datagram, 16),
		done: make(chan struct{}),
	}
	r.srv = &http.Server{
		Handler:           http.HandlerFunc(r.serveKnock),
		ReadHeaderTimeout: httpCarrierReadHeaderTimeout,
		ReadTimeout:       httpCarrierReadTimeout,
		WriteTimeout:      httpCarrierWriteTimeout,
		IdleTimeout:       httpCarrierIdleTimeout,
		MaxHeaderBytes:    httpCarrierMaxHeaderBytes,
	}
	// Keep-alives off, and this is a uniformity control rather than a
	// performance choice. With them on, net/http decides per response whether
	// to add "Connection: close" — it does so, among other cases, when a
	// handler returned without draining an oversized request body. That would
	// make the response to a too-large body differ, in a header, from the
	// response to a valid knock: exactly the oracle this file exists to
	// prevent, arriving through the transport rather than through the
	// handler. Off, every response carries the same header, always.
	r.srv.SetKeepAlivesEnabled(false)
	go func() {
		// The error is deliberately dropped. Serve returns ErrServerClosed on
		// our own Close, and any other failure is already observable as a
		// carrier that stops producing datagrams — while the UDP carrier, the
		// gate, and agent_up all keep running. An HTTP listener that died must
		// not be able to take the daemon down: it is the fallback path, and
		// making it fatal would let a problem on the fallback cause the outage
		// the fallback exists to survive.
		_ = r.srv.Serve(ln)
	}()
	return r
}

// serveKnock is the whole HTTP surface. Every request gets the same answer.
//
// Same status, same body, same headers, for a valid knock, a replay, random
// bytes, a body of the wrong length, a GET with no body at all, and a request
// to any path or with any method. There is no 400-for-bad-input and
// 204-for-good-input, because that pair is an oracle: it tells whoever is
// probing the port exactly when they have found a valid operator key.
//
// Two structural choices keep that true rather than merely intended:
//
//  1. The response is written BEFORE the datagram is handed to the pipeline,
//     and the handler never learns the outcome. Not "the handler ignores the
//     result" — it has no result to ignore. Validation happens on the daemon's
//     packet loop, asynchronously, exactly as it does for a UDP datagram. So
//     response content and response timing are both independent of whether the
//     packet was valid, by construction rather than by discipline.
//
//  2. Nothing here inspects the body. No length check, no method check, no
//     path check, no content-type check. Whatever was read is handed on, and
//     spa.TrialOpen's exact-length test — validation step 1, the cheapest
//     rejection in the system — is what rejects it. One pipeline, one set of
//     rules, no second opinion that could drift from the first.
//
// What is left is a real timing signal and this comment does not pretend
// otherwise: the body read itself takes time proportional to the body's size.
// That size is chosen by the peer and known to them, so it discloses nothing
// they did not already have.
func (r *httpReceiver) serveKnock(w http.ResponseWriter, req *http.Request) {
	// LimitReader rather than http.MaxBytesReader: MaxBytesReader signals the
	// server to close the connection when the limit is hit, which shows up as
	// a header difference between an oversized body and a valid one. Reading
	// one byte past the cap is how an oversized body is detected without
	// asking the transport to behave differently for it.
	body, readErr := io.ReadAll(io.LimitReader(req.Body, httpCarrierMaxBody+1))

	source := peerAddrPort(req)

	// Answered here, at the one point every path passes through, before
	// anything is decided about the bytes.
	w.WriteHeader(http.StatusNoContent)

	if readErr != nil || len(body) > httpCarrierMaxBody {
		return
	}
	// An unresolvable peer is dropped: the observed source is what a gate is
	// opened for, and a Datagram with a zero Source would ask the gate to
	// admit the zero address.
	if !source.IsValid() {
		return
	}

	dg := Datagram{
		Payload: body,
		Source:  source,
		// Always false, never derived from anything a peer sends. The
		// always-allow path is what liveness binds to, and liveness is the one
		// case where postern transmits at all; a carrier that could claim that
		// path would be a way to make the host answer. The UDP receiver reads
		// this from the kernel's per-packet ancillary data, which has no TCP
		// equivalent this listener can trust, so the honest answer is no.
		OnAlwaysAllowPath: false,
	}
	select {
	case r.in <- dg:
	case <-r.done:
	}
}

// peerAddrPort is the observed source, and it is the TCP peer, full stop.
//
// X-Forwarded-For, X-Real-IP, Forwarded, and every other header of that shape
// are ignored — not sanitised, not preferred-if-present, ignored. This value
// decides whose address gets a firewall hole on a break-glass host, and a
// proxy header is a string the attacker wrote. Honouring one would let anyone
// who can reach the port open the gate for an address of their choosing,
// which is the entire authorization model handed to the peer.
//
// Running the carrier behind a reverse proxy is therefore not supported: the
// gate would open for the proxy. That is a documented limitation, and the
// alternative — a trusted-proxy list — is a configuration mistake away from
// the hole above.
func peerAddrPort(req *http.Request) netip.AddrPort {
	ap, err := netip.ParseAddrPort(req.RemoteAddr)
	if err != nil {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// Addr reports the address the carrier is actually listening on, so a caller
// that asked for port 0 can find out what it got.
func (r *httpReceiver) Addr() net.Addr { return r.ln.Addr() }

func (r *httpReceiver) Receive(ctx context.Context) (Datagram, error) {
	select {
	case dg := <-r.in:
		return dg, nil
	case <-ctx.Done():
		return Datagram{}, ctx.Err()
	case <-r.done:
		return Datagram{}, net.ErrClosed
	}
}

// Reply never transmits. See ErrHTTPCarrierCannotReply.
func (r *httpReceiver) Reply(context.Context, netip.AddrPort, uint16, []byte) error {
	return ErrHTTPCarrierCannotReply
}

func (r *httpReceiver) Close() error {
	var err error
	r.closeOnce.Do(func() {
		close(r.done)
		err = r.srv.Close()
	})
	return err
}

var _ Receiver = (*httpReceiver)(nil)
