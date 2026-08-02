package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"time"
)

// Carrier names how a knock leaves this machine. The packet is identical
// either way — the same padded datagram over the same 224-byte sealed record,
// same signature, same seal — so this chooses an envelope, never a protocol.
type Carrier string

const (
	// CarrierUDP is the default: one datagram, no reply, nothing to wait for.
	CarrierUDP Carrier = "udp"
	// CarrierHTTP posts the same datagram to the agent's HTTP carrier port,
	// for the networks that block outbound UDP.
	CarrierHTTP Carrier = "http"
)

// ParseCarrier resolves the operator's --carrier value. Empty selects UDP.
func ParseCarrier(s string) (Carrier, error) {
	switch Carrier(s) {
	case "", CarrierUDP:
		return CarrierUDP, nil
	case CarrierHTTP:
		return CarrierHTTP, nil
	default:
		return "", fmt.Errorf("unknown carrier %q; want %q or %q", s, CarrierUDP, CarrierHTTP)
	}
}

// httpKnockTimeout bounds the whole POST. The agent answers immediately and
// unconditionally, so anything slower than this is a network that is not
// carrying the request rather than an agent thinking about it.
const httpKnockTimeout = 10 * time.Second

// HTTPSend is the Sender for CarrierHTTP: one POST whose body is the sealed
// datagram, to a host and port and nothing else — no path that has to match,
// no header the agent reads, no content type it checks. The agent's handler
// looks at the body and at the TCP peer, so anything else this function put
// on the request would be decoration.
//
// The response is deliberately not interpreted. The agent answers every
// request identically on purpose — that uniformity is the property that stops
// the listener being an oracle — so a status code here carries no information
// about whether the knock was valid, and treating one as failure would invent
// a signal the protocol does not have. Only a transport failure (nothing
// listening, connection refused, timed out) is an error, which is exactly the
// same thing UDPSend reports: this machine could not put the bytes on the
// wire.
//
// That symmetry is the point. Neither carrier can tell an operator their
// knock was accepted. Both leave that to the confirmation connect.
func HTTPSend(ctx context.Context, to netip.AddrPort, payload []byte) error {
	ctx, cancel := context.WithTimeout(ctx, httpKnockTimeout)
	defer cancel()

	url := "http://" + to.String() + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build http knock to %s: %w", to, err)
	}
	req.ContentLength = int64(len(payload))

	// A client of our own rather than http.DefaultClient: redirects are
	// refused, because following one would send a signed packet — addressed to
	// this host, sealed to this host's key — somewhere a response header chose.
	// It could not be opened there, but a break-glass tool should not be
	// steerable by the thing it is trying to reach.
	c := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("send to %s: %w", to, err)
	}
	defer func() { _ = resp.Body.Close() }()
	// Drained, bounded, and discarded. Reading it lets the connection be
	// reused and keeps a hostile responder from being able to feed this
	// process an unbounded body; the content is never examined.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return nil
}

// SenderFor returns the Sender for a carrier.
func SenderFor(c Carrier) Sender {
	if c == CarrierHTTP {
		return HTTPSend
	}
	return UDPSend
}
