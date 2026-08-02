package agent_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/agent"
	"github.com/jotra7/postern/internal/spa"
)

// carrierHarness is a live HTTP carrier on loopback plus the raw-socket
// client the response-uniformity tests need.
//
// Raw sockets rather than net/http on the client side, because the property
// is "every response is byte-identical" and an http.Response has already
// thrown away the bytes: header order, capitalisation, the status line's
// exact spelling, and whether a body was framed at all are all things a
// parsed response normalises away, and all things an attacker watching the
// wire would see.
type carrierHarness struct {
	t    *testing.T
	recv agent.Receiver
	addr string
}

func newCarrierHarness(t *testing.T) *carrierHarness {
	t.Helper()
	recv, addr, err := agent.NewLoopbackHTTPCarrier()
	if err != nil {
		t.Fatalf("NewLoopbackHTTPCarrier: %v", err)
	}
	t.Cleanup(func() { _ = recv.Close() })
	return &carrierHarness{t: t, recv: recv, addr: addr.String()}
}

// dateHeader matches the one header whose value legitimately differs between
// two responses a second apart. It is normalised rather than dropped, so a
// response that stopped carrying a Date at all — a real difference — still
// shows up as one.
var dateHeader = regexp.MustCompile(`(?im)^Date: .*$`)

// rawPost writes a hand-built HTTP request and returns every byte of the
// response, with Date normalised.
func (h *carrierHarness) rawPost(body []byte, extraHeaders ...string) string {
	h.t.Helper()
	var req bytes.Buffer
	req.WriteString("POST / HTTP/1.1\r\n")
	fmt.Fprintf(&req, "Host: %s\r\n", h.addr)
	fmt.Fprintf(&req, "Content-Length: %d\r\n", len(body))
	for _, line := range extraHeaders {
		req.WriteString(line + "\r\n")
	}
	req.WriteString("\r\n")
	req.Write(body)
	return h.rawExchange(req.Bytes())
}

func (h *carrierHarness) rawExchange(request []byte) string {
	h.t.Helper()
	conn, err := net.DialTimeout("tcp", h.addr, 5*time.Second)
	if err != nil {
		h.t.Fatalf("dial the carrier: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		h.t.Fatalf("set deadline: %v", err)
	}
	if _, err := conn.Write(request); err != nil {
		h.t.Fatalf("write the request: %v", err)
	}
	resp, err := io.ReadAll(conn)
	if err != nil {
		h.t.Fatalf("read the response: %v", err)
	}
	return dateHeader.ReplaceAllString(string(resp), "Date: NORMALISED")
}

// received drains whatever the carrier delivered within a short window.
func (h *carrierHarness) received() []agent.Datagram {
	h.t.Helper()
	var out []agent.Datagram
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		dg, err := h.recv.Receive(ctx)
		cancel()
		if err != nil {
			return out
		}
		out = append(out, dg)
	}
}

// The listener must be as silent as the UDP port it stands in for. A valid
// knock, random garbage, a body of the wrong length, an oversized body, and a
// request with no body at all must produce responses that are identical byte
// for byte — same status line, same headers in the same order, same framing,
// same absence of a body.
//
// The mutation this is aimed at is the obvious and tempting one: answering
// 400 for a body that is not 224 bytes and 204 for one that is. That pair is
// an oracle. It tells whoever is sweeping the port exactly when they have
// found a live operator key, which is the single fact the whole design spends
// its silence protecting.
//
// The valid knock here is a REAL one — sealed to this host's key by a granted
// operator — rather than 224 arbitrary bytes, so the comparison is against
// the response to a packet that would genuinely open a gate, not merely
// against one of the right size.
func TestAgent_HTTPCarrier_ValidAndInvalidRequestsGetIdenticalResponses(t *testing.T) {
	f := newFixture(t)
	h := newCarrierHarness(t)

	valid := f.seal(f.gateRequest())
	if len(valid) != spa.DatagramSize {
		t.Fatalf("precondition: sealed datagram is %d bytes, want %d", len(valid), spa.DatagramSize)
	}

	cases := []struct {
		name string
		body []byte
	}{
		{"a valid, granted, freshly sealed knock", valid},
		{"the same knock again, which the replay store would refuse", valid},
		{"random bytes of the right length", bytes.Repeat([]byte{0xA5}, spa.DatagramSize)},
		{"a body one byte short", valid[:len(valid)-1]},
		{"a body one byte long", append(append([]byte(nil), valid...), 0x00)},
		{"no body at all", nil},
		{"a body far over the cap", bytes.Repeat([]byte{0x00}, agent.HTTPCarrierMaxBodyForTest*4)},
	}

	want := h.rawPost(cases[0].body)
	if !strings.Contains(want, "204") {
		t.Fatalf("precondition: the carrier's answer is not a 204:\n%q", want)
	}
	for _, tc := range cases[1:] {
		if got := h.rawPost(tc.body); got != want {
			t.Errorf("the response to %s differs from the response to a valid knock.\n got: %q\nwant: %q",
				tc.name, got, want)
		}
	}
}

// The method and the path are not part of the protocol either, and answering
// them differently would be the same oracle wearing different clothes: a
// scanner that learns POST / is special has learned where to aim.
func TestAgent_HTTPCarrier_EveryMethodAndPathGetsTheSameResponse(t *testing.T) {
	f := newFixture(t)
	h := newCarrierHarness(t)
	valid := f.seal(f.gateRequest())

	want := h.rawPost(valid)
	for _, req := range []string{
		"GET / HTTP/1.1\r\nHost: %s\r\nContent-Length: 0\r\n\r\n",
		"GET /knock HTTP/1.1\r\nHost: %s\r\nContent-Length: 0\r\n\r\n",
		"PUT /../../etc/passwd HTTP/1.1\r\nHost: %s\r\nContent-Length: 0\r\n\r\n",
		"DELETE / HTTP/1.1\r\nHost: %s\r\nContent-Length: 0\r\n\r\n",
	} {
		got := h.rawExchange([]byte(fmt.Sprintf(req, h.addr)))
		if got != want {
			t.Errorf("%q answered differently from a POST of a valid knock.\n got: %q\nwant: %q", req, got, want)
		}
	}
}

// The observed source is the TCP peer, full stop.
//
// X-Forwarded-For decides nothing, because it is a string the attacker wrote
// and this value decides whose address gets a firewall hole. Honouring it —
// even "only when present", even "only from a trusted range" — hands the
// authorization model to whoever can reach the port.
//
// This is checked at the receiver rather than at the gate on purpose: by the
// time a Datagram reaches Validate the source is just an address, and nothing
// downstream could tell that it had been chosen by a header. The lie has to
// be refused here or not at all.
func TestAgent_HTTPCarrier_ProxyHeadersDoNotChangeTheObservedSource(t *testing.T) {
	f := newFixture(t)
	h := newCarrierHarness(t)

	h.rawPost(f.seal(f.gateRequest()),
		"X-Forwarded-For: 203.0.113.9",
		"X-Real-IP: 203.0.113.9",
		"Forwarded: for=203.0.113.9",
		"True-Client-IP: 203.0.113.9",
		"CF-Connecting-IP: 203.0.113.9",
	)

	got := h.received()
	if len(got) != 1 {
		t.Fatalf("delivered %d datagrams, want 1", len(got))
	}
	if !got[0].Source.Addr().IsLoopback() {
		t.Fatalf("observed source is %s; the headers chose the address the gate would open for, "+
			"and the only address that may do that is the TCP peer", got[0].Source)
	}
}

// The cap is enforced, and it is enforced by refusing rather than by
// truncating. A truncated oversized body would arrive at spa.TrialOpen as a
// correctly-sized record, and the exact-length check — the cheapest rejection
// in the system, and the one that rejects essentially all garbage without
// touching key material — would never fire on it.
//
// The boundary is checked from both sides so "refused" cannot be satisfied by
// a receiver that refuses everything.
func TestAgent_HTTPCarrier_OversizedBodyIsRefusedNotTruncated(t *testing.T) {
	h := newCarrierHarness(t)

	atCap := bytes.Repeat([]byte{0x11}, agent.HTTPCarrierMaxBodyForTest)
	overCap := bytes.Repeat([]byte{0x22}, agent.HTTPCarrierMaxBodyForTest+1)

	h.rawPost(atCap)
	got := h.received()
	if len(got) != 1 {
		t.Fatalf("a body exactly at the cap delivered %d datagrams, want 1", len(got))
	}
	if len(got[0].Payload) != agent.HTTPCarrierMaxBodyForTest {
		t.Fatalf("delivered %d bytes, want the whole %d-byte body", len(got[0].Payload), agent.HTTPCarrierMaxBodyForTest)
	}

	h.rawPost(overCap)
	if got := h.received(); len(got) != 0 {
		t.Fatalf("a body over the cap was delivered anyway (%d bytes); an oversized body must be "+
			"refused, never truncated into something the length check would accept", len(got[0].Payload))
	}
}

// The cap is larger than one record, for the same reason the UDP receive
// buffer is. If it equalled spa.DatagramSize an oversized body would be
// silently cut down to a valid-looking length.
func TestAgent_HTTPCarrier_BodyCapIsLargerThanOneRecord(t *testing.T) {
	if agent.HTTPCarrierMaxBodyForTest <= spa.DatagramSize {
		t.Fatalf("the body cap is %d and a record is %d; a cap at or below the record size truncates "+
			"an oversized body into one the exact-length check accepts",
			agent.HTTPCarrierMaxBodyForTest, spa.DatagramSize)
	}
}

// The carrier never claims the always-allow path.
//
// Liveness — the one packet postern ever answers — is bound to that path, and
// the UDP receiver establishes it from the kernel's per-packet ancillary
// data. This carrier has no equivalent it could trust, so it must report
// false unconditionally: a carrier that could claim the path would be a way
// to make a break-glass host transmit on demand.
func TestAgent_HTTPCarrier_NeverClaimsTheAlwaysAllowPath(t *testing.T) {
	f := newFixture(t)
	h := newCarrierHarness(t)

	challenge, err := spa.EncodeLivenessPayload([16]byte{9, 9, 9})
	if err != nil {
		t.Fatalf("EncodeLivenessPayload: %v", err)
	}
	h.rawPost(f.seal(f.actionRequest(livenessName, challenge)))

	got := h.received()
	if len(got) != 1 {
		t.Fatalf("delivered %d datagrams, want 1", len(got))
	}
	if got[0].OnAlwaysAllowPath {
		t.Fatal("the http carrier reported a packet as having arrived on the always-allow path; " +
			"liveness binds to that path and this carrier cannot establish it")
	}
}

// And the carrier refuses to transmit at all, which is the second half of the
// same property: even if something upstream decided a pong was owed, there is
// no path through this receiver that puts bytes on the wire.
func TestAgent_HTTPCarrier_RefusesToReply(t *testing.T) {
	h := newCarrierHarness(t)
	err := h.recv.Reply(context.Background(), netip.MustParseAddrPort("198.51.100.5:1234"), 0, []byte("pong"))
	if err == nil {
		t.Fatal("the http carrier accepted a Reply; it must never transmit")
	}
}

// A peer that connects and sends nothing must not own a handler goroutine
// forever. The read timeout is what bounds it, and this proves the server
// actually hangs up rather than waiting on a body that never comes.
func TestAgent_HTTPCarrier_StalledRequestIsClosedByTheReadTimeout(t *testing.T) {
	h := newCarrierHarness(t)

	conn, err := net.DialTimeout("tcp", h.addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	// A complete head promising a body that never arrives.
	if _, err := fmt.Fprintf(conn, "POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 224\r\n\r\n", h.addr); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	// The server's own read timeout must end this well inside the deadline
	// above; without one, this read blocks until the test's deadline fires.
	if _, err := io.ReadAll(conn); err != nil {
		t.Fatalf("the connection was not closed by the server: %v", err)
	}
	if got := h.received(); len(got) != 0 {
		t.Fatalf("a truncated request delivered %d datagrams", len(got))
	}
}

// Sanity: the carrier is an ordinary HTTP server to an ordinary HTTP client,
// so the shipped client's own sender has something to talk to. Without this
// the tests above would all pass against a listener that answered nothing
// usable.
func TestAgent_HTTPCarrier_AcceptsAnOrdinaryHTTPPost(t *testing.T) {
	f := newFixture(t)
	h := newCarrierHarness(t)

	datagram := f.seal(f.gateRequest())
	resp, err := http.Post("http://"+h.addr+"/", "application/octet-stream", bytes.NewReader(datagram))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()

	got := h.received()
	if len(got) != 1 {
		t.Fatalf("delivered %d datagrams, want 1", len(got))
	}
	if !bytes.Equal(got[0].Payload, datagram) {
		t.Fatal("the delivered payload is not the datagram that was posted; the carrier must not " +
			"transform the packet in any way")
	}
}
