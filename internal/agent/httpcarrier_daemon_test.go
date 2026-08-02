package agent_test

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/jotra7/postern/internal/agent"
	"github.com/jotra7/postern/internal/gate"
)

// httpCarrierDaemon starts a daemon whose receiver is the fake UDP-side
// receiver every other daemon test uses, fanned in with a real HTTP carrier
// on loopback. Both feed one packet loop, which is the arrangement production
// uses.
type httpCarrierDaemon struct {
	*daemonHarness
	knockURL string
}

func newHTTPCarrierDaemon(t *testing.T) *httpCarrierDaemon {
	t.Helper()
	carrier, addr, err := agent.NewLoopbackHTTPCarrier()
	if err != nil {
		t.Fatalf("NewLoopbackHTTPCarrier: %v", err)
	}
	h := newDaemonHarness(t, func(o *agent.Options) {
		// o.Receiver is the harness's own fake UDP-side receiver, already set
		// by the time tune runs. It stays the primary — it is the only one
		// that can report the always-allow path, and so the only one a pong
		// could ever go back through.
		o.Receiver = agent.NewMultiReceiverForTest(o.Receiver, o.Receiver, carrier)
	})
	h.start(t)
	return &httpCarrierDaemon{daemonHarness: h, knockURL: "http://" + addr.String() + "/"}
}

func (c *httpCarrierDaemon) post(t *testing.T, datagram []byte) {
	t.Helper()
	resp, err := http.Post(c.knockURL, "application/octet-stream", bytes.NewReader(datagram))
	if err != nil {
		t.Fatalf("post the knock: %v", err)
	}
	_ = resp.Body.Close()
}

// The whole point of the carrier: a knock delivered over HTTP opens the same
// gate, for the same source, for the same TTL, as the same packet over UDP.
//
// It is one packet compared against itself rather than two packets that
// happen to agree, so nothing about the comparison can drift: the same sealed
// bytes are sent twice, once down each carrier, and the two resulting Open
// calls must agree on everything except the address — which differs only
// because the two carriers observed different peers, which is exactly what
// "the observed source is where the packet came from" means.
//
// The mutation this catches is a second validation path. If the HTTP handler
// grew its own idea of what a packet authorizes — a different TTL clamp, a
// skipped grant check, a source taken from somewhere other than the peer —
// the two Open calls would stop matching.
func TestAgent_HTTPCarrier_KnockOpensTheSameGateAsOverUDP(t *testing.T) {
	c := newHTTPCarrierDaemon(t)

	datagram := c.seal(c.gateRequest())
	c.send(t, datagram, false)
	waitFor(t, "the udp-carried knock to open the gate", func() bool { return len(c.gate.openCalls()) == 1 })
	viaUDP := c.gate.openCalls()[0]

	// A second, independently sealed copy: the same request would be refused
	// by the replay store, which is the next test's subject, not this one's.
	c.post(t, c.seal(c.gateRequest()))
	waitFor(t, "the http-carried knock to open the gate", func() bool { return len(c.gate.openCalls()) == 2 })
	viaHTTP := c.gate.openCalls()[1]

	if viaHTTP.service != viaUDP.service {
		t.Errorf("http opened %q, udp opened %q", viaHTTP.service, viaUDP.service)
	}
	if viaHTTP.ttl != viaUDP.ttl {
		t.Errorf("http granted ttl %s, udp granted %s", viaHTTP.ttl, viaUDP.ttl)
	}
	if viaHTTP.src.Kind != gate.SourceObserved {
		t.Errorf("http opened a %v source, want the observed one", viaHTTP.src.Kind)
	}
	if !viaHTTP.src.Prefix.Addr().IsLoopback() {
		t.Errorf("http opened %s; it must be the TCP peer this test connected from", viaHTTP.src.Prefix)
	}
	if viaHTTP.src.Prefix.Bits() != viaHTTP.src.Prefix.Addr().BitLen() {
		t.Errorf("http opened %s, which is not a single address", viaHTTP.src.Prefix)
	}
}

// One replay store, not one per carrier. A packet accepted over UDP is spent
// everywhere, and a packet accepted over HTTP is spent everywhere, because
// there is exactly one Reserve on exactly one path.
//
// This is the control that would break first if the HTTP handler ever
// validated inline: a second pipeline with its own store — or with no store —
// turns the new carrier into a replay bypass for the old one, and the knock
// an attacker captured off the wire becomes reusable by posting it.
//
// Both directions are checked. UDP-then-HTTP catches a carrier that keeps its
// own reservations; HTTP-then-HTTP catches one that keeps none at all.
func TestAgent_HTTPCarrier_ReplayIsRefusedByTheSameStore(t *testing.T) {
	c := newHTTPCarrierDaemon(t)

	overUDP := c.seal(c.gateRequest())
	c.send(t, overUDP, false)
	waitFor(t, "the first knock to open the gate", func() bool { return len(c.gate.openCalls()) == 1 })

	// The identical bytes, now over the other carrier.
	c.post(t, overUDP)
	c.awaitProcessed(t, 2)
	if n := len(c.gate.openCalls()); n != 1 {
		t.Fatalf("a packet already spent over udp opened the gate again over http (%d opens); "+
			"the two carriers must share one replay store", n)
	}

	overHTTP := c.seal(c.gateRequest())
	c.post(t, overHTTP)
	waitFor(t, "the http knock to open the gate", func() bool { return len(c.gate.openCalls()) == 2 })
	c.post(t, overHTTP)
	c.awaitProcessed(t, 4)
	if n := len(c.gate.openCalls()); n != 2 {
		t.Fatalf("an http-carried packet was accepted twice (%d opens)", n)
	}
}

// The carrier is not a way around any other check either. A packet for a host
// that is not this one, and a packet naming no configured service, are
// refused over HTTP exactly as they are over UDP — silently, with the gate
// untouched, because the same Validate rejected them.
func TestAgent_HTTPCarrier_RejectedPacketsOpenNothingAndAreNotAnswered(t *testing.T) {
	c := newHTTPCarrierDaemon(t)

	wrongHost := c.gateRequest()
	wrongHost.HostID = [16]byte{0xFE}
	c.post(t, c.seal(wrongHost))

	c.post(t, []byte("not a postern packet at all"))

	c.awaitProcessed(t, 2)
	if calls := c.gate.openCalls(); len(calls) != 0 {
		t.Fatalf("a rejected http-carried packet opened the gate: %v", calls)
	}
	if n := c.recv.replyCount(); n != 0 {
		t.Fatalf("the daemon transmitted %d replies; nothing on the http carrier is ever answered", n)
	}
}
