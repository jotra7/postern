package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"testing"
	"time"
)

// freePort binds a throwaway UDP socket on loopback to learn a port number
// the kernel currently considers free, closes it immediately, and returns
// the number.
//
// This races the allocator: between the close below and the real bind a
// test performs a moment later, some other process on the machine could
// grab the same port. The task this test belongs to accepts that risk
// rather than testing against port 0, because a fixed live set of specific,
// known port numbers is the only way to assert "a datagram to this exact
// port is delivered" and "a datagram to that exact port is refused" — the
// two properties Rebind exists to provide.
func freePort(t *testing.T) uint16 {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("freePort: bind throwaway socket: %v", err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	if err := conn.Close(); err != nil {
		t.Fatalf("freePort: close throwaway socket: %v", err)
	}
	return uint16(port)
}

func freePorts(t *testing.T, n int) []uint16 {
	t.Helper()
	ports := make([]uint16, n)
	for i := range ports {
		ports[i] = freePort(t)
	}
	return ports
}

// sendTo fires one UDP datagram at 127.0.0.1:port. It does not wait for or
// expect a response — postern's SPA carriers never answer anything but a
// liveness pong.
func sendTo(t *testing.T, port uint16, payload []byte) {
	t.Helper()
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(port)})
	if err != nil {
		t.Fatalf("dial port %d: %v", port, err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write to port %d: %v", port, err)
	}
}

// receiveN drains exactly n datagrams from r, failing the test if any one of
// them does not arrive within timeout.
func receiveN(t *testing.T, r Receiver, n int, timeout time.Duration) [][]byte {
	t.Helper()
	got := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		dg, err := r.Receive(ctx)
		cancel()
		if err != nil {
			t.Fatalf("Receive (%d of %d): %v", i+1, n, err)
		}
		got = append(got, dg.Payload)
	}
	return got
}

// assertPayloadSet checks got and want hold the same payloads, ignoring
// order — Receive fans in from several sockets pumped concurrently, so
// which one wins the race to the shared channel first is not part of the
// contract.
func assertPayloadSet(t *testing.T, got [][]byte, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("received %d datagrams, want %d", len(got), len(want))
	}
	gotSet := make(map[string]int, len(got))
	for _, p := range got {
		gotSet[string(p)]++
	}
	for _, w := range want {
		if gotSet[w] == 0 {
			t.Errorf("payload %q was not among the received datagrams %v", w, got)
			continue
		}
		gotSet[w]--
	}
}

func TestAgent_RotatingReceiver_ReceivesOnEveryLivePort(t *testing.T) {
	ports := freePorts(t, 3)

	r, err := newRotatingUDPReceiver(ports, "")
	if err != nil {
		t.Fatalf("newRotatingUDPReceiver: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })

	for i, port := range ports {
		sendTo(t, port, []byte(fmt.Sprintf("payload-%d", i)))
	}

	got := receiveN(t, r, len(ports), 2*time.Second)
	assertPayloadSet(t, got, "payload-0", "payload-1", "payload-2")
}

// TestAgent_RotatingReceiver_DatagramLocalPortMatchesArrivalSocket sends one
// ping to each of several live ports and checks that every received
// Datagram's LocalPort names the actual socket it arrived on, not some other
// live port. Reply's fix depends entirely on this being right: Reply trusts
// LocalPort to pick the reply socket, so a mistagged Datagram would send the
// pong out the wrong port even with Reply itself correct.
func TestAgent_RotatingReceiver_DatagramLocalPortMatchesArrivalSocket(t *testing.T) {
	ports := freePorts(t, 3)

	r, err := newRotatingUDPReceiver(ports, "")
	if err != nil {
		t.Fatalf("newRotatingUDPReceiver: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })

	wantPort := make(map[string]uint16, len(ports))
	for i, port := range ports {
		payload := fmt.Sprintf("payload-%d", i)
		wantPort[payload] = port
		sendTo(t, port, []byte(payload))
	}

	for range ports {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		dg, err := r.Receive(ctx)
		cancel()
		if err != nil {
			t.Fatalf("Receive: %v", err)
		}
		want, ok := wantPort[string(dg.Payload)]
		if !ok {
			t.Fatalf("received unexpected payload %q", dg.Payload)
		}
		if dg.LocalPort != want {
			t.Errorf("payload %q arrived tagged LocalPort %d, want %d", dg.Payload, dg.LocalPort, want)
		}
	}
}

func TestAgent_RotatingReceiver_RebindClosesDroppedPortsAndOpensNewOnes(t *testing.T) {
	ports := freePorts(t, 4)
	a, b, c, d := ports[0], ports[1], ports[2], ports[3]

	r, err := newRotatingUDPReceiver([]uint16{a, b, c}, "")
	if err != nil {
		t.Fatalf("newRotatingUDPReceiver: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })

	// Queued before the rebind, so a datagram already sitting in b and c's
	// kernel receive buffers is the thing under test, not one sent after
	// the swap has already settled.
	sendTo(t, b, []byte("to-b"))
	sendTo(t, c, []byte("to-c"))

	// Captured before the rebind so the check below is a real proof that b
	// and c's sockets were not reopened, not just that they still work.
	bBefore := r.sockets[b]
	cBefore := r.sockets[c]

	if err := r.Rebind(context.Background(), []uint16{b, c, d}); err != nil {
		t.Fatalf("Rebind: %v", err)
	}

	if r.sockets[b] != bBefore {
		t.Error("Rebind reopened port b's socket even though b was live before and after")
	}
	if r.sockets[c] != cBefore {
		t.Error("Rebind reopened port c's socket even though c was live before and after")
	}
	if _, ok := r.sockets[a]; ok {
		t.Error("Rebind left port a's socket open after a left the live set")
	}
	if _, ok := r.sockets[d]; !ok {
		t.Error("Rebind did not open a socket for port d, which entered the live set")
	}

	sendTo(t, d, []byte("to-d"))
	// a is no longer live; this must go nowhere the receiver hears.
	sendTo(t, a, []byte("to-a"))

	got := receiveN(t, r, 3, 2*time.Second)
	assertPayloadSet(t, got, "to-b", "to-c", "to-d")

	// Confirm "to-a" really was refused rather than merely arriving last:
	// nothing more should show up within a short window.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if dg, err := r.Receive(ctx); err == nil {
		t.Fatalf("received an unexpected fourth datagram %q; port a should have been refused after Rebind", dg.Payload)
	}
}

func TestAgent_RotatingReceiver_RebindAfterCloseReturnsClosedError(t *testing.T) {
	ports := freePorts(t, 2)

	r, err := newRotatingUDPReceiver(ports[:1], "")
	if err != nil {
		t.Fatalf("newRotatingUDPReceiver: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	before := len(r.sockets)
	if err := r.Rebind(context.Background(), ports); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Rebind after Close returned %v, want %v", err, net.ErrClosed)
	}
	if got := len(r.sockets); got != before {
		t.Errorf("Rebind after Close changed the socket count from %d to %d; it should have opened nothing", before, got)
	}
}

// TestAgent_RotatingReceiver_ReplyGoesOutTheArrivalPortSocket is a real round
// trip proving the fix for the live liveness-pong bug: the client's reply
// socket is connected (Dial'd) to the exact port it pinged, so the kernel
// delivers a reply to it only when that reply's *source* port matches. A
// pong sent from the wrong live socket — the highest port, say, rather than
// the one the ping arrived on — would be silently dropped by the client
// exactly the way it was on the live host this bug was found on.
//
// This test pings a NON-highest live port on purpose: that is the case the
// bug broke (Reply used to always answer from the highest port, so a ping to
// any other port never got a reply the client would accept).
func TestAgent_RotatingReceiver_ReplyGoesOutTheArrivalPortSocket(t *testing.T) {
	ports := freePorts(t, 3)
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	lowest, highest := ports[0], ports[2]
	if lowest == highest {
		t.Fatal("test needs three distinct ports")
	}

	r, err := newRotatingUDPReceiver(ports, "")
	if err != nil {
		t.Fatalf("newRotatingUDPReceiver: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })

	// The client's liveness socket: connected to the low, non-highest port,
	// so it only accepts a reply whose source address is that exact port.
	clientConn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(lowest)})
	if err != nil {
		t.Fatalf("dial low port %d: %v", lowest, err)
	}
	defer func() { _ = clientConn.Close() }()
	clientAddr := netip.MustParseAddrPort(clientConn.LocalAddr().String())

	if _, err := clientConn.Write([]byte("ping")); err != nil {
		t.Fatalf("write ping to port %d: %v", lowest, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	dg, err := r.Receive(ctx)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if dg.LocalPort != lowest {
		t.Fatalf("Datagram.LocalPort = %d, want the arrival port %d (the low, non-highest port the ping was sent to)", dg.LocalPort, lowest)
	}
	// A dual-stack listener reports an IPv4 peer in its ::ffff:-mapped form;
	// unmap before comparing, the same normalization the rest of the
	// codebase applies to any address a socket hands back (see gate.go,
	// config/resolve.go, metrics/bind.go).
	gotSource := netip.AddrPortFrom(dg.Source.Addr().Unmap(), dg.Source.Port())
	wantSource := netip.AddrPortFrom(clientAddr.Addr().Unmap(), clientAddr.Port())
	if gotSource != wantSource {
		t.Fatalf("Datagram.Source = %v, want the client's address %v", gotSource, wantSource)
	}

	if err := r.Reply(context.Background(), dg.Source, dg.LocalPort, []byte("pong")); err != nil {
		t.Fatalf("Reply: %v", err)
	}

	if err := clientConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 16)
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatalf("the client's socket (connected to port %d) never received the reply: %v", lowest, err)
	}
	if got := string(buf[:n]); got != "pong" {
		t.Fatalf("reply payload = %q, want %q", got, "pong")
	}
}

// TestAgent_RotatingReceiver_ReplyToStaleArrivalPortIsRefused covers the
// narrow race the fix's doc comment calls out: if the window rotates between
// Receive and Reply, the arrival port may no longer be live. Reply must
// refuse rather than silently answer from a different socket, because a
// pong from any other port would just be dropped by the client anyway.
func TestAgent_RotatingReceiver_ReplyToStaleArrivalPortIsRefused(t *testing.T) {
	ports := freePorts(t, 3)
	stale := freePort(t) // never live on r; stands in for a port that rotated out

	r, err := newRotatingUDPReceiver(ports, "")
	if err != nil {
		t.Fatalf("newRotatingUDPReceiver: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })

	peerConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("bind listening peer: %v", err)
	}
	defer func() { _ = peerConn.Close() }()
	peerAddr := netip.MustParseAddrPort(peerConn.LocalAddr().String())

	if err := r.Reply(context.Background(), peerAddr, stale, []byte("pong")); err == nil {
		t.Fatal("Reply succeeded for a port with no live socket; it should have refused rather than picking a different one")
	}
}
