package client_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/client"
	"github.com/jotra7/postern/internal/identity"
	"github.com/jotra7/postern/internal/knockport"
	"github.com/jotra7/postern/internal/spa"
)

// rotationSecret is the fixed port_rotation secret rotationHost writes into
// its fixture. It is exposed so a test can compute the expected port
// independently, straight from knockport, rather than by calling
// Host.CurrentKnockPort a second time — which would only ever agree with
// itself and could not catch a mutation inside CurrentKnockPort.
func rotationSecret() []byte {
	return bytesN(0x24, knockport.SecretSize)
}

// rotationHost is testHost's shape plus a port_rotation block, so the client
// resolves a current-window port instead of the entry's fixed knock_port.
func rotationHost(t *testing.T) *client.Host {
	t.Helper()
	host := mustGenerate(t, "web-01")
	enc, sign := host.Public().Encryption, host.Public().Signing
	secret := rotationSecret()
	yamlDoc := "" +
		"operator: laptop-primary\n" +
		"hosts:\n" +
		"  - name: web-01\n" +
		"    host_id: " + hex.EncodeToString(bytes16(0x3a)) + "\n" +
		"    knock_addr: 203.0.113.9\n" +
		"    knock_port: 62201\n" +
		"    host_encryption: " + base64.StdEncoding.EncodeToString(enc[:]) + "\n" +
		"    host_signing: " + base64.StdEncoding.EncodeToString(sign[:]) + "\n" +
		"    recovery_service: ssh\n" +
		"    port_rotation:\n" +
		"      secret: " + base64.StdEncoding.EncodeToString(secret) + "\n" +
		"      window: 10m\n" +
		"      range: 20000-30000\n" +
		"    services:\n" +
		"      ssh: { port: 22, ttl: 120s }\n"
	cfg, err := client.ParseConfig([]byte(yamlDoc))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	h, err := cfg.Host("web-01")
	if err != nil {
		t.Fatalf("Host: %v", err)
	}
	return h
}

func bytesN(fill byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = fill
	}
	return b
}

type recordingSend struct {
	to      []netip.AddrPort
	payload [][]byte
	err     error
}

func (r *recordingSend) send(_ context.Context, to netip.AddrPort, payload []byte) error {
	r.to = append(r.to, to)
	r.payload = append(r.payload, append([]byte(nil), payload...))
	return r.err
}

// Invariant 1. The fixture's host has knock_addr 203.0.113.9 and SSH
// hostname web-01.example.com — the CDN-fronted shape design section 6
// describes, where the name resolves to an edge rather than to the origin
// the gate protects.
//
// Both halves are asserted: the datagram goes to knock_addr, and so does the
// confirmation connect. Sending the knock to the origin and then confirming
// against the edge would report a proxy's behaviour as the gate's.
//
// Mutation verified: pointing ConnectAddr at any address other than
// h.KnockAddr fails this test's second half. The send half is defended by
// the type as much as by the test — h.SSH.Host is a string and
// KnockAddrPort returns a netip.AddrPort, so wiring one to the other does
// not compile.
func TestClient_Open_SendsToKnockAddrNotTheSSHHostname(t *testing.T) {
	op := mustGenerate(t, "laptop-primary")
	host := mustGenerate(t, "web-01")
	h := testHost(t, host.Public().Encryption, host.Public().Signing)

	if h.SSH.Host != "web-01.example.com" {
		t.Fatalf("fixture lost its distinct SSH hostname (%q); this test asserts nothing without it", h.SSH.Host)
	}

	sender := &recordingSend{}
	var dialed string
	dial := func(_ context.Context, _, address string) (net.Conn, error) {
		dialed = address
		return nil, nil
	}

	rep, err := client.Open(context.Background(), client.OpenOptions{
		Builder: client.Builder{Signer: op},
		Host:    h,
		Service: "ssh",
		Counter: client.NewCounter(filepath.Join(t.TempDir(), "counter.json")),
		Send:    sender.send,
		Dial:    dial,
		NowMS:   fixedClock(testNowMS),
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if len(sender.to) != 1 {
		t.Fatalf("sent %d datagrams, want exactly one; the SPA path is one packet", len(sender.to))
	}
	if got := sender.to[0].String(); got != "203.0.113.9:62201" {
		t.Fatalf("knock went to %s, want 203.0.113.9:62201 (knock_addr, not %q)", got, h.SSH.Host)
	}
	if rep.KnockAddr.String() != "203.0.113.9:62201" {
		t.Fatalf("report names %s as the knock address", rep.KnockAddr)
	}
	if dialed != "203.0.113.9:22" {
		t.Fatalf("confirmation connected to %q, want 203.0.113.9:22; connecting to the SSH hostname "+
			"would resolve a name during an emergency open and, on a fronted host, reach an edge", dialed)
	}
	if strings.Contains(dialed, "example.com") {
		t.Fatalf("the confirmation resolved a hostname: %q", dialed)
	}
}

func TestClient_Open_SendsExactlyOneDatagramTheHostCanOpen(t *testing.T) {
	op := mustGenerate(t, "laptop-primary")
	host := mustGenerate(t, "web-01")
	h := testHost(t, host.Public().Encryption, host.Public().Signing)

	opener, _, err := spa.NewOpenerFromSigner(host, []identity.PublicIdentity{op.Public()})
	if err != nil {
		t.Fatalf("NewOpenerFromSigner: %v", err)
	}

	sender := &recordingSend{}
	_, err = client.Open(context.Background(), client.OpenOptions{
		Builder: client.Builder{Signer: op},
		Host:    h,
		Service: "ssh",
		TTL:     90 * time.Second,
		Counter: client.NewCounter(filepath.Join(t.TempDir(), "counter.json")),
		Send:    sender.send,
		Dial:    func(context.Context, string, string) (net.Conn, error) { return nil, nil },
		NowMS:   fixedClock(testNowMS),
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	req, who, err := opener.TrialOpen(sender.payload[0])
	if err != nil {
		t.Fatalf("the host could not open the datagram: %v", err)
	}
	if who.Name != "laptop-primary" {
		t.Fatalf("datagram attributed to %q", who.Name)
	}
	if req.Kind != spa.KindGate {
		t.Fatalf("kind = %v, want gate", req.Kind)
	}
	if req.TTLSeconds != 90 {
		t.Fatalf("ttl_seconds = %d, want 90", req.TTLSeconds)
	}
	if req.Counter != testNowMS {
		t.Fatalf("counter = %d, want the clock %d", req.Counter, testNowMS)
	}
}

// A failed send must not suppress the confirmation. A gate opened by an
// earlier knock may still be live, and telling an operator only that the
// send failed sends them after the wrong thing.
//
// The assertion is on the order of events rather than on a dialled flag: open
// also connects once before the knock, so a flag would be set by that connect
// and would stay green against an implementation that gave up after the send
// failed.
func TestClient_Open_ConfirmsEvenWhenTheSendFailed(t *testing.T) {
	op := mustGenerate(t, "laptop-primary")
	host := mustGenerate(t, "web-01")
	h := testHost(t, host.Public().Encryption, host.Public().Signing)

	log := &eventLog{}
	d := &dialScript{replies: []error{nil}, log: log}
	rep, err := client.Open(context.Background(), client.OpenOptions{
		Builder: client.Builder{Signer: op},
		Host:    h,
		Service: "ssh",
		Counter: client.NewCounter(filepath.Join(t.TempDir(), "counter.json")),
		Send:    log.sender(errors.New("network is down")),
		Dial:    d.dial,
		NowMS:   fixedClock(testNowMS),
	})
	if err == nil {
		t.Fatal("a failed send returned no error")
	}
	events := log.events()
	if len(events) == 0 || events[len(events)-1] == "knock" {
		t.Fatalf("nothing connected after the send failed; the sequence was %v", events)
	}
	if rep.Sent.Delivered {
		t.Fatal("Sent.Delivered is true after a failed send; the timeout advice depends on this")
	}
	if rep.Result.Outcome != client.Connected {
		t.Fatalf("outcome = %q, want connected — the port was in fact reachable", rep.Result.Outcome)
	}
}

func TestClient_Open_UsesTheServiceTTLFromConfigWhenNoneIsGiven(t *testing.T) {
	op := mustGenerate(t, "laptop-primary")
	host := mustGenerate(t, "web-01")
	h := testHost(t, host.Public().Encryption, host.Public().Signing)

	sender := &recordingSend{}
	rep, err := client.Open(context.Background(), client.OpenOptions{
		Builder: client.Builder{Signer: op},
		Host:    h,
		Service: "ssh",
		Counter: client.NewCounter(filepath.Join(t.TempDir(), "counter.json")),
		Send:    sender.send,
		Dial:    func(context.Context, string, string) (net.Conn, error) { return nil, nil },
		NowMS:   fixedClock(testNowMS),
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if rep.Sent.TTL != 120*time.Second {
		t.Fatalf("ttl = %s, want the configured 120s", rep.Sent.TTL)
	}
}

func TestClient_Open_RefusesAServiceTheHostDoesNotDeclare(t *testing.T) {
	op := mustGenerate(t, "laptop-primary")
	host := mustGenerate(t, "web-01")
	h := testHost(t, host.Public().Encryption, host.Public().Signing)

	sender := &recordingSend{}
	_, err := client.Open(context.Background(), client.OpenOptions{
		Builder: client.Builder{Signer: op},
		Host:    h,
		Service: "postgres",
		Send:    sender.send,
		NowMS:   fixedClock(testNowMS),
	})
	if err == nil {
		t.Fatal("an unknown service was accepted; the packet would have named a service_id the host " +
			"cannot resolve and been dropped in silence")
	}
	if len(sender.to) != 0 {
		t.Fatal("a datagram was sent for an unknown service")
	}
}

// --source-cidr is the only mitigation postern has for the CGNAT split, and
// the only advice `open` gives that an operator could not have derived. Two
// seams carry it and both were previously untested: the prefix reaching the
// packet, and the prefix reaching Advise.
//
// This is the first. Mutation verified: passing nil instead of o.SourceCIDR
// to Builder.Gate makes the retry the hint recommends do nothing at all —
// the operator follows the instruction, the same observed-source gate opens
// again, and nothing changes.
func TestClient_Open_SealsTheAssertedSourceIntoThePacket(t *testing.T) {
	op := mustGenerate(t, "laptop-primary")
	host := mustGenerate(t, "web-01")
	h := testHost(t, host.Public().Encryption, host.Public().Signing)

	opener, _, err := spa.NewOpenerFromSigner(host, []identity.PublicIdentity{op.Public()})
	if err != nil {
		t.Fatalf("NewOpenerFromSigner: %v", err)
	}

	asserted := mustPrefix(t, "203.0.113.0/24")
	sender := &recordingSend{}
	if _, err := client.Open(context.Background(), client.OpenOptions{
		Builder:    client.Builder{Signer: op},
		Host:       h,
		Service:    "ssh",
		SourceCIDR: &asserted,
		Counter:    client.NewCounter(filepath.Join(t.TempDir(), "counter.json")),
		Send:       sender.send,
		Dial:       func(context.Context, string, string) (net.Conn, error) { return nil, nil },
		NowMS:      fixedClock(testNowMS),
	}); err != nil {
		t.Fatalf("Open: %v", err)
	}

	req, _, err := opener.TrialOpen(sender.payload[0])
	if err != nil {
		t.Fatalf("TrialOpen: %v", err)
	}
	payload, err := req.GatePayload()
	if err != nil {
		t.Fatalf("GatePayload: %v", err)
	}
	if payload.SourceKind != spa.SourceAsserted {
		t.Fatal("--source-cidr produced an observed-source packet; the agent would open the gate for " +
			"the address the knock came from, which is the exact thing the operator was told to work around")
	}
	if got := payload.Prefix.String(); got != "203.0.113.0/24" {
		t.Fatalf("asserted prefix = %s, want 203.0.113.0/24", got)
	}
}

// The second seam. An operator who has just followed the --source-cidr
// advice and still timed out must not be told to try --source-cidr.
//
// Mutation verified: setting Sent.AssertedSource to nil regardless of
// o.SourceCIDR makes Advise re-emit the hint, and fails this test.
func TestClient_Open_DoesNotRepeatTheSourceCIDRHintAfterAssertingOne(t *testing.T) {
	op := mustGenerate(t, "laptop-primary")
	host := mustGenerate(t, "web-01")
	h := testHost(t, host.Public().Encryption, host.Public().Signing)

	asserted := mustPrefix(t, "203.0.113.0/24")
	rep, err := client.Open(context.Background(), client.OpenOptions{
		Builder:         client.Builder{Signer: op},
		Host:            h,
		Service:         "ssh",
		SourceCIDR:      &asserted,
		Counter:         client.NewCounter(filepath.Join(t.TempDir(), "counter.json")),
		Send:            (&recordingSend{}).send,
		Dial:            func(context.Context, string, string) (net.Conn, error) { return nil, context.DeadlineExceeded },
		ConnectAttempts: 1,
		NowMS:           fixedClock(testNowMS),
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if rep.Result.Outcome != client.TimedOut {
		t.Fatalf("outcome = %q, want timeout — this test asserts nothing on any other branch", rep.Result.Outcome)
	}
	if rep.Sent.AssertedSource == nil {
		t.Fatal("the report does not record that a source was asserted, so every downstream " +
			"decision about it is made on wrong information")
	}
	if rep.Advice.SourceCIDRHint {
		t.Fatalf("the operator asserted %s and was told to retry with --source-cidr; advice that "+
			"fires after it has been followed teaches an operator to ignore it", asserted)
	}
	if !strings.Contains(rep.Advice.Detail, asserted.String()) {
		t.Fatalf("the timeout detail does not name the prefix that was asserted:\n%s", rep.Advice.Detail)
	}
}

// The client sends exactly one datagram, to its own current-window port. It
// does not fan out to the neighbor ports: the agent already holds the current
// window and both neighbors live, so one knock to port(w) lands whenever the
// two clocks are within about one window, and a single packet avoids the
// burst fingerprint three simultaneous datagrams to three ports would
// present to an observer.
func TestClient_Open_RotationSendsOneDatagramToTheCurrentWindowPort(t *testing.T) {
	op := mustGenerate(t, "laptop-primary")
	h := rotationHost(t)
	var sentTo []netip.AddrPort
	rec := func(_ context.Context, to netip.AddrPort, _ []byte) error {
		sentTo = append(sentTo, to)
		return nil
	}
	// A fixed Now so the window, and therefore the port, is deterministic.
	_, err := client.Open(t.Context(), client.OpenOptions{
		Builder: client.Builder{Signer: op}, Host: h, Service: "ssh", Send: rec,
		NowMS: func() uint64 { return 600_000 }, // unix 600 -> window 1 at the 10m default
		Dial:  func(context.Context, string, string) (net.Conn, error) { return nil, context.DeadlineExceeded },
	})
	// Open returns the confirm outcome, not an error, for a refused connect.
	_ = err
	if len(sentTo) != 1 {
		t.Fatalf("sent %d datagrams, want exactly one: %v", len(sentTo), sentTo)
	}
	if _, ok := h.CurrentKnockPort(600); !ok {
		t.Fatal("CurrentKnockPort reported no rotation port on a rotation host")
	}
	// Computed straight from knockport rather than through h.CurrentKnockPort,
	// so this is independent of that method's own correctness: a mutation
	// inside CurrentKnockPort (the wrong window, say) makes the datagram's
	// port disagree with this one instead of agreeing with itself.
	wantWindow := knockport.Window(600, 10*time.Minute)
	wantPort := knockport.Port(rotationSecret(), wantWindow, 20000, 30000)
	if sentTo[0].Addr() != h.KnockAddr || sentTo[0].Port() != wantPort {
		t.Fatalf("datagram went to %s, want %s:%d (the current-window port)", sentTo[0], h.KnockAddr, wantPort)
	}
}

// A host with no port_rotation block sends exactly one datagram to
// KnockAddrPort(), exactly as before rotation existed. Guards the branch: a
// fixed-port host must not go anywhere near knockport.
func TestClient_Open_FixedHostSendsToTheSingleKnockPort(t *testing.T) {
	op := mustGenerate(t, "laptop-primary")
	host := mustGenerate(t, "web-01")
	h := testHost(t, host.Public().Encryption, host.Public().Signing)

	if h.PortRotation != nil {
		t.Fatal("the fixture host has a PortRotation set; this test asserts nothing without a fixed-port host")
	}

	var sentTo []netip.AddrPort
	rec := func(_ context.Context, to netip.AddrPort, _ []byte) error {
		sentTo = append(sentTo, to)
		return nil
	}
	_, err := client.Open(t.Context(), client.OpenOptions{
		Builder: client.Builder{Signer: op}, Host: h, Service: "ssh", Send: rec,
		NowMS: fixedClock(testNowMS),
		Dial:  func(context.Context, string, string) (net.Conn, error) { return nil, context.DeadlineExceeded },
	})
	_ = err
	if len(sentTo) != 1 {
		t.Fatalf("sent %d datagrams, want exactly one: %v", len(sentTo), sentTo)
	}
	if sentTo[0] != h.KnockAddrPort() {
		t.Fatalf("datagram went to %s, want %s (KnockAddrPort, the fixed knock port)", sentTo[0], h.KnockAddrPort())
	}
}
