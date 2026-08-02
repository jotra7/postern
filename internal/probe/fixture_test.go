package probe_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/client"
	"github.com/jotra7/postern/internal/identity"
	"github.com/jotra7/postern/internal/knockport"
	"github.com/jotra7/postern/internal/probe"
)

// testHost is the probe's view of a host: a canary gate on 62202 with
// nothing behind it, and an SSH hostname deliberately different from
// knock_addr so a connect to the wrong one is visible.
func testHost(t *testing.T) *client.Host {
	t.Helper()
	var enc [32]byte
	copy(enc[:], mustBase64(t, testHostEncryptionB64))
	yaml := "" +
		"operator: probe-local\n" +
		"hosts:\n" +
		"  - name: web-01\n" +
		"    host_id: " + hex.EncodeToString(make([]byte, 16)) + "\n" +
		"    knock_addr: 203.0.113.9\n" +
		"    knock_port: 62201\n" +
		"    host_encryption: " + base64.StdEncoding.EncodeToString(enc[:]) + "\n" +
		"    recovery_service: ssh\n" +
		"    ssh: { host: web-01.example.com, user: ops, port: 22 }\n" +
		"    services:\n" +
		"      ssh: { port: 22, ttl: 120s }\n" +
		"      canary: { port: 62202, ttl: 30s }\n"
	cfg, err := client.ParseConfig([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	h, err := cfg.Host("web-01")
	if err != nil {
		t.Fatalf("Host: %v", err)
	}
	return h
}

// A real X25519 public key, so Seal succeeds. Its private half is nobody's.
const testHostEncryptionB64 = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr06H5F9wKgcHU="

// rotationSecret is the fixed port_rotation secret rotationTestHost writes
// into its fixture, exposed so a test can compute the expected port
// independently, straight from knockport, the same reason
// internal/client's own rotationSecret() is exposed to its tests.
func rotationSecret() []byte {
	b := make([]byte, knockport.SecretSize)
	for i := range b {
		b[i] = 0x24
	}
	return b
}

// rotationTestHost is testHost's shape plus a port_rotation block, so the
// probe resolves a current-window port for its knock instead of knock_port.
func rotationTestHost(t *testing.T) *client.Host {
	t.Helper()
	var enc [32]byte
	copy(enc[:], mustBase64(t, testHostEncryptionB64))
	yaml := "" +
		"operator: probe-local\n" +
		"hosts:\n" +
		"  - name: web-01\n" +
		"    host_id: " + hex.EncodeToString(make([]byte, 16)) + "\n" +
		"    knock_addr: 203.0.113.9\n" +
		"    knock_port: 62201\n" +
		"    host_encryption: " + base64.StdEncoding.EncodeToString(enc[:]) + "\n" +
		"    recovery_service: ssh\n" +
		"    port_rotation:\n" +
		"      secret: " + base64.StdEncoding.EncodeToString(rotationSecret()) + "\n" +
		"      window: 10m\n" +
		"      range: 20000-30000\n" +
		"    ssh: { host: web-01.example.com, user: ops, port: 22 }\n" +
		"    services:\n" +
		"      ssh: { port: 22, ttl: 120s }\n" +
		"      canary: { port: 62202, ttl: 30s }\n"
	cfg, err := client.ParseConfig([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	h, err := cfg.Host("web-01")
	if err != nil {
		t.Fatalf("Host: %v", err)
	}
	return h
}

func mustBase64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	return b
}

func mustSigner(t *testing.T) identity.Signer {
	t.Helper()
	s, err := identity.Generate("probe-local")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return s
}

// dialResult is one scripted connect outcome. Every one of these returns
// immediately: a test whose failure under mutation is a hang emits neither a
// pass nor a FAIL and is invisible in a batch run, and a probe made of
// timeouts is unusually good at producing exactly that.
type dialResult func(t *testing.T) (net.Conn, error)

// timedOut is what a DROPped packet looks like once the per-attempt deadline
// fires.
func timedOut(*testing.T) (net.Conn, error) { return nil, context.DeadlineExceeded }

// refused is a TCP RST, wrapped the way the standard library wraps it, so
// client.Classify's errors.Is walk is what is under test rather than a bare
// errno this code would never see in production.
func refused(*testing.T) (net.Conn, error) {
	return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
}

// connected is a successful TCP connection: on the canary port, a listener
// where the configuration declares none.
func connected(t *testing.T) (net.Conn, error) {
	near, far := net.Pipe()
	t.Cleanup(func() { _ = far.Close() })
	return near, nil
}

func noRoute(*testing.T) (net.Conn, error) {
	return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.EHOSTUNREACH)}
}

// dialCall records what one connect was asked to do.
type dialCall struct {
	address string
	// at is when the connect was made and deadline what its context carried,
	// so a test can assert on the budget the probe handed it rather than on
	// how long the call actually took.
	at       time.Time
	deadline time.Time
	ok       bool
}

// budget is the per-attempt timeout this connect was given.
func (c dialCall) budget() time.Duration { return c.deadline.Sub(c.at) }

// scriptedDialer answers connects from a list, repeating the last entry once
// the list runs out.
type scriptedDialer struct {
	t       *testing.T
	mu      sync.Mutex
	results []dialResult
	calls   []dialCall
}

func newDialer(t *testing.T, results ...dialResult) *scriptedDialer {
	t.Helper()
	return &scriptedDialer{t: t, results: results}
}

func (d *scriptedDialer) dial(ctx context.Context, _, address string) (net.Conn, error) {
	d.mu.Lock()
	i := len(d.calls)
	deadline, ok := ctx.Deadline()
	d.calls = append(d.calls, dialCall{address: address, at: time.Now(), deadline: deadline, ok: ok})
	if i >= len(d.results) {
		i = len(d.results) - 1
	}
	if i < 0 {
		d.mu.Unlock()
		return nil, context.DeadlineExceeded
	}
	fn := d.results[i]
	d.mu.Unlock()
	return fn(d.t)
}

func (d *scriptedDialer) record() []dialCall {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]dialCall(nil), d.calls...)
}

// countingSender records every datagram it was asked to send.
type countingSender struct {
	mu   sync.Mutex
	to   []netip.AddrPort
	err  error
	sent int
}

func (s *countingSender) send(_ context.Context, to netip.AddrPort, _ []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent++
	s.to = append(s.to, to)
	return s.err
}

func (s *countingSender) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sent
}

// newProber wires a prober whose every timing bound is instant and whose
// clock advances by a fixed step per read, so Duration is deterministic and
// nothing waits.
func newProber(t *testing.T, d *scriptedDialer, s *countingSender) *probe.Prober {
	t.Helper()
	var ticks int
	base := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	return &probe.Prober{
		Builder:       client.Builder{Signer: mustSigner(t)},
		Host:          testHost(t),
		Counter:       client.NewCounter(t.TempDir() + "/counter.json"),
		Send:          s.send,
		Dial:          d.dial,
		Now:           func() time.Time { ticks++; return base.Add(time.Duration(ticks) * time.Second) },
		Sleep:         func(context.Context, time.Duration) error { return nil },
		ClosedTimeout: 2 * time.Second,
		OpenTimeout:   4 * time.Second,
		OpenAttempts:  2,
		Settle:        time.Millisecond,
	}
}
