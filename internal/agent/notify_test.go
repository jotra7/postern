package agent_test

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/agent"
)

// SdNotify is what makes WatchdogSec mean anything: Type=notify units are
// killed at TimeoutStartSec if READY=1 never arrives, and never restarted
// for a wedge if WATCHDOG=1 never stops arriving. Both halves of that are a
// datagram this function either sends or does not.
//
// The mutation this catches: writing to the socket path as a stream rather
// than a datagram, or forgetting to honour NOTIFY_SOCKET at all — the second
// is the one that matters, because it fails silently on a host with systemd
// and passes every test that does not look at the socket.
func TestAgent_SdNotify_SendsTheStateToNotifySocket(t *testing.T) {
	// Not t.TempDir(): a unix socket path is bounded by sun_path (104 bytes
	// on darwin, 108 on Linux), and t.TempDir() embeds the test's full name,
	// which overruns it. A short directory is a requirement here, not a
	// preference.
	dir, err := os.MkdirTemp("", "p")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "n.sock")

	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = conn.Close() }()

	t.Setenv("NOTIFY_SOCKET", sock)
	if err := agent.SdNotify("READY=1"); err != nil {
		t.Fatalf("SdNotify: %v", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 64)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := string(buf[:n]); got != "READY=1" {
		t.Fatalf("received %q, want %q", got, "READY=1")
	}
}

// Outside systemd — in the test container, or under an operator debugging by
// hand — NOTIFY_SOCKET is unset and notifying must be a no-op rather than an
// error. A daemon that treated it as an error would refuse to start
// anywhere systemd is not.
func TestAgent_SdNotify_IsANoOpWithoutNotifySocket(t *testing.T) {
	if err := os.Unsetenv("NOTIFY_SOCKET"); err != nil {
		t.Fatalf("unsetenv: %v", err)
	}
	if err := agent.SdNotify("WATCHDOG=1"); err != nil {
		t.Fatalf("SdNotify with no NOTIFY_SOCKET = %v, want nil", err)
	}
}
