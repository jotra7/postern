package console_test

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/jotra7/postern/internal/console"
)

func TestConsole_ResolveBind_RefusesIPv4Wildcard(t *testing.T) {
	_, err := console.ResolveBind("0.0.0.0:8177")
	if !errors.Is(err, console.ErrWildcardBind) {
		t.Fatalf("ResolveBind(0.0.0.0) error = %v, want ErrWildcardBind: an unauthenticated endpoint that "+
			"can knock every host in the fleet must not land on every interface the machine has", err)
	}
}

func TestConsole_ResolveBind_RefusesIPv6Wildcard(t *testing.T) {
	_, err := console.ResolveBind("[::]:8177")
	if !errors.Is(err, console.ErrWildcardBind) {
		t.Fatalf("ResolveBind([::]) error = %v, want ErrWildcardBind", err)
	}
}

func TestConsole_ResolveBind_RefusesANonLoopbackLiteral(t *testing.T) {
	// A real, specific, routable address. It is not a wildcard, so only the
	// loopback rule can catch it.
	_, err := console.ResolveBind("203.0.113.9:8177")
	if !errors.Is(err, console.ErrNotLoopback) {
		t.Fatalf("ResolveBind(203.0.113.9) error = %v, want ErrNotLoopback", err)
	}
}

func TestConsole_ResolveBind_RefusesAHostname(t *testing.T) {
	got, err := console.ResolveBind("console.example.com:8177")
	if err == nil {
		t.Fatalf("ResolveBind(hostname) = %v, want an error: resolving a name would move the decision "+
			"about where this listens out of the machine's own configuration and into DNS", got)
	}
	if errors.Is(err, console.ErrWildcardBind) || errors.Is(err, console.ErrNotLoopback) {
		t.Fatalf("ResolveBind(hostname) error = %v, want the not-a-literal refusal; a name must be "+
			"refused for being a name, not incidentally", err)
	}
}

func TestConsole_ResolveBind_EmptyHostMeansLoopback(t *testing.T) {
	got, err := console.ResolveBind(":8177")
	if err != nil {
		t.Fatalf("ResolveBind(:8177) = %v, want loopback", err)
	}
	if !got.Addr().IsLoopback() || got.Port() != 8177 {
		t.Fatalf("ResolveBind(:8177) = %s, want a loopback address on port 8177", got)
	}
}

func TestConsole_ResolveBind_AcceptsIPv6Loopback(t *testing.T) {
	got, err := console.ResolveBind("[::1]:8177")
	if err != nil {
		t.Fatalf("ResolveBind([::1]) = %v, want acceptance", err)
	}
	if !got.Addr().IsLoopback() {
		t.Fatalf("ResolveBind([::1]) = %s, want a loopback address", got)
	}
}

func TestConsole_Listen_ClosesASocketThatIsNotLoopback(t *testing.T) {
	// ResolveBind is bypassed on purpose. Listen's check is not redundant
	// with it: it observes what the kernel actually handed back, and it is
	// the only check that would still catch a caller who built an AddrPort
	// some other way.
	ln, err := console.Listen(netip.AddrPortFrom(netip.AddrFrom4([4]byte{0, 0, 0, 0}), 0))
	if err == nil {
		_ = ln.Close()
		t.Fatal("Listen(0.0.0.0:0) returned a listener, want a refusal and a closed socket")
	}
	if !errors.Is(err, console.ErrWildcardBind) {
		t.Fatalf("Listen(0.0.0.0:0) error = %v, want ErrWildcardBind", err)
	}
}

func TestConsole_Listen_BindsLoopback(t *testing.T) {
	ln, err := console.Listen(netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 0))
	if err != nil {
		t.Fatalf("Listen(127.0.0.1:0) = %v, want a listener", err)
	}
	defer func() { _ = ln.Close() }()
	host, _, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort(%s): %v", ln.Addr(), err)
	}
	if addr, perr := netip.ParseAddr(host); perr != nil || !addr.IsLoopback() {
		t.Fatalf("Listen bound %s, want loopback", ln.Addr())
	}
}
