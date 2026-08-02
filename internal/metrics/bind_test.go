package metrics_test

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/jotra7/postern/internal/metrics"
)

const meshIface = "tailscale0"

// meshAddrs stands in for an always-allow interface carrying one routable
// address and one link-local one, which is what a mesh interface actually
// looks like.
func meshAddrs(t *testing.T) metrics.InterfaceAddrs {
	t.Helper()
	return func(name string) ([]netip.Addr, error) {
		if name != meshIface {
			return nil, errors.New("no such interface")
		}
		return []netip.Addr{
			netip.MustParseAddr("fe80::1"),
			netip.MustParseAddr("100.64.0.7"),
		}, nil
	}
}

func TestMetrics_ResolveBind_RefusesIPv4Wildcard(t *testing.T) {
	_, err := metrics.ResolveBind("0.0.0.0:9873", meshIface, meshAddrs(t))
	if !errors.Is(err, metrics.ErrWildcardBind) {
		t.Fatalf("ResolveBind(0.0.0.0) error = %v, want ErrWildcardBind: a root daemon's gate state must "+
			"never be published on every interface the host has", err)
	}
}

func TestMetrics_ResolveBind_RefusesIPv6Wildcard(t *testing.T) {
	_, err := metrics.ResolveBind("[::]:9873", meshIface, meshAddrs(t))
	if !errors.Is(err, metrics.ErrWildcardBind) {
		t.Fatalf("ResolveBind([::]) error = %v, want ErrWildcardBind", err)
	}
}

func TestMetrics_ResolveBind_RefusesAddressOffTheAlwaysAllowInterface(t *testing.T) {
	// A real, specific, public address. It is not a wildcard, so only the
	// membership check can catch it.
	_, err := metrics.ResolveBind("203.0.113.9:9873", meshIface, meshAddrs(t))
	if !errors.Is(err, metrics.ErrBindNotPermitted) {
		t.Fatalf("ResolveBind(203.0.113.9) error = %v, want ErrBindNotPermitted", err)
	}
}

func TestMetrics_ResolveBind_RefusesHostname(t *testing.T) {
	got, err := metrics.ResolveBind("metrics.example.com:9873", meshIface, meshAddrs(t))
	if err == nil {
		t.Fatalf("ResolveBind(hostname) = %v, want an error: resolving a name would move the decision "+
			"about where a root daemon listens into DNS", got)
	}
}

func TestMetrics_ResolveBind_AllowsLoopback(t *testing.T) {
	got, err := metrics.ResolveBind("127.0.0.1:9873", meshIface, meshAddrs(t))
	if err != nil {
		t.Fatalf("ResolveBind(loopback): %v", err)
	}
	if got.String() != "127.0.0.1:9873" {
		t.Fatalf("ResolveBind(loopback) = %s, want 127.0.0.1:9873", got)
	}
}

func TestMetrics_ResolveBind_AllowsAnAddressOnTheAlwaysAllowInterface(t *testing.T) {
	got, err := metrics.ResolveBind("100.64.0.7:9873", meshIface, meshAddrs(t))
	if err != nil {
		t.Fatalf("ResolveBind(mesh address): %v", err)
	}
	if got.String() != "100.64.0.7:9873" {
		t.Fatalf("ResolveBind(mesh address) = %s, want 100.64.0.7:9873", got)
	}
}

func TestMetrics_ResolveBind_EmptyHostPicksTheAlwaysAllowAddress(t *testing.T) {
	got, err := metrics.ResolveBind(":9873", meshIface, meshAddrs(t))
	if err != nil {
		t.Fatalf("ResolveBind(:9873): %v", err)
	}
	// Not fe80::1: a link-local address needs a zone the scraper would also
	// have to know, and getting it wrong is a startup failure on the daemon
	// that has to survive.
	if got.String() != "100.64.0.7:9873" {
		t.Fatalf("ResolveBind(:9873) = %s, want the interface's routable address 100.64.0.7:9873", got)
	}
}

func TestMetrics_ResolveBind_EmptyHostFallsBackToLoopbackWithNoRoutableAddress(t *testing.T) {
	onlyLinkLocal := func(string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("fe80::1")}, nil
	}
	got, err := metrics.ResolveBind(":9873", meshIface, onlyLinkLocal)
	if err != nil {
		t.Fatalf("ResolveBind(:9873) with no routable address: %v", err)
	}
	if got.String() != "127.0.0.1:9873" {
		t.Fatalf("ResolveBind(:9873) = %s, want the loopback fallback 127.0.0.1:9873", got)
	}
}

func TestMetrics_ResolveBind_EmptyHostFallsBackToLoopbackWhenTheInterfaceIsGone(t *testing.T) {
	missing := func(string) ([]netip.Addr, error) { return nil, errors.New("no such device") }
	got, err := metrics.ResolveBind(":9873", meshIface, missing)
	if err != nil {
		t.Fatalf("ResolveBind(:9873) with a missing interface: %v", err)
	}
	if got.String() != "127.0.0.1:9873" {
		t.Fatalf("ResolveBind(:9873) = %s, want 127.0.0.1:9873; a mesh interface that has not come back "+
			"yet must not become a wildcard bind", got)
	}
}

// TestMetrics_Listen_BindsSomethingSpecific is the socket-level half of the
// same claim: whatever ResolveBind decided, the thing that actually binds is
// checked, so a caller who built an AddrPort some other way still cannot
// serve a root daemon's gate state on every interface.
func TestMetrics_Listen_BindsSomethingSpecific(t *testing.T) {
	ln, err := metrics.Listen(netip.MustParseAddrPort("127.0.0.1:0"))
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	tcp, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("Listen bound a %T, want *net.TCPAddr", ln.Addr())
	}
	if tcp.IP.IsUnspecified() {
		t.Fatalf("Listen bound the wildcard address %s", tcp)
	}
	if !tcp.IP.IsLoopback() {
		t.Fatalf("Listen bound %s, want loopback", tcp)
	}
}

func TestMetrics_Listen_RefusesAWildcardAddrPort(t *testing.T) {
	ln, err := metrics.Listen(netip.MustParseAddrPort("0.0.0.0:0"))
	if err == nil {
		_ = ln.Close()
		t.Fatal("Listen(0.0.0.0:0) succeeded; the post-bind check must close a wildcard socket rather " +
			"than serve on it")
	}
	if !errors.Is(err, metrics.ErrWildcardBind) {
		t.Fatalf("Listen(0.0.0.0:0) error = %v, want ErrWildcardBind", err)
	}
}

// serveTest runs metrics.Serve on a loopback listener and returns its base
// URL. The handler stands in for a registry: what is under test here is the
// mux Serve builds, not what a scrape renders.
func serveTest(t *testing.T, extra ...metrics.Route) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("exposition"))
	})
	srv := metrics.Serve(ln, h, extra...)
	t.Cleanup(func() { _ = srv.Close() })
	return "http://" + ln.Addr().String()
}

func serveGet(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url) //nolint:gosec // test-controlled URL
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, string(body)
}

// An exposition listener with no extra routes carries /metrics and nothing
// else, which is what every caller that passes no extras is relying on.
func TestMetrics_Serve_ServesMetricsAndNoOtherPath(t *testing.T) {
	base := serveTest(t)

	if code, body := serveGet(t, base+"/metrics"); code != http.StatusOK || body != "exposition" {
		t.Fatalf("GET /metrics = %d %q, want 200 with the handler's body", code, body)
	}
	for _, path := range []string{"/", "/beats", "/debug/pprof/", "/metrics/extra"} {
		if code, _ := serveGet(t, base+path); code != http.StatusNotFound {
			t.Errorf("GET %s on an endpoint with no extra routes = %d, want 404", path, code)
		}
	}
}

// An extra route is reachable, and adding one does not turn the endpoint into
// a catch-all: everything still unnamed is a 404.
func TestMetrics_Serve_ServesAnExtraRouteBesideMetrics(t *testing.T) {
	base := serveTest(t, metrics.Route{
		Pattern: "GET /beats",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("beats"))
		}),
	})

	if code, body := serveGet(t, base+"/beats"); code != http.StatusOK || body != "beats" {
		t.Fatalf("GET /beats = %d %q, want 200 with the extra route's body", code, body)
	}
	if code, body := serveGet(t, base+"/metrics"); code != http.StatusOK || body != "exposition" {
		t.Fatalf("GET /metrics alongside an extra route = %d %q, want 200 with the handler's body", code, body)
	}
	if code, _ := serveGet(t, base+"/still-nothing"); code != http.StatusNotFound {
		t.Fatalf("GET /still-nothing = %d, want 404", code)
	}
}

// The pattern reaches http.ServeMux unmodified, so a caller that wrote a
// method into it gets the method restriction rather than a route that quietly
// answers anything.
func TestMetrics_Serve_ExtraRoutePatternKeepsItsMethodRestriction(t *testing.T) {
	base := serveTest(t, metrics.Route{
		Pattern: "GET /beats",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("beats"))
		}),
	})

	resp, err := http.Post(base+"/beats", "application/json", strings.NewReader("{}")) //nolint:gosec // test URL
	if err != nil {
		t.Fatalf("POST /beats: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST to a route registered as \"GET /beats\" = %d, want 405", resp.StatusCode)
	}
}
