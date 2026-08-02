package metrics

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"
)

// The agent runs as root, holds the fleet's gate state, and is the one
// process that is supposed to still be reachable when everything else is
// down. Design section 8 therefore constrains where its exposition endpoint
// may live: "the agent's endpoint binds to the always-allow interface or
// localhost."
//
// That is a security requirement, not a preference, so it is enforced here as
// a refusal rather than documented as a convention. Three things are refused:
//
//   - a wildcard bind (0.0.0.0, ::, or an empty host in an explicit address),
//     which is how a metrics endpoint accidentally lands on a public
//     interface;
//   - a hostname, because resolving one at bind time would move the decision
//     off this host and into DNS;
//   - any literal address that is neither loopback nor currently configured on
//     the always-allow interface.
//
// Everything else is allowed, and the caller is expected to pass the resolved
// AddrPort straight to net.Listen — Listen below does exactly that and then
// checks the socket it actually got, because the refusal above is only worth
// as much as the thing that finally binds.

var (
	// ErrWildcardBind means the requested bind would have listened on every
	// interface. It is separate from ErrBindNotPermitted because it is the
	// mistake that actually happens: ":9873" is what everyone types.
	ErrWildcardBind = errors.New("metrics: refusing to bind a /metrics endpoint to a wildcard address")

	// ErrBindNotPermitted means the requested address is a real address that
	// is neither loopback nor on the always-allow interface.
	ErrBindNotPermitted = errors.New("metrics: refusing to bind the agent's /metrics endpoint to an address " +
		"that is neither loopback nor on the always-allow interface")
)

// InterfaceAddrs reports the addresses currently configured on a named
// interface. It is a function so the bind rules are testable without a host
// that happens to have the right interfaces on it.
type InterfaceAddrs func(name string) ([]netip.Addr, error)

// SystemInterfaceAddrs is the production lookup.
func SystemInterfaceAddrs(name string) ([]netip.Addr, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		addr, ok := netip.AddrFromSlice(ipn.IP)
		if !ok {
			continue
		}
		out = append(out, addr.Unmap())
	}
	return out, nil
}

// ResolveBind turns an operator's --metrics-listen value into the address the
// endpoint may actually bind to, or refuses it.
//
// spec is "host:port" or ":port". A host is optional and, when omitted, is
// filled in from the always-allow interface: the first routable address it
// carries, falling back to loopback when it carries none. The fallback is
// deliberate — pre-arm already reports an always-allow interface with no
// address as degraded and arms anyway, and an agent that refused to start
// because its monitoring endpoint had nowhere to live would turn a monitoring
// problem into a lockout. Loopback is always in bounds.
//
// A link-local address is never chosen automatically. Binding one requires a
// zone, a scraper has to know that zone too, and getting it wrong is a
// startup failure on the break-glass daemon; loopback is the better default.
// An operator who genuinely wants it can still name it explicitly.
func ResolveBind(spec, alwaysAllowIface string, lookup InterfaceAddrs) (netip.AddrPort, error) {
	addr, port, err := parseBindSpec(spec)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if !addr.IsValid() {
		return netip.AddrPortFrom(defaultBindAddr(alwaysAllowIface, lookup), port), nil
	}
	if !addr.IsLoopback() {
		if err := onInterface(addr, alwaysAllowIface, lookup); err != nil {
			return netip.AddrPort{}, err
		}
	}
	return netip.AddrPortFrom(addr, port), nil
}

// CheckBindSpec applies the half of the bind rules that can be answered
// without the host the endpoint will run on: the address parses, it is a
// literal rather than a name, and it is not a wildcard.
//
// It exists so enrollment can refuse a bad --metrics-listen while the
// operator still has a working way in and nothing has been written, which is
// where this project already puts its other enrollment-time refusals. The
// membership half — is this address actually on the always-allow interface —
// deliberately stays at agent startup: a config generated for another host
// cannot answer it, and guessing would either block a correct enrollment or
// wave through an incorrect one.
//
// An empty host ("​:9873") passes: it means "the always-allow interface,
// falling back to loopback", which is resolved on the host at startup.
func CheckBindSpec(spec string) error {
	_, _, err := parseBindSpec(spec)
	return err
}

// parseBindSpec returns the literal address the spec names — invalid when the
// host part was omitted — and its port.
func parseBindSpec(spec string) (netip.Addr, uint16, error) {
	host, portStr, err := net.SplitHostPort(spec)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("metrics: %q is not a host:port address: %w", spec, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("metrics: %q has no valid port: %w", spec, err)
	}
	if host == "" {
		//nolint:gosec // G115: ParseUint above is bounded to 16 bits.
		return netip.Addr{}, uint16(port), nil
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		// Deliberately not resolved. A hostname would move the decision about
		// which interface a root daemon's exposition endpoint lands on out of
		// this host's configuration and into whatever DNS answers at boot.
		return netip.Addr{}, 0, fmt.Errorf("metrics: %q is not a literal IP address; postern's /metrics "+
			"endpoint is not bound by name: %w", host, err)
	}
	addr = addr.Unmap()
	if addr.IsUnspecified() {
		return netip.Addr{}, 0, fmt.Errorf("%w: %q", ErrWildcardBind, spec)
	}
	//nolint:gosec // G115: ParseUint above is bounded to 16 bits.
	return addr, uint16(port), nil
}

func onInterface(addr netip.Addr, iface string, lookup InterfaceAddrs) error {
	if iface == "" || lookup == nil {
		return fmt.Errorf("%w: %s, and no always-allow interface is configured to permit it", ErrBindNotPermitted, addr)
	}
	addrs, err := lookup(iface)
	if err != nil {
		return fmt.Errorf("%w: %s: always-allow interface %q could not be read: %v",
			ErrBindNotPermitted, addr, iface, err)
	}
	for _, have := range addrs {
		if have.Unmap() == addr {
			return nil
		}
	}
	return fmt.Errorf("%w: %s is not on always-allow interface %q", ErrBindNotPermitted, addr, iface)
}

// FirstRoutableAddr is the address postern names when it has to choose one of
// an interface's addresses on the operator's behalf: the first the kernel
// reports that is neither loopback, unspecified, nor link-local. ok is false
// when the interface cannot be read or carries no such address, which is a
// state the caller has to answer for rather than a value it can substitute
// for.
//
// A link-local address is never chosen. Binding or knocking one requires a
// zone, whoever is on the other end has to know that zone too, and getting it
// wrong is a failure on the break-glass path. An operator who genuinely wants
// it can still name it explicitly.
//
// Exported because `postern init-standalone` records the always-allow
// interface's address in the client host entry that `postern status` later
// pings, and this package resolves the same interface's address for the
// agent's /metrics bind. Two rules would be two answers about one interface,
// and an operator reading `--metrics-listen :9873` beside their own host entry
// would have no way to tell which of them was lying.
func FirstRoutableAddr(iface string, lookup InterfaceAddrs) (netip.Addr, bool) {
	if iface == "" || lookup == nil {
		return netip.Addr{}, false
	}
	addrs, err := lookup(iface)
	if err != nil {
		return netip.Addr{}, false
	}
	for _, a := range addrs {
		a = a.Unmap()
		if a.IsLoopback() || a.IsUnspecified() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() {
			continue
		}
		return a, true
	}
	return netip.Addr{}, false
}

// defaultBindAddr picks the address an unqualified ":port" means.
func defaultBindAddr(iface string, lookup InterfaceAddrs) netip.Addr {
	if addr, ok := FirstRoutableAddr(iface, lookup); ok {
		return addr
	}
	return netip.AddrFrom4([4]byte{127, 0, 0, 1})
}

// Listen binds the resolved address and returns the listener.
//
// The IsUnspecified check after the bind is not redundant with ResolveBind.
// ResolveBind decides; this observes what the kernel actually handed back,
// and it is the only check that would still catch a future caller who built
// an AddrPort some other way. A metrics endpoint that ended up on 0.0.0.0
// publishes a root daemon's gate state to every network the host is on, so
// the socket is closed rather than served.
func Listen(addr netip.AddrPort) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr.String())
	if err != nil {
		return nil, err
	}
	got, ok := ln.Addr().(*net.TCPAddr)
	if !ok || got.IP.IsUnspecified() {
		_ = ln.Close()
		return nil, fmt.Errorf("%w: the socket bound to %s", ErrWildcardBind, ln.Addr())
	}
	return ln, nil
}

// ResolveProbeBind is the bind rule for `postern probe --metrics-listen`.
//
// It is deliberately not ResolveBind. The probe runs on an operator's laptop
// or a monitoring box, which has no always-allow interface to bind to and no
// gate state to leak, so the membership half of the agent's rule has nothing
// to test against. What survives is the half that is about the operator's
// mistake rather than about the host: a wildcard and a hostname are still
// refused, because the probe's exposition says which hosts are unreachable
// right now — which is a shopping list — and because resolving a name at bind
// time would move the decision into DNS either way.
//
// An omitted host means loopback. The agent's ":port" means "the always-allow
// interface, falling back to loopback"; here there is no interface to prefer,
// and a probe whose metrics an operator wants scraped from elsewhere names
// the address.
func ResolveProbeBind(spec string) (netip.AddrPort, error) {
	addr, port, err := parseBindSpec(spec)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if !addr.IsValid() {
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), port), nil
	}
	return netip.AddrPortFrom(addr, port), nil
}

// Route is one extra path a caller wants on its exposition listener beside
// /metrics. Pattern is handed to http.ServeMux unchanged, so a caller that
// writes "GET /beats" gets the method restriction too.
type Route struct {
	Pattern string
	Handler http.Handler
}

// Serve runs an exposition endpoint on ln until Shutdown is called on the
// returned server. It serves /metrics, plus whatever routes the caller names
// in extra, and nothing else; every other path is a 404, so the endpoint
// offers no other surface to probe.
//
// It takes a handler rather than a *Recorder because the probe serves a
// Canary's registry and the agent serves a Recorder's, and the two are
// different objects for the reason spelled out on Canary: the probe is not on
// the host.
//
// extra is how a caller puts an operator-only route on the listener /metrics
// is already restricted to, rather than standing up a second server with a
// second set of bind rules and timeouts to keep in step with these. The hub's
// per-host heartbeat freshness document is the one use today, and the reason
// it lives here rather than beside the bundle fetch is that a listener an
// operator reaches and a listener the internet reaches are not the same
// listener.
func Serve(ln net.Listener, h http.Handler, extra ...Route) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", h)
	for _, r := range extra {
		mux.Handle(r.Pattern, r.Handler)
	}
	srv := &http.Server{
		Handler: mux,
		// A scrape is small and local. These bounds exist so a stuck or
		// hostile scraper cannot pin file descriptors on the daemon that has
		// to survive to be useful.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	return srv
}
