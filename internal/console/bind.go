package console

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

// DefaultListen is where `postern ui` listens when the operator says nothing.
const DefaultListen = "127.0.0.1:8177"

// The console drives a fleet: it knocks gates, ratifies configuration
// changes, and signs the bundles a hub serves. internal/metrics/bind.go
// already refuses a wildcard for the agent's exposition endpoint, on the
// reasoning that ":9873" is what everyone types and a root daemon's gate
// state must not land on a public interface by accident. The same reasoning
// applies here and applies harder, because this endpoint does not report
// state — it changes it.
//
// So the rule is narrower than the agent's. The agent's endpoint may bind an
// address on the always-allow interface, because a scraper elsewhere on the
// mesh has a legitimate reason to reach it. Nothing has a legitimate reason
// to reach this console except the machine it runs on, and there is no
// authentication in front of it to make a remote bind survivable. Three
// things are refused:
//
//   - a wildcard bind (0.0.0.0, ::, or an empty host in an explicit
//     address), which is the mistake that actually happens;
//   - a hostname, because resolving one at bind time would move the decision
//     off this machine and into whatever DNS answers;
//   - any literal address that is not loopback.
//
// There is deliberately no override. An override would have to say out loud
// what it exposes, and what it exposes is an unauthenticated fleet-control
// endpoint — which is not a thing to put behind a flag whose warning an
// operator reads once. An operator who wants this console from another
// machine already has the tool for it: an SSH port forward, where the
// authentication lives in SSH where it belongs.
var (
	// ErrWildcardBind means the requested bind would have listened on every
	// interface.
	ErrWildcardBind = errors.New("console: refusing to bind the console to a wildcard address")

	// ErrNotLoopback means the requested address is a real address that is
	// not loopback.
	ErrNotLoopback = errors.New("console: refusing to bind the console to a non-loopback address")
)

// ResolveBind turns a --listen value into the address the console may
// actually bind, or refuses it.
//
// spec is "host:port" or ":port". An omitted host means loopback, which is
// the only thing it could mean here.
func ResolveBind(spec string) (netip.AddrPort, error) {
	host, portStr, err := net.SplitHostPort(spec)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("console: %q is not a host:port address: %w", spec, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("console: %q has no valid port: %w", spec, err)
	}
	if host == "" {
		return netip.AddrPortFrom(loopback4(), uint16(port)), nil //nolint:gosec // G115: ParseUint above is bounded to 16 bits
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		// Deliberately not resolved. A name would move the decision about
		// where an unauthenticated fleet-control endpoint listens out of this
		// machine's own configuration and into DNS.
		return netip.AddrPort{}, fmt.Errorf("console: %q is not a literal IP address; the console is not "+
			"bound by name: %w", host, err)
	}
	addr = addr.Unmap()
	if addr.IsUnspecified() {
		return netip.AddrPort{}, fmt.Errorf("%w: %q", ErrWildcardBind, spec)
	}
	if !addr.IsLoopback() {
		return netip.AddrPort{}, fmt.Errorf("%w: %s. This console holds an unlocked operator key and can "+
			"knock every host in the fleet; reach it from elsewhere with an SSH port forward, where the "+
			"authentication lives in SSH", ErrNotLoopback, addr)
	}
	return netip.AddrPortFrom(addr, uint16(port)), nil //nolint:gosec // G115: ParseUint above is bounded to 16 bits
}

// Listen binds a resolved address and returns the listener.
//
// The check after the bind is not redundant with ResolveBind. ResolveBind
// decides; this observes what the kernel actually handed back, and it is the
// only check that would still catch a future caller who built an AddrPort
// some other way. A console that ended up on 0.0.0.0 is an unauthenticated
// fleet-control endpoint on every network the machine is on, so the socket
// is closed rather than served.
func Listen(addr netip.AddrPort) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr.String())
	if err != nil {
		return nil, err
	}
	got, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		_ = ln.Close()
		return nil, fmt.Errorf("%w: the socket bound to %s", ErrNotLoopback, ln.Addr())
	}
	bound, ok := netip.AddrFromSlice(got.IP)
	if !ok || bound.Unmap().IsUnspecified() {
		_ = ln.Close()
		return nil, fmt.Errorf("%w: the socket bound to %s", ErrWildcardBind, ln.Addr())
	}
	if !bound.Unmap().IsLoopback() {
		_ = ln.Close()
		return nil, fmt.Errorf("%w: the socket bound to %s", ErrNotLoopback, ln.Addr())
	}
	return ln, nil
}

func loopback4() netip.Addr { return netip.AddrFrom4([4]byte{127, 0, 0, 1}) }
