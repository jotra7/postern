package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
)

// PortRebinder is implemented by receivers whose live port set changes over
// time. Only the rotating-knock-port carrier does; the fixed-port carrier
// never needs to move, which is why bindCarriers hands back a nil
// PortRebinder in fixed mode rather than growing a no-op implementation.
type PortRebinder interface {
	Receiver
	// Rebind opens a socket for every port in ports that is not already
	// live, and closes every live socket whose port is not in ports. A port
	// present both before and after the call keeps its existing socket: it
	// is not reopened, and a datagram already queued on it is not dropped.
	Rebind(ctx context.Context, ports []uint16) error
}

// rotatingSocket is one live port's socket, plus the signal its pump uses to
// tell a deliberate close (Rebind dropping the port, or the receiver
// stopping entirely) from a genuine socket failure worth reporting.
type rotatingSocket struct {
	recv    *udpReceiver
	closing chan struct{}
}

// rotatingUDPReceiver is the PortRebinder for rotating-knock-port mode: one
// UDP socket per port in the current window's live set, all pumped onto a
// single channel the same way multiReceiver merges several carriers into
// one. Rebind swaps the live set for a new window in place, so a port that
// survives the swap keeps its socket rather than being torn down and
// rebuilt.
type rotatingUDPReceiver struct {
	alwaysAllowIface string

	mu      sync.Mutex
	sockets map[uint16]*rotatingSocket

	out  chan Datagram
	errc chan error

	stop      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// newRotatingUDPReceiver binds one socket per port in ports and starts
// pumping every one of them onto a shared channel. It is the initial bind
// for rotation mode; bindCarriers calls it with the first window's live set.
func newRotatingUDPReceiver(ports []uint16, alwaysAllowIface string) (*rotatingUDPReceiver, error) {
	r := &rotatingUDPReceiver{
		alwaysAllowIface: alwaysAllowIface,
		sockets:          make(map[uint16]*rotatingSocket),
		out:              make(chan Datagram),
		errc:             make(chan error, 8),
		stop:             make(chan struct{}),
	}
	for _, port := range ports {
		if _, ok := r.sockets[port]; ok {
			continue // the live set may repeat a port at a window edge
		}
		if err := r.openLocked(port); err != nil {
			_ = r.Close()
			return nil, err
		}
	}
	return r, nil
}

// openLocked binds port and starts its pump. Every caller either holds r.mu
// (Rebind) or is still inside single-goroutine construction
// (newRotatingUDPReceiver), so the map write is always safe.
func (r *rotatingUDPReceiver) openLocked(port uint16) error {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: int(port)})
	if err != nil {
		return fmt.Errorf("agent: bind rotating spa port %d: %w", port, err)
	}
	if err := enablePathDetection(conn); err != nil {
		_ = conn.Close()
		return fmt.Errorf("agent: enable arrival-path detection on port %d: %w", port, err)
	}
	entry := &rotatingSocket{
		recv: &udpReceiver{
			conn:  conn,
			iface: r.alwaysAllowIface,
			port:  port,
			buf:   make([]byte, receiveBufferSize),
			oob:   make([]byte, 1024),
		},
		closing: make(chan struct{}),
	}
	r.sockets[port] = entry
	r.wg.Add(1)
	go r.pump(entry)
	return nil
}

// closeLocked closes port's socket and signals its pump that the closure was
// deliberate. Every caller holds r.mu.
func (r *rotatingUDPReceiver) closeLocked(port uint16) error {
	entry, ok := r.sockets[port]
	if !ok {
		return nil
	}
	delete(r.sockets, port)
	close(entry.closing)
	return entry.recv.Close()
}

// pump moves one socket's datagrams onto the shared channel, exactly the
// shape multiReceiver.pump uses: it holds no state and makes no decisions,
// so everything that can wedge stays in the daemon's single select. What
// unblocks a pump stuck in a read is the same thing that unblocks
// multiReceiver's: closing the underlying socket, not context cancellation —
// so closeLocked closes entry.closing before it closes the conn, giving the
// pump a way to tell that closure apart from a genuine read failure.
func (r *rotatingUDPReceiver) pump(entry *rotatingSocket) {
	defer r.wg.Done()
	for {
		dg, err := entry.recv.Receive(context.Background())
		if err != nil {
			select {
			case <-entry.closing:
				// This port was dropped by Rebind, or the whole receiver is
				// closing. Either way the error is the socket closing on
				// purpose, not a failure worth reporting.
				return
			case <-r.stop:
				return
			default:
			}
			select {
			case r.errc <- err:
			case <-entry.closing:
			case <-r.stop:
			}
			return
		}
		select {
		case r.out <- dg:
		case <-entry.closing:
			return
		case <-r.stop:
			return
		}
	}
}

// Receive selects over out, errc, ctx.Done() and stop exactly as
// multiReceiver.Receive does.
func (r *rotatingUDPReceiver) Receive(ctx context.Context) (Datagram, error) {
	select {
	case dg := <-r.out:
		return dg, nil
	case err := <-r.errc:
		return Datagram{}, err
	case <-ctx.Done():
		return Datagram{}, ctx.Err()
	case <-r.stop:
		return Datagram{}, net.ErrClosed
	}
}

// Reply writes through the socket bound to fromPort — the port the ping this
// pong answers actually arrived on. That is not a convenience: the client's
// reply socket is connected to the exact port it pinged, so it accepts a UDP
// datagram only from that same port, and a pong sent from any other live
// socket would just be silently dropped on arrival. If fromPort is no longer
// live — the window rotated between Receive and this call, a narrow race —
// there is no socket that would reach the client either, so this returns an
// error rather than falling back to a different one.
func (r *rotatingUDPReceiver) Reply(ctx context.Context, to netip.AddrPort, fromPort uint16, payload []byte) error {
	r.mu.Lock()
	entry, ok := r.sockets[fromPort]
	r.mu.Unlock()
	if !ok {
		return fmt.Errorf("agent: no live reply socket for arrival port %d", fromPort)
	}
	return entry.recv.Reply(ctx, to, fromPort, payload)
}

// Rebind diffs ports against the live set: it closes every socket whose port
// left the set, opens a socket for every port that is new, and leaves a port
// present in both untouched.
//
// Rebind refuses once Close has run. Without that guard, a Rebind landing
// after (or racing) Close would still open sockets and start pump goroutines
// that nothing left alive would ever close: Close's own cleanup only closes
// what is in r.sockets at the moment it holds r.mu, and a Rebind call that
// starts after Close has already finished never happens under that lock at
// the same time Close's closing loop runs.
func (r *rotatingUDPReceiver) Rebind(ctx context.Context, ports []uint16) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	want := make(map[uint16]struct{}, len(ports))
	for _, p := range ports {
		want[p] = struct{}{}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	select {
	case <-r.stop:
		return net.ErrClosed
	default:
	}

	for port := range r.sockets {
		if _, ok := want[port]; !ok {
			if err := r.closeLocked(port); err != nil {
				return err
			}
		}
	}

	var errs []error
	for port := range want {
		if _, ok := r.sockets[port]; ok {
			continue // already live: keep its socket, drop nothing in flight
		}
		if err := r.openLocked(port); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Close closes every live socket and waits for its pump to finish, so a
// stopped receiver leaves no goroutine holding a socket.
func (r *rotatingUDPReceiver) Close() error {
	var errs []error
	r.closeOnce.Do(func() {
		close(r.stop)
		r.mu.Lock()
		for port := range r.sockets {
			if err := r.closeLocked(port); err != nil {
				errs = append(errs, err)
			}
		}
		r.mu.Unlock()
		r.wg.Wait()
	})
	return errors.Join(errs...)
}

var _ Receiver = (*rotatingUDPReceiver)(nil)
var _ PortRebinder = (*rotatingUDPReceiver)(nil)
