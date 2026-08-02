package agent

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
)

// multiReceiver merges several carriers into the one Receiver the daemon
// consumes.
//
// This is the structural answer to "both carriers must reach the same
// validation code". The alternative — a second receive loop, or a Validate
// call inside the HTTP handler — would mean two places that decide what a
// packet authorizes, and the second one would drift. Here the HTTP carrier's
// output is a Datagram, the UDP carrier's output is a Datagram, and from
// Daemon.receiveLoop downward there is exactly one path: one Validate, one
// replay store, one gate, one set of counters. A carrier cannot be given
// special treatment because by the time the daemon sees a packet there is
// nothing left that says which carrier brought it.
type multiReceiver struct {
	// primary is where Reply goes. Postern transmits exactly once — the
	// liveness pong — and only for a packet that arrived on the always-allow
	// path, which only the UDP carrier ever reports. Routing every reply to
	// the primary rather than back to the carrier a packet came from is
	// therefore not a simplification: it is the same "the one place postern
	// writes to the network is a single auditable method" property the
	// Receiver interface was built for.
	primary   Receiver
	receivers []Receiver

	out chan Datagram
	// errc carries the first failure from any carrier.
	errc chan error

	stop      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// newMultiReceiver starts one pump goroutine per carrier. primary must be one
// of receivers; it is the one Reply is routed to.
func newMultiReceiver(primary Receiver, receivers ...Receiver) *multiReceiver {
	m := &multiReceiver{
		primary:   primary,
		receivers: receivers,
		out:       make(chan Datagram),
		errc:      make(chan error, len(receivers)),
		stop:      make(chan struct{}),
	}
	for _, rcv := range receivers {
		m.wg.Add(1)
		go m.pump(rcv)
	}
	return m
}

// pump moves one carrier's datagrams onto the shared channel. It holds no
// state and makes no decisions, the same way Daemon.receiveLoop does not:
// everything that can wedge stays in the daemon's single select.
func (m *multiReceiver) pump(rcv Receiver) {
	defer m.wg.Done()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-m.stop
		cancel()
	}()
	for {
		dg, err := rcv.Receive(ctx)
		if err != nil {
			select {
			case <-m.stop:
				// A closed carrier's own error. Reporting it would turn an
				// ordinary shutdown into a receive failure the daemon maps to a
				// non-zero exit.
			case m.errc <- err:
			}
			return
		}
		select {
		case m.out <- dg:
		case <-m.stop:
			return
		}
	}
}

func (m *multiReceiver) Receive(ctx context.Context) (Datagram, error) {
	select {
	case dg := <-m.out:
		return dg, nil
	case err := <-m.errc:
		return Datagram{}, err
	case <-ctx.Done():
		return Datagram{}, ctx.Err()
	case <-m.stop:
		return Datagram{}, net.ErrClosed
	}
}

func (m *multiReceiver) Reply(ctx context.Context, to netip.AddrPort, fromPort uint16, payload []byte) error {
	return m.primary.Reply(ctx, to, fromPort, payload)
}

// Close closes every carrier and waits for its pump to finish, so a stopped
// daemon leaves no goroutine holding a socket.
func (m *multiReceiver) Close() error {
	var errs []error
	m.closeOnce.Do(func() {
		close(m.stop)
		for _, rcv := range m.receivers {
			if err := rcv.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		m.wg.Wait()
	})
	return errors.Join(errs...)
}

var _ Receiver = (*multiReceiver)(nil)
