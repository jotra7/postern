package agent

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/jotra7/postern/internal/spa"
)

// receiveBufferSize holds a full padded datagram (up to spa.MaxDatagram) with
// room to spare. The datagram is the sealed record plus a random amount of
// padding, and TrialOpen accepts a length in [DatagramSize, MaxDatagram] and
// slices off the record; the buffer must be big enough to read the whole
// padded packet, or a legitimately-padded datagram would be truncated below
// its real length. The extra headroom past MaxDatagram is what lets an
// oversized packet arrive larger than MaxDatagram and be rejected by the
// bounded-length check, rather than being silently truncated into range.
const receiveBufferSize = spa.MaxDatagram + 64

// udpReceiver is the production Receiver: one UDP socket on the SPA port.
//
// It reports, per datagram, whether the packet arrived on the always-allow
// interface. That fact cannot be recovered from the payload or the source
// address — an operator's address is the same address whichever path carried
// it — so it is read from the kernel's per-packet ancillary data. Validate
// binds liveness to that path (design section 5), and liveness is the one
// case where postern transmits at all, so getting this from the socket
// rather than inferring it is what keeps the reply from becoming a scanning
// oracle.
type udpReceiver struct {
	conn  *net.UDPConn
	iface string
	port  uint16 // the local port conn is bound to; stamped onto every Datagram

	mu      sync.Mutex
	ifIndex int // 0 means "not resolved yet"; the interface may appear later
	buf     []byte
	oob     []byte
}

// NewUDPReceiver binds the SPA port. alwaysAllowIface is the interface whose
// arrivals count as the always-allow path; it may legitimately not exist
// yet, which is why the index is resolved lazily rather than at bind time
// (the boot ruleset has the same property, which is why it matches on
// iifname rather than iif).
func NewUDPReceiver(port uint16, alwaysAllowIface string) (Receiver, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: int(port)})
	if err != nil {
		return nil, err
	}
	r := &udpReceiver{
		conn:  conn,
		iface: alwaysAllowIface,
		port:  port,
		buf:   make([]byte, receiveBufferSize),
		oob:   make([]byte, 1024),
	}
	if err := enablePathDetection(conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("agent: enable arrival-path detection: %w", err)
	}
	return r, nil
}

// Reply transmits to a source address. The daemon calls this only for a
// liveness pong on a packet that arrived on the always-allow path; nothing
// else in postern ever writes to the network. udpReceiver has exactly one
// socket, so fromPort is always that socket's own port and is not otherwise
// consulted; the parameter exists for symmetry with rotatingUDPReceiver,
// which has to pick a socket from several.
func (r *udpReceiver) Reply(_ context.Context, to netip.AddrPort, _ uint16, payload []byte) error {
	_, err := r.conn.WriteToUDPAddrPort(payload, to)
	return err
}

func (r *udpReceiver) Close() error { return r.conn.Close() }

// onAlwaysAllowPath compares a packet's arrival interface index against the
// configured interface. The index is re-resolved whenever it does not match,
// so an interface that appears after the agent started — the ordinary case
// for a mesh VPN — starts counting as the always-allow path without a
// restart, and an index reused by a different interface does not keep
// counting as one.
func (r *udpReceiver) onAlwaysAllowPath(ifIndex int) bool {
	if ifIndex == 0 || r.iface == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ifIndex == ifIndex {
		return true
	}
	iface, err := net.InterfaceByName(r.iface)
	if err != nil {
		return false
	}
	r.ifIndex = iface.Index
	return r.ifIndex == ifIndex
}
