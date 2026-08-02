//go:build linux

package agent

import (
	"context"
	"encoding/binary"
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// enablePathDetection asks the kernel to attach the arrival interface to
// every datagram. Without it there is no way to distinguish a packet that
// came in over the mesh from one that came in over the public internet, and
// the liveness binding design section 5 requires would have nothing to
// stand on.
func enablePathDetection(conn *net.UDPConn) error {
	sc, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var v4Err, v6Err error
	ctrlErr := sc.Control(func(fd uintptr) {
		// The uintptr -> int conversion is what x/sys/unix's own API demands
		// for a descriptor; a Go socket's fd is a small non-negative int
		// widened to uintptr by the SyscallConn contract, so it cannot wrap.
		sock := int(fd) //nolint:gosec // G115: see comment above
		v4Err = unix.SetsockoptInt(sock, unix.IPPROTO_IP, unix.IP_PKTINFO, 1)
		v6Err = unix.SetsockoptInt(sock, unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1)
	})
	if ctrlErr != nil {
		return ctrlErr
	}
	// A dual-stack socket carries both; a v4-only or v6-only one carries the
	// option it understands and refuses the other. Only a socket that
	// accepted neither is unable to report an arrival path at all.
	if v4Err != nil && v6Err != nil {
		return errors.Join(v4Err, v6Err)
	}
	return nil
}

func (r *udpReceiver) Receive(ctx context.Context) (Datagram, error) {
	if err := ctx.Err(); err != nil {
		return Datagram{}, err
	}
	n, oobn, _, addr, err := r.conn.ReadMsgUDPAddrPort(r.buf, r.oob)
	if err != nil {
		return Datagram{}, err
	}

	// Copied, not aliased: r.buf is reused on the next read, and a Datagram
	// that outlived one iteration would otherwise be silently rewritten.
	payload := make([]byte, n)
	copy(payload, r.buf[:n])

	return Datagram{
		Payload:           payload,
		Source:            addr,
		OnAlwaysAllowPath: r.onAlwaysAllowPath(arrivalInterface(r.oob[:oobn])),
		LocalPort:         r.port,
	}, nil
}

// arrivalInterface pulls the receiving interface index out of a datagram's
// ancillary data. It returns 0 when the kernel supplied none, which
// onAlwaysAllowPath treats as "not the always-allow path" — the safe
// direction, since the only thing that fact unlocks is the single reply
// postern ever sends.
func arrivalInterface(oob []byte) int {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return 0
	}
	for _, m := range msgs {
		switch {
		case m.Header.Level == unix.IPPROTO_IP && m.Header.Type == unix.IP_PKTINFO:
			// struct in_pktinfo { int ipi_ifindex; ... }
			if len(m.Data) >= 4 {
				// ipi_ifindex is a signed int in the kernel struct; the
				// uint32 -> int32 round trip preserves its bits, and an
				// interface index is never negative in practice.
				return int(int32(binary.NativeEndian.Uint32(m.Data[0:4]))) //nolint:gosec // G115: see comment above
			}
		case m.Header.Level == unix.IPPROTO_IPV6 && m.Header.Type == unix.IPV6_PKTINFO:
			// struct in6_pktinfo { struct in6_addr ipi6_addr; unsigned int ipi6_ifindex; }
			if len(m.Data) >= 20 {
				return int(binary.NativeEndian.Uint32(m.Data[16:20]))
			}
		}
	}
	return 0
}
