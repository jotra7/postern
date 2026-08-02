//go:build !linux

package agent

import (
	"context"
	"net"
)

// postern targets Linux: the gate backend is nftables and the boot path is
// systemd. This file exists so the package builds, and its pure logic stays
// testable, on a developer's macOS machine — not so postern runs there.
//
// The consequence is deliberate and one-directional: without per-packet
// arrival data, every datagram is reported as NOT having arrived on the
// always-allow path. Validate refuses liveness on that basis, so a non-Linux
// build is a build that never transmits. Erring the other way would make a
// developer's laptop answer liveness probes for every packet it received.

func enablePathDetection(*net.UDPConn) error { return nil }

func (r *udpReceiver) Receive(ctx context.Context) (Datagram, error) {
	if err := ctx.Err(); err != nil {
		return Datagram{}, err
	}
	n, addr, err := r.conn.ReadFromUDPAddrPort(r.buf)
	if err != nil {
		return Datagram{}, err
	}
	payload := make([]byte, n)
	copy(payload, r.buf[:n])
	return Datagram{Payload: payload, Source: addr, OnAlwaysAllowPath: false, LocalPort: r.port}, nil
}
