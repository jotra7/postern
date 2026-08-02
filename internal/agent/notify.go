package agent

import (
	"net"
	"os"
	"strings"
)

// SdNotify sends one sd_notify(3) state string to systemd. It is a no-op
// when NOTIFY_SOCKET is unset, so the same daemon runs unchanged outside
// systemd — in the test container, or under an operator debugging by hand.
//
// The protocol is a single datagram to an AF_UNIX socket, which is why this
// needs no library: postern sends exactly two states, READY=1 once and
// WATCHDOG=1 from each successful beat.
func SdNotify(state string) error {
	path := os.Getenv("NOTIFY_SOCKET")
	if path == "" {
		return nil
	}
	// A leading "@" names an abstract socket, which Go expresses as a
	// leading NUL byte.
	if strings.HasPrefix(path, "@") {
		path = "\x00" + path[1:]
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_, err = conn.Write([]byte(state))
	return err
}
