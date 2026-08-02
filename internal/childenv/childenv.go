// Package childenv builds the environment postern hands to the processes it
// spawns.
//
// It removes exactly one variable, NOTIFY_SOCKET. systemd sets that on a
// Type=notify service so the service can send sd_notify(3) state strings back;
// a child that inherits it can send them too, and systemd reads the sender's
// PID off the socket rather than believing anything in the datagram. On
// posternd that shows up as a log line per child:
//
//	Got notification message from PID N, but reception only permitted for main PID M
//
// The daemon's own READY=1 and WATCHDOG=1 come from the main PID and are
// accepted, so the noise is only noise. The reason to remove the variable
// anyway is what the obvious alternative would cost. Silencing those lines
// with NotifyAccess=all would make systemd accept state strings from every
// descendant, and then a stray WATCHDOG=1 from a systemctl, an nft, or an
// operator's gate script would pet the watchdog on behalf of a packet loop
// that had wedged, disabling the detection the watchdog exists to provide.
// posternd keeps NotifyAccess=main (see gate.RenderPosterndUnit) and takes the
// socket away from its children instead.
//
// The gate script backend is the case that motivates a package rather than a
// line of code at one call site: that child is an executable postern does not
// control, running as root, and handing it a socket that talks to systemd
// about postern is a capability nothing in the script contract asks for.
package childenv

import (
	"os"
	"os/exec"
	"strings"
)

// notifySocketPrefix matches the NOTIFY_SOCKET entry of an environment block
// and nothing else. The trailing "=" is why: os/exec entries are always
// NAME=VALUE, so a bare "NOTIFY_SOCKET" prefix would also swallow a variable
// that merely starts with the name.
const notifySocketPrefix = "NOTIFY_SOCKET="

// Sanitize replaces cmd.Env with the environment the child should see: the
// entries cmd.Env already holds, or this process's own environment when it
// holds none, minus NOTIFY_SOCKET.
//
// It assigns cmd.Env even when there was nothing to remove. A nil cmd.Env is
// os/exec's "inherit this process's environment" default, so leaving it nil
// on the theory that nothing needed filtering would reinstate exactly the
// inheritance this is here to stop.
func Sanitize(cmd *exec.Cmd) {
	env := cmd.Env
	if env == nil {
		env = os.Environ()
	}
	kept := make([]string, 0, len(env))
	for _, entry := range env {
		if strings.HasPrefix(entry, notifySocketPrefix) {
			continue
		}
		kept = append(kept, entry)
	}
	cmd.Env = kept
}
