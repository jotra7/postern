package main

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/jotra7/postern/internal/client"
)

func init() {
	register(&command{
		name:    "status",
		usage:   "status <host> [flags]",
		summary: "prove the always-allow path still works, on both ports that matter",
		run:     runStatus,
	})
}

// runStatus performs design section 7's two arm-time assertions: the
// authenticated liveness ping over the always-allow path, and a TCP connect
// to the recovery service over that same path.
//
// Two assertions rather than one because a pong proves mesh routing, a live
// agent, and successful authentication — on UDP 62201. Mesh ACLs are
// routinely written per port, so a rule permitting UDP 62201 while dropping
// TCP 22 leaves the pong green with no shell available, which is the false
// green this check exists to remove.
func runStatus(ctx context.Context, e *env, args []string) error {
	fs := newFlagSet(e, "status", "status <host> [flags]")
	var cf clientFlags
	cf.bind(fs)
	recovery := fs.String("recovery-service", "", "override the host's configured recovery_service")
	// The escape hatch for a host whose always-allow address has moved since
	// it was enrolled. Without it the only repair is re-running
	// init-standalone on the host, over a shell that `status` was being run to
	// establish the existence of; a mesh re-address turns that into a check
	// that cannot be run until the thing it checks is already known to work.
	//
	// `open` has no equivalent and should not grow one: a knock sent somewhere
	// unintended opens a gate for whoever is there, while a status sent
	// somewhere unintended costs one wrong answer on a laptop.
	via := fs.String("via", "",
		"reach the host at this `ADDR` instead of the always_allow_addr its entry records. An IP "+
			"literal, for a host whose always-allow address has changed since enrollment. Both "+
			"assertions follow it, because a pong and a connect that took different routes prove "+
			"nothing about either")
	wait := fs.Duration("wait", client.DefaultPongWait, "how long to wait for the liveness pong")
	timeout := fs.Duration("timeout", client.DefaultConnectTimeout, "timeout for the recovery-service connect")
	positional, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		fs.Usage()
		return usagef("status takes exactly one host")
	}
	var viaAddr netip.Addr
	if *via != "" {
		viaAddr, err = netip.ParseAddr(*via)
		if err != nil {
			return usagef("--via %q is not an IP literal: %v", *via, err)
		}
	}

	cfg, err := cf.load(e)
	if err != nil {
		return err
	}
	host, err := cfg.Host(positional[0])
	if err != nil {
		return usageError{err}
	}
	signer, err := cf.signer(e, cfg)
	if err != nil {
		return err
	}

	rep, err := client.Status(ctx, client.StatusOptions{
		Builder:         client.Builder{Signer: signer},
		Host:            host,
		RecoveryService: *recovery,
		Via:             viaAddr,
		PongWait:        *wait,
		ConnectTimeout:  *timeout,
	})
	if err != nil {
		return err
	}
	printStatus(e, host, rep)
	if !rep.Healthy() {
		return failedError{fmt.Errorf("the always-allow path to %s did not prove healthy", host.Name)}
	}
	return nil
}

func printStatus(e *env, host *client.Host, rep client.StatusReport) {
	// The address, not knock_addr, because on a host where the two differ the
	// header would otherwise name an address nothing in this report was sent
	// to. Same reasoning for the port on a rotation host: pingOnce sent the
	// pong request to the current window's port, not SPAPort's fixed
	// default, so the header names that one — approximated by recomputing it
	// now rather than threading the exact value Status used back out through
	// StatusReport, which is close enough for a line whose job is orienting
	// a human, not authenticating anything.
	pingPort := host.SPAPort()
	if port, ok := host.CurrentKnockPort(time.Now().Unix()); ok {
		pingPort = port
	}
	outf(e.stdout, "host %s (%s)\n", host.Name, netip.AddrPortFrom(rep.Addr, pingPort))
	if rep.Pong {
		outf(e.stdout, "  liveness  ok    signed pong in %s, host clock skew %s\n", rep.PongRTT, rep.ClockSkew)
	} else {
		outf(e.stdout, "  liveness  FAIL  %v\n", rep.PongErr)
		if rep.Addr == host.KnockAddr && !host.AlwaysAllowAddr.IsValid() {
			// The failure the field exists to end. This entry records no
			// always-allow address, so both assertions fell back to
			// knock_addr; on a host whose two addresses differ, that is the
			// public one, a ping there arrives on the public interface, and
			// the agent refuses it without replying. What an operator sees is
			// an i/o timeout against an agent that is armed, healthy, and
			// answering everybody else.
			outln(e.stdout, indent(indent(wrap(
				"this entry records no always_allow_addr, so the check fell back to knock_addr. A pong "+
					"is emitted only for a ping that arrived on the host's always-allow interface and a "+
					"ping that arrives anywhere else is refused in silence, so on a host reached publicly "+
					"at one address and over a mesh at another this reads as a timeout however healthy "+
					"the agent is. Re-enroll the host, or pass --via with its address on that interface.",
				76))))
		}
	}

	switch {
	case rep.RecoveryService == "":
		// Not a failure: a host with no fail-closed service has nothing to
		// recover into, and arming is where an unset recovery_service is
		// refused.
		outln(e.stdout, "  recovery  --    no recovery_service configured for this host")
	case rep.Recovery.Outcome == client.Connected:
		// The address, because --via and the knock_addr fallback both mean this
		// connect does not always go where the words "the always-allow path"
		// would promise, and a green line naming a path it did not take is the
		// kind of false green this whole command exists to remove.
		outf(e.stdout, "  recovery  ok    %s reachable at %s\n", rep.RecoveryService, rep.Addr)
	default:
		outf(e.stdout, "  recovery  FAIL  %s: %s\n", rep.RecoveryService, rep.Recovery.Outcome)
		outln(e.stdout, indent(indent(
			"a pong proves the mesh routes UDP to the agent; it says nothing about the port you would "+
				"actually recover with. Mesh ACLs are routinely written per port.")))
	}

	// Standalone mode offers no continuous liveness, and saying so is the
	// point (design section 7): an implied continuous check that silently
	// does not exist is the precise failure this design was built around.
	outln(e.stdout, "  continuous liveness: not offered in standalone mode — this is a point-in-time check")
}
