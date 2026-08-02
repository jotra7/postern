package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/netip"
	"time"

	"github.com/jotra7/postern/internal/client"
	"github.com/jotra7/postern/internal/spa"
)

func init() {
	register(&command{
		name:    "confirm",
		usage:   "confirm <host> --revision N --nonce HEX",
		summary: "ratify one armed-but-unconfirmed configuration change",
		run:     runConfirm,
	})
}

// runConfirm sends the confirm action.
//
// Both --revision and --nonce are required and neither has a default. That
// is the whole security property of this command: a confirm carrying no
// arguments means "confirm whatever happens to be pending when this lands",
// which can ratify an unrelated future rollout the operator never approved
// (design section 5). The agent refuses an unbound confirm outright; the
// client must not be able to send one by omission either.
//
// Where the two values come from: the process that arms a new ruleset
// prepares the transaction first, learns the pair, and returns it to the
// operator BEFORE arming — so the pair travels over a channel the new rules
// have not yet had a chance to break. In fleet mode that channel is the
// heartbeat. In M1 standalone there is no deploy and no hub, so the pair
// reaches the operator on the terminal of the session that armed, which is
// safe for the same reason the runbook depends on elsewhere: boot.nft's
// input chain accepts established connections above every other rule, so an
// SSH session open before the arm survives it.
func runConfirm(ctx context.Context, e *env, args []string) error {
	fs := newFlagSet(e, "confirm", "confirm <host> --revision N --nonce HEX")
	var cf clientFlags
	cf.bind(fs)
	revision := fs.Uint64("revision", 0, "the pending_revision the agent reported when it prepared the transaction")
	nonceHex := fs.String("nonce", "", "the deployment_nonce the agent reported, 32 hex characters")
	// Arm-time liveness (design section 7, I5). A confirm makes an armed
	// configuration permanent, so by default it first proves the operator still
	// has a way back in over the always-allow path before ratifying it. --force
	// skips that, for an operator confirming from a spot without recovery-path
	// access; --via, --wait and --timeout tune the check the same way `postern
	// status` does, since it is the same check.
	force := fs.Bool("force", false,
		"confirm even if the always-allow recovery path does not prove healthy, or cannot be reached from "+
			"here. The dead-man timer still reverts a confirm that never lands, so this overrides only the "+
			"pre-check, not the safety net")
	via := fs.String("via", "",
		"run the liveness pre-check against this `ADDR` instead of the entry's always_allow_addr, for a "+
			"host whose always-allow address has moved since enrollment")
	wait := fs.Duration("wait", client.DefaultPongWait, "how long the liveness pre-check waits for the pong")
	timeout := fs.Duration("timeout", client.DefaultConnectTimeout, "timeout for the pre-check's recovery-service connect")
	// More than one datagram, unless told otherwise. See
	// client.DefaultActionSends: a confirm is one UDP packet, the SPA path
	// never answers, and a lost one costs an automatic revert ten minutes
	// later rather than an error the operator can see and retry.
	sends := fs.Int("sends", client.DefaultActionSends,
		"how many copies of the confirm datagram to send. A confirm is one UDP packet and UDP does not "+
			"guarantee delivery; the agent refuses a duplicate as a replay, so extra copies cost nothing "+
			"and a lost one costs an automatic revert")
	positional, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		fs.Usage()
		return usagef("confirm takes exactly one host")
	}
	// Both are required, and neither has a default. The nonce is the
	// unguessable half, so the security property rests on it — but a
	// silently-defaulted revision produces a confirm the agent refuses for a
	// reason the operator can never see, because the SPA path never replies.
	// A missing binding must fail here, on their terminal, or it fails
	// nowhere they can observe.
	if !flagWasSet(fs, "revision") {
		return usagef("--revision is required: it is half the binding, and a confirm carrying the " +
			"wrong revision is refused by the agent in silence — the SPA path never replies, so a " +
			"defaulted value fails where you cannot see it")
	}
	if *nonceHex == "" {
		return usagef("--nonce is required: an unbound confirm ratifies whatever happens to be pending " +
			"when it lands, which is the wrong thing by construction")
	}
	nonce, err := decodeNonce(*nonceHex)
	if err != nil {
		return usageError{err}
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
	b := client.Builder{Signer: signer}

	var viaAddr netip.Addr
	if *via != "" {
		viaAddr, err = netip.ParseAddr(*via)
		if err != nil {
			return usagef("--via %q is not an IP literal: %v", *via, err)
		}
	}
	if err := confirmLivenessPrecheck(ctx, e, b, host, viaAddr, *wait, *timeout, *force); err != nil {
		return err
	}

	rep, err := client.SendAction(ctx, client.ActionOptions{Builder: b, Host: host, Sends: *sends},
		func(nowMS uint64) (*spa.Request, error) {
			return b.Confirm(host, *revision, nonce, nowMS)
		})
	if err != nil {
		return err
	}
	// The count is printed, not implied. An operator reading this during a
	// confirmation window has to be able to tell "postern sent three and one
	// of them should have landed" from "postern sent one and it did not".
	outf(e.stdout, "confirm sent to %s (%s, revision %d, nonce %s), %d of %d datagrams\n",
		rep.To, host.Name, *revision, *nonceHex, rep.Sent, rep.Attempted)
	// There is nothing to wait for: the SPA path never replies, and a confirm
	// is not a gate, so no port becomes reachable to prove it landed. What
	// proves it landed is that the dead-man timer does not revert.
	outln(e.stdout, indent(
		"the SPA path never answers, so this reports only that the datagrams left. The confirmation "+
			"landed if the agent's dead-man timer does not revert the change."))
	return nil
}

// confirmLivenessPrecheck is design section 7's I5 enforced on the operator's
// side: a confirm makes an armed configuration permanent, so before ratifying
// one it proves the operator still has a way back in -- the authenticated
// liveness pong over the always-allow path and a connect to the recovery
// service. A fail-closed configuration confirmed without that is the lockout
// this project exists to prevent, and the confirm is the last point an operator
// can still stop it: the dead-man timer reverts an unconfirmed arm, but a
// confirm is exactly the signal that turns that safety net off.
//
// It is skipped in two cases, both deliberate. --force is the operator
// confirming from a spot the always-allow path does not reach (the split-plane
// case: the confirm goes over the public path, and the recovery path is a
// separate network); the dead-man timer still covers a confirm that never
// lands, so this overrides only the pre-check. And a host with no always-allow
// address to reach -- none recorded and no --via given -- has no recovery path
// to prove, the single-path host the design allows to arm anyway.
func confirmLivenessPrecheck(ctx context.Context, e *env, b client.Builder, host *client.Host, via netip.Addr, wait, timeout time.Duration, force bool) error {
	if force {
		return nil
	}
	if !host.AlwaysAllowAddr.IsValid() && !via.IsValid() {
		return nil
	}
	rep, err := client.Status(ctx, client.StatusOptions{
		Builder:        b,
		Host:           host,
		Via:            via,
		PongWait:       wait,
		ConnectTimeout: timeout,
	})
	if err != nil {
		return err
	}
	if rep.Healthy() {
		return nil
	}
	// printStatus writes the FAIL lines; this writes what to do about them. A
	// failedError is not reprinted by main (it treats the command as having
	// diagnosed itself), so the actionable line has to be emitted here or the
	// operator never sees the --force escape hatch.
	printStatus(e, host, rep)
	outln(e.stderr, indent(wrap(fmt.Sprintf(
		"refusing to confirm %s: the always-allow recovery path did not prove healthy, so ratifying this "+
			"configuration could lock you out. Fix the path (run `postern status %s`), pass --via if its "+
			"always-allow address has moved, or --force to confirm anyway -- the dead-man timer still "+
			"reverts a confirm that never lands.", host.Name, host.Name), 76)))
	return failedError{fmt.Errorf("the always-allow recovery path to %s is not healthy", host.Name)}
}

func decodeNonce(s string) ([16]byte, error) {
	var out [16]byte
	raw, err := hex.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("--nonce %q is not hex: %w", s, err)
	}
	if len(raw) != 16 {
		return out, fmt.Errorf("--nonce is %d bytes, want 16 (32 hex characters)", len(raw))
	}
	copy(out[:], raw)
	return out, nil
}
