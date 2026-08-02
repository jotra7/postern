package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/jotra7/postern/internal/agent"
	"github.com/jotra7/postern/internal/client"
	"github.com/jotra7/postern/internal/gate"
	"github.com/jotra7/postern/internal/spa"
)

func init() {
	register(&command{
		name:    "disarm",
		usage:   "disarm <host> | disarm --local [flags]",
		summary: "panic button: remove both tables, delete boot.nft, disable both units",
		run:     runDisarm,
	})
}

// Disarm has two forms and they fail in opposite circumstances, which is why
// both exist.
//
// `disarm <host>` sends one action packet. SPA packets are host-bound, so
// one packet disarms one host and a fleet-wide disarm is the client
// iterating (design section 7). It needs a live agent, which makes it
// unavailable in exactly the case fail-closed is designed for.
//
// `disarm --local` is that floor, run on the host itself: it is the manual
// recovery sequence from design section 7 as a command rather than five
// lines of runbook an operator types from a phone. It needs no agent.
func runDisarm(ctx context.Context, e *env, args []string) error {
	fs := newFlagSet(e, "disarm", "disarm <host> | disarm --local [flags]")
	var cf clientFlags
	cf.bind(fs)
	local := fs.Bool("local", false, "disarm this machine directly, without an agent (run as root on the host)")
	dir := fs.String("dir", defaultStateDirs.etc, "postern's configuration directory (--local only)")
	stateDir := fs.String("state-dir", defaultStateDirs.state, "postern's state directory (--local only)")
	nftPath := fs.String("nft", gate.DefaultNFTPath, "path to nft(8) (--local only)")
	systemctl := fs.String("systemctl", "systemctl", "path to systemctl (--local only)")
	positional, err := parseFlags(fs, args)
	if err != nil {
		return err
	}

	if *local {
		if len(positional) != 0 {
			fs.Usage()
			return usagef("--local disarms this machine and takes no host argument")
		}
		return runLocalDisarm(ctx, e, localDisarm{
			Boot:      agent.NFTRuleset{NFT: *nftPath, Table: gate.TableBoot},
			Open:      agent.NFTRuleset{NFT: *nftPath, Table: gate.TableOpen},
			BootUnit:  agent.SystemdUnit{Name: gate.BootUnitName, Systemctl: *systemctl},
			AgentUnit: agent.SystemdUnit{Name: gate.PosterndUnitName, Systemctl: *systemctl},
			Paths: agent.Paths{
				BootNFT: filepath.Join(*dir, "boot.nft"),
				State:   filepath.Join(*stateDir, "state.json"),
				Pending: filepath.Join(*stateDir, "pending.json"),
			},
		})
	}

	if len(positional) != 1 {
		fs.Usage()
		return usagef("disarm takes exactly one host, or --local")
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

	// Sent more than once, for the reason `postern confirm` is: this is one
	// UDP datagram, the SPA path never answers, and the panic button is the
	// last command an operator has any appetite for retrying by hand.
	rep, err := client.SendAction(ctx, client.ActionOptions{
		Builder: b, Host: host, Sends: client.DefaultActionSends,
	}, func(nowMS uint64) (*spa.Request, error) { return b.Disarm(host, nowMS) })
	if err != nil {
		return err
	}
	outf(e.stdout, "disarm sent to %s (%s), %d datagrams\n", rep.To, host.Name, rep.Sent)
	outln(e.stdout, indent(wrap(
		"This needs a live agent, so it is unavailable in the case fail-closed is designed for. "+
			"If the host is already unreachable, reach it over the always-allow path or the provider "+
			"console and run `postern disarm --local` there.", 76)))
	return nil
}

// localDisarm is the four artifacts a disarm must clear, each behind an
// interface so this wiring is testable without a firewall or an init system.
//
// All four, not three. A disarm that removes the live tables and leaves
// /etc/postern/boot.nft behind looks successful — the host is reachable, the
// operator moves on — and then re-locks at the next reboot, when the boot
// unit loads the ruleset nobody deleted. Leaving the unit enabled with the
// file gone is the same failure one step removed: the unit's
// ConditionPathExists makes it a no-op today and a live re-lock the moment
// anything writes that path again.
type localDisarm struct {
	// Boot is the persistent postern_boot table.
	Boot agent.LiveRuleset
	// Open is postern_open, the agent's own table. It has no on-disk form,
	// but a disarmed host must not keep the agent's drop rules standing.
	Open agent.LiveRuleset
	// BootUnit and AgentUnit are postern-boot.service and posternd.service.
	// Both, because a panic button that left the agent enabled would have the
	// host recreate postern_open at the next boot, and one that left the boot
	// unit enabled without the agent would re-lock it outright.
	BootUnit  agent.Unit
	AgentUnit agent.Unit
	Paths     agent.Paths
}

func runLocalDisarm(ctx context.Context, e *env, d localDisarm) error {
	var errs []error

	// agent.Transactions owns all but one: the postern_boot table, boot.nft,
	// both units' enabled states, and the recorded state file. Reused rather
	// than reimplemented, so the panic button and the agent's own disarm
	// cannot drift apart.
	txns := &agent.Transactions{
		Paths:     d.Paths,
		BootUnit:  d.BootUnit,
		AgentUnit: d.AgentUnit,
		Ruleset:   d.Boot,
	}
	if err := txns.Disarm(ctx); err != nil {
		errs = append(errs, err)
	}
	// Restoring an empty snapshot means "this table did not exist", which for
	// NFTRuleset is a delete.
	if d.Open != nil {
		if err := d.Open.Restore(ctx, nil); err != nil {
			errs = append(errs, fmt.Errorf("remove the live %s table: %w", gate.TableOpen, err))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}

	outln(e.stdout, "disarmed this machine:")
	outf(e.stdout, "  removed table inet %s and table inet %s\n", gate.TableOpen, gate.TableBoot)
	outf(e.stdout, "  deleted %s, %s and %s\n", d.Paths.BootNFT, d.Paths.State, d.Paths.Pending)
	outf(e.stdout, "  disabled %s and %s\n", gate.BootUnitName, gate.PosterndUnitName)
	outln(e.stdout, indent("posternd itself is still installed and may still be running; "+
		"`systemctl stop "+gate.PosterndUnitName+"` stops it from recreating "+gate.TableOpen+
		" before the next boot."))
	return nil
}

// defaultStateDirs are the conventional locations. They are variables rather
// than constants so a test can point a whole disarm at a temp directory.
var defaultStateDirs = struct{ etc, state string }{
	etc:   "/etc/postern",
	state: "/var/lib/postern",
}
