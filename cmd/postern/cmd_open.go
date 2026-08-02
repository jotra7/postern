package main

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/jotra7/postern/internal/client"
)

func init() {
	register(&command{
		name:    "open",
		usage:   "open <host> [service] [flags]",
		summary: "knock a host and confirm the service became reachable",
		run:     runOpen,
	})
}

func runOpen(ctx context.Context, e *env, args []string) error {
	fs := newFlagSet(e, "open", "open <host> [service] [flags]")
	var cf clientFlags
	cf.bind(fs)
	ttl := fs.Duration("ttl", 0, "how long to hold the gate open (0 uses the host's configured default)")
	sourceCIDR := fs.String("source-cidr", "",
		"assert this source prefix instead of letting the agent use the address it observed; "+
			"the fix for a carrier NAT that egresses UDP and TCP from different pools")
	carrier := fs.String("carrier", string(client.CarrierUDP),
		"how to deliver the knock: `udp` (one datagram) or `http` (the same packet POSTed to the host's "+
			"spa_http_port, for networks that block outbound UDP). Explicit on purpose: there is no automatic "+
			"fallback, so a broken UDP path is something you find out about here rather than somewhere with neither")
	timeout := fs.Duration("timeout", client.DefaultConnectTimeout, "per-attempt timeout for the confirmation connect")
	attempts := fs.Int("attempts", client.DefaultConnectAttempts, "confirmation connect attempts")
	preTimeout := fs.Duration("pre-timeout", client.DefaultPreConnectTimeout,
		"how long to spend connecting once BEFORE the knock, which is what lets a successful open say the "+
			"port was shut and then opened rather than only that it answers; 0 skips it, and it is capped "+
			"at --timeout either way")
	positional, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positional) < 1 || len(positional) > 2 {
		fs.Usage()
		return usagef("open takes a host and an optional service")
	}

	cfg, err := cf.load(e)
	if err != nil {
		return err
	}
	host, err := cfg.Host(positional[0])
	if err != nil {
		return usageError{err}
	}
	var service string
	if len(positional) == 2 {
		service = positional[1]
	}
	if service == "" {
		// The recovery service is what an operator would actually use to fix
		// this host, which is what they almost always want when they type
		// `postern open web-01` with nothing after it.
		service = host.RecoveryService
	}
	if service == "" {
		return usagef("host %q has no recovery_service, so `open` has no default service — name one", host.Name)
	}

	var asserted *netip.Prefix
	if *sourceCIDR != "" {
		p, perr := netip.ParsePrefix(*sourceCIDR)
		if perr != nil {
			return usagef("--source-cidr %q: %v", *sourceCIDR, perr)
		}
		asserted = &p
	}

	// Parsed before the key is unlocked: a misspelled --carrier is a usage
	// error, and asking for a passphrase before reporting one is a poor trade
	// during an outage.
	chosen, err := client.ParseCarrier(*carrier)
	if err != nil {
		return usagef("--carrier: %v", err)
	}

	signer, err := cf.signer(e, cfg)
	if err != nil {
		return err
	}

	// Zero is how a flag says "none" and how OpenOptions says "the default",
	// so the two conventions are reconciled here rather than by making one of
	// them surprising to its own audience.
	pre := *preTimeout
	if pre <= 0 {
		pre = -1
	}

	rep, err := client.Open(ctx, client.OpenOptions{
		Carrier:           chosen,
		Builder:           client.Builder{Signer: signer},
		Host:              host,
		Service:           service,
		TTL:               *ttl,
		SourceCIDR:        asserted,
		Counter:           client.NewCounter(cfg.CounterFilePath()),
		ConnectTimeout:    *timeout,
		ConnectAttempts:   *attempts,
		PreConnectTimeout: pre,
	})
	printOpenReport(e, host, rep)
	if err != nil {
		return err
	}
	if rep.Result.Outcome != client.Connected {
		return failedError{fmt.Errorf("%s: %s", rep.Result.Outcome, rep.Advice.Summary)}
	}
	return nil
}

// printOpenReport is the product. An operator reads this at the moment they
// are locked out, so the outcome comes first, the reasoning second, and the
// next command to run last — including, on the CGNAT case, a command they
// can paste.
func printOpenReport(e *env, host *client.Host, rep client.OpenReport) {
	if line := beforeLine(rep); line != "" {
		outln(e.stdout, line)
	}
	if rep.KnockAddr.IsValid() {
		verb := "sent"
		if !rep.Sent.Delivered {
			verb = "NOT sent"
		}
		outf(e.stdout, "knock %s to %s over %s (%s/%s, ttl %s)\n",
			verb, rep.KnockAddr, rep.Carrier, rep.Sent.Host, rep.Sent.Service, rep.Sent.TTL)
	}
	if rep.Advice.Summary == "" {
		return
	}
	outf(e.stdout, "%s: %s\n", rep.Result.Outcome, rep.Advice.Summary)
	if rep.Advice.Detail != "" {
		outln(e.stdout, indent(wrap(rep.Advice.Detail, 76)))
	}
	if rep.Advice.Hint != "" {
		outf(e.stdout, "  next: %s\n", rep.Advice.Hint)
	}
	if rep.Advice.Verify != "" {
		// Printed for the outcomes that cannot establish whether postern did
		// anything, which includes the one that looks most like success.
		outf(e.stdout, "  verify: %s\n", rep.Advice.Verify)
	}
	if rep.Result.Outcome == client.Connected && host.SSH.Host != "" {
		outf(e.stdout, "  then: %s\n", sshCommand(host))
	}
}

// beforeLine reports the connect made before the knock, and prints first
// because it happened first. An operator reading three lines in the order they
// occurred can see the change for themselves, which is a stronger thing to
// hand them than a verdict they have to take on trust.
func beforeLine(rep client.OpenReport) string {
	target := rep.Sent.Addr
	if !target.IsValid() {
		return ""
	}
	switch rep.Sent.Prior {
	case client.PriorShut:
		return fmt.Sprintf("before the knock, %s did not answer", target)
	case client.PriorAnswering:
		return fmt.Sprintf("before the knock, %s already answered (%s)", target, rep.Before.Outcome)
	case client.PriorUnclear:
		return fmt.Sprintf("before the knock, %s could not be measured (%s)", target, rep.Before.Outcome)
	default:
		return ""
	}
}

func sshCommand(h *client.Host) string {
	target := h.SSH.Host
	if h.SSH.User != "" {
		target = h.SSH.User + "@" + target
	}
	if h.SSH.Port != 0 && h.SSH.Port != 22 {
		return fmt.Sprintf("ssh -p %d %s", h.SSH.Port, target)
	}
	return "ssh " + target
}

// wrap breaks a diagnosis at word boundaries. The timeout explanation is
// four sentences long on purpose; an unwrapped four-sentence line in a
// terminal is a paragraph nobody reads.
func wrap(s string, width int) string {
	var out, line []rune
	col := 0
	for _, word := range splitWords(s) {
		if col > 0 && col+1+len([]rune(word)) > width {
			out = append(out, line...)
			out = append(out, '\n')
			line = nil
			col = 0
		}
		if col > 0 {
			line = append(line, ' ')
			col++
		}
		line = append(line, []rune(word)...)
		col += len([]rune(word))
	}
	return string(append(out, line...))
}

func splitWords(s string) []string {
	var words []string
	cur := ""
	for _, r := range s {
		if r == ' ' || r == '\n' || r == '\t' {
			if cur != "" {
				words = append(words, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		words = append(words, cur)
	}
	return words
}
