//go:build !linux

package main

import "context"

// The host-side subcommands exist on every platform so that `postern help`
// and `postern agent` on a laptop say what is wrong rather than "unknown
// subcommand", which reads like a broken build. They refuse rather than
// pretending: the gate backend is nftables and there is no second one.
func init() {
	for _, c := range []struct{ name, usage, summary string }{
		{"agent", "agent --config /etc/postern/postern.yaml [flags]",
			"run posternd: bind the SPA port, validate packets, open gates (Linux, root)"},
		{"gate-teardown", "gate-teardown [--config PATH] [flags]",
			"remove postern_open and empty every fail-closed gate set (Linux, root)"},
		{"gate-flush", "gate-flush [--config PATH] [flags]",
			"empty every fail-closed gate set, leaving its drop rules standing (Linux, root)"},
	} {
		name := c.name
		register(&command{
			name:    c.name,
			usage:   c.usage,
			summary: c.summary,
			run: func(context.Context, *env, []string) error {
				return usagef("%s runs only on Linux: postern's gate backend is nftables. "+
					"The client half (open, status, confirm, disarm, enroll) runs here.", name)
			},
		})
	}
}
