package main

import (
	"context"
	"io"
)

// This file is the other half of #28's split of the old combined `enroll`:
// registering a host. See cmd_operator.go for minting the identity this
// assumes already exists, and cmd_enroll.go for the deprecated alias that
// still conflates all of it.

func init() {
	register(&command{
		name:    "host",
		usage:   "host <verb> [flags]",
		summary: "register a host (add)",
		run:     runHost,
	})
}

func runHost(ctx context.Context, e *env, args []string) error {
	if len(args) == 0 {
		printHostUsage(e.stderr)
		return usagef("host needs a verb: add")
	}
	verb, rest := args[0], args[1:]
	switch verb {
	case "add":
		return runHostAdd(ctx, e, rest)
	case "-h", "--help", "help":
		printHostUsage(e.stdout)
		return nil
	default:
		printHostUsage(e.stderr)
		return usagef("postern host: unknown verb %q", verb)
	}
}

func printHostUsage(w io.Writer) {
	outln(w, "usage: postern host <verb> [flags]")
	outln(w)
	outln(w, "verbs:")
	outf(w, "  %-6s %s\n", "add", "register a host, from a file init-standalone printed")
	outln(w)
	outln(w, "run `postern host <verb> -h` for a verb's own flags")
}

// runHostAdd registers a host from a file `postern init-standalone` printed.
// Unlike the old combined `enroll`, it never mints an operator identity —
// see loadOperatorContext.
func runHostAdd(_ context.Context, e *env, args []string) error {
	usage := "host add <name> --from FILE"
	fs := newFlagSet(e, "host add", usage)
	var cf clientFlags
	cf.bindForExistingKey(fs)
	from := fs.String("from", "", "read the host entry `postern init-standalone` printed (\"-\" for stdin)")

	positional, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positional) > 1 {
		fs.Usage()
		return usagef("host add takes at most one host name")
	}
	var hostArg string
	if len(positional) == 1 {
		hostArg = positional[0]
	}
	if *from == "" {
		return usagef("host add needs --from FILE; see `postern host add -h`")
	}

	path, cfg, _, err := loadOperatorContext(e, &cf)
	if err != nil {
		return err
	}

	entryData, err := readEntryBytes(e, *from)
	if err != nil {
		return err
	}

	entry, unknown, err := parseHostEntry(entryData)
	if err != nil {
		return err
	}
	warnUnknownEntryKeys(e, unknown)
	if hostArg != "" && entry.Name != hostArg {
		return usagef("the host entry names %q but the command names %q", entry.Name, hostArg)
	}
	if err := upsertHost(cfg, entry); err != nil {
		return err
	}
	if err := writeClientConfig(path, cfg); err != nil {
		return err
	}
	outf(e.stderr, "registered host %q in %s\n", entry.Name, path)
	noteAssertedSource(e, entry, cfg.Operator)
	outf(e.stderr, "next: postern status %s\n", entry.Name)
	return nil
}
