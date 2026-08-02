package main

import (
	"context"
)

func init() {
	register(&command{
		name:    "enroll",
		usage:   "enroll <host> [--from FILE|-] [flags]",
		summary: "deprecated: use `operator init` and `host add` instead",
		run:     runEnroll,
	})
}

// runEnroll is the deprecated, still-fully-functional original enroll
// command (#28). It used to be the only way to do any of this; it conflated
// minting the operator's own identity with registering a host, and made a
// destructive host re-key reachable as `-- --force` behind a verb that reads
// like ordinary setup. It is kept working, unchanged, so that nobody's
// runbook breaks silently — see operator init and host add for the split
// this now points at.
//
// There are two ways to reach the same end state, and they differ only in
// how the host entry gets here. With no --from it prints what the host
// needs and stops; with --from it consumes what somebody ran init-standalone
// by hand to produce.
func runEnroll(_ context.Context, e *env, args []string) error {
	outf(e.stderr, "postern enroll is deprecated: use `postern operator init` to mint an identity and "+
		"`postern host add` to register a host. To re-key an already-enrolled host, run "+
		"`postern init-standalone --force --go-live` on it. This run proceeds exactly as it always has.\n")

	usage := "enroll <host> [--from FILE|-] [flags]"
	fs := newFlagSet(e, "enroll", usage)
	var cf clientFlags
	cf.bind(fs)
	operator := fs.String("operator", "", "operator name for a new identity (default: the config's, else $USER)")
	from := fs.String("from", "", "read the host entry `postern init-standalone` printed (\"-\" for stdin)")

	positional, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positional) > 1 {
		fs.Usage()
		return usagef("enroll takes at most one host name")
	}
	var hostArg string
	if len(positional) == 1 {
		hostArg = positional[0]
	}

	path := cf.config
	if path == "" {
		if path, err = defaultConfigPath(e); err != nil {
			return usageError{err}
		}
	}
	cfg, configIsNew, err := loadOrCreateConfig(path, *operator, e)
	if err != nil {
		return err
	}

	keyPath := cf.keyFile
	if keyPath == "" {
		keyPath = cfg.KeyFilePath()
	}
	signer, created, err := loadOrCreateIdentity(e, &cf, keyPath, cfg.Operator)
	if err != nil {
		return err
	}
	// The two halves of enrollment are two commands, and the first one writes
	// only the key: a config with no hosts is not a valid config, so it is not
	// written until a host entry joins it. That leaves a window where the key
	// exists and the config does not, and the second command has to name the
	// operator from somewhere. Defaulting again — $USER, else "operator" —
	// silently produced a config naming an operator the key does not hold,
	// which every later command refuses with "key file holds identity X but
	// the config names operator Y". The key is the fact; adopt it.
	if !created && configIsNew && signer.Public().Name != cfg.Operator {
		cfg.Operator = signer.Public().Name
	}
	if signer.Public().Name != cfg.Operator {
		return usagef("key file %s holds identity %q but %s names operator %q; enroll will not write a "+
			"config whose every command would be refused", keyPath, signer.Public().Name, path, cfg.Operator)
	}
	if created {
		outf(e.stderr, "generated operator identity %q at %s\n", cfg.Operator, keyPath)
		if cf.noPassphrase {
			// Loud, because --no-passphrase is a real choice with a real cost
			// and the operator will not see this file again until an outage.
			outf(e.stderr, "WARNING: %s is stored unencrypted. Anything running as this user can "+
				"sign knocks as %q against every host you enroll.\n", keyPath, cfg.Operator)
		}
	}

	var entryData []byte
	switch {
	case *from != "":
		entryData, err = readEntryBytes(e, *from)
	default:
		printEnrollInstructions(e, cfg.Operator, signer.Public(), hostArg)
		return nil
	}
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
