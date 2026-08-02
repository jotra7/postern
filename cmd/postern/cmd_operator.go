package main

import (
	"context"
	"io"
)

// This file is half of #28's split of the old combined `enroll`: the half
// that only ever touches the operator's own identity. See cmd_host.go for
// the other half, and cmd_enroll.go for the deprecated alias that still does
// both at once.

func init() {
	register(&command{
		name:    "operator",
		usage:   "operator <verb> [flags]",
		summary: "manage the operator identity (init)",
		run:     runOperator,
	})
}

func runOperator(_ context.Context, e *env, args []string) error {
	if len(args) == 0 {
		printOperatorUsage(e.stderr)
		return usagef("operator needs a verb: init")
	}
	verb, rest := args[0], args[1:]
	switch verb {
	case "init":
		return runOperatorInit(e, rest)
	case "-h", "--help", "help":
		printOperatorUsage(e.stdout)
		return nil
	default:
		printOperatorUsage(e.stderr)
		return usagef("postern operator: unknown verb %q", verb)
	}
}

func printOperatorUsage(w io.Writer) {
	outln(w, "usage: postern operator <verb> [flags]")
	outln(w)
	outln(w, "verbs:")
	outf(w, "  %-6s %s\n", "init", "mint (or load) this operator's own identity")
	outln(w)
	outln(w, "run `postern operator <verb> -h` for a verb's own flags")
}

// runOperatorInit mints the operator's identity if there is not one yet, or
// reports the one that already exists. It never touches a host: registering
// one is `host add`'s job, and needing an identity before that job can run is
// exactly the point of the split — see cmd_host.go's loadOperatorContext.
//
// It does not write a client config. A config with no hosts does not pass
// ParseConfig, and should not: one is written only once a host joins it,
// which is what makes running this before any host exists, and re-running it
// after, both safe.
func runOperatorInit(e *env, args []string) error {
	usage := "operator init [--operator NAME] [--no-passphrase] [flags]"
	fs := newFlagSet(e, "operator init", usage)
	var cf clientFlags
	cf.bind(fs)
	operator := fs.String("operator", "", "operator name for a new identity (default: the config's, else $USER)")

	positional, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positional) > 0 {
		fs.Usage()
		return usagef("operator init takes no positional arguments")
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
	// See runEnroll's identical comment: the key is the fact once it already
	// existed and the config had to be invented to describe it.
	if !created && configIsNew && signer.Public().Name != cfg.Operator {
		cfg.Operator = signer.Public().Name
	}
	if signer.Public().Name != cfg.Operator {
		return usagef("key file %s holds identity %q but %s names operator %q; operator init will not "+
			"write a config whose every later command would be refused", keyPath, signer.Public().Name, path, cfg.Operator)
	}

	if created {
		outf(e.stderr, "generated operator identity %q at %s\n", cfg.Operator, keyPath)
		if cf.noPassphrase {
			// Loud, because --no-passphrase is a real choice with a real cost
			// and the operator will not see this file again until an outage.
			outf(e.stderr, "WARNING: %s is stored unencrypted. Anything running as this user can "+
				"sign knocks as %q against every host you enroll.\n", keyPath, cfg.Operator)
		}
	} else {
		outf(e.stderr, "operator identity %q already exists at %s\n", cfg.Operator, keyPath)
	}
	printEnrollInstructions(e, cfg.Operator, signer.Public(), "")
	return nil
}
