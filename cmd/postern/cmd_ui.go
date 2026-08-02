package main

import (
	"context"

	"github.com/jotra7/postern/internal/client"
	"github.com/jotra7/postern/internal/console"
)

func init() {
	register(&command{
		name:    "ui",
		usage:   "ui [--listen ADDR] [--inventory FILE] [--bundles DIR] [--hub URL] [--sign-key FILE]",
		summary: "optional local web console for fleet management (loopback only)",
		run:     runUI,
	})
}

// runUI is a thin flag.FlagSet over console.Serve: every decision about what
// the console does — where it may bind, what a state-changing request has to
// carry, what it will not do at all — lives in internal/console, not here.
//
// The console is optional in the strongest sense. postern works with this
// command never run, everything it offers is doable with `postern open`,
// `postern confirm`, `postern status` and `postern sign`, and nothing on a
// host or in the SPA path imports the package behind it.
func runUI(ctx context.Context, e *env, args []string) error {
	usage := "ui [--listen ADDR] [--inventory FILE] [--bundles DIR] [--hub URL] [--sign-key FILE]"
	fs := newFlagSet(e, "ui", usage)
	var cf clientFlags
	cf.bindForExistingKey(fs)
	listen := fs.String("listen", console.DefaultListen,
		"address to bind, which must be loopback: this console holds an unlocked operator key and "+
			"can knock every host in the fleet, and there is no authentication in front of it")
	inventory := fs.String("inventory", "", "path to the fleet inventory YAML")
	bundles := fs.String("bundles", "", "directory `postern sign` writes bundles and index.json into")
	hub := fs.String("hub", "", "a hub's public listener, e.g. https://hub.example:8443; empty asks no hub anything")
	signKey := fs.String("sign-key", "", "the bundle-signing operator's key file; required to sign from here")
	idle := fs.Duration("idle-timeout", console.DefaultIdleTimeout,
		"how long an unlocked key is held with nothing happening")
	positional, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 0 {
		fs.Usage()
		return usagef("ui takes no positional arguments")
	}

	// The client config is optional: a console pointed at an inventory alone
	// can still show the fleet and sign bundles. It just cannot knock, and it
	// says so on the page rather than refusing to start — an operator whose
	// laptop is not enrolled against these hosts still has a use for the
	// fleet view.
	//
	// The reason it could not be loaded is printed rather than swallowed. A
	// missing config and a malformed one both land here, and an operator who
	// mistyped a host entry should not discover it as a console that silently
	// offers no knock button.
	var cfg *client.Config
	if loaded, lerr := cf.load(e); lerr == nil {
		cfg = loaded
	} else {
		outf(e.stderr, "postern ui: no usable client config, so nothing can be knocked from here: %v\n", lerr)
	}

	origin, wait, err := console.Serve(ctx, console.Config{
		Listen:          *listen,
		InventoryPath:   *inventory,
		OutDir:          *bundles,
		HubURL:          *hub,
		ClientConfig:    cfg,
		OperatorKeyFile: cf.keyFile,
		SignerKeyFile:   *signKey,
		IdleTimeout:     *idle,
	})
	if err != nil {
		return usageError{err}
	}
	outf(e.stderr, "postern ui: %s\n", origin)
	outln(e.stderr, indent(wrap(
		"Loopback only, and no key is unlocked until you unlock one on the page. This console offers "+
			"no disarm on any route and loads no recovery key, so it cannot strip a host whatever key "+
			"is unlocked. Run `postern disarm` from a terminal to do that.", 76)))
	return wait()
}
