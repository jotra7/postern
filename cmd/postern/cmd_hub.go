package main

import (
	"context"

	"github.com/jotra7/postern/internal/hub"
)

func init() {
	register(&command{
		name:    "hub",
		usage:   "hub --store DIR --addr ADDR [--metrics-addr ADDR] [--tls-cert FILE --tls-key FILE]",
		summary: "serve sealed bundles from `postern sign` and ingest signed heartbeats",
		run:     runHub,
	})
}

// runHub is a thin flag.FlagSet over hub.Serve: every decision about what a
// hub does, which routes are on which listener, the TLS rule, where the
// private listener may and may not bind, lives in internal/hub rather than
// here. This command's whole job is turning five flags into a hub.Config and
// running until ctx is cancelled.
func runHub(ctx context.Context, e *env, args []string) error {
	usage := "hub --store DIR --addr ADDR [--metrics-addr ADDR] [--tls-cert FILE --tls-key FILE]"
	fs := newFlagSet(e, "hub", usage)
	store := fs.String("store", "", "directory `postern sign` wrote bundles and index.json into (required)")
	addr := fs.String("addr", "", "address the public bundle-and-heartbeat listener binds, as host:port or :port (required)")
	metricsAddr := fs.String("metrics-addr", "", "serve Prometheus /metrics and the per-host heartbeat freshness "+
		"document at "+hub.BeatsPath+" on this `address`; empty serves neither. "+
		"Must not equal --addr: this hub's own operator sees fleet size, per-host health and which hosts have "+
		"gone quiet here, and the public listener must never publish any of it")
	tlsCert := fs.String("tls-cert", "", "TLS certificate file for the public listener; set together with --tls-key to turn on TLS")
	tlsKey := fs.String("tls-key", "", "TLS private key file for the public listener")
	positional, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 0 {
		fs.Usage()
		return usagef("hub takes no positional arguments")
	}
	if *store == "" {
		return usagef("--store is required")
	}
	if *addr == "" {
		return usagef("--addr is required")
	}

	outf(e.stderr, "postern hub: serving %s from %s\n", *addr, *store)
	if *metricsAddr != "" {
		outf(e.stderr, "postern hub: serving /metrics and %s on %s\n", hub.BeatsPath, *metricsAddr)
	}

	return hub.Serve(ctx, hub.Config{
		Addr:        *addr,
		MetricsAddr: *metricsAddr,
		TLSCertFile: *tlsCert,
		TLSKeyFile:  *tlsKey,
		StoreDir:    *store,
	})
}
