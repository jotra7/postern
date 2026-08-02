package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jotra7/postern/internal/client"
	"github.com/jotra7/postern/internal/metrics"
	"github.com/jotra7/postern/internal/probe"
)

func init() {
	register(&command{
		name:    "probe",
		usage:   "probe <host> [flags]",
		summary: "prove from outside that the gate is shut and a knock opens it",
		run:     runProbe,
	})
}

// runProbe is the external evidence postern's own reports cannot supply.
//
// `postern open` reports what its connect found, and says plainly that a
// successful connect does not establish that postern did it — a fail-open
// service on a host whose agent has died looks identical from there, and so
// does a host with no firewall tables at all. The probe closes that gap by
// measuring the closed state first: a canary port that answers *before* the
// knock is a failure, whatever happens after it.
func runProbe(ctx context.Context, e *env, args []string) error {
	fs := newFlagSet(e, "probe", "probe <host> [flags]")
	var cf clientFlags
	cf.bind(fs)
	service := fs.String("service", probe.DefaultService, "the canary gate service to sweep")
	once := fs.Bool("once", false, "run one sweep and exit; the exit code is the verdict")
	interval := fs.Duration("interval", probe.DefaultInterval,
		"sweep period before jitter; deliberately not a multiple of the 60s heartbeat")
	jitter := fs.Float64("jitter", probe.DefaultJitterFraction,
		"fraction of the interval to jitter by; greater than 0 and at most 1, and it cannot be turned off")
	threshold := fs.Int("failure-threshold", probe.DefaultFailureThreshold, "consecutive failing sweeps that turn a host red")
	ttl := fs.Duration("ttl", 0, "gate ttl to request (0 uses the host's configured default)")
	closedTimeout := fs.Duration("closed-timeout", probe.DefaultClosedTimeout,
		"how long phase 1 waits for the silence that proves the gate is shut")
	openTimeout := fs.Duration("open-timeout", probe.DefaultOpenTimeout, "per-attempt timeout for the post-knock connect")
	openAttempts := fs.Int("open-attempts", probe.DefaultOpenAttempts, "post-knock connect attempts")
	settle := fs.Duration("settle", probe.DefaultSettle, "pause between the knock and the post-knock connect")
	webhookURL := fs.String("webhook", "", "POST each sweep as JSON to this URL")
	webhookToken := fs.String("webhook-token", "", "bearer token for --webhook (default $POSTERN_WEBHOOK_TOKEN)")
	metricsListen := fs.String("metrics-listen", "",
		"serve this probe's Prometheus /metrics on `address` (host:port, or :port for loopback). This is "+
			"the second scrape target design section 8's \"health is the join\" needs: the agent's own "+
			"/metrics is on the host, and the probe is not")

	positional, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		fs.Usage()
		return usagef("probe takes exactly one host")
	}
	// Every one of these is replaced by its default inside internal/probe when
	// it is zero or negative, which is the right behaviour for a caller
	// building a Runner in code and the wrong behaviour for an operator who
	// typed a number. `--interval 0` becoming 137 seconds, or
	// `--failure-threshold 0` becoming 3, is a flag accepted and silently
	// ignored — so they are refused here instead, where the message can say so.
	for _, f := range []struct {
		name string
		ok   bool
	}{
		{"interval", *interval > 0},
		{"failure-threshold", *threshold >= 1},
		{"closed-timeout", *closedTimeout > 0},
		{"open-timeout", *openTimeout > 0},
		{"open-attempts", *openAttempts >= 1},
		{"settle", *settle > 0},
	} {
		if !f.ok {
			return usagef("--%s must be positive; a zero or negative value here is silently replaced by "+
				"postern's default, so it is refused rather than ignored", f.name)
		}
	}
	// A scrape endpoint on a process that exits after one sweep is a target
	// Prometheus would find down every time it looked. Refused rather than
	// served for a few milliseconds, because a flag that appears to work and
	// produces a permanently down target is worse than one that says no.
	if *metricsListen != "" && *once {
		return usagef("--metrics-listen has nothing to serve under --once: the process exits before a " +
			"scrape can arrive. Run the probe continuously, or drop --metrics-listen and use --webhook")
	}
	if *jitter <= 0 || *jitter > 1 {
		return usagef("--jitter must be greater than 0 and at most 1. It cannot be turned off: a fleet of " +
			"probes started by one deploy would otherwise knock every host in lockstep, and a fixed period " +
			"samples the same moment of each agent's cycle forever. Pass a small fraction if you want the " +
			"schedule nearly fixed.")
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

	token := *webhookToken
	if token == "" {
		token = e.getenv("POSTERN_WEBHOOK_TOKEN")
	}

	prober := &probe.Prober{
		Builder:       client.Builder{Signer: signer},
		Host:          host,
		Service:       *service,
		TTL:           *ttl,
		Counter:       client.NewCounter(cfg.CounterFilePath()),
		ClosedTimeout: *closedTimeout,
		OpenTimeout:   *openTimeout,
		OpenAttempts:  *openAttempts,
		Settle:        *settle,
	}
	runner := &probe.Runner{
		Prober:           prober,
		Interval:         *interval,
		JitterFraction:   *jitter,
		FailureThreshold: *threshold,
		Observe:          func(sw probe.Sweep, st probe.State) { printSweep(e, sw, st, *once) },
		OnError:          func(err error) { outf(e.stderr, "postern probe: %v\n", err) },
	}
	if *webhookURL != "" {
		runner.Reporter = &probe.Webhook{URL: *webhookURL, Token: token}
	}

	// The canary is wired unconditionally, not only when --metrics-listen was
	// given. It costs nothing, and it means the emission path an operator
	// eventually scrapes is the same one every run exercises rather than a
	// branch that is only taken in the configuration nobody tested.
	canary, err := metrics.NewCanary(nil)
	if err != nil {
		return err
	}
	// The join key, published before the first sweep: a host that is
	// unreachable from the very first measurement still has to be joinable to
	// its own agent's series.
	canary.SetTarget(host.Name, host.RawHostID)
	runner.Metrics = canary

	if *metricsListen != "" {
		addr, err := metrics.ResolveProbeBind(*metricsListen)
		if err != nil {
			return usageError{err}
		}
		ln, err := metrics.Listen(addr)
		if err != nil {
			return err
		}
		srv := metrics.Serve(ln, canary.Handler())
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = srv.Shutdown(shutdownCtx)
		}()
		// stderr, not stdout: stdout is the sweep report a harness reads.
		outf(e.stderr, "postern probe: serving metrics on http://%s/metrics\n", ln.Addr())
	}

	if err := runner.Validate(); err != nil {
		return usageError{err}
	}

	if *once {
		sw, _, err := runner.Once(ctx)
		if err != nil {
			return err
		}
		if !sw.Passed() {
			return failedError{fmt.Errorf("%s: %s", sw.Reason, sw.Summary)}
		}
		return nil
	}

	st, err := runner.Run(ctx)
	// A cancelled context is how this command ends: it runs until the
	// operator or systemd stops it. The final state is printed so a run that
	// ends is not silent about what it last knew.
	outln(e.stdout, st.Line(time.Now()))
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if st.Health == probe.HealthRed {
		return failedError{fmt.Errorf("%s is red: %d consecutive failing sweeps (%s)",
			st.Host, st.ConsecutiveFailures, st.LastReason)}
	}
	return nil
}

// printSweep is the product for a human. The two phases are printed
// separately and always, including on a pass, because "phase 1 timed out"
// is the half an operator never thinks to ask for and the half that makes
// the rest mean anything.
func printSweep(e *env, sw probe.Sweep, st probe.State, once bool) {
	// The reason is printed alongside the prose because it is the stable,
	// greppable token: a monitoring harness — or the end-to-end sequence —
	// asserting on a sentence would break the day the sentence improves,
	// and asserting on the exit code alone cannot tell "the gate did not
	// open" from "the port answers with no gate at all", which is the whole
	// distinction this command exists to draw.
	if sw.Passed() {
		outf(e.stdout, "PASS %s\n", sw.Summary)
	} else {
		outf(e.stdout, "FAIL [%s] %s\n", sw.Reason, sw.Summary)
	}
	// A sweep that never reached phase 1 measured nothing, and printing a
	// phase line with an empty outcome would read as a measurement.
	if sw.Closed.Attempts == 0 {
		outln(e.stdout, "  no connect was made, so nothing about the host was measured")
	} else {
		outf(e.stdout, "  phase 1  gate closed → connect %s → %s%s\n",
			sw.ConnectAddr, sw.Closed.Outcome, wantSuffix(sw.Closed.Outcome == client.TimedOut, "timeout"))
		switch {
		case sw.Knocked:
			outf(e.stdout, "  knock    sent to %s (%s/%s)\n", sw.KnockAddr, sw.Host, sw.Service)
			outf(e.stdout, "  phase 2  gate open   → connect %s → %s%s\n",
				sw.ConnectAddr, sw.Open.Outcome, wantSuffix(sw.Open.Outcome == client.Refused, "refused"))
		case sw.Reason == probe.ReasonGateNotClosed || sw.Reason == probe.ReasonListenerPresent:
			outln(e.stdout, "  knock    not sent: phase 1 already failed, and opening a gate cannot un-answer a port")
		default:
			outln(e.stdout, "  knock    NOT sent")
		}
	}
	if sw.Detail != "" {
		outln(e.stdout, indent(wrap(sw.Detail, 76)))
	}
	// The streak line is the thing that turns a host red, so it is printed on
	// every continuous sweep — and never on a single --once run, where a
	// streak of one would read as a claim about history this process does not
	// have.
	if !once {
		outf(e.stdout, "  %s\n", st.Line(time.Now()))
	}
}

func wantSuffix(ok bool, want string) string {
	if ok {
		return ""
	}
	return "  (want " + want + ")"
}
