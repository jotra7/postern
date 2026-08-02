package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/probe"
)

// probeHome enrolls a host whose canary port is a real, local TCP port, so
// the assertions below are made against actual connect outcomes rather than
// against a fake dialer. knock_addr is 127.0.0.1: the SPA datagram goes to a
// UDP port nothing binds, which is exactly what a knock into a black hole
// looks like, and none of these tests depend on it being answered.
func probeHome(t *testing.T, canaryPort int) string {
	t.Helper()
	home := t.TempDir()
	entry := fmt.Sprintf(""+
		"name: web-01\n"+
		"host_id: 3a713a713a713a713a713a713a713a71\n"+
		"knock_addr: 127.0.0.1\n"+
		"knock_port: 62201\n"+
		"host_encryption: %s\n"+
		"recovery_service: ssh\n"+
		"services:\n"+
		"  ssh: { port: 22, ttl: 120s }\n"+
		"  canary: { port: %d, ttl: 30s }\n", testHostEncryptionB64, canaryPort)
	entryPath := filepath.Join(home, "entry.yaml")
	if err := os.WriteFile(entryPath, []byte(entry), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	e, _, errBuf := envWithHome(t, home)
	if code := runCLI(t, e, "enroll", "web-01", "--from", entryPath, "--no-passphrase"); code != exitOK {
		t.Fatalf("enroll exited %d: %s", code, errBuf.String())
	}
	return home
}

// freePort returns a TCP port on the loopback interface with nothing bound
// to it. A connect there is refused by the kernel, which is precisely what a
// canary port with no drop rule in front of it does — the state `postern
// open` cannot distinguish from a working gate, and the state this whole
// package exists to catch.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return port
}

// The heart of the probe, asserted through the real command against a real
// socket: a canary port that answers before the knock is a FAILURE.
//
// This is the state the probe was commissioned for. A host with no agent and
// no firewall tables at all answers every connect with RST, and `postern
// open` against it reports the port reachable — correctly, and uselessly.
// A probe that checked only the post-knock connect would agree, forever.
//
// Mutation verified: adding client.Refused to closedFailure's passing set in
// internal/probe makes this command exit 0 and this test fail.
func TestMain_Probe_FailsWhenTheCanaryPortAnswersBeforeTheKnock(t *testing.T) {
	home := probeHome(t, freePort(t))
	e, out, _ := envWithHome(t, home)

	code := runCLI(t, e, "probe", "web-01", "--once",
		"--closed-timeout", "500ms", "--open-timeout", "200ms", "--open-attempts", "1", "--settle", "1ms")
	if code == exitOK {
		t.Fatalf("a sweep against an unfiltered canary port exited 0:\n%s", out.String())
	}
	if code != exitFailed {
		t.Errorf("exit = %d, want %d (the sweep ran and did not establish what it exists to establish)", code, exitFailed)
	}
	got := out.String()
	// "gate not closed" is the categorical token a monitoring harness greps
	// for; the prose beside it is for a human. Both are asserted, because a
	// report that only carries one of them is only useful to one of them.
	for _, want := range []string{"FAIL", "[gate not closed]", "phase 1", "refused", "no gate open"} {
		if !strings.Contains(got, want) {
			t.Errorf("the report does not contain %q:\n%s", want, got)
		}
	}
	// The sweep must stop at phase 1 rather than knocking: opening a gate to
	// a port that already answers cannot make it say anything new.
	if strings.Contains(got, "knock    sent") {
		t.Errorf("the probe knocked after phase 1 had already failed:\n%s", got)
	}
	if strings.Contains(got, "phase 2") {
		t.Errorf("the probe ran phase 2 after phase 1 failed:\n%s", got)
	}
}

// A listener behind the canary port is red on its own (design section 4):
// it turns the probe identity from one that can open a port with nothing
// behind it into one that can open a reachable service.
func TestMain_Probe_FailsWhenSomethingIsListeningOnTheCanaryPort(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = l.Close() }()
	// Accept in the background so the connect completes rather than sitting
	// in the backlog. Bounded: the listener is closed when the test ends,
	// which ends the Accept loop.
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	home := probeHome(t, l.Addr().(*net.TCPAddr).Port)
	e, out, _ := envWithHome(t, home)

	code := runCLI(t, e, "probe", "web-01", "--once",
		"--closed-timeout", "2s", "--open-timeout", "200ms", "--open-attempts", "1", "--settle", "1ms")
	if code == exitOK {
		t.Fatalf("a sweep that connected to the canary port exited 0:\n%s", out.String())
	}
	got := out.String()
	for _, want := range []string{"FAIL", "listening", "listener_expectation"} {
		if !strings.Contains(got, want) {
			t.Errorf("the report does not contain %q:\n%s", want, got)
		}
	}
}

// The interval guard is a startup refusal, and it has to be wired into the
// command rather than only into the package: a probe whose sweeps trip over
// their own gate leases reports a permanently red host with a working gate.
func TestMain_Probe_RefusesAnIntervalShorterThanTheGateItOpens(t *testing.T) {
	home := probeHome(t, freePort(t))
	e, out, errBuf := envWithHome(t, home)

	code := runCLI(t, e, "probe", "web-01", "--interval", "20s")
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d (a configuration refusal, before anything was attempted):\nout: %s\nerr: %s",
			code, exitUsage, out.String(), errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "30s") {
		t.Errorf("the refusal does not name the gate's ttl:\n%s", errBuf.String())
	}
	// Nothing may have been measured: this is a refusal, not a failed sweep.
	if strings.Contains(out.String(), "phase 1") {
		t.Errorf("the probe swept despite refusing its own configuration:\n%s", out.String())
	}
}

// A probe pointed at a host whose entry has no canary is a local
// misconfiguration, and must be refused at startup rather than reported as a
// red host every 137 seconds forever.
func TestMain_Probe_RefusesAHostWithNoCanaryService(t *testing.T) {
	home := t.TempDir()
	entry := "" +
		"name: web-01\n" +
		"host_id: 3a713a713a713a713a713a713a713a71\n" +
		"knock_addr: 127.0.0.1\n" +
		"host_encryption: " + testHostEncryptionB64 + "\n" +
		"recovery_service: ssh\n" +
		"services:\n" +
		"  ssh: { port: 22, ttl: 120s }\n"
	entryPath := filepath.Join(home, "entry.yaml")
	if err := os.WriteFile(entryPath, []byte(entry), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	e, _, errBuf := envWithHome(t, home)
	if code := runCLI(t, e, "enroll", "web-01", "--from", entryPath, "--no-passphrase"); code != exitOK {
		t.Fatalf("enroll exited %d: %s", code, errBuf.String())
	}

	e2, out, errBuf2 := envWithHome(t, home)
	code := runCLI(t, e2, "probe", "web-01", "--once")
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d:\nout: %s\nerr: %s", code, exitUsage, out.String(), errBuf2.String())
	}
	if !strings.Contains(errBuf2.String(), "canary") {
		t.Errorf("the refusal does not mention the canary:\n%s", errBuf2.String())
	}
}

// --webhook has to reach the reporter, not just parse. A flag that is
// accepted and then dropped produces a probe whose findings go nowhere and
// whose exit code is the only survivor, which is the failure mode a
// reporting flag exists to prevent.
func TestMain_Probe_PostsTheSweepToTheWebhook(t *testing.T) {
	type posted struct {
		auth string
		body []byte
	}
	got := make(chan posted, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got <- posted{auth: r.Header.Get("Authorization"), body: body}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	home := probeHome(t, freePort(t))
	e, _, _ := envWithHome(t, home)
	// The sweep fails — the canary port is unfiltered — and the report must
	// go out anyway. A reporter that only fires on success reports nothing on
	// the day it matters.
	code := runCLI(t, e, "probe", "web-01", "--once",
		"--webhook", srv.URL, "--webhook-token", "s3cret",
		"--closed-timeout", "500ms", "--open-timeout", "200ms", "--open-attempts", "1", "--settle", "1ms")
	if code == exitOK {
		t.Fatalf("the sweep exited 0 against an unfiltered canary port")
	}

	select {
	case p := <-got:
		if p.auth != "Bearer s3cret" {
			t.Errorf("Authorization = %q, want the configured bearer token", p.auth)
		}
		var rep probe.WebhookReport
		if err := json.Unmarshal(p.body, &rep); err != nil {
			t.Fatalf("the posted body is not a WebhookReport: %v\n%s", err, p.body)
		}
		if rep.Verdict != probe.Fail || rep.Reason != probe.ReasonGateNotClosed {
			t.Errorf("posted verdict/reason = %s/%s, want %s/%s",
				rep.Verdict, rep.Reason, probe.Fail, probe.ReasonGateNotClosed)
		}
		if rep.ClosedPhaseOutcome != "refused" {
			t.Errorf("posted closed_phase_outcome = %q, want refused", rep.ClosedPhaseOutcome)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("nothing was posted to the webhook: the flag is accepted and then dropped")
	}
}

// A numeric flag whose value internal/probe would silently replace with its
// own default is refused here instead. `--interval 0` becoming 137 seconds
// is a flag accepted and ignored, which is indistinguishable from a flag
// that does not exist — except that the operator believes it worked.
func TestMain_Probe_RefusesFlagValuesItWouldOtherwiseIgnore(t *testing.T) {
	home := probeHome(t, freePort(t))
	cases := []struct {
		flag, value string
	}{
		{"--interval", "0"},
		{"--failure-threshold", "0"},
		{"--closed-timeout", "0"},
		{"--open-timeout", "0"},
		{"--open-attempts", "0"},
		{"--settle", "0"},
		{"--jitter", "0"},
		{"--jitter", "1.5"},
	}
	for _, tc := range cases {
		t.Run(tc.flag+"="+tc.value, func(t *testing.T) {
			e, out, errBuf := envWithHome(t, home)
			code := runCLI(t, e, "probe", "web-01", "--once", tc.flag, tc.value)
			if code != exitUsage {
				t.Fatalf("exit = %d, want %d:\nout: %s\nerr: %s", code, exitUsage, out.String(), errBuf.String())
			}
			if strings.Contains(out.String(), "phase 1") {
				t.Errorf("the probe swept despite a refused flag value:\n%s", out.String())
			}
		})
	}
}

// probe takes one host, and says so rather than silently probing the first.
func TestMain_Probe_RefusesAnythingOtherThanOneHost(t *testing.T) {
	home := probeHome(t, freePort(t))
	for _, args := range [][]string{{"probe"}, {"probe", "web-01", "web-02"}} {
		e, _, _ := envWithHome(t, home)
		if code := runCLI(t, e, args...); code != exitUsage {
			t.Errorf("%v exited %d, want %d", args, code, exitUsage)
		}
	}
}

// TestMain_Probe_ServesTheJoinsHalfOnItsOwnEndpoint drives the real command
// with a real listener and scrapes it over real HTTP.
//
// This is the wiring the whole "health is the join" task turns on, and it is
// the one thing a unit test in internal/metrics cannot establish: that
// `postern probe` builds a Canary, hands it to the Runner, publishes the join
// key, and serves the result. A metrics implementation that existed and was
// never reached from the command would pass every test in internal/metrics.
//
// The sweep here fails — the canary port is an unfiltered loopback port, so
// phase 1 is refused — which is deliberate. Red with a reason is the state the
// join reads, and a test that only ever saw green would not exercise it.
func TestMain_Probe_ServesTheJoinsHalfOnItsOwnEndpoint(t *testing.T) {
	home := probeHome(t, freePort(t))
	e, _, errBuf := envWithHome(t, home)
	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, e, []string{"probe", "web-01",
			"--metrics-listen", addr, "--failure-threshold", "1",
			"--closed-timeout", "200ms", "--open-timeout", "100ms", "--open-attempts", "1", "--settle", "1ms"})
	}()

	// Bounded by a deadline rather than by a sleep, so a mutation that breaks
	// the wiring fails this test instead of hanging it.
	var body string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if body = fetchMetrics(addr); strings.Contains(body, `postern_probe_health{host="web-01",state="red"} 1`) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done

	for _, want := range []string{
		// The join key, published from the client config's host_id — the same
		// identifier the agent puts on postern_agent_info.
		`postern_probe_target_info{host="web-01",host_id="3a713a713a713a713a713a713a713a71"} 1`,
		// The probe's half of the join, as an enumeration: red is 1 and the
		// other states have series of their own at 0.
		`postern_probe_health{host="web-01",state="red"} 1`,
		`postern_probe_health{host="web-01",state="green"} 0`,
		// The reason, which is the distinction the exit code cannot draw.
		`postern_probe_sweeps_total{host="web-01",reason="gate_not_closed",service="canary",verdict="fail"} 1`,
		// Never proven reachable is 0, not a missing series.
		`postern_probe_last_pass_timestamp_seconds{host="web-01"} 0`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("the probe's /metrics does not contain %q\n--- stderr ---\n%s\n--- scrape ---\n%s",
				want, errBuf.String(), body)
		}
	}
	// A probe is not an agent. Serving the agent's families at zero would show
	// an operator a healthy agent on a machine that has none.
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "postern_agent_") || strings.HasPrefix(line, "postern_gate_") {
			t.Fatalf("the probe's /metrics serves %q", line)
		}
	}
}

func fetchMetrics(addr string) string {
	req, err := http.NewRequest(http.MethodGet, "http://"+addr+"/metrics", nil)
	if err != nil {
		return ""
	}
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return string(raw)
}

// TestMain_Probe_RefusesAMetricsEndpointItWouldImmediatelyClose keeps
// --metrics-listen from being a flag that appears to work and produces a
// scrape target that is down every time Prometheus looks.
func TestMain_Probe_RefusesAMetricsEndpointItWouldImmediatelyClose(t *testing.T) {
	home := probeHome(t, freePort(t))
	e, _, errBuf := envWithHome(t, home)

	code := runCLI(t, e, "probe", "web-01", "--once", "--metrics-listen", "127.0.0.1:9874")
	if code != exitUsage {
		t.Fatalf("probe --once --metrics-listen exited %d, want %d: %s", code, exitUsage, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "nothing to serve under --once") {
		t.Fatalf("the refusal does not say why: %s", errBuf.String())
	}
}

// TestMain_Probe_RefusesAWildcardMetricsBind applies the same rule the agent's
// endpoint gets, for a narrower but real reason: the probe's exposition names
// which hosts are unreachable right now.
//
// The bounded context is load-bearing. This command has no --once here — it
// cannot, because --metrics-listen with --once is refused for its own reasons —
// so a mutation that accepted the wildcard would start a continuous probe and
// turn this test into a hang, which emits neither a pass nor a --- FAIL. With
// the deadline it fails in three seconds instead.
func TestMain_Probe_RefusesAWildcardMetricsBind(t *testing.T) {
	home := probeHome(t, freePort(t))
	for _, spec := range []string{"0.0.0.0:9874", "[::]:9874", "probe.example.com:9874"} {
		e, _, errBuf := envWithHome(t, home)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		code := run(ctx, e, []string{"probe", "web-01", "--metrics-listen", spec})
		cancel()
		if code != exitUsage {
			t.Errorf("probe --metrics-listen %s exited %d, want %d: %s", spec, code, exitUsage, errBuf.String())
		}
	}
}
