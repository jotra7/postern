package gate

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/config"
)

// fakeGate records what reached the base backend. It is not a stand-in for
// nftables' behaviour — the netlink tests cover that — only for which calls
// arrive.
type fakeGate struct {
	opened      []string
	stated      []string
	closed      int
	refresh     int
	expiry      int
	silenced    int
	health      int
	applied     int
	policies    int
	refreshPort int
	expiryFor   int

	setPolicyErr error
}

func (g *fakeGate) Open(_ context.Context, service string, _ Source, _ time.Duration) error {
	g.opened = append(g.opened, service)
	return nil
}

func (g *fakeGate) State(_ context.Context, service string) (ServiceState, error) {
	g.stated = append(g.stated, service)
	return ServiceState{Service: service}, nil
}

func (g *fakeGate) Health(context.Context) (Health, error) {
	g.health++
	return Health{Healthy: true, Detail: "from the base gate"}, nil
}

func (g *fakeGate) Close(context.Context) error { g.closed++; return nil }

func (g *fakeGate) RefreshAgentUp(context.Context, time.Duration) error { g.refresh++; return nil }

func (g *fakeGate) AgentUpExpiry(context.Context) (time.Duration, error) {
	g.expiry++
	return 90 * time.Second, nil
}

func (g *fakeGate) SilenceAgentUp(context.Context) error { g.silenced++; return nil }

func (g *fakeGate) RefreshAgentUpPorts(context.Context, []uint16, time.Duration) error {
	g.refreshPort++
	return nil
}

func (g *fakeGate) AgentUpExpiryFor(context.Context, uint16) (time.Duration, error) {
	g.expiryFor++
	return 90 * time.Second, nil
}

func (g *fakeGate) ApplyOpen(context.Context) error { g.applied++; return nil }

func (g *fakeGate) SetPolicy(*config.Policy) error {
	g.policies++
	return g.setPolicyErr
}

// fakeBackend is a ServiceBackend that records the same way.
type fakeBackend struct {
	opened []string
	stated []string
	closed int
}

func (b *fakeBackend) Open(_ context.Context, service string, _ Source, _ time.Duration) error {
	b.opened = append(b.opened, service)
	return nil
}

func (b *fakeBackend) State(_ context.Context, service string) (ServiceState, error) {
	b.stated = append(b.stated, service)
	return ServiceState{Service: service}, nil
}

func (b *fakeBackend) Close(context.Context) error { b.closed++; return nil }

// mixedPolicy declares one service on each backend, which is the deployment
// the script backend is meant for: the kernel holds the local bolt while a
// script handles the perimeter in front of it.
func mixedPolicy() *config.Policy {
	return &config.Policy{
		SPAPort:            62201,
		AlwaysAllowIface:   "tailscale0",
		FreshnessWindow:    60 * time.Second,
		FreshnessWindowMax: 24 * time.Hour,
		Services: map[string]config.Service{
			"ssh": {
				Name: "ssh", Kind: config.KindGate, Proto: "tcp", Ports: []uint16{22},
				DefaultTTL: 120 * time.Second, MaxTTL: 300 * time.Second,
				FailPosture: config.PostureOpen, ListenerExpectation: config.ListenerPresent,
				Backend: config.BackendNFTables,
			},
			"perimeter": {
				Name: "perimeter", Kind: config.KindGate, Proto: "tcp", Ports: []uint16{22},
				DefaultTTL: 120 * time.Second, MaxTTL: 300 * time.Second,
				FailPosture: config.PostureOpen, ListenerExpectation: config.ListenerUnchecked,
				Backend: config.BackendScript, ScriptPath: "/opt/postern/perimeter.sh",
				ScriptTimeout: 15 * time.Second,
			},
		},
	}
}

func TestGate_Dispatcher_RoutesEachServiceToItsOwnBackend(t *testing.T) {
	base := &fakeGate{}
	backend := &fakeBackend{}
	d, err := NewDispatcher(base, backend, mixedPolicy())
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	src := Source{Kind: SourceObserved}
	if err := d.Open(context.Background(), "ssh", src, time.Minute); err != nil {
		t.Fatalf("Open ssh: %v", err)
	}
	if err := d.Open(context.Background(), "perimeter", src, time.Minute); err != nil {
		t.Fatalf("Open perimeter: %v", err)
	}
	if _, err := d.State(context.Background(), "ssh"); err != nil {
		t.Fatalf("State ssh: %v", err)
	}
	if _, err := d.State(context.Background(), "perimeter"); err != nil {
		t.Fatalf("State perimeter: %v", err)
	}

	if got := strings.Join(base.opened, ","); got != "ssh" {
		t.Errorf("base saw opens for %q, want %q", got, "ssh")
	}
	if got := strings.Join(backend.opened, ","); got != "perimeter" {
		t.Errorf("backend saw opens for %q, want %q", got, "perimeter")
	}
	if got := strings.Join(base.stated, ","); got != "ssh" {
		t.Errorf("base saw state reads for %q, want %q", got, "ssh")
	}
	if got := strings.Join(backend.stated, ","); got != "perimeter" {
		t.Errorf("backend saw state reads for %q, want %q", got, "perimeter")
	}
}

// agent_up is invariant 1: the SPA port is reachable only while nftables
// holds that element. It stays with nftables on a host where every gate has
// opted out, or the concealment of the port would depend on a subprocess.
func TestGate_Dispatcher_AgentUpStaysWithTheBaseGateWhenEveryServiceIsScripted(t *testing.T) {
	base := &fakeGate{}
	backend := &fakeBackend{}
	p := mixedPolicy()
	delete(p.Services, "ssh")

	d, err := NewDispatcher(base, backend, p)
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	if err := d.RefreshAgentUp(context.Background(), 90*time.Second); err != nil {
		t.Fatalf("RefreshAgentUp: %v", err)
	}
	if _, err := d.AgentUpExpiry(context.Background()); err != nil {
		t.Fatalf("AgentUpExpiry: %v", err)
	}
	if err := d.SilenceAgentUp(context.Background()); err != nil {
		t.Fatalf("SilenceAgentUp: %v", err)
	}
	if err := d.ApplyOpen(context.Background()); err != nil {
		t.Fatalf("ApplyOpen: %v", err)
	}

	if base.refresh != 1 || base.expiry != 1 || base.silenced != 1 || base.applied != 1 {
		t.Errorf("base saw refresh=%d expiry=%d silence=%d applyOpen=%d, want 1 of each",
			base.refresh, base.expiry, base.silenced, base.applied)
	}
}

// Health is pre-arm's global precondition, and a false there keeps the agent
// inert — no agent_up, no SPA, for every service on the host. A subprocess
// must not be able to cause that.
func TestGate_Dispatcher_HealthIsTheBaseGatesAnswerAlone(t *testing.T) {
	base := &fakeGate{}
	backend := &fakeBackend{}
	d, err := NewDispatcher(base, backend, mixedPolicy())
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	h, err := d.Health(context.Background())
	if err != nil {
		t.Fatalf("Health: %v", err)
	}
	if h.Detail != "from the base gate" {
		t.Errorf("Health detail = %q, want the base gate's", h.Detail)
	}
	if base.health != 1 {
		t.Errorf("base saw %d health calls, want 1", base.health)
	}
}

func TestGate_Dispatcher_CloseTearsDownBothBackends(t *testing.T) {
	base := &fakeGate{}
	backend := &fakeBackend{}
	d, err := NewDispatcher(base, backend, mixedPolicy())
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	if err := d.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if base.closed != 1 || backend.closed != 1 {
		t.Errorf("closed base=%d backend=%d, want 1 of each", base.closed, backend.closed)
	}
}

// postern_open outliving the process is the failure with a fail-closed
// service behind it, so the base teardown runs even when the script backend's
// fails — and the script backend's failure is still reported.
func TestGate_Dispatcher_CloseReachesTheBaseEvenWhenTheBackendFails(t *testing.T) {
	base := &fakeGate{}
	backend := &failingBackend{}
	d, err := NewDispatcher(base, backend, mixedPolicy())
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	err = d.Close(context.Background())
	if err == nil {
		t.Fatal("Close swallowed the backend's failure")
	}
	if base.closed != 1 {
		t.Errorf("base saw %d closes, want 1", base.closed)
	}
}

type failingBackend struct{ fakeBackend }

func (b *failingBackend) Close(context.Context) error { return errors.New("backend teardown failed") }

// A policy naming a script-backed service with nothing to route it to is a
// host where every knock for that service resolves, is authorized, consumes
// its replay slot, and then fails on an nftables set that BuildRulesetPlan
// deliberately never created.
func TestGate_Dispatcher_RefusesAScriptServiceWithNoBackend(t *testing.T) {
	_, err := NewDispatcher(&fakeGate{}, nil, mixedPolicy())
	if err == nil {
		t.Fatal("NewDispatcher accepted a script-backed service with no backend to route it to")
	}
	if !strings.Contains(err.Error(), "perimeter") {
		t.Errorf("error does not name the service: %v", err)
	}
}

// With no script service declared, the dispatcher is behaviourally the base
// gate — which is what makes "nftables is the default and current behaviour
// is unchanged" true by construction.
func TestGate_Dispatcher_WithNoScriptServicesRoutesEverythingToTheBase(t *testing.T) {
	base := &fakeGate{}
	p := mixedPolicy()
	delete(p.Services, "perimeter")

	d, err := NewDispatcher(base, nil, p)
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}
	if err := d.Open(context.Background(), "ssh", Source{}, time.Minute); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got := strings.Join(base.opened, ","); got != "ssh" {
		t.Errorf("base saw opens for %q, want %q", got, "ssh")
	}
}

// The agent swaps its policy one step before it opens the next packet's gate,
// so a revision one half adopts and the other refuses is a window a knock
// lands in.
func TestGate_Dispatcher_SetPolicyPassesThePolicyToBothBackends(t *testing.T) {
	base := &fakeGate{}
	backend := &reloadableBackend{}
	d, err := NewDispatcher(base, backend, mixedPolicy())
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}
	// One from construction, one from the explicit call below.
	if err := d.SetPolicy(mixedPolicy()); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}
	if base.policies != 2 || backend.policies != 2 {
		t.Errorf("policies adopted: base=%d backend=%d, want 2 each", base.policies, backend.policies)
	}
	if backend.checked != 2 {
		t.Errorf("backend was asked to check %d policies, want 2", backend.checked)
	}
}

// A backend that would refuse the new catalogue stops the base adopting it,
// so the two halves never disagree about which revision is live.
func TestGate_Dispatcher_SetPolicyRefusedByTheBackendLeavesTheBaseAlone(t *testing.T) {
	base := &fakeGate{}
	backend := &reloadableBackend{checkErr: errors.New("script is world-writable")}
	d := &Dispatcher{base: base, backend: backend, routed: map[string]bool{}}

	if err := d.SetPolicy(mixedPolicy()); err == nil {
		t.Fatal("SetPolicy accepted a policy the backend refused")
	}
	if base.policies != 0 {
		t.Errorf("base adopted %d policies, want 0", base.policies)
	}
}

type reloadableBackend struct {
	fakeBackend
	policies int
	checked  int
	checkErr error
}

func (b *reloadableBackend) CheckPolicy(*config.Policy) error { b.checked++; return b.checkErr }
func (b *reloadableBackend) SetPolicy(*config.Policy) error   { b.policies++; return nil }
