package agent_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/agent"
	"github.com/jotra7/postern/internal/gate"
	"github.com/jotra7/postern/internal/replay"
)

// StoreUnusable is the trigger condition for invariant 8's shutdown
// sequence: an ordinary rejection (ErrDuplicate, ErrCapacity) must not
// incapacitate the agent, but anything else from the store must.
func TestAgent_StoreUnusable_ClassifiesFatalStoreErrorsOnly(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"duplicate", replay.ErrDuplicate, false},
		{"capacity", replay.ErrCapacity, false},
		{"disk failure", errors.New("write record: no space left on device"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := agent.StoreUnusable(tc.err); got != tc.want {
				t.Fatalf("StoreUnusable(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// fakeGate is an in-memory gate.Gate that records call order, standing in
// for the nftables backend per the brief ("no kernel is needed for this
// package").
type fakeGate struct {
	calls                []string
	silenceErr, closeErr error
}

func (g *fakeGate) Open(context.Context, string, gate.Source, time.Duration) error {
	g.calls = append(g.calls, "Open")
	return nil
}

func (g *fakeGate) State(context.Context, string) (gate.ServiceState, error) {
	g.calls = append(g.calls, "State")
	return gate.ServiceState{}, nil
}

func (g *fakeGate) Health(context.Context) (gate.Health, error) {
	g.calls = append(g.calls, "Health")
	return gate.Health{}, nil
}

func (g *fakeGate) Close(context.Context) error {
	g.calls = append(g.calls, "Close")
	return g.closeErr
}

func (g *fakeGate) RefreshAgentUp(context.Context, time.Duration) error {
	g.calls = append(g.calls, "RefreshAgentUp")
	return nil
}

func (g *fakeGate) AgentUpExpiry(context.Context) (time.Duration, error) {
	g.calls = append(g.calls, "AgentUpExpiry")
	return time.Minute, nil
}

func (g *fakeGate) SilenceAgentUp(context.Context) error {
	g.calls = append(g.calls, "SilenceAgentUp")
	return g.silenceErr
}

func (g *fakeGate) RefreshAgentUpPorts(context.Context, []uint16, time.Duration) error {
	g.calls = append(g.calls, "RefreshAgentUpPorts")
	return nil
}

func (g *fakeGate) AgentUpExpiryFor(context.Context, uint16) (time.Duration, error) {
	g.calls = append(g.calls, "AgentUpExpiryFor")
	return time.Minute, nil
}

var _ gate.Gate = (*fakeGate)(nil)

// Invariant 8 (the shutdown-sequence half): when the replay store proves
// unusable, the agent must remove agent_up before tearing down the rest of
// its state — so the SPA port goes silent immediately rather than at lease
// expiry — and only then empty the fail-closed sets / tear down
// postern_open, both of which are gate.Gate.Close's contract.
func TestAgent_Incapacitate_SilencesAgentUpBeforeClosingTheGate(t *testing.T) {
	g := &fakeGate{}

	if err := agent.Incapacitate(context.Background(), g); err != nil {
		t.Fatalf("Incapacitate: %v", err)
	}
	if len(g.calls) != 2 || g.calls[0] != "SilenceAgentUp" || g.calls[1] != "Close" {
		t.Fatalf("calls = %v, want [SilenceAgentUp Close]", g.calls)
	}
}

// A failure in the first step must not skip the second: an agent that is
// declaring itself incapable has already lost the option of leaving
// anything half-done.
func TestAgent_Incapacitate_AttemptsCloseEvenWhenSilenceAgentUpFails(t *testing.T) {
	g := &fakeGate{silenceErr: errors.New("silence failed"), closeErr: errors.New("close failed")}

	err := agent.Incapacitate(context.Background(), g)
	if err == nil {
		t.Fatal("Incapacitate = nil error, want both underlying failures reported")
	}
	if !strings.Contains(err.Error(), "silence failed") || !strings.Contains(err.Error(), "close failed") {
		t.Fatalf("Incapacitate error = %q, want it to mention both failures", err.Error())
	}
	if len(g.calls) != 2 || g.calls[0] != "SilenceAgentUp" || g.calls[1] != "Close" {
		t.Fatalf("calls = %v, want both steps attempted, in order, despite the first failing", g.calls)
	}
}
