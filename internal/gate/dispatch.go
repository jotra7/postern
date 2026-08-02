package gate

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jotra7/postern/internal/config"
)

// ServiceBackend is a gate implementation that owns some services' admissions
// and nothing else.
//
// It is deliberately narrower than Gate. The three methods Gate carries that
// are missing here — RefreshAgentUp, AgentUpExpiry, SilenceAgentUp — manage
// the agent_up dead-man element that makes the SPA port reachable at all
// (design section 4, invariant 1), and they are not per-service and never
// will be: there is one SPA port on a host, its concealment is what the whole
// product rests on, and a second implementation of it is a second way to lose
// it. The nftables backend keeps them.
type ServiceBackend interface {
	// Open admits src into service's gate for ttl.
	Open(ctx context.Context, service string, src Source, ttl time.Duration) error
	// State reports what this backend is currently admitting for service.
	State(ctx context.Context, service string) (ServiceState, error)
	// Close withdraws everything this backend admitted.
	Close(ctx context.Context) error
}

// Dispatcher is the Gate the agent actually holds when any service opts out
// of nftables.
//
// It routes Open and State per service, and it delegates everything else to
// the nftables backend unconditionally. "Everything else" is the load-bearing
// part: agent_up, its expiry readback, its silencing, the capability check
// pre-arm treats as a global precondition, and postern_open's creation all go
// to nftables no matter what any service declares. A host with every gate on
// a script backend still has an nftables-owned SPA port with a kernel dead-man
// on it.
type Dispatcher struct {
	mu      sync.Mutex
	base    Gate
	backend ServiceBackend
	// routed names the services the backend owns. A service absent from this
	// map goes to base, which is what makes "nftables is the default and the
	// behaviour is unchanged" true by construction rather than by review.
	routed map[string]bool
}

var _ Gate = (*Dispatcher)(nil)

// policyReloader is the optional interface a backend implements when it holds
// a service catalogue that a fetched bundle can replace. It mirrors
// agent.PolicyReloader, which this package cannot import.
type policyReloader interface {
	SetPolicy(*config.Policy) error
}

// NewDispatcher wires base and backend together against policy.
//
// backend may be nil when policy declares no script-backed service, which is
// every host that has not asked for one; the result then routes every service
// to base and is behaviourally identical to base.
func NewDispatcher(base Gate, backend ServiceBackend, policy *config.Policy) (*Dispatcher, error) {
	if base == nil {
		return nil, errors.New("gate: NewDispatcher: base gate is required; nftables always exists")
	}
	d := &Dispatcher{base: base, backend: backend}
	if err := d.SetPolicy(policy); err != nil {
		return nil, err
	}
	return d, nil
}

// SetPolicy rebuilds the routing table and passes the policy on to whichever
// of the two backends can adopt it.
//
// A policy naming a script-backed service with no backend to route it to is
// refused rather than silently sent to nftables — which has no rules for that
// service, since BuildRulesetPlan skips it, so every knock would resolve, be
// authorized, consume its replay slot, and fail at a set lookup for a set
// that was never meant to exist.
func (d *Dispatcher) SetPolicy(policy *config.Policy) error {
	if policy == nil {
		return errors.New("gate: Dispatcher.SetPolicy: policy is nil")
	}
	routed := map[string]bool{}
	for name, svc := range policy.Services {
		if svc.Kind != config.KindGate || svc.Backend != config.BackendScript {
			continue
		}
		if d.backend == nil {
			return fmt.Errorf("gate: service %q declares backend %q but this gate was built with no "+
				"script backend to route it to", name, config.BackendScript)
		}
		routed[name] = true
	}

	// Both backends are asked whether they *would* accept before either is
	// told to. A policy one half adopts and the other refuses is a gate whose
	// two halves hold different catalogues, and the agent swaps its own
	// policy one step before it opens the next packet's gate — so the window
	// in which they disagree is exactly the window a knock lands in.
	if c, ok := d.backend.(interface {
		CheckPolicy(*config.Policy) error
	}); ok {
		if err := c.CheckPolicy(policy); err != nil {
			return err
		}
	}
	if r, ok := d.base.(policyReloader); ok {
		if err := r.SetPolicy(policy); err != nil {
			return err
		}
	}
	if r, ok := d.backend.(policyReloader); ok {
		if err := r.SetPolicy(policy); err != nil {
			return err
		}
	}

	d.mu.Lock()
	d.routed = routed
	d.mu.Unlock()
	return nil
}

// ApplyOpen forwards to the base gate, which owns postern_open. A script
// backend has no equivalent: it creates no table, so there is nothing for the
// agent's startup to bring into being on its behalf.
func (d *Dispatcher) ApplyOpen(ctx context.Context) error {
	if a, ok := d.base.(interface {
		ApplyOpen(context.Context) error
	}); ok {
		return a.ApplyOpen(ctx)
	}
	return nil
}

func (d *Dispatcher) routeFor(service string) ServiceBackend {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.routed[service] {
		return d.backend
	}
	return nil
}

// Open sends the admission to whichever backend owns this service.
func (d *Dispatcher) Open(ctx context.Context, service string, src Source, ttl time.Duration) error {
	if b := d.routeFor(service); b != nil {
		return b.Open(ctx, service, src, ttl)
	}
	return d.base.Open(ctx, service, src, ttl)
}

// State reads back from whichever backend owns this service.
func (d *Dispatcher) State(ctx context.Context, service string) (ServiceState, error) {
	if b := d.routeFor(service); b != nil {
		return b.State(ctx, service)
	}
	return d.base.State(ctx, service)
}

// Health is the base gate's answer alone, and that is a decision rather than
// an omission.
//
// Pre-arm treats this as a global precondition: a false here keeps the agent
// inert, which leaves agent_up unset and the SPA port silent for every
// service on the host (design section 7). Folding a subprocess's verdict into
// it would mean one operator's cloud API having an afternoon could take
// break-glass away from a host whose kernel firewall is working perfectly —
// the same "a database outage would have removed the door built for outages"
// shape the global/per-service split exists to prevent. A script service's
// own health is reported per service; see Script.ServiceHealth.
func (d *Dispatcher) Health(ctx context.Context) (Health, error) { return d.base.Health(ctx) }

// Close tears down both backends. The base's teardown runs even if the
// backend's fails, because postern_open outliving the process is the failure
// with a fail-closed service behind it.
func (d *Dispatcher) Close(ctx context.Context) error {
	var errs []error
	if d.backend != nil {
		if err := d.backend.Close(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if err := d.base.Close(ctx); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// RefreshAgentUp, AgentUpExpiry, SilenceAgentUp, RefreshAgentUpPorts and
// AgentUpExpiryFor are the nftables backend's, always. See the type doc and
// ServiceBackend's.
func (d *Dispatcher) RefreshAgentUp(ctx context.Context, ttl time.Duration) error {
	return d.base.RefreshAgentUp(ctx, ttl)
}

func (d *Dispatcher) AgentUpExpiry(ctx context.Context) (time.Duration, error) {
	return d.base.AgentUpExpiry(ctx)
}

func (d *Dispatcher) SilenceAgentUp(ctx context.Context) error { return d.base.SilenceAgentUp(ctx) }

func (d *Dispatcher) RefreshAgentUpPorts(ctx context.Context, ports []uint16, ttl time.Duration) error {
	return d.base.RefreshAgentUpPorts(ctx, ports, ttl)
}

func (d *Dispatcher) AgentUpExpiryFor(ctx context.Context, port uint16) (time.Duration, error) {
	return d.base.AgentUpExpiryFor(ctx, port)
}
