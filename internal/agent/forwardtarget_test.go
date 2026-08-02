package agent_test

import (
	"context"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/agent"
	"github.com/jotra7/postern/internal/config"
	"github.com/jotra7/postern/internal/gate"
	"github.com/jotra7/postern/internal/spa"
)

// The DNAT target of a forwarded path lives in the host's configuration and
// never in the packet. If a packet could name it, an operator's key would stop
// meaning "open the path this host declared" and start meaning "forward me to
// any address this box can reach": a pivot into the internal network handed to
// whoever holds a key, or to whoever ever steals one.
//
// The tests below are tripwires on the type level rather than assertions about
// behaviour, because the property is that a channel does not exist. Behaviour
// cannot demonstrate the absence of a channel; a widening can only be caught
// where it would have to be written.

// addressShaped reports whether a type can carry a destination. netip.Prefix is
// included: it is the shape an asserted SOURCE takes, and the allowlists below
// name the two fields entitled to be one, so a third would fail here.
func addressShaped(t reflect.Type) bool {
	switch t {
	case reflect.TypeOf(netip.Addr{}),
		reflect.TypeOf(netip.AddrPort{}),
		reflect.TypeOf(netip.Prefix{}),
		reflect.TypeOf(config.Forward{}),
		reflect.TypeOf(&config.Forward{}):
		return true
	}
	return false
}

// addressShapedFields returns every field of a struct type that could carry a
// destination, walking embedded structs so a target hidden one level down is
// still found.
func addressShapedFields(t reflect.Type, prefix string) []string {
	var out []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := prefix + f.Name
		if addressShaped(f.Type) {
			out = append(out, name)
			continue
		}
		if f.Type.Kind() == reflect.Struct && f.Type.PkgPath() != "net/netip" {
			out = append(out, addressShapedFields(f.Type, name+".")...)
		}
	}
	return out
}

// A gate packet's decoded payload carries a source assertion and nothing else.
// The whole 32-byte union is a source kind, an address family, a prefix length,
// an address, and reserved bytes that spa.Request.GatePayload requires to be
// zero, so there is not even a spare field a target could be smuggled in.
func TestAgent_ForwardTarget_TheGatePayloadCarriesOnlyASource(t *testing.T) {
	// GatePayload.Prefix is the operator's asserted source CIDR, checked
	// against the grant's own floor by config.Grant.AllowsSource before it
	// reaches a gate. It is a source, and it is the only address on the wire.
	allowed := map[string]bool{"Prefix": true}

	for _, name := range addressShapedFields(reflect.TypeOf(spa.GatePayload{}), "") {
		if !allowed[name] {
			t.Errorf("spa.GatePayload grew an address-shaped field %q. The SPA packet may select "+
				"WHICH configured forward, by service id, and may not supply an address, a port, or "+
				"anything an address is derived from", name)
		}
	}
}

// agent.Decision is what a validated packet authorizes, and it is the last
// thing standing between the wire and the firewall. A destination here would
// be a destination the packet chose.
func TestAgent_ForwardTarget_ADecisionCarriesNoDestination(t *testing.T) {
	// Decision.Source.Prefix is the address to admit, either observed from the
	// datagram's own UDP source or asserted inside the signed payload. It is a
	// source in both cases.
	allowed := map[string]bool{"Source.Prefix": true}

	for _, name := range addressShapedFields(reflect.TypeOf(agent.Decision{}), "") {
		if !allowed[name] {
			t.Errorf("agent.Decision grew an address-shaped field %q. A forward's target comes from "+
				"config.Service.Forward, resolved into the ruleset at arm time; nothing a packet "+
				"produced may reach a DNAT rule", name)
		}
	}
}

// Gate.Open is the call a validated packet turns into. It takes a service
// name, a source, and a ttl: threading a target through it would be the first
// place the widening had to be written.
func TestAgent_ForwardTarget_GateOpenTakesNoDestination(t *testing.T) {
	open, ok := reflect.TypeOf((*gate.Gate)(nil)).Elem().MethodByName("Open")
	if !ok {
		t.Fatal("gate.Gate has no Open method")
	}

	want := []reflect.Type{
		reflect.TypeOf((*context.Context)(nil)).Elem(),
		reflect.TypeOf(""),
		reflect.TypeOf(gate.Source{}),
		reflect.TypeOf(time.Duration(0)),
	}
	if got := open.Type.NumIn(); got != len(want) {
		t.Fatalf("gate.Gate.Open takes %d arguments, want %d (ctx, service, source, ttl); a fifth is "+
			"how a caller would hand a gate a destination", got, len(want))
	}
	for i, w := range want {
		if got := open.Type.In(i); got != w {
			t.Errorf("gate.Gate.Open argument %d is %v, want %v", i, got, w)
		}
	}
}

// The service name is the whole of a packet's say in which forward it selects,
// and the name is carried as a hash rather than as text. Nothing in the
// selection path is an address.
func TestAgent_ForwardTarget_AForwardIsSelectedByTheSameServiceIDAsAnyGate(t *testing.T) {
	local := config.Service{Name: "ssh", Kind: config.KindGate}
	fwd := config.Service{
		Name: "dbhost", Kind: config.KindGate,
		Forward: &config.Forward{To: netip.MustParseAddr("10.0.0.5"), Port: 22},
	}
	other := config.Service{
		Name: "dbhost", Kind: config.KindGate,
		Forward: &config.Forward{To: netip.MustParseAddr("192.0.2.77"), Port: 5432},
	}

	if fwd.ID() != other.ID() {
		t.Fatal("two forwards sharing a name have different service ids; the id is derived from the " +
			"target rather than from the name, which would put the target on the wire")
	}
	if fwd.ID() == local.ID() {
		t.Fatal("a forward and a local gate with different names share a service id")
	}
	plain := config.Service{Name: "dbhost", Kind: config.KindGate}
	if fwd.ID() != plain.ID() {
		t.Fatal("a service id depends on whether the service is a forward")
	}
}

// The packet-facing half of the same rule, stated where an operator meets it:
// a host that declares a forward gets a ruleset naming the configured target,
// and the only thing a knock contributes to that ruleset is a set element.
func TestAgent_ForwardTarget_TheRulesetNamesTheConfiguredTargetAndNothingElse(t *testing.T) {
	policy := &config.Policy{
		SPAPort:          62201,
		AlwaysAllowIface: "tailscale0",
		Services: map[string]config.Service{
			"dbhost": {
				Name: "dbhost", Kind: config.KindGate, Proto: "tcp", Ports: []uint16{2222},
				DefaultTTL: time.Minute, MaxTTL: 5 * time.Minute,
				FailPosture: config.PostureClosed, ListenerExpectation: config.ListenerUnchecked,
				Backend: config.BackendNFTables,
				Forward: &config.Forward{To: netip.MustParseAddr("10.0.0.5"), Port: 22},
			},
		},
	}
	plan, err := gate.BuildRulesetPlan(policy)
	if err != nil {
		t.Fatalf("BuildRulesetPlan: %v", err)
	}

	out := gate.RenderBootNFT(plan)
	if !strings.Contains(out, "dnat ip to 10.0.0.5:22") {
		t.Fatalf("ruleset does not translate to the configured target:\n%s", out)
	}
	// A knock's asserted source is the one operator-supplied address on the
	// path. It must never appear as a translation target, which it cannot,
	// because BuildRulesetPlan's only input is the policy and nothing re-renders
	// per packet.
	if strings.Contains(out, "dnat ip to 198.51.100") {
		t.Fatalf("ruleset translates to an address no policy declared:\n%s", out)
	}
}
