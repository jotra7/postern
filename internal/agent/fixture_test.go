package agent_test

import (
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/config"
	"github.com/jotra7/postern/internal/identity"
	"github.com/jotra7/postern/internal/replay"
	"github.com/jotra7/postern/internal/spa"
)

const (
	sshName      = "ssh"
	confirmName  = "confirm"
	disarmName   = "disarm"
	livenessName = "liveness"
)

// fixture is one operator, one host, and a Policy granting that operator
// every service, backed by a real (file-based) replay.Store so the
// counter/high-water tests exercise the actual retention and max()
// semantics rather than a hand-rolled stand-in for them.
type fixture struct {
	t        *testing.T
	operator identity.Signer
	host     identity.Signer
	opener   *spa.Opener
	policy   *config.Policy
	store    replay.Store
	now      time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	op, err := identity.Generate("laptop-primary")
	if err != nil {
		t.Fatalf("Generate operator: %v", err)
	}
	host, err := identity.Generate("web-01")
	if err != nil {
		t.Fatalf("Generate host: %v", err)
	}
	opener, _, err := spa.NewOpenerFromSigner(host, []identity.PublicIdentity{op.Public()})
	if err != nil {
		t.Fatalf("NewOpenerFromSigner: %v", err)
	}

	var hostID [16]byte
	for i := range hostID {
		hostID[i] = byte(i + 1)
	}

	policy := &config.Policy{
		HostID:             hostID,
		FreshnessWindow:    60 * time.Second,
		FreshnessWindowMax: 24 * time.Hour,
		Services: map[string]config.Service{
			sshName: {
				Name:                sshName,
				Kind:                config.KindGate,
				Proto:               "tcp",
				Ports:               []uint16{22},
				DefaultTTL:          120 * time.Second,
				MaxTTL:              300 * time.Second,
				FailPosture:         config.PostureClosed,
				ListenerExpectation: config.ListenerPresent,
			},
			confirmName:  {Name: confirmName, Kind: config.KindAction},
			disarmName:   {Name: disarmName, Kind: config.KindAction},
			livenessName: {Name: livenessName, Kind: config.KindAction},
		},
		Operators: []config.Operator{
			{
				Identity: op.Public(),
				Grants: []config.Grant{
					{
						Services:        []string{sshName, confirmName, disarmName, livenessName},
						MaxTTL:          300 * time.Second,
						AllowSourceCIDR: true,
						MinIPv4Prefix:   24,
						MinIPv6Prefix:   64,
					},
				},
			},
		},
	}

	store, err := replay.Open(filepath.Join(t.TempDir(), "replay.db"), replay.Options{})
	if err != nil {
		t.Fatalf("replay.Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	return &fixture{
		t:        t,
		operator: op,
		host:     host,
		opener:   opener,
		policy:   policy,
		store:    store,
		now:      time.Now(),
	}
}

func serviceID(name string) [16]byte {
	return config.Service{Name: name}.ID()
}

func randID() [16]byte {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return b
}

// gateRequest builds a canonical, observed-source gate request granted to
// f.operator for the ssh service, fresh as of f.now.
func (f *fixture) gateRequest() *spa.Request {
	f.t.Helper()
	pl, err := spa.EncodeGatePayload(spa.GatePayload{SourceKind: spa.SourceObserved})
	if err != nil {
		f.t.Fatalf("EncodeGatePayload: %v", err)
	}
	return &spa.Request{
		Version:     spa.Version1,
		Alg:         spa.AlgEd25519X25519,
		Kind:        spa.KindGate,
		KeyID:       f.operator.Public().KeyID(),
		HostID:      f.policy.HostID,
		RequestID:   randID(),
		ServiceID:   serviceID(sshName),
		Counter:     uint64(f.now.UnixMilli()),
		TimestampMS: uint64(f.now.UnixMilli()),
		TTLSeconds:  120,
		Payload:     pl,
	}
}

// actionRequest builds a canonical action request naming service with the
// given payload, fresh as of f.now, counter zero (as the wire format
// requires for every action).
func (f *fixture) actionRequest(service string, payload [32]byte) *spa.Request {
	return &spa.Request{
		Version:     spa.Version1,
		Alg:         spa.AlgEd25519X25519,
		Kind:        spa.KindAction,
		KeyID:       f.operator.Public().KeyID(),
		HostID:      f.policy.HostID,
		RequestID:   randID(),
		ServiceID:   serviceID(service),
		TimestampMS: uint64(f.now.UnixMilli()),
		Payload:     payload,
	}
}

func (f *fixture) seal(r *spa.Request) []byte {
	f.t.Helper()
	dg, err := spa.Seal(r, f.operator, f.host.Public().Encryption)
	if err != nil {
		f.t.Fatalf("Seal: %v", err)
	}
	return dg
}
