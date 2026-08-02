package agent_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/jotra7/postern/internal/agent"
	"github.com/jotra7/postern/internal/config"
)

// consoleRecoveryBundlePolicyBytes marshals a bundle policy that would turn
// this host into a console-recovery host: no always_allow_iface, with the
// ConsoleRecovery acknowledgment and a Console URL the bundle itself carries
// (a bundle can assert whatever it likes about itself; that is exactly the
// value this guard must not trust).
func consoleRecoveryBundlePolicyBytes(t *testing.T, h *bundleHarness, revision uint64) []byte {
	t.Helper()
	p := *h.policy
	p.Revision = revision
	p.SPAPort = 62201
	p.RecoveryService = sshName
	p.AlwaysAllowIface = ""
	p.ConsoleRecovery = true
	p.Console = "https://provider.example/console"
	data, err := config.MarshalStandalone(&p)
	if err != nil {
		t.Fatalf("MarshalStandalone: %v", err)
	}
	return data
}

// A bundle that drops the always-allow interface (turning a host into a
// console-recovery host) is refused unless the LOCAL config acknowledged
// console-recovery. The hub must not be able to strip a host's recovery path
// by carrying its own ConsoleRecovery:true in the fetched policy.
func TestAgent_Daemon_ABundleCannotEnableConsoleRecovery(t *testing.T) {
	srv, set := newBundleServer(t)
	// LocalConsoleRecovery defaults false; the harness's own fixture policy
	// has a real always_allow_iface, i.e. the local bootstrap never
	// acknowledged console-recovery.
	h := newBundleHarness(t, srv.URL, 0, nil)

	const version = txnHarnessRecordedRevision + 1
	set(h.sealValid(t, version, consoleRecoveryBundlePolicyBytes(t, h, version)))

	before := h.daemon.Policy()
	if err := h.daemon.Puller().PullOnce(context.Background()); err == nil {
		t.Fatal("PullOnce() = nil, want an error refusing to enable console-recovery")
	}
	if diff := cmp.Diff(before, h.daemon.Policy()); diff != "" {
		t.Errorf("running policy changed after a bundle tried to enable console-recovery (-before +after):\n%s", diff)
	}
	if _, ok, err := h.txn.txns.LastArm(); err != nil {
		t.Fatalf("LastArm: %v", err)
	} else if ok {
		t.Fatal("a transaction was armed for a bundle that should have been refused before arming")
	}
}

// The mirror case: a host whose LOCAL config DID acknowledge console-recovery
// accepts the identical bundle.
func TestAgent_Daemon_ABundleEnablingConsoleRecoveryIsAcceptedWhenTheLocalConfigAcknowledgedIt(t *testing.T) {
	srv, set := newBundleServer(t)
	h := newBundleHarnessTuned(t, srv.URL, 0, nil, func(o *agent.Options) {
		o.LocalConsoleRecovery = true
	})

	const version = txnHarnessRecordedRevision + 1
	set(h.sealValid(t, version, consoleRecoveryBundlePolicyBytes(t, h, version)))

	if err := h.daemon.Puller().PullOnce(context.Background()); err != nil {
		t.Fatalf("PullOnce() = %v, want nil; the local config acknowledged console-recovery", err)
	}
	if got := h.daemon.Policy().Revision; got != version {
		t.Fatalf("running policy revision = %d, want %d", got, version)
	}
	if got := h.daemon.Policy().AlwaysAllowIface; got != "" {
		t.Fatalf("running policy always_allow_iface = %q, want empty (console-recovery armed)", got)
	}
}
