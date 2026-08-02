package agent

import (
	"context"
	"net"
	"time"
)

// CommitTransactionForTest drives the confirm-commit step directly, binding
// the commit to (revision, nonce) exactly as a validated confirm Decision
// does. The seam exists because the defect it guards lives in the window
// between a confirm's validation and its commit: a BeginTransaction landing
// there makes d.pending name a revision the confirm was never bound to, and
// reproducing that through the packet loop would be racing the very window the
// fix closes. Verifying by construction — a commit bound to one transaction
// refusing to ratify another — is what the fix is.
func CommitTransactionForTest(d *Daemon, ctx context.Context, revision uint64, nonce [16]byte) error {
	return d.commitTransaction(ctx, revision, nonce)
}

// ClassifyAlwaysAllowIface exposes the verdict half of the always-allow
// precondition. The seam exists because the states that matter most — down,
// and up with no address — cannot be produced on the machine running the
// tests without root and a synthetic interface, and a branch that can only
// be exercised on somebody's laptop is a branch nothing checks.
func ClassifyAlwaysAllowIface(name string, flags net.Flags, addrs int, addrErr error) error {
	return classifyAlwaysAllowIface(name, flags, addrs, addrErr)
}

// SetAfterResolveHook installs a callback that runs between a transaction
// being resolved and the pending slot being cleared. See Daemon's
// afterResolveHook field for why the seam exists: the interleaving
// clearPending guards against is unreachable through the public API now that
// Transactions serializes Prepare against Revert, and a guard that cannot be
// driven is a guard nobody can prove still works.
func SetAfterResolveHook(d *Daemon, f func()) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.afterResolveHook = f
}

// PullerNextInterval exposes the jittered-sleep computation Run uses between
// pulls, so a test can sample its distribution directly rather than timing
// real sleeps.
func PullerNextInterval(p *Puller) time.Duration {
	return p.jitteredInterval()
}

// MaxBundleResponseBytesForTest exposes the fetch size cap, so a test can
// build a response that is exactly at, or exactly over, the boundary without
// hard-coding the constant a second time.
const MaxBundleResponseBytesForTest = maxBundleResponseBytes

// SetBeatDurableCheckpoint installs a callback that runs after every fsync
// the heartbeat state file performs, with the file's path.
//
// The seam exists because the defect it guards against lived only BETWEEN
// two durable states: the old compaction truncated the file to nothing,
// rewrote the header, and only then wrote the record, so a crash in the
// middle left a header-only file whose reopen restarted the sequence at 1 —
// and the hub then refused every beat for the life of the epoch. A test that
// could only look at the file before and after a compaction would have seen
// nothing wrong with either.
//
// Passing nil removes it. Callers must remove it before returning, or a
// later test's Beater will call into a closed-over *testing.T.
func SetBeatDurableCheckpoint(f func(path string)) {
	beatCheckpointMu.Lock()
	defer beatCheckpointMu.Unlock()
	beatCheckpoint = f
}

// BeatStateCompactThreshold exposes how many records accumulate before the
// state file is compacted, so a test can stage a file one record short of it
// rather than hard-coding the number a second time.
const BeatStateCompactThreshold = beatStateCompactThreshold

// NewLoopbackHTTPCarrier binds the HTTP carrier on an ephemeral loopback port
// and reports the address it got.
//
// Loopback and port zero, deliberately: these tests drive a real net/http
// server, because the properties under test — that every response is
// byte-identical, that a proxy header cannot choose whose address the gate
// opens for — are properties of what actually crosses a socket, and a test
// that called the handler through httptest.NewRecorder would be checking a
// handler rather than a listener. Nothing here should be reachable from
// outside the machine running the test.
func NewLoopbackHTTPCarrier() (Receiver, net.Addr, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	r := newHTTPReceiverOn(ln)
	return r, r.Addr(), nil
}

// HTTPCarrierMaxBodyForTest exposes the body cap so a test can build a request
// exactly at, and exactly over, the boundary without restating the number.
const HTTPCarrierMaxBodyForTest = httpCarrierMaxBody

// NewMultiReceiverForTest fans several carriers into one, exposing the seam
// the daemon uses so a test can drive both carriers into a single packet loop
// without binding real sockets for the UDP half.
func NewMultiReceiverForTest(primary Receiver, all ...Receiver) Receiver {
	return newMultiReceiver(primary, all...)
}

// RejectLogWindowFactorForTest exposes the multiple of a loop's interval that
// its rejection logging is throttled to, so a test can step past the window
// without hard-coding the number a second time.
const RejectLogWindowFactorForTest = rejectLogWindowFactor

// LoopStopTimeoutForTest exposes how long shutdown waits for Run's background
// loops, so a test can assert against the real bound rather than restating it
// and can size its own deadlines above it.
const LoopStopTimeoutForTest = loopStopTimeout

// PullLoopNameForTest exposes the name shutdown logs for the bundle puller,
// so a test asserting on that line matches the name the code actually uses
// rather than a copy of it that a rename would leave behind.
const PullLoopNameForTest = pullLoopName

// BeatLoopNameForTest exposes the name shutdown logs for the heartbeat
// emitter, for the same reason PullLoopNameForTest exposes the puller's.
const BeatLoopNameForTest = beatLoopName
