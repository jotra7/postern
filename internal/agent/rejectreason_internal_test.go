package agent

import (
	"fmt"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/metrics"
	"github.com/jotra7/postern/internal/replay"
	"github.com/jotra7/postern/internal/spa"
)

func TestAgent_RejectReason_MapsEachSentinelToItsOwnLabel(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{spa.ErrWrongSize, "wrong_size"},
		{spa.ErrNotCanonical, "not_canonical"},
		{spa.ErrUnsupportedVersion, "unsupported_version"},
		{spa.ErrUnknownKind, "unknown_kind"},
		{spa.ErrNoOperator, "undecryptable"},
		{spa.ErrKeyIDMismatch, "key_id_mismatch"},
		{spa.ErrBadSignature, "bad_signature"},
		{ErrWrongHost, "wrong_host"},
		{ErrTooOld, "too_old"},
		{ErrNotFresh, "not_fresh"},
		{ErrUnknownService, "unknown_service"},
		{ErrNotGranted, "not_granted"},
		{ErrKindMismatch, "kind_mismatch"},
		{ErrConfirmUnbound, "confirm_unbound"},
		{ErrSourceNotAllowed, "source_not_allowed"},
		{ErrUnsupportedAction, "unsupported_action"},
		{ErrLivenessOffPath, "liveness_off_path"},
	}
	seen := map[string]error{}
	for _, tc := range cases {
		// Wrapped, because Validate wraps several of these before the daemon
		// ever sees them and an == comparison would silently fall through.
		got := rejectReason(fmt.Errorf("validate: %w", tc.err))
		if got != tc.want {
			t.Errorf("rejectReason(%v) = %q, want %q", tc.err, got, tc.want)
		}
		if prev, dup := seen[got]; dup {
			t.Errorf("rejectReason maps both %v and %v to %q; two rejections an operator must "+
				"distinguish would share a series", prev, tc.err, got)
		}
		seen[got] = tc.err
	}
}

// TestAgent_RejectReason_ReplayOutcomesOutrankTheStoreLabel is the ordering
// this mapping gets wrong if the ErrStore case is moved up: Validate wraps
// both replay outcomes in ErrStore, so a store-wide label would hide the one
// rejection an operator acts on. A duplicate request_id is a replay, not a
// disk problem.
func TestAgent_RejectReason_ReplayOutcomesOutrankTheStoreLabel(t *testing.T) {
	dup := fmt.Errorf("%w: %w", ErrStore, replay.ErrDuplicate)
	if got := rejectReason(dup); got != "replay" {
		t.Errorf("rejectReason(store-wrapped duplicate) = %q, want %q", got, "replay")
	}
	full := fmt.Errorf("%w: %w", ErrStore, replay.ErrCapacity)
	if got := rejectReason(full); got != "replay_capacity" {
		t.Errorf("rejectReason(store-wrapped capacity) = %q, want %q", got, "replay_capacity")
	}
	disk := fmt.Errorf("%w: %v", ErrStore, "read-only file system")
	if got := rejectReason(disk); got != "store" {
		t.Errorf("rejectReason(bare store failure) = %q, want %q", got, "store")
	}
}

func TestAgent_RejectReason_UnknownErrorIsOther(t *testing.T) {
	if got := rejectReason(fmt.Errorf("something nobody mapped")); got != metrics.ReasonOther {
		t.Errorf("rejectReason(unmapped) = %q, want %q", got, metrics.ReasonOther)
	}
}

// TestAgent_SignedSkew_KeepsDirection matters because the histogram takes the
// magnitude: without the sign, a host running an hour fast is indistinguishable
// from one running an hour slow, and the two have different causes.
func TestAgent_SignedSkew_KeepsDirection(t *testing.T) {
	const nowMS = uint64(1_700_000_000_000)
	if got := signedSkew(nowMS, nowMS-3_600_000); got != time.Hour {
		t.Errorf("signedSkew with a packet an hour old = %v, want +1h", got)
	}
	if got := signedSkew(nowMS, nowMS+3_600_000); got != -time.Hour {
		t.Errorf("signedSkew with a packet an hour in the future = %v, want -1h", got)
	}
	if got := signedSkew(nowMS, nowMS); got != 0 {
		t.Errorf("signedSkew with no skew = %v, want 0", got)
	}
}

// TestAgent_SignedSkew_CapsAnAbsurdTimestamp keeps a packet claiming a
// timestamp near the top of its uint64 field from wrapping into a small,
// innocuous-looking skew. The packet is unauthenticated input at the point
// its timestamp is first read, so the field is attacker-chosen.
func TestAgent_SignedSkew_CapsAnAbsurdTimestamp(t *testing.T) {
	got := signedSkew(1_700_000_000_000, ^uint64(0))
	if got >= 0 {
		t.Fatalf("signedSkew with a far-future timestamp = %v, want a large negative duration", got)
	}
	if got > -100*365*24*time.Hour {
		t.Fatalf("signedSkew with a far-future timestamp = %v, want it capped at a very large "+
			"magnitude rather than wrapped into a small one", got)
	}
}
