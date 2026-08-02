package probe

import (
	"net/netip"
	"testing"

	"github.com/jotra7/postern/internal/client"
)

// Every reason must have its own diagnosis, and the diagnoses must differ.
//
// describe() ends in a default branch that says "nothing is ruled in or out",
// which is the right answer for an unclassified connect error and the wrong
// answer for anything else: a reason added to the constants without a case
// here would report ignorance about a cause the code had already determined,
// and would do it silently. That is the failure this test exists for, and it
// is why the assertion is on distinctness rather than on non-emptiness — the
// default branch is non-empty.
//
// Mutation verified: deleting the ReasonNoRoute case from describe() makes it
// fall through to the default and collide with ReasonUnclassified, which
// fails here.
func TestProbe_Describe_GivesEveryReasonItsOwnDiagnosis(t *testing.T) {
	sw := Sweep{
		Host:        "web-01",
		Service:     "canary",
		ConnectAddr: netip.MustParseAddrPort("203.0.113.9:62202"),
	}
	seen := map[string]Reason{}
	for _, r := range Reasons {
		sw.Reason = r
		summary, detail := describe(sw)
		if summary == "" || detail == "" {
			t.Errorf("reason %q has summary %q and detail %q", r, summary, detail)
			continue
		}
		if prev, dup := seen[detail]; dup {
			t.Errorf("reason %q and reason %q share a diagnosis, so one of them has no case in describe():\n%s",
				r, prev, detail)
		}
		seen[detail] = r
	}
	// The count is the cardinality claim internal/metrics will rely on for
	// the `reason` label. Asserted rather than described.
	if len(Reasons) != 8 {
		t.Errorf("Reasons holds %d entries, want 8 (seven failures plus the empty reason a pass carries)", len(Reasons))
	}
	if Reasons[0] != ReasonNone {
		t.Errorf("Reasons[0] = %q, want the empty reason a passing sweep carries", Reasons[0])
	}
}

// Phase 1 and `postern open`'s pre-knock connect are the same measurement
// asked of the same outcomes, and they must not be able to disagree about
// which of those outcomes means the port was shut. If they drift, one of the
// two commands starts calling a host healthy on evidence the other calls a
// missing drop rule, and the two are looking at the same packet.
//
// The two are asserted as exact complements rather than by checking the pass
// case alone: a phase 1 that passed everything would satisfy "a timeout
// passes" and report every host green forever.
//
// Mutation verified: adding `case client.Refused: return ReasonNone, false`
// to closedFailure fails the refused row, and returning true for a timeout
// fails the timeout row.
func TestProbe_ClosedFailure_AgreesWithTheClientAboutWhatShutMeans(t *testing.T) {
	for _, o := range []client.Outcome{
		client.TimedOut,
		client.Connected,
		client.Refused,
		client.NoRoute,
		client.Unclassified,
		client.Outcome("something added later"),
	} {
		t.Run(string(o), func(t *testing.T) {
			_, failed := closedFailure(o)
			shut := client.PriorFrom(o) == client.PriorShut
			if failed == shut {
				t.Fatalf("phase 1 %s on %q while the client calls it shut=%v; the two judgements have "+
					"come apart", map[bool]string{true: "fails", false: "passes"}[failed], o, shut)
			}
		})
	}
}
