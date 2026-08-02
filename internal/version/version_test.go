package version_test

import (
	"testing"

	"github.com/jotra7/postern/internal/version"
)

func TestVersion_Version_NonEmpty(t *testing.T) {
	if version.Version() == "" {
		t.Fatal("Version() returned empty string")
	}
}

func TestVersion_BuildTime_DefaultsToZeroWhenUnset(t *testing.T) {
	// buildUnix is empty in an unstamped test binary, so the zero value is the
	// only correct answer. A regression returning time.Now() here would be
	// indistinguishable from a real build timestamp to the clock-sanity check
	// that consumes this.
	if got := version.BuildTime(); !got.IsZero() {
		t.Fatalf("BuildTime() = %v, want zero for an unstamped build", got)
	}
}
