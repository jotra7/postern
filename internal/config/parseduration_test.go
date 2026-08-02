package config

import (
	"testing"
	"time"
)

// parseDuration takes a fallback and returns it for an empty string. That is
// correct for an *absent* key, but MarshalStandalone must never rely on it
// for a legitimately zero Duration: formatDuration renders zero as "0s", not
// "", specifically so this case never reaches the fallback branch. This
// pins that down directly, with a fallback deliberately different from zero
// so a bug that returned the fallback instead of parsing would be visible.
func TestConfig_ParseDuration_ZeroStringDoesNotFallBack(t *testing.T) {
	var errs ErrorList
	fallback := 5 * time.Minute

	got := parseDuration("0s", fallback, "test.field", &errs)

	if err := errs.Err(); err != nil {
		t.Fatalf("parseDuration(\"0s\", ...) reported an error: %v", err)
	}
	if got != 0 {
		t.Errorf("parseDuration(\"0s\", %s, ...) = %s, want 0 (must parse, not fall back)", fallback, got)
	}
}
