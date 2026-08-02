// Package version exposes build identity. BuildTime is consumed by the
// agent's clock-sanity check: a packet timestamp preceding the binary's
// build date indicates a broken host clock (design section 5).
package version

import (
	"strconv"
	"time"
)

// Set with -ldflags "-X github.com/jotra7/postern/internal/version.version=... -X ...buildUnix=..."
var (
	version   = "dev"
	buildUnix = ""
)

// Version returns the build version, or "dev" for an unstamped build.
func Version() string { return version }

// BuildTime returns the build timestamp, or the zero time when unstamped.
func BuildTime() time.Time {
	if buildUnix == "" {
		return time.Time{}
	}
	secs, err := strconv.ParseInt(buildUnix, 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(secs, 0).UTC()
}
