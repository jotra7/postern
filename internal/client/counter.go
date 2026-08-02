package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sync"
)

// Counter is the client half of design section 5's freshness rule: the
// packet's counter is derived from the client's clock as unix milliseconds,
// with the client persisting the last value sent and using
//
//	max(now_ms, last_sent + 1)
//
// Both halves of that expression are load-bearing and each covers a
// different failure.
//
// now_ms is what keeps a client that lost its state usable at all: a fresh
// counter file still produces a value above every counter this operator sent
// more than a millisecond ago, so the agent's high-water mark does not
// permanently lock out a laptop that was reimaged.
//
// last_sent+1 is what keeps the sequence monotonic when the clock is not.
// Without it, two knocks inside the same millisecond produce the same
// counter — and the second one then fails the agent's strictly-greater
// comparison and falls back to the timestamp path, which is exactly the
// tolerance that path exists to provide for a different failure. A clock
// stepped backwards (NTP correction, a laptop resuming in another timezone
// with a bad RTC) is the same case, larger.
//
// The file is the operator's, not the agent's: the agent keeps its own
// high-water mark per key_id and never reads this.
type Counter struct {
	path string
	mu   sync.Mutex
}

// counterFile is the on-disk form. JSON rather than a bare integer so a
// future field (a per-host counter, say) does not need a format flag day.
type counterFile struct {
	LastCounter uint64 `json:"last_counter"`
}

// NewCounter returns a counter persisted at path. The path is a parameter
// rather than derived from the environment so a test can point it at a temp
// directory and assert on the real file.
func NewCounter(path string) *Counter {
	return &Counter{path: path}
}

// Next returns the counter for the next packet and persists it before
// returning, so a crash between minting and sending burns a counter rather
// than reusing one.
func (c *Counter) Next(nowMS uint64) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	last, err := c.read()
	if err != nil {
		return 0, err
	}
	// Refused rather than wrapped. A counter of 2^64-1 that rolls to 0 does
	// not fail visibly: the agent's high_water[key_id] stays pinned at the
	// maximum, every later knock from this operator fails the strictly-
	// greater comparison, and the counter path is gone for good on that host
	// — leaving only the timestamp path, which works until the day the clock
	// is the thing that is wrong. That is a silent, permanent loss of the
	// drift tolerance the counter exists to provide, so it is an error.
	if last == math.MaxUint64 {
		return 0, fmt.Errorf("counter state %s has reached the uint64 maximum; wrapping to zero would "+
			"pin the agent's high-water mark and silently disable the counter freshness path for this "+
			"operator forever", c.path)
	}
	next := nowMS
	if last+1 > next {
		next = last + 1
	}
	if err := c.write(next); err != nil {
		return 0, err
	}
	return next, nil
}

// Last reports the last counter handed out, or zero if none has been.
func (c *Counter) Last() (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.read()
}

func (c *Counter) read() (uint64, error) {
	data, err := os.ReadFile(c.path) //nolint:gosec // the path is the caller's own state file
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read counter state: %w", err)
	}
	var f counterFile
	if err := json.Unmarshal(data, &f); err != nil {
		return 0, fmt.Errorf("parse counter state %s: %w", c.path, err)
	}
	return f.LastCounter, nil
}

// write is atomic: a torn counter file would read as zero and hand the next
// knock a counter below the agent's high-water mark, which fails the counter
// path silently and leaves only the timestamp path — working, until the
// clock is the thing that is wrong.
func (c *Counter) write(v uint64) error {
	dir := filepath.Dir(c.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create counter directory: %w", err)
	}
	body, err := json.Marshal(counterFile{LastCounter: v})
	if err != nil {
		return fmt.Errorf("encode counter state: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".counter-*.tmp")
	if err != nil {
		return fmt.Errorf("create counter temp file: %w", err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()

	if _, err := tmp.Write(append(body, '\n')); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write counter state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync counter state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close counter state: %w", err)
	}
	if err := os.Chmod(name, 0o600); err != nil {
		return fmt.Errorf("chmod counter state: %w", err)
	}
	return os.Rename(name, c.path)
}
