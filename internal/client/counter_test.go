package client_test

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jotra7/postern/internal/client"
)

// Invariant 2. The counter must be max(now_ms, last_sent+1) and it must
// survive the process, because both halves cover a different failure and a
// counter that is neither is a knock the agent's counter path silently
// declines.
//
// The mutations this catches, verified by making each one:
//
//   - next := nowMS (drop last+1): the second call inside one millisecond
//     repeats a counter, and "strictly greater" fails on the agent.
//   - next := last + 1 (drop nowMS): a client whose state file was lost
//     restarts at 1 and never again exceeds the agent's high-water mark.
//   - drop the write: nothing persists and every run starts over.
func TestClient_Counter_IsMonotonicAcrossClockAndProcess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "counter.json")
	c := client.NewCounter(path)

	first, err := c.Next(1000)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if first != 1000 {
		t.Fatalf("a fresh counter at now_ms=1000 = %d, want 1000; without the now_ms half a client "+
			"that lost its state starts below the agent's high-water mark", first)
	}

	// Same millisecond: only last+1 can produce a greater value.
	second, err := c.Next(1000)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if second != 1001 {
		t.Fatalf("two knocks in the same millisecond produced %d then %d; the second must be the "+
			"first plus one, or the agent's strictly-greater comparison rejects it", first, second)
	}

	// Clock stepped backwards — an NTP correction, or a laptop resuming with
	// a bad RTC. The sequence must not go with it.
	third, err := c.Next(500)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if third != 1002 {
		t.Fatalf("after the clock stepped back to 500 the counter was %d, want 1002", third)
	}

	// A new Counter over the same path is a new process.
	reopened := client.NewCounter(path)
	fourth, err := reopened.Next(500)
	if err != nil {
		t.Fatalf("Next after reopen: %v", err)
	}
	if fourth != 1003 {
		t.Fatalf("a reopened counter produced %d, want 1003; the value did not survive the process", fourth)
	}
}

func TestClient_Counter_TracksAheadOfAWallClockThatMovesForward(t *testing.T) {
	c := client.NewCounter(filepath.Join(t.TempDir(), "counter.json"))
	if _, err := c.Next(1000); err != nil {
		t.Fatalf("Next: %v", err)
	}
	// A later knock, minutes later. now_ms wins; the counter does not crawl
	// upward one at a time from where it was.
	got, err := c.Next(1_000_000)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if got != 1_000_000 {
		t.Fatalf("counter = %d, want the wall clock 1000000; the now_ms half is what keeps a client "+
			"usable after its state file is lost", got)
	}
}

func TestClient_Counter_WritesTheStateFileWithOwnerOnlyPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "counter.json")
	c := client.NewCounter(path)
	if _, err := c.Next(1000); err != nil {
		t.Fatalf("Next: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("counter file mode = %o, want 600", perm)
	}
}

func TestClient_Counter_RejectsACorruptStateFileRatherThanRestartingFromZero(t *testing.T) {
	path := filepath.Join(t.TempDir(), "counter.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := client.NewCounter(path).Next(1000); err == nil {
		t.Fatal("a corrupt counter file was accepted; silently restarting from zero would produce " +
			"counters below the agent's high-water mark with no diagnostic")
	}
}

// The mutex is load-bearing, not tidiness. Two `postern open` invocations in
// one process — and, once this package grows a concurrent caller, any two
// goroutines — that both read `last` before either writes mint the same
// counter. The consequence is bounded rather than dangerous (the second
// packet fails the agent's strictly-greater comparison and falls back to the
// timestamp path, which is exactly what that path is for), but a counter
// that silently stops being monotonic under concurrency is not the thing
// this type claims to be.
//
// The clock is frozen so `last+1` is the only source of increase: any
// interleaving that reads a stale `last` produces a duplicate rather than
// merely a smaller gap.
//
// Mutation verified: deleting c.mu.Lock()/Unlock() from Next fails this
// test, with and without -race.
func TestClient_Counter_IsMonotonicUnderConcurrentCallers(t *testing.T) {
	c := client.NewCounter(filepath.Join(t.TempDir(), "counter.json"))

	const workers, each = 8, 25
	results := make(chan uint64, workers*each)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				v, err := c.Next(1000)
				if err != nil {
					t.Errorf("Next: %v", err)
					return
				}
				results <- v
			}
		}()
	}
	wg.Wait()
	close(results)

	seen := map[uint64]bool{}
	for v := range results {
		if seen[v] {
			t.Fatalf("counter %d was handed out twice; two knocks carrying the same counter mean the "+
				"second one fails the agent's strictly-greater comparison", v)
		}
		seen[v] = true
	}
	if len(seen) != workers*each {
		t.Fatalf("got %d distinct counters from %d calls", len(seen), workers*each)
	}
}

// Wrapping to zero is not a distant hypothetical to leave undefined: it
// pins the agent's high-water mark at the maximum and removes the counter
// freshness path for this operator permanently, with no diagnostic.
func TestClient_Counter_RefusesToWrapPastTheUint64Maximum(t *testing.T) {
	path := filepath.Join(t.TempDir(), "counter.json")
	body := fmt.Sprintf(`{"last_counter":%d}`, uint64(math.MaxUint64))
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := client.NewCounter(path).Next(1000)
	if err == nil {
		t.Fatalf("Next returned %d instead of refusing to wrap; a wrapped counter silently disables "+
			"the counter freshness path for this operator forever", got)
	}
	if !strings.Contains(err.Error(), "maximum") {
		t.Fatalf("the error does not explain what happened: %v", err)
	}
}
