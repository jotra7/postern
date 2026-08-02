package hub

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/attest"
)

// clockAt pins the hub's clock so every age in the document is arithmetic
// rather than a race with how long the test took to run.
func clockAt(now time.Time) func(*server) {
	return func(s *server) { s.now = func() time.Time { return now } }
}

// observingSince pins when this hub process began keeping beats.
func observingSince(since time.Time) func(*server) {
	return func(s *server) { s.since = since }
}

// enroll rewrites the test store's index.json to name exactly ids, which is
// what makes a host known to the hub before it has said anything.
func enroll(t *testing.T, h *testHub, ids ...[16]byte) {
	t.Helper()
	entries := make([]string, 0, len(ids))
	for _, id := range ids {
		entries = append(entries, `"`+hex.EncodeToString(id[:])+`":{"signing":"AA==","version":1}`)
	}
	writeIndex(t, h.dir, `{"hosts":{`+strings.Join(entries, ",")+`}}`)
}

// record puts a beat straight into the hub's memory at a chosen receipt time.
// It bypasses the HTTP route on purpose: the signature path is server_test's
// subject, and what these tests need is control of the hub's clock at the
// moment of acceptance.
func record(t *testing.T, h *testHub, id [16]byte, epoch, sequence uint64, at time.Time) {
	t.Helper()
	b := &attest.Beat{
		HostID:   id,
		Epoch:    epoch,
		Sequence: sequence,
		// Deliberately hours away from at, so a document that reported the
		// host's own clock instead of the hub's would be obvious.
		SentAt: at.Add(9 * time.Hour),
		Body:   attest.Body{AgentVersion: "0.0.0-test", ConfigHash: "deadbeef"},
	}
	if err := h.Beats.Accept(b, at); err != nil {
		t.Fatalf("Accept(%x, epoch %d, sequence %d): %v", id, epoch, sequence, err)
	}
}

// fetchBeats reads the freshness document off the private listener.
func fetchBeats(t *testing.T, h *testHub) (*BeatsDoc, []byte) {
	t.Helper()
	resp := get(t, h.PrivateURL+BeatsPath)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s body: %v", BeatsPath, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d %q, want 200", BeatsPath, resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var doc BeatsDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decode %s body %q: %v", BeatsPath, body, err)
	}
	return &doc, body
}

func hostEntry(t *testing.T, doc *BeatsDoc, id [16]byte) HostBeat {
	t.Helper()
	want := hex.EncodeToString(id[:])
	for _, entry := range doc.Hosts {
		if entry.HostID == want {
			return entry
		}
	}
	t.Fatalf("no entry for host %s in %+v", want, doc.Hosts)
	return HostBeat{}
}

// --- the split that keeps this off the public listener ----------------------

// A per-host freshness route on the public listener would hand a stranger the
// list of host_ids and mark the ones that stopped answering.
//
// Both halves are asserted against the same path on the same hub, and the
// private half is asserted first and by content rather than by status alone.
// A test that only checked for a 404 on the public listener would pass if
// BeatsPath were misspelled here, or renamed out from under it, or if the
// route stopped existing altogether, which are three ways to prove nothing.
// The pair can only pass while the route both exists and is on exactly one of
// the two listeners.
func TestHub_BeatsRoute_IsOnThePrivateListenerAndNotThePublicOne(t *testing.T) {
	h := startTestHub(t)

	priv := get(t, h.PrivateURL+BeatsPath)
	body, err := io.ReadAll(priv.Body)
	_ = priv.Body.Close()
	if err != nil {
		t.Fatalf("read private %s: %v", BeatsPath, err)
	}
	if priv.StatusCode != http.StatusOK {
		t.Fatalf("GET %s on the private listener = %d %q, want 200", BeatsPath, priv.StatusCode, body)
	}
	if !bytes.Contains(body, []byte(`"hosts"`)) || !bytes.Contains(body, []byte(`"observed_since"`)) {
		t.Fatalf("the private listener answered %s with %q, which is not the freshness document; "+
			"the public assertion below proves nothing unless this really is the route", BeatsPath, body)
	}

	pub := get(t, h.PublicURL+BeatsPath)
	_ = pub.Body.Close()
	if pub.StatusCode != http.StatusNotFound {
		t.Fatalf("GET %s on the public listener = %d, want 404. This route says which host_ids exist "+
			"and which of them have gone quiet, which is exactly what an opaque host_id exists to deny",
			BeatsPath, pub.StatusCode)
	}
}

// The private listener still carries /metrics; the freshness document is
// beside it, not instead of it.
func TestHub_BeatsRoute_IsServedBesideMetrics(t *testing.T) {
	h := startTestHub(t)
	resp := get(t, h.PrivateURL+"/metrics")
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /metrics: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /metrics on the private listener = %d, want 200", resp.StatusCode)
	}
	if !bytes.Contains(body, []byte("postern_hub_known_hosts")) {
		t.Fatalf("/metrics on the private listener does not carry the hub registry: %q", body)
	}
}

func TestHub_BeatsRoute_RejectsPOST(t *testing.T) {
	h := startTestHub(t)
	resp := post(t, h.PrivateURL+BeatsPath, []byte("{}"))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST %s = %d, want 405", BeatsPath, resp.StatusCode)
	}
}

// --- absence -----------------------------------------------------------------

// The two facts an operator has to be able to tell apart. A host that has
// never checked in is in the document with no last beat at all; a host that
// checked in and went quiet is in it with a last beat whose age keeps
// growing. Reporting only the second set would make the first invisible,
// which is the one an operator most needs to see.
func TestHub_BeatsRoute_DistinguishesAHostThatNeverBeatFromOneThatWentQuiet(t *testing.T) {
	now := time.Date(2026, 5, 4, 9, 0, 0, 0, time.UTC)
	h := startTestHub(t, clockAt(now))
	quiet := h.hostID
	never := [16]byte{0xf0, 0x0d}
	enroll(t, h, quiet, never)
	record(t, h, quiet, 3, 91, now.Add(-2*time.Hour))

	doc, _ := fetchBeats(t, h)
	if len(doc.Hosts) != 2 {
		t.Fatalf("document has %d hosts, want 2: %+v", len(doc.Hosts), doc.Hosts)
	}

	if last := hostEntry(t, doc, never).Last; last != nil {
		t.Errorf("a host that has never beaten carries last = %+v, want null", last)
	}
	last := hostEntry(t, doc, quiet).Last
	if last == nil {
		t.Fatal("a host that beat two hours ago carries no last beat, so it is indistinguishable " +
			"from one that has never reported")
	}
	if last.AgeSeconds != int64(2*time.Hour/time.Second) {
		t.Errorf("age_seconds = %d, want %d", last.AgeSeconds, int64(2*time.Hour/time.Second))
	}
}

// A host removed from index.json after it last reported still has a record in
// memory, and dropping it from the document would make a host the hub is
// still holding state for look like it does not exist.
func TestHub_BeatsRoute_KeepsAHostRemovedFromTheIndexWhileItStillHasARecord(t *testing.T) {
	now := time.Date(2026, 5, 4, 9, 0, 0, 0, time.UTC)
	h := startTestHub(t, clockAt(now))
	record(t, h, h.hostID, 1, 1, now.Add(-time.Minute))

	other := [16]byte{0x0b}
	enroll(t, h, other) // h.hostID is no longer named

	doc, _ := fetchBeats(t, h)
	if len(doc.Hosts) != 2 {
		t.Fatalf("document has %d hosts, want 2 (the one still enrolled and the one still on record): %+v",
			len(doc.Hosts), doc.Hosts)
	}
	if last := hostEntry(t, doc, h.hostID).Last; last == nil || last.Sequence != 1 {
		t.Fatalf("a host with a record but no index entry carries last = %+v, want its recorded beat", last)
	}
}

// Nothing is persisted, so a hub that has just restarted reports every host as
// never having beaten. observed_since is what tells a reader that the silence
// belongs to the hub rather than to the fleet.
func TestHub_BeatsRoute_ReportsWhenThisProcessBeganObserving(t *testing.T) {
	now := time.Date(2026, 5, 4, 9, 0, 0, 0, time.UTC)
	since := now.Add(-30 * time.Second)
	h := startTestHub(t, clockAt(now), observingSince(since))

	doc, _ := fetchBeats(t, h)
	if !doc.ObservedSince.Equal(since) {
		t.Fatalf("observed_since = %v, want %v", doc.ObservedSince, since)
	}
	if !doc.Now.Equal(now) {
		t.Fatalf("now = %v, want the hub's clock %v", doc.Now, now)
	}
	if last := hostEntry(t, doc, h.hostID).Last; last != nil {
		t.Fatalf("a host that has not beaten since the process started carries last = %+v, want null", last)
	}
}

// --- what a record carries ---------------------------------------------------

// Epoch, sequence, and the hub's own receipt time. Epoch is the half that
// moves when a host is reinstalled or restored and its sequence counter goes
// backwards, so a document without it cannot tell that event from a replay
// being refused.
func TestHub_BeatsRoute_CarriesEpochSequenceAndTheHubsOwnReceiptTime(t *testing.T) {
	now := time.Date(2026, 5, 4, 9, 0, 0, 0, time.UTC)
	receivedAt := now.Add(-90 * time.Second)
	h := startTestHub(t, clockAt(now))
	record(t, h, h.hostID, 4, 12345, receivedAt)

	doc, _ := fetchBeats(t, h)
	last := hostEntry(t, doc, h.hostID).Last
	if last == nil {
		t.Fatal("no last beat for a host that just reported")
	}
	if last.Epoch != 4 {
		t.Errorf("epoch = %d, want 4; without it a reinstalled host is indistinguishable from a replay",
			last.Epoch)
	}
	if last.Sequence != 12345 {
		t.Errorf("sequence = %d, want 12345", last.Sequence)
	}
	if !last.ReceivedAt.Equal(receivedAt) {
		t.Fatalf("received_at = %v, want the hub's own clock at acceptance (%v); the beat's sent_at was "+
			"%v, and a host with a fast clock must not be able to report itself fresher than the hub saw it",
			last.ReceivedAt, receivedAt, receivedAt.Add(9*time.Hour))
	}
	if last.AgeSeconds != 90 {
		t.Errorf("age_seconds = %d, want 90", last.AgeSeconds)
	}
	if want := int64(doc.Now.Sub(last.ReceivedAt) / time.Second); last.AgeSeconds != want {
		t.Errorf("age_seconds = %d, but now minus received_at is %d; the two must agree or a reader "+
			"has two answers to the same question", last.AgeSeconds, want)
	}
}

// The document's keys are a contract an operator tool decodes, and the beat
// body is deliberately not among them: it is the host's own account of
// itself, with map keys the host chooses, and freshness is answered from this
// hub's clock instead.
func TestHub_BeatsRoute_CarriesOnlyTheHubsObservationAndNoneOfTheBeatBody(t *testing.T) {
	now := time.Date(2026, 5, 4, 9, 0, 0, 0, time.UTC)
	h := startTestHub(t, clockAt(now))
	// A host that has beaten and one that has not, because the two carry
	// different shapes and both are part of the contract.
	silent := [16]byte{0x00, 0x01}
	enroll(t, h, h.hostID, silent)
	record(t, h, h.hostID, 1, 1, now.Add(-time.Second))

	doc, raw := fetchBeats(t, h)

	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatalf("decode document: %v", err)
	}
	assertKeys(t, "the document", top, "now", "observed_since", "hosts")

	var hosts []map[string]json.RawMessage
	if err := json.Unmarshal(top["hosts"], &hosts); err != nil {
		t.Fatalf("decode hosts: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("hosts has %d entries, want 2", len(hosts))
	}
	// Ordered, so index 0 is the silent host and index 1 the one that beat.
	if doc.Hosts[0].HostID != hex.EncodeToString(silent[:]) {
		t.Fatalf("first host is %s, want the silent one", doc.Hosts[0].HostID)
	}
	for i, entry := range hosts {
		assertKeys(t, "a host entry", entry, "host_id", "last")
		if i == 0 && string(entry["last"]) != "null" {
			t.Errorf("a host that has never beaten carries last = %s, want an explicit null so a reader "+
				"never has to tell an absent key from a misspelt one", entry["last"])
		}
	}

	var last map[string]json.RawMessage
	if err := json.Unmarshal(hosts[1]["last"], &last); err != nil {
		t.Fatalf("decode last: %v", err)
	}
	assertKeys(t, "a last beat", last, "epoch", "sequence", "received_at", "age_seconds")

	// The body fields record() put on the beat, and any verdict the hub might
	// have been tempted to compute on the reader's behalf.
	for _, forbidden := range []string{"agent_version", "config_hash", "0.0.0-test", "deadbeef",
		"fresh", "stale", "sent_at"} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Errorf("the document carries %q: %s", forbidden, raw)
		}
	}
}

func assertKeys(t *testing.T, what string, got map[string]json.RawMessage, want ...string) {
	t.Helper()
	keys := make([]string, 0, len(got))
	for k := range got {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	sort.Strings(want)
	if strings.Join(keys, ",") != strings.Join(want, ",") {
		t.Errorf("%s has keys %v, want %v", what, keys, want)
	}
}

// --- ordering and failure ----------------------------------------------------

// Sorted by host_id, so two reads a second apart differ only where something
// changed rather than wherever Go's map iteration happened to land.
func TestHub_BeatsRoute_OrdersHostsByHostID(t *testing.T) {
	h := startTestHub(t)
	// Eight, not two or three: Go randomises map iteration, so a handful of
	// hosts would come out sorted by chance often enough for a missing sort
	// to pass this test on most runs.
	ids := [][16]byte{{0xff}, {0x01}, {0x7f}, {0x00, 0x02}, {0x91}, {0x10}, {0x40}, {0xc3}}
	enroll(t, h, ids...)

	doc, _ := fetchBeats(t, h)
	if len(doc.Hosts) != len(ids) {
		t.Fatalf("document has %d hosts, want %d", len(doc.Hosts), len(ids))
	}
	for i := 1; i < len(doc.Hosts); i++ {
		if doc.Hosts[i-1].HostID >= doc.Hosts[i].HostID {
			t.Fatalf("hosts are not ordered by host_id: %q before %q",
				doc.Hosts[i-1].HostID, doc.Hosts[i].HostID)
		}
	}
}

// An index.json that cannot be parsed means the fleet cannot be enumerated,
// and a document served anyway would silently be missing every host that has
// not beaten yet.
func TestHub_BeatsRoute_FailsWhenTheIndexCannotBeRead(t *testing.T) {
	h := startTestHub(t)
	writeIndex(t, h.dir, `{"hosts": [ not json at all`)

	resp := get(t, h.PrivateURL+BeatsPath)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("GET %s with an unparseable index.json = %d, want 500", BeatsPath, resp.StatusCode)
	}
}
