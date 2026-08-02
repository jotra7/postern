package hub

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"
	"time"

	"github.com/jotra7/postern/internal/metrics"
)

// BeatsPath is where the per-host heartbeat freshness document is served, on
// the private listener Config.MetricsAddr names, alongside /metrics, and never
// on the public one.
//
// The split is the security property here, not a deployment convenience. A
// per-host freshness route reachable from the public listener would answer,
// for anyone who asked, which host_ids exist and which of them have stopped
// reporting: an inventory of the estate with the unattended machines marked.
// That is the reconnaissance the opaque 16-byte host_id was chosen to deny,
// and it is the same argument that keeps host names out of index.json.
const BeatsPath = "/beats"

// BeatsDoc is the body of a GET on BeatsPath: what this hub has observed of
// each host's checking in, and nothing about what the beats said.
//
// The beat body is deliberately absent. It is the host's own account of
// itself (agent version, gate element counts, listener status), telemetry that
// is additive by design and carries map keys the reporting host chooses.
// When a host last checked in is a different question, answered from this
// hub's clock rather than from anything a host claimed, and answering both at
// once would put host-chosen keys on an operator surface as a side effect of
// asking about freshness.
type BeatsDoc struct {
	// Now is this hub's clock when it built the document. Every AgeSeconds
	// below is measured against it, so a reader whose own clock disagrees
	// with the hub's still gets the ages the hub meant.
	Now time.Time `json:"now"`
	// ObservedSince is when this hub process began keeping heartbeats.
	// Nothing is persisted (see doc.go), so a host whose last beat predates
	// this instant is indistinguishable from one that has never beaten, and a
	// reader needs this to tell "quiet for an hour" from "the hub restarted a
	// minute ago".
	ObservedSince time.Time `json:"observed_since"`
	// Hosts is ordered by HostID, so two reads a second apart differ only
	// where something actually changed.
	Hosts []HostBeat `json:"hosts"`
}

// HostBeat is one host's line in a BeatsDoc.
type HostBeat struct {
	// HostID is the same 32 hex characters that name this host on the bundle
	// route and in index.json.
	HostID string `json:"host_id"`
	// Last is null for a host this hub knows of that has sent no beat since
	// BeatsDoc.ObservedSince. That is what separates a host which has never
	// checked in from one that checked in and went quiet: the second has a
	// Last whose ReceivedAt simply keeps ageing. The key is always present
	// and explicitly null rather than omitted, so a reader never has to tell
	// an absent field from a field it failed to spell.
	Last *LastBeat `json:"last"`
}

// LastBeat is what this hub observed of one host's most recent accepted beat.
type LastBeat struct {
	// Epoch and Sequence are the pair a beat's freshness is ordered by.
	// Epoch is the half that moves when a host is reinstalled or restored
	// from a snapshot and its own sequence counter goes backwards, so an
	// epoch that changed since an operator last looked is that event and no
	// other.
	Epoch    uint64 `json:"epoch"`
	Sequence uint64 `json:"sequence"`
	// ReceivedAt is this hub's own clock when it accepted the beat, never the
	// beat's self-reported sent_at. See Beats.Latest for why a host's own clock
	// is the wrong thing to measure its freshness with.
	ReceivedAt time.Time `json:"received_at"`
	// AgeSeconds is BeatsDoc.Now minus ReceivedAt, truncated toward zero. It
	// is the number this document exists to publish, computed once by the hub
	// so that every reader agrees on it.
	AgeSeconds int64 `json:"age_seconds"`
}

// privateRoutes is what the hub adds to its metrics listener beside /metrics.
// Serve is the only caller; it is a function rather than a literal in Serve
// so a test can mount exactly what production mounts.
func privateRoutes(s *server) []metrics.Route {
	return []metrics.Route{{
		// Method-restricted for the same reason the public mux's patterns
		// are: a route that answers only GET cannot be reached by anything
		// that mistook it for a write.
		Pattern: http.MethodGet + " " + BeatsPath,
		Handler: http.HandlerFunc(s.handleBeats),
	}}
}

// handleBeats builds the freshness document over the union of two sets: the
// hosts index.json names, and the hosts this process has accepted a beat
// from.
//
// Neither set alone will do. index.json is the only source that knows about a
// host which has never reported, which is the fact an operator most needs and
// the one a listing of beats cannot supply. The beat records are the only
// source for a host that has been removed from index.json since it last
// reported: Store re-reads that file on every request, so a host deleted
// between beats would otherwise vanish from this document while the hub was
// still holding its record and still had something to say about it.
func (s *server) handleBeats(w http.ResponseWriter, r *http.Request) {
	known, err := s.store.Hosts()
	if err != nil {
		// The store is the hub's own problem, and this listener is the
		// operator's own, so the status is the useful part rather than the
		// text: something is wrong with index.json, and the document would be
		// missing hosts if it were served anyway.
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	now := s.now()
	observed := s.beats.Snapshot()

	ids := make(map[[16]byte]struct{}, len(known)+len(observed))
	for _, id := range known {
		ids[id] = struct{}{}
	}
	for id := range observed {
		ids[id] = struct{}{}
	}

	doc := BeatsDoc{
		Now:           now.UTC(),
		ObservedSince: s.since.UTC(),
		Hosts:         make([]HostBeat, 0, len(ids)),
	}
	for id := range ids {
		entry := HostBeat{HostID: hex.EncodeToString(id[:])}
		if obs, ok := observed[id]; ok {
			entry.Last = &LastBeat{
				Epoch:      obs.Beat.Epoch,
				Sequence:   obs.Beat.Sequence,
				ReceivedAt: obs.At.UTC(),
				AgeSeconds: int64(now.Sub(obs.At) / time.Second),
			}
		}
		doc.Hosts = append(doc.Hosts, entry)
	}
	slices.SortFunc(doc.Hosts, func(a, b HostBeat) int {
		switch {
		case a.HostID < b.HostID:
			return -1
		case a.HostID > b.HostID:
			return 1
		}
		return 0
	})

	// Marshalled whole before a byte is written, rather than streamed with
	// json.NewEncoder(w): an encoder that fails partway has already committed
	// a 200 and a half-written body, and a reader cannot tell that from a
	// truncated transfer.
	body, err := json.Marshal(&doc)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}
