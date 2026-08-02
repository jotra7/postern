package spa_test

import (
	"net/netip"
	"testing"

	"github.com/jotra7/postern/internal/spa"
)

// FuzzParse asserts that Parse never panics and never accepts a record it
// cannot re-encode byte-identically. This package parses attacker-controlled
// bytes as root, which is what earns a fuzz target.
func FuzzParse(f *testing.F) {
	// Seed with one of each valid shape plus a few structurally interesting
	// mutations, so the fuzzer starts near the boundary rather than at random.
	f.Add(sampleGate().Marshal())

	asserted := sampleGate()
	pl, err := spa.EncodeGatePayload(spa.GatePayload{
		SourceKind: spa.SourceAsserted,
		Prefix:     netip.MustParsePrefix("2001:db8::/32"),
	})
	if err != nil {
		f.Fatalf("EncodeGatePayload: %v", err)
	}
	asserted.Payload = pl
	f.Add(asserted.Marshal())

	confirm := sampleGate()
	confirm.Kind = spa.KindAction
	confirm.Counter = 0
	confirm.TTLSeconds = 0
	confirm.Payload, _ = spa.EncodeConfirmPayload(7, [16]byte{1, 2, 3})
	f.Add(confirm.Marshal())

	f.Add(make([]byte, spa.InnerSize))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		req, err := spa.Parse(data)
		if err != nil {
			if req != nil {
				t.Fatal("Parse returned both a request and an error")
			}
			return
		}

		// A record that parses must round-trip exactly. If it does not, two
		// distinct byte strings map to one meaning, which is the property
		// canonical encoding exists to prevent.
		out := req.Marshal()
		if len(out) != len(data) {
			t.Fatalf("re-encode length %d, input %d", len(out), len(data))
		}
		for i := range out {
			if out[i] != data[i] {
				t.Fatalf("re-encode differs at byte %d: got %#x, input %#x", i, out[i], data[i])
			}
		}
	})
}
