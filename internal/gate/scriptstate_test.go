package gate

import (
	"strings"
	"testing"
	"time"
)

// The header is what stops output from something else — an older revision of
// this format, an unrelated tool, a script printing usage on stdout — being
// read as a gate holding no admissions. "Holds nothing" is the one answer
// that makes a live hole invisible.
func TestGate_ParseScriptState_RequiresTheVersionHeader(t *testing.T) {
	if _, err := parseScriptState([]byte("203.0.113.5/32 observed 84\n")); err == nil {
		t.Fatal("parsed output with no version header")
	}
	if _, err := parseScriptState(nil); err == nil {
		t.Fatal("parsed empty output as an empty admission list")
	}
	if _, err := parseScriptState([]byte("postern-state-v2\n")); err == nil {
		t.Fatal("parsed output claiming a different format version")
	}
}

func TestGate_ParseScriptState_AcceptsAnEmptyAdmissionList(t *testing.T) {
	got, err := parseScriptState([]byte("postern-state-v1\n"))
	if err != nil {
		t.Fatalf("parseScriptState: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("elements = %d, want 0", len(got))
	}
}

func TestGate_ParseScriptState_IgnoresBlankAndCommentLines(t *testing.T) {
	in := "\n# leading comment\npostern-state-v1\n\n# another\n203.0.113.5/32 observed 30\n\n"
	got, err := parseScriptState([]byte(in))
	if err != nil {
		t.Fatalf("parseScriptState: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("elements = %d, want 1: %+v", len(got), got)
	}
	if got[0].Expires != 30*time.Second {
		t.Errorf("expires = %s, want 30s", got[0].Expires)
	}
}

// A bare address is the natural thing to echo back from a provider that
// stores single hosts, and everywhere else in this package that means a
// full-length prefix.
func TestGate_ParseScriptState_AcceptsABareAddressAsAFullLengthPrefix(t *testing.T) {
	got, err := parseScriptState([]byte("postern-state-v1\n203.0.113.5 observed -\n2001:db8::1 observed -\n"))
	if err != nil {
		t.Fatalf("parseScriptState: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("elements = %d, want 2", len(got))
	}
	if s := got[0].Source.Prefix.String(); s != "203.0.113.5/32" {
		t.Errorf("ipv4 prefix = %q, want 203.0.113.5/32", s)
	}
	if s := got[1].Source.Prefix.String(); s != "2001:db8::1/128" {
		t.Errorf("ipv6 prefix = %q, want 2001:db8::1/128", s)
	}
}

// An IPv4-mapped IPv6 address has to come back as IPv4, the same unmapping
// the packet path applies. Otherwise a script echoing ::ffff:203.0.113.5 back
// would never match the lease this backend recorded for 203.0.113.5, and its
// expiry could never be filled in.
func TestGate_ParseScriptState_UnmapsAnIPv4MappedAddress(t *testing.T) {
	got, err := parseScriptState([]byte("postern-state-v1\n::ffff:203.0.113.5/128 observed -\n"))
	if err != nil {
		t.Fatalf("parseScriptState: %v", err)
	}
	if s := got[0].Source.Prefix.String(); s != "203.0.113.5/32" {
		t.Errorf("prefix = %q, want 203.0.113.5/32", s)
	}
}

// Every malformed line is an error rather than a skipped line. A parser that
// dropped what it did not understand would report fewer open holes than
// really exist, which is the wrong direction for a tool whose job is knowing
// what is open.
func TestGate_ParseScriptState_RejectsMalformedLines(t *testing.T) {
	cases := map[string]string{
		"too few fields":     "postern-state-v1\n203.0.113.5/32 observed\n",
		"too many fields":    "postern-state-v1\n203.0.113.5/32 observed 30 extra\n",
		"not an address":     "postern-state-v1\nnot-an-address observed 30\n",
		"unknown kind":       "postern-state-v1\n203.0.113.5/32 guessed 30\n",
		"negative seconds":   "postern-state-v1\n203.0.113.5/32 observed -30\n",
		"non-numeric expiry": "postern-state-v1\n203.0.113.5/32 observed soon\n",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if got, err := parseScriptState([]byte(in)); err == nil {
				t.Fatalf("parsed %q as %+v, want an error", in, got)
			}
		})
	}
}

func TestGate_ParseScriptState_RejectsMoreAdmissionsThanTheCap(t *testing.T) {
	var b strings.Builder
	b.WriteString(ScriptStateHeader)
	b.WriteString("\n")
	for i := 0; i <= scriptStateMaxLines; i++ {
		b.WriteString("203.0.113.5/32 observed -\n")
	}
	if _, err := parseScriptState([]byte(b.String())); err == nil {
		t.Fatal("parsed more admissions than the cap allows")
	}
}

// The parse error has to name the line, because the operator's next move is
// to look at that line in their script's output.
func TestGate_ParseScriptState_ErrorNamesTheOffendingLine(t *testing.T) {
	_, err := parseScriptState([]byte("postern-state-v1\n203.0.113.5/32 observed 30\nbroken\n"))
	if err == nil {
		t.Fatal("no error")
	}
	if !strings.Contains(err.Error(), "line 3") {
		t.Errorf("error does not name line 3: %v", err)
	}
}
