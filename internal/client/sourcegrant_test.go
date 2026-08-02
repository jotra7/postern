package client_test

import (
	"context"
	"encoding/base64"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/client"
)

// hostAllowing returns the fixture host with its asserted-source record set
// to allowed, refused, or absent. It goes through ParseConfig rather than
// setting the field directly, so what is under test is the entry an operator
// actually holds on disk — including the case where the key is missing from
// it entirely.
func hostAllowing(t *testing.T, line string) *client.Host {
	t.Helper()
	hostKey := mustGenerate(t, "web-01").Public()
	yaml := "" +
		"operator: laptop-primary\n" +
		"hosts:\n" +
		"  - name: web-01\n" +
		"    host_id: 3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a\n" +
		"    knock_addr: 203.0.113.9\n" +
		"    knock_port: 62201\n" +
		"    host_encryption: " + base64.StdEncoding.EncodeToString(hostKey.Encryption[:]) + "\n" +
		"    recovery_service: ssh\n" +
		line +
		"    services:\n" +
		"      ssh: { port: 22, ttl: 120s }\n"
	cfg, err := client.ParseConfig([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	h, err := cfg.Host("web-01")
	if err != nil {
		t.Fatalf("Host: %v", err)
	}
	return h
}

// The entry is the only thing the client can consult, and it has three
// answers, not two. Collapsing "the entry does not say" into "the host
// refuses" would suppress the one piece of advice a client can offer on
// every host enrolled before the field existed.
func TestClient_Host_AssertedSourceGrantDistinguishesSilenceFromRefusal(t *testing.T) {
	for _, tc := range []struct {
		name string
		line string
		want client.AssertedSourceGrant
	}{
		{"the entry allows it", "    allow_source_cidr: true\n", client.AssertedSourceGranted},
		{"the entry refuses it", "    allow_source_cidr: false\n", client.AssertedSourceNotGranted},
		{"the entry does not say", "", client.AssertedSourceUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := hostAllowing(t, tc.line).AssertedSourceGrant(); got != tc.want {
				t.Fatalf("AssertedSourceGrant() = %v, want %v", got, tc.want)
			}
		})
	}
}

// The defect this fixes. On a host enrolled without the grant, retrying with
// --source-cidr is refused by the agent, and refused without a reply — so an
// operator who follows the advice waits out a second identical timeout while
// still locked out. The advice must not be given in that case, and must still
// be given when the entry does not know, because there it may well work.
//
// Mutation verified: restoring the unconditional hint (dropping the
// AssertedSourceNotGranted branch from Advise) fails the "refused" row on
// SourceCIDRHint; making the not-granted branch also cover Unknown fails the
// "does not say" row.
func TestClient_Advise_WithholdsTheSourceCIDRRetryWhenTheEntrySaysItIsRefused(t *testing.T) {
	base := client.Sent{
		Host:      "web-01",
		Service:   "ssh",
		Addr:      addr(t, "203.0.113.9:22"),
		Delivered: true,
		TTL:       2 * time.Minute,
	}
	for _, tc := range []struct {
		name     string
		grant    client.AssertedSourceGrant
		wantHint bool
		wantSaid string
	}{
		{"the entry allows it", client.AssertedSourceGranted, true, "enrolled to accept one"},
		{"the entry refuses it", client.AssertedSourceNotGranted, false, "enrolled to accept none"},
		{"the entry does not say", client.AssertedSourceUnknown, true, "does not record whether"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sent := base
			sent.SourceGrant = tc.grant
			a := client.Advise(client.Result{Outcome: client.TimedOut}, sent)

			if a.SourceCIDRHint != tc.wantHint {
				t.Fatalf("SourceCIDRHint = %v, want %v; hint reads: %s", a.SourceCIDRHint, tc.wantHint, a.Hint)
			}
			if got := strings.Contains(a.Hint, "--source-cidr"); got != tc.wantHint {
				t.Fatalf("hint names --source-cidr = %v, want %v: %s", got, tc.wantHint, a.Hint)
			}
			if a.SourceGrant != tc.grant {
				t.Fatalf("Advice.SourceGrant = %v, want %v", a.SourceGrant, tc.grant)
			}
			if !strings.Contains(a.Detail, tc.wantSaid) {
				t.Fatalf("the detail does not say %q, so the operator cannot tell how much the client "+
					"actually knows:\n%s", tc.wantSaid, a.Detail)
			}
		})
	}
}

// Withholding the retry is only half of it. An operator staring at a timeout
// needs to be told what would grant it, and told that it happens on the host
// — which is the thing they cannot reach, and the reason the whole failure is
// worth this much prose.
func TestClient_Advise_RefusedAssertionNamesTheEnrollmentFlagThatWouldGrantIt(t *testing.T) {
	a := client.Advise(client.Result{Outcome: client.TimedOut}, client.Sent{
		Host:        "web-01",
		Service:     "ssh",
		Addr:        addr(t, "203.0.113.9:22"),
		Delivered:   true,
		SourceGrant: client.AssertedSourceNotGranted,
	})
	for _, want := range []string{"--allow-source-cidr", "init-standalone", "web-01", "silent"} {
		if !strings.Contains(a.Hint, want) {
			t.Fatalf("the hint does not mention %q, so it says what will not work without saying what "+
				"would:\n%s", want, a.Hint)
		}
	}
}

// The wiring, which is the part that has been missing before in this project:
// a rule that is documented and unit-tested and never reached from the code
// an operator runs. Open must read the grant off the host entry it was given
// and put it where Advise will see it.
//
// Mutation verified: dropping SourceGrant from the Sent that Open builds
// leaves it at AssertedSourceUnknown, and the hint comes back — failing both
// assertions below.
func TestClient_Open_CarriesTheEntrysAssertedSourceGrantIntoTheAdvice(t *testing.T) {
	op := mustGenerate(t, "laptop-primary")
	h := hostAllowing(t, "    allow_source_cidr: false\n")

	rep, err := client.Open(context.Background(), client.OpenOptions{
		Builder:         client.Builder{Signer: op},
		Host:            h,
		Service:         "ssh",
		Counter:         client.NewCounter(filepath.Join(t.TempDir(), "counter.json")),
		Send:            (&recordingSend{}).send,
		Dial:            func(context.Context, string, string) (net.Conn, error) { return nil, context.DeadlineExceeded },
		ConnectAttempts: 1,
		NowMS:           fixedClock(testNowMS),
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if rep.Result.Outcome != client.TimedOut {
		t.Fatalf("outcome = %q, want timeout — this test asserts nothing on any other branch", rep.Result.Outcome)
	}
	if rep.Sent.SourceGrant != client.AssertedSourceNotGranted {
		t.Fatalf("Sent.SourceGrant = %v; Open did not read it off the host entry, so every decision "+
			"downstream is made on a default", rep.Sent.SourceGrant)
	}
	if rep.Advice.SourceCIDRHint {
		t.Fatalf("`postern open` told the operator to retry with --source-cidr against a host their own "+
			"entry says will refuse it: %s", rep.Advice.Hint)
	}
}
