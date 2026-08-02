package main

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jotra7/postern/internal/agent"
	"github.com/jotra7/postern/internal/client"
	"github.com/jotra7/postern/internal/config"
	"github.com/jotra7/postern/internal/gate"
	"github.com/jotra7/postern/internal/identity"
	"github.com/jotra7/postern/internal/replay"
	"github.com/jotra7/postern/internal/spa"
)

// enrolledHost runs the real init-standalone with whatever extra flags a test
// wants, and returns the directory it wrote into plus the host entry it
// printed. Nothing is injected: this is the command an operator types, and
// the config under test is the file it left on disk.
func enrolledHost(t *testing.T, operator string, sign, enc string, extra ...string) (dir, entry string) {
	t.Helper()
	dir = t.TempDir()
	e, out, errBuf := envWithHome(t, dir)
	args := append([]string{
		"init-standalone", "--no-nft-check",
		"--dir", filepath.Join(dir, "etc"),
		"--state-dir", filepath.Join(dir, "var"),
		"--unit-dir", filepath.Join(dir, "units"),
		"--host-name", "cg-01",
		"--knock-addr", "203.0.113.9",
		"--always-allow-iface", "tailscale0", "--no-iface-check",
		"--exec-start", "/usr/local/bin/postern agent",
		"--operator", operator + "=" + sign + "," + enc,
	}, extra...)
	if code := runCLI(t, e, args...); code != exitOK {
		t.Fatalf("init-standalone exited %d: %s", code, errBuf.String())
	}
	return dir, out.String()
}

// generatedPolicy parses and validates a generated config exactly as the
// agent does at startup. Validate is the check that refuses allow_source_cidr
// without both minimum prefixes, so a generator that emitted one without the
// others produces a host that will not start — and this is where that shows
// up as a test failure rather than as an unreachable host.
func generatedPolicy(t *testing.T, dir string) *config.Policy {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(dir, "etc", "postern.yaml")) //nolint:gosec // a test reading a file it just generated
	if err != nil {
		t.Fatalf("no generated config: %v", err)
	}
	policy, err := config.ParseStandalone(body)
	if err != nil {
		t.Fatalf("the generated config does not parse:\n%v\n%s", err, body)
	}
	if err := policy.Validate(); err != nil {
		t.Fatalf("the generated config does not validate, so the agent would refuse to start on the "+
			"host this command just enrolled:\n%v\n%s", err, body)
	}
	if _, err := gate.BuildRulesetPlan(policy); err != nil {
		t.Fatalf("the generated config cannot be planned into a ruleset: %v\n%s", err, body)
	}
	return policy
}

// The whole defect, in one test: a knock that asserts a source prefix,
// against a host enrolled by the real init-standalone, decided by the real
// agent validation pipeline.
//
// This is the carrier-NAT split reproduced in-process. The datagram is
// observed arriving from 10.2.0.10 — the UDP pool — and asserts 10.2.0.0/24,
// the prefix that covers the TCP pool the operator's connect will egress
// from. Without the grant the agent refuses it, and refuses in silence, which
// is what a locked-out operator experiences as a second identical timeout.
//
// Mutation verified: dropping ", allow_source_cidr: true" from
// sourceGrantFields fails the granted subtest with ErrSourceNotAllowed;
// dropping only the two minimums fails it earlier, at Validate, because the
// generated config no longer loads; granting it unconditionally (ignoring
// operatorSpec.allowSourceCIDR) fails the default subtest.
func TestMain_InitStandalone_AssertedSourceIsAdmittedOnlyWhenEnrollmentGrantedIt(t *testing.T) {
	op, err := identity.Generate("laptop-primary")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	pub := op.Public()
	sign := base64.StdEncoding.EncodeToString(pub.Signing[:])
	enc := base64.StdEncoding.EncodeToString(pub.Encryption[:])
	asserted := netip.MustParsePrefix("10.2.0.0/24")
	observed := netip.MustParseAddr("10.2.0.10")

	for _, tc := range []struct {
		name  string
		extra []string
		want  error // nil means the knock must be admitted
	}{
		{
			name:  "granted at enrollment",
			extra: []string{"--allow-source-cidr", "laptop-primary"},
		},
		{
			// The state every host was in before this flag existed.
			name: "a default enrollment",
			want: agent.ErrSourceNotAllowed,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, entryYAML := enrolledHost(t, "laptop-primary", sign, enc, tc.extra...)
			policy := generatedPolicy(t, dir)

			hostSigner, err := identity.LoadFile(filepath.Join(dir, "etc", "host.key"), nil)
			if err != nil {
				t.Fatalf("load host key: %v", err)
			}
			ops := make([]identity.PublicIdentity, 0, len(policy.Operators))
			for _, o := range policy.Operators {
				ops = append(ops, o.Identity)
			}
			opener, rejected, err := spa.NewOpenerFromSigner(hostSigner, ops)
			if err != nil {
				t.Fatalf("NewOpenerFromSigner: %v", err)
			}
			if len(rejected) != 0 {
				t.Fatalf("the generated config carries operator keys the host rejects: %v", rejected)
			}
			store, err := replay.Open(filepath.Join(t.TempDir(), "replay.db"), replay.Options{})
			if err != nil {
				t.Fatalf("replay.Open: %v", err)
			}
			defer func() { _ = store.Close() }()

			host := hostFromEntry(t, entryYAML)
			var sent [][]byte
			if _, err := client.Open(context.Background(), client.OpenOptions{
				Builder:    client.Builder{Signer: op},
				Host:       host,
				Service:    "ssh",
				SourceCIDR: &asserted,
				Counter:    client.NewCounter(filepath.Join(t.TempDir(), "counter.json")),
				Send: func(_ context.Context, _ netip.AddrPort, payload []byte) error {
					sent = append(sent, payload)
					return nil
				},
				Dial: func(context.Context, string, string) (net.Conn, error) { return nil, nil },
			}); err != nil {
				t.Fatalf("Open: %v", err)
			}
			if len(sent) != 1 {
				t.Fatalf("sent %d datagrams, want one", len(sent))
			}

			dec, err := agent.Validate(sent[0], observed, policy, opener, store,
				agent.PendingTransaction{}, false, time.Now())
			if tc.want != nil {
				if !errors.Is(err, tc.want) {
					t.Fatalf("the host accepted an asserted source it was never granted: err = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("the host refused a knock its own generated config grants: %v", err)
			}
			if got := dec.Source.Prefix.String(); got != asserted.String() {
				t.Fatalf("the gate would open for %s, not the asserted %s — the connect egresses from a "+
					"different pool address than the knock did, which is the whole point", got, asserted)
			}
		})
	}
}

// Opt-in is the security half of this. An asserted prefix widens the gate to
// everything behind it, so a host nobody asked to allow one must not.
//
// Mutation verified: defaulting operatorSpec.allowSourceCIDR to true fails
// here on the grant, before any packet is involved.
func TestMain_InitStandalone_DefaultEnrollmentGrantsNoAssertedSource(t *testing.T) {
	sign, enc := publicKeyPairB64(t)
	dir, entryYAML := enrolledHost(t, "laptop-primary", sign, enc)
	policy := generatedPolicy(t, dir)

	for _, o := range policy.Operators {
		for _, g := range o.Grants {
			if g.AllowSourceCIDR {
				t.Fatalf("operator %q may assert a source prefix on a host nobody asked to allow one; "+
					"an asserted /24 opens the gate to 256 addresses", o.Identity.Name)
			}
			if err := g.AllowsSource(netip.MustParsePrefix("10.2.0.0/24")); err == nil {
				t.Fatalf("operator %q's grant admits an asserted prefix by default", o.Identity.Name)
			}
		}
	}
	if !strings.Contains(entryYAML, "allow_source_cidr: false") {
		t.Fatalf("the host entry does not record that no asserted source is permitted, so the client "+
			"cannot tell this apart from a host it knows nothing about:\n%s", entryYAML)
	}
}

// The flags that would produce a grant nobody gets, or a config the agent
// refuses to load, are refused here — where the operator is on the host, is
// looking at the output, and nothing has been written yet.
//
// Mutation verified: returning nil from applySourceCIDRGrants makes every
// subtest fail; the config-existence assertion is what catches the two
// out-of-range rows, since a written-then-unloadable config is the harm.
func TestMain_InitStandalone_RefusesSourceCIDRFlagsThatGrantNothingOrCannotLoad(t *testing.T) {
	sign, enc := publicKeyPairB64(t)
	for _, tc := range []struct {
		name  string
		extra []string
		says  string
	}{
		{"a name matching no operator", []string{"--allow-source-cidr", "laptop-primry"}, "laptop-primary"},
		{"a minimum with no grant to bound", []string{"--min-ipv4-prefix", "16"}, "--allow-source-cidr"},
		{"an IPv4 minimum out of range", []string{"--allow-source-cidr", "laptop-primary", "--min-ipv4-prefix", "33"}, "1..32"},
		{"an IPv6 minimum out of range", []string{"--allow-source-cidr", "laptop-primary", "--min-ipv6-prefix", "129"}, "1..128"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			e, _, errBuf := envWithHome(t, dir)
			args := append([]string{
				"init-standalone", "--no-nft-check",
				"--dir", filepath.Join(dir, "etc"),
				"--state-dir", filepath.Join(dir, "var"),
				"--unit-dir", filepath.Join(dir, "units"),
				"--host-name", "cg-01",
				"--knock-addr", "203.0.113.9",
				"--always-allow-iface", "tailscale0", "--no-iface-check",
				"--exec-start", "/usr/local/bin/postern agent",
				"--operator", "laptop-primary=" + sign + "," + enc,
			}, tc.extra...)
			if code := runCLI(t, e, args...); code != exitUsage {
				t.Fatalf("exit = %d, want a usage refusal: %s", code, errBuf.String())
			}
			if !strings.Contains(errBuf.String(), tc.says) {
				t.Fatalf("the refusal does not mention %q, so an operator cannot act on it:\n%s",
					tc.says, errBuf.String())
			}
			if _, err := os.Stat(filepath.Join(dir, "etc", "postern.yaml")); err == nil {
				t.Fatal("a config was written despite the refusal; the retry after fixing the flag then " +
					"hits the already-exists guard")
			}
		})
	}
}

// One host entry is printed per host and handed to every operator enrolled in
// that invocation, so it may only state what is true for all of them. When
// their grants differ it says nothing, and the client treats that silence as
// silence rather than as a refusal.
//
// Mutation verified: returning (true, true) from assertedSourceEntryValue
// whenever any operator is granted fails the mixed row; returning (false,
// true) always fails the granted row.
func TestMain_InitStandalone_HostEntryClaimsAnAssertedSourceOnlyWhenEveryOperatorHasOne(t *testing.T) {
	signA, encA := publicKeyPairB64(t)
	signB, encB := publicKeyPairB64(t)

	for _, tc := range []struct {
		name  string
		extra []string
		want  string // "" means the key must be absent
	}{
		{"the only operator is granted", []string{"--allow-source-cidr", "laptop-primary"}, "allow_source_cidr: true"},
		{"the only operator is not", nil, "allow_source_cidr: false"},
		{
			name: "two operators, one granted",
			extra: []string{
				"--operator", "phone-backup=" + signB + "," + encB,
				"--allow-source-cidr", "laptop-primary",
			},
			want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, entryYAML := enrolledHost(t, "laptop-primary", signA, encA, tc.extra...)
			if tc.want == "" {
				if strings.Contains(entryYAML, "allow_source_cidr") {
					t.Fatalf("the entry answers for operators whose grants differ, so it is wrong for at "+
						"least one of the people holding it:\n%s", entryYAML)
				}
				// Silence has to survive the round trip as silence.
				if got := hostFromEntry(t, entryYAML).AssertedSourceGrant(); got != client.AssertedSourceUnknown {
					t.Fatalf("AssertedSourceGrant() = %v, want unknown", got)
				}
				return
			}
			if !strings.Contains(entryYAML, tc.want) {
				t.Fatalf("the entry does not carry %q:\n%s", tc.want, entryYAML)
			}
		})
	}
}

// Enrollment is the last moment the operator reliably has a working way in,
// and the only moment at which the fix costs nothing. A host that will refuse
// an asserted source says so here rather than at the timeout.
//
// The silent rows matter as much as the loud one: a note that also fired on
// an entry that says nothing would fire on every host enrolled before this
// field existed, and be wallpaper by the time it mattered.
//
// Mutation verified: dropping the AssertedSourceNotGranted guard from
// noteAssertedSource fails both silent rows; removing the call from runEnroll
// fails the loud one.
func TestMain_Enroll_SaysSoWhenTheHostWillRefuseAnAssertedSource(t *testing.T) {
	for _, tc := range []struct {
		name     string
		line     string
		wantNote bool
	}{
		{"the host permits none", "allow_source_cidr: false\n", true},
		{"the host permits one", "allow_source_cidr: true\n", false},
		{"the entry does not say", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			entryPath := filepath.Join(home, "entry.yaml")
			entry := "" +
				"name: cg-01\n" +
				"host_id: 3a713a713a713a713a713a713a713a71\n" +
				"knock_addr: 203.0.113.9\n" +
				"knock_port: 62201\n" +
				"host_encryption: " + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n" +
				tc.line +
				"services:\n" +
				"  ssh: { port: 22 }\n"
			if err := os.WriteFile(entryPath, []byte(entry), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			e, _, errBuf := envWithHome(t, home)
			if code := runCLI(t, e, "enroll", "cg-01", "--from", entryPath,
				"--operator", "laptop-primary", "--no-passphrase"); code != exitOK {
				t.Fatalf("enroll exited %d: %s", code, errBuf.String())
			}

			said := strings.Contains(errBuf.String(), "--allow-source-cidr")
			if said != tc.wantNote {
				t.Fatalf("enrollment named --allow-source-cidr = %v, want %v:\n%s",
					said, tc.wantNote, errBuf.String())
			}
			if tc.wantNote {
				for _, want := range []string{"cg-01", "laptop-primary", "silently"} {
					if !strings.Contains(errBuf.String(), want) {
						t.Fatalf("the note does not mention %q, so it is not actionable:\n%s", want, errBuf.String())
					}
				}
			}
		})
	}
}

// The two halves have to fit: what init-standalone prints about asserted
// sources is what `enroll --from` has to persist, and what `open` later reads
// off the written config. A field that survives the entry and is dropped by
// the config writer would leave every advice decision made on a default.
//
// Mutation verified: clearing entry.AllowSourceCIDR in upsertHost fails on
// the reloaded grant; retagging the field `yaml:"-"` on client.Host fails
// earlier, at the entry parse, because the key init-standalone printed is
// then unknown to the reader.
func TestMain_Enroll_PersistsTheAssertedSourcePermissionIntoTheClientConfig(t *testing.T) {
	sign, enc := publicKeyPairB64(t)
	_, entryYAML := enrolledHost(t, "laptop-primary", sign, enc, "--allow-source-cidr", "laptop-primary")

	home := t.TempDir()
	entryPath := filepath.Join(home, "entry.yaml")
	if err := os.WriteFile(entryPath, []byte(entryYAML), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	e, _, errBuf := envWithHome(t, home)
	if code := runCLI(t, e, "enroll", "cg-01", "--from", entryPath,
		"--operator", "laptop-primary", "--no-passphrase"); code != exitOK {
		t.Fatalf("enroll exited %d: %s", code, errBuf.String())
	}

	cfg, err := client.LoadConfig(filepath.Join(home, "config.yaml"))
	if err != nil {
		t.Fatalf("the written client config does not load: %v", err)
	}
	host, err := cfg.Host("cg-01")
	if err != nil {
		t.Fatalf("Host: %v", err)
	}
	if got := host.AssertedSourceGrant(); got != client.AssertedSourceGranted {
		t.Fatalf("the reloaded entry reports %v; `open` would withhold or hedge the one piece of advice "+
			"that works on this host", got)
	}
}

// hostFromEntry parses a printed host entry the way `enroll --from` does.
func hostFromEntry(t *testing.T, entryYAML string) *client.Host {
	t.Helper()
	home := t.TempDir()
	path := filepath.Join(home, "entry.yaml")
	if err := os.WriteFile(path, []byte(entryYAML), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	e, _, _ := envWithHome(t, home)
	data, err := readEntryBytes(e, path)
	if err != nil {
		t.Fatalf("read the printed host entry: %v", err)
	}
	h, _, err := parseHostEntry(data)
	if err != nil {
		t.Fatalf("the printed host entry does not parse as one: %v\n%s", err, entryYAML)
	}
	// The entry alone is not a config. Round-tripping it through the writer
	// and the parser `enroll` uses is what gives the returned host its decoded
	// fields, and it is also the step that would silently drop a field the
	// config writer does not carry.
	cfg := &client.Config{Operator: "laptop-primary"}
	cfg.SetDir(home)
	if err := upsertHost(cfg, h); err != nil {
		t.Fatalf("upsertHost: %v", err)
	}
	body, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	loaded, err := client.ParseConfig(body)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	out, err := loaded.Host(h.Name)
	if err != nil {
		t.Fatalf("Host: %v", err)
	}
	return out
}
