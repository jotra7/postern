package main

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jotra7/postern/internal/client"
	"github.com/jotra7/postern/internal/identity"
	"github.com/jotra7/postern/internal/metrics"
)

func testPublicIdentity(t *testing.T) identity.PublicIdentity {
	t.Helper()
	s, err := identity.Generate("web-01")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return s.Public()
}

// fakeAddrs is an interface lookup with no host under it, so the choice
// between an interface's several addresses can be asserted on values a test
// picked rather than on whatever this machine happens to be plugged into.
func fakeAddrs(want string, addrs ...string) metrics.InterfaceAddrs {
	return func(name string) ([]netip.Addr, error) {
		if name != want {
			return nil, fmt.Errorf("no such interface %q", name)
		}
		out := make([]netip.Addr, 0, len(addrs))
		for _, a := range addrs {
			out = append(out, netip.MustParseAddr(a))
		}
		return out, nil
	}
}

// A mesh interface routinely carries several addresses at once: tailscale0
// holds a 100.x IPv4 and an fd7a: IPv6 together, plus whatever link-local the
// kernel put there. Either of the routable two reaches the agent, so the rule
// only has to be one an operator can predict and one that agrees with the
// other place postern already picks an address of this same interface.
func TestMain_AlwaysAllowEntryAddr_PicksTheFirstRoutableAddressOfSeveral(t *testing.T) {
	for _, tc := range []struct {
		name  string
		addrs []string
		want  string
	}{
		{"skips link-local", []string{"fe80::1", "100.64.0.4"}, "100.64.0.4"},
		{"skips loopback", []string{"127.0.0.1", "100.64.0.4"}, "100.64.0.4"},
		{"skips the unspecified address", []string{"0.0.0.0", "100.64.0.4"}, "100.64.0.4"},
		{"keeps the kernel's order", []string{"100.64.0.4", "fd7a::1"}, "100.64.0.4"},
		{"an IPv6-only interface is fine", []string{"fe80::1", "fd7a::1"}, "fd7a::1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := alwaysAllowEntryAddr("tailscale0", false, fakeAddrs("tailscale0", tc.addrs...))
			if got.String() != tc.want {
				t.Fatalf("alwaysAllowEntryAddr() = %s, want %s", got, tc.want)
			}
		})
	}
}

// Recording nothing is the honest answer twice over: an interface that is not
// on this machine belongs to the host being configured from elsewhere, and one
// that carries no routable address has not come up yet. Either way an address
// invented here would describe something other than the host being enrolled,
// and the client already falls back to knock_addr when the entry says nothing.
func TestMain_AlwaysAllowEntryAddr_RecordsNothingWhenThereIsNoHonestAnswer(t *testing.T) {
	for _, tc := range []struct {
		name    string
		offHost bool
		lookup  metrics.InterfaceAddrs
	}{
		{"the interface is not on this machine", false, fakeAddrs("mesh0")},
		{"the interface carries no address at all", false, fakeAddrs("tailscale0")},
		{"the interface carries only link-local", false, fakeAddrs("tailscale0", "fe80::1")},
		{"there is no lookup", false, nil},
		{"--no-iface-check, even with a same-named interface right here", true,
			fakeAddrs("tailscale0", "100.64.0.4")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := alwaysAllowEntryAddr("tailscale0", tc.offHost, tc.lookup); got.IsValid() {
				t.Fatalf("alwaysAllowEntryAddr() = %s, want no address recorded", got)
			}
		})
	}
}

// The printed entry is the whole interface between the host and the operator's
// laptop, so the key has to be there when there is an address and absent when
// there is not, because a written-out zero address would be a value the client
// parses and then pings.
func TestMain_RenderHostEntry_WritesTheAlwaysAllowAddressOnlyWhenThereIsOne(t *testing.T) {
	o := initOptions{hostName: "web-01", knockAddr: "203.0.113.9", spaPort: 62201, recoveryService: "ssh"}

	with := renderHostEntry(o, [16]byte{0x3a}, testPublicIdentity(t), netip.MustParseAddr("198.51.100.4"))
	if !strings.Contains(with, "always_allow_addr: 198.51.100.4\n") {
		t.Errorf("the entry does not record the always-allow address:\n%s", with)
	}
	without := renderHostEntry(o, [16]byte{0x3a}, testPublicIdentity(t), netip.Addr{})
	if strings.Contains(without, "always_allow_addr") {
		t.Errorf("the entry names always_allow_addr with no address to put in it:\n%s", without)
	}
	// Both must still parse as a client host entry, since that is what
	// `postern host add --from` does with them.
	for _, entry := range []string{with, without} {
		if _, _, err := parseHostEntry([]byte(entry)); err != nil {
			t.Fatalf("parseHostEntry: %v\n%s", err, entry)
		}
	}
}

// Off-host generation has no interfaces worth reading, so it records nothing,
// and the operator has to be told, because the consequence lands later and
// somewhere else: `postern status` silently checks the wrong address, and the
// timeout it prints is what a healthy agent looks like from the public path.
func TestMain_InitStandalone_SaysSoWhenItRecordsNoAlwaysAllowAddress(t *testing.T) {
	dir := t.TempDir()
	e, out, errBuf := envWithHome(t, dir)
	sign, enc := publicKeyPairB64(t)

	code := runCLI(t, e, append(initArgs(dir, "tailscale0", sign, enc), "--no-iface-check")...)
	if code != exitOK {
		t.Fatalf("exit = %d, want %d:\n%s", code, exitOK, errBuf.String())
	}
	if strings.Contains(out.String(), "always_allow_addr") {
		t.Errorf("the entry claims an always-allow address for a host this machine is not:\n%s", out.String())
	}
	if !strings.Contains(errBuf.String(), "always_allow_addr") {
		t.Errorf("nothing told the operator that `status` will fall back to knock_addr:\n%s", errBuf.String())
	}
}

// The wiring, end to end through the real command: an interface that exists
// here and carries a routable address puts that address in the entry.
//
// Skipped on a machine with no such interface, which is why the fleet
// end-to-end sequence asserts the same thing against mesh0 under real systemd.
func TestMain_InitStandalone_RecordsTheAlwaysAllowInterfacesOwnAddress(t *testing.T) {
	var iface string
	var want netip.Addr
	for _, name := range nonLoopbackIfaceNames() {
		if addr, ok := metrics.FirstRoutableAddr(name, metrics.SystemInterfaceAddrs); ok {
			iface, want = name, addr
			break
		}
	}
	if iface == "" {
		t.Skip("this machine has no non-loopback interface carrying a routable address")
	}

	dir := t.TempDir()
	e, out, errBuf := envWithHome(t, dir)
	sign, enc := publicKeyPairB64(t)

	if code := runCLI(t, e, initArgs(dir, iface, sign, enc)...); code != exitOK {
		t.Fatalf("exit = %d, want %d:\n%s", code, exitOK, errBuf.String())
	}
	if !strings.Contains(out.String(), "always_allow_addr: "+want.String()+"\n") {
		t.Fatalf("the entry does not record %s's own address %s:\n%s", iface, want, out.String())
	}
}

// The entry has to survive being written into the operator's config and read
// back out, which is a different code path from parsing it: the config is
// re-marshalled from the Host struct, so a field with no serialised form would
// be lost at exactly this step and nowhere else.
func TestMain_HostAdd_KeepsTheAlwaysAllowAddressInTheWrittenConfig(t *testing.T) {
	home := t.TempDir()
	entry := "" +
		"name: web-01\n" +
		"host_id: 3a713a713a713a713a713a713a713a71\n" +
		"knock_addr: 203.0.113.9\n" +
		"knock_port: 62201\n" +
		"always_allow_addr: 198.51.100.4\n" +
		"host_encryption: " + testHostEncryptionB64 + "\n" +
		"recovery_service: ssh\n" +
		"services:\n" +
		"  ssh: { port: 22, ttl: 120s }\n"
	entryPath := filepath.Join(home, "entry.yaml")
	if err := os.WriteFile(entryPath, []byte(entry), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	e, _, errBuf := envWithHome(t, home)
	if code := runCLI(t, e, "enroll", "web-01", "--from", entryPath, "--no-passphrase"); code != exitOK {
		t.Fatalf("enroll exited %d: %s", code, errBuf.String())
	}

	cfg, err := client.LoadConfig(filepath.Join(home, "config.yaml"))
	if err != nil {
		t.Fatalf("the written client config does not load: %v", err)
	}
	host, err := cfg.Host("web-01")
	if err != nil {
		t.Fatalf("Host: %v", err)
	}
	if got := host.StatusAddr().String(); got != "198.51.100.4" {
		t.Fatalf("StatusAddr() = %s after a round trip through the config file, want 198.51.100.4", got)
	}
	if got := host.KnockAddrPort().String(); got != "203.0.113.9:62201" {
		t.Fatalf("KnockAddrPort() = %s, want the public address unchanged", got)
	}
}

// The report an operator reads has to name the address the check actually
// used, and, on the entry shape that produced the live failure (one with no
// always_allow_addr at all), say why a timeout there proves nothing about the
// agent.
//
// Neither run can pass: the ssh port is closed and the entry carries no
// host_signing, so both fail fast without touching the network. What is under
// test is what gets printed, not whether the host answers.
func TestMain_Status_NamesTheAddressItCheckedAndWhyKnockAddrIsTheWrongOne(t *testing.T) {
	closed := freePort(t)
	statusHome := func(t *testing.T, extra string) string {
		t.Helper()
		home := t.TempDir()
		entry := fmt.Sprintf(""+
			"name: web-01\n"+
			"host_id: 3a713a713a713a713a713a713a713a71\n"+
			"knock_addr: 127.0.0.1\n"+
			"knock_port: %d\n"+
			"%s"+
			"host_encryption: %s\n"+
			"recovery_service: ssh\n"+
			"services:\n"+
			"  ssh: { port: %d, ttl: 120s }\n", closed, extra, testHostEncryptionB64, closed)
		entryPath := filepath.Join(home, "entry.yaml")
		if err := os.WriteFile(entryPath, []byte(entry), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		e, _, errBuf := envWithHome(t, home)
		if code := runCLI(t, e, "enroll", "web-01", "--from", entryPath, "--no-passphrase"); code != exitOK {
			t.Fatalf("enroll exited %d: %s", code, errBuf.String())
		}
		return home
	}

	t.Run("no always_allow_addr", func(t *testing.T) {
		e, out, _ := envWithHome(t, statusHome(t, ""))
		if code := runCLI(t, e, "status", "web-01", "--wait", "200ms", "--timeout", "200ms"); code != exitFailed {
			t.Fatalf("exit = %d, want %d", code, exitFailed)
		}
		if !strings.Contains(out.String(), "records no always_allow_addr") {
			t.Fatalf("nothing said the check fell back to the public address:\n%s", out.String())
		}
	})

	// The green half of the same line. It names the address rather than
	// asserting "the always-allow path", because --via and the knock_addr
	// fallback both mean the connect does not always go where that phrase
	// promises. A real listener stands in for sshd; the pong still fails,
	// which is what makes this a test of one line rather than of two.
	t.Run("a recovery service that answers", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Listen: %v", err)
		}
		defer func() { _ = ln.Close() }()
		port := ln.Addr().(*net.TCPAddr).Port

		home := t.TempDir()
		entry := fmt.Sprintf(""+
			"name: web-01\n"+
			"host_id: 3a713a713a713a713a713a713a713a71\n"+
			"knock_addr: 203.0.113.9\n"+
			"knock_port: %d\n"+
			"always_allow_addr: 127.0.0.1\n"+
			"host_encryption: %s\n"+
			"recovery_service: ssh\n"+
			"services:\n"+
			"  ssh: { port: %d, ttl: 120s }\n", closed, testHostEncryptionB64, port)
		entryPath := filepath.Join(home, "entry.yaml")
		if err := os.WriteFile(entryPath, []byte(entry), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		e, _, errBuf := envWithHome(t, home)
		if code := runCLI(t, e, "enroll", "web-01", "--from", entryPath, "--no-passphrase"); code != exitOK {
			t.Fatalf("enroll exited %d: %s", code, errBuf.String())
		}

		e2, out, _ := envWithHome(t, home)
		if code := runCLI(t, e2, "status", "web-01", "--wait", "200ms", "--timeout", "2s"); code != exitFailed {
			t.Fatalf("exit = %d, want %d:\n%s", code, exitFailed, out.String())
		}
		if !strings.Contains(out.String(), "recovery  ok    ssh reachable at 127.0.0.1") {
			t.Fatalf("the recovery line does not name the address it connected to:\n%s", out.String())
		}
	})

	t.Run("an always_allow_addr that differs", func(t *testing.T) {
		e, out, _ := envWithHome(t, statusHome(t, "always_allow_addr: 127.0.0.2\n"))
		if code := runCLI(t, e, "status", "web-01", "--wait", "200ms", "--timeout", "200ms"); code != exitFailed {
			t.Fatalf("exit = %d, want %d", code, exitFailed)
		}
		if !strings.Contains(out.String(), fmt.Sprintf("host web-01 (127.0.0.2:%d)", closed)) {
			t.Errorf("the header does not name the address the check used:\n%s", out.String())
		}
		if strings.Contains(out.String(), "records no always_allow_addr") {
			t.Errorf("an entry that records one was told it does not:\n%s", out.String())
		}
	})
}

// --via is an address, not a name, for knock_addr's reason and one more: it is
// typed at the moment the always-allow path is in doubt, and a resolver is one
// of the things that may be down with it.
func TestMain_Status_RefusesAViaThatIsNotAnIPLiteral(t *testing.T) {
	home := t.TempDir()
	entry := "" +
		"name: web-01\n" +
		"host_id: 3a713a713a713a713a713a713a713a71\n" +
		"knock_addr: 127.0.0.1\n" +
		"host_encryption: " + testHostEncryptionB64 + "\n" +
		"services:\n" +
		"  ssh: { port: 22, ttl: 120s }\n"
	entryPath := filepath.Join(home, "entry.yaml")
	if err := os.WriteFile(entryPath, []byte(entry), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	e, _, errBuf := envWithHome(t, home)
	if code := runCLI(t, e, "enroll", "web-01", "--from", entryPath, "--no-passphrase"); code != exitOK {
		t.Fatalf("enroll exited %d: %s", code, errBuf.String())
	}
	e2, _, errBuf2 := envWithHome(t, home)
	if code := runCLI(t, e2, "status", "web-01", "--via", "web-01.mesh"); code != exitUsage {
		t.Fatalf("exit = %d, want %d; a hostname was accepted as --via", code, exitUsage)
	}
	if !strings.Contains(errBuf2.String(), "--via") {
		t.Fatalf("the refusal does not name the flag:\n%s", errBuf2.String())
	}
}

// A host entry is written by the host, so a key this laptop does not know
// means the host is newer than the laptop. client.ParseConfig already takes
// that position for the config derived from this file; the entry parser itself
// took the opposite one, which put the refusal one step earlier in the same
// pipeline and made an operator unable to enroll during the outage the laptop
// was kept for.
//
// The entry here is otherwise complete and valid, so the only thing that could
// reject it is the unknown key.
func TestMain_ParseHostEntry_AcceptsAKeyThisBuildDoesNotKnow(t *testing.T) {
	entry := []byte(`
name: futurehost
host_id: aabbccddeeff00112233445566778899
knock_addr: 203.0.113.9
knock_port: 62201
host_encryption: 7JSucLvs8MTRpMeR3opObV7ccFF86M/rzG+1UTgCs1Q=
host_signing: BB39U3OveyKCLU6+rpsjOf7FHTQLikpskxdU4aZDoEQ=
recovery_service: ssh
some_field_from_a_newer_host: true
`)
	h, unknown, err := parseHostEntry(entry)
	if err != nil {
		t.Fatalf("parseHostEntry refused an entry from a newer host: %v. The laptop that cannot enroll "+
			"finds out during the outage it was kept for", err)
	}
	if h.Name != "futurehost" {
		t.Fatalf("name = %q, want futurehost", h.Name)
	}
	if len(unknown) != 1 || unknown[0] != "some_field_from_a_newer_host" {
		t.Fatalf("unknown keys = %v, want exactly [some_field_from_a_newer_host]: the key is reported "+
			"because the other thing it can mean is a typo that quietly costs a capability", unknown)
	}
}

// The counterpart, so the acceptance above cannot be satisfied by a parser
// that stopped looking: an entry with no unknown key reports none.
func TestMain_ParseHostEntry_ReportsNoUnknownKeysForAnOrdinaryEntry(t *testing.T) {
	entry := []byte(`
name: ordinary
host_id: aabbccddeeff00112233445566778899
knock_addr: 203.0.113.9
host_encryption: 7JSucLvs8MTRpMeR3opObV7ccFF86M/rzG+1UTgCs1Q=
host_signing: BB39U3OveyKCLU6+rpsjOf7FHTQLikpskxdU4aZDoEQ=
`)
	_, unknown, err := parseHostEntry(entry)
	if err != nil {
		t.Fatalf("parseHostEntry: %v", err)
	}
	if len(unknown) != 0 {
		t.Fatalf("unknown keys = %v, want none", unknown)
	}
}
