package client_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/client"
	"github.com/jotra7/postern/internal/identity"
	"github.com/jotra7/postern/internal/knockport"
	"github.com/jotra7/postern/internal/spa"
)

// answerPong plays the agent: it opens the ping, and answers it with a
// correctly signed pong — unless a mutate hook alters the reply first, which
// is how the client's own verification is exercised.
func answerPong(
	t *testing.T,
	host identity.Signer,
	op identity.PublicIdentity,
	hostID [16]byte,
	nowMS uint64,
	mutate func(*spa.Pong),
) client.Exchanger {
	t.Helper()
	return answerPongSignedBy(t, host, host, op, hostID, nowMS, mutate)
}

// answerPongSignedBy splits the two jobs answerPong's single signer does: opener
// owns the host's encryption key and is what the ping is sealed to, while
// pongSigner is the key the reply is signed with. They are the same identity
// everywhere except the role-reuse tests, which need a host whose host_signing
// key is the operator's while its host_encryption key is still its own.
func answerPongSignedBy(
	t *testing.T,
	host identity.Signer,
	pongSigner identity.Signer,
	op identity.PublicIdentity,
	hostID [16]byte,
	nowMS uint64,
	mutate func(*spa.Pong),
) client.Exchanger {
	t.Helper()
	opener, _, err := spa.NewOpenerFromSigner(host, []identity.PublicIdentity{op})
	if err != nil {
		t.Fatalf("NewOpenerFromSigner: %v", err)
	}
	return func(_ context.Context, _ netip.AddrPort, payload []byte, _ time.Duration) ([]byte, error) {
		req, _, err := opener.TrialOpen(payload)
		if err != nil {
			return nil, err
		}
		challenge, err := req.LivenessPayload()
		if err != nil {
			return nil, err
		}
		p := &spa.Pong{
			Version:     spa.Version1,
			Alg:         spa.AlgEd25519X25519,
			HostID:      hostID,
			RequestID:   req.RequestID,
			Challenge:   challenge,
			TimestampMS: nowMS,
		}
		if mutate != nil {
			mutate(p)
		}
		return spa.SignPong(p, pongSigner)
	}
}

func TestClient_Status_VerifiesThePongAndTheRecoveryService(t *testing.T) {
	op := mustGenerate(t, "laptop-primary")
	host := mustGenerate(t, "web-01")
	h := testHost(t, host.Public().Encryption, host.Public().Signing)

	var dialed string
	rep, err := client.Status(context.Background(), client.StatusOptions{
		Builder:  client.Builder{Signer: op},
		Host:     h,
		Exchange: answerPong(t, host, op.Public(), h.HostID, testNowMS, nil),
		Dial: func(_ context.Context, _, address string) (net.Conn, error) {
			dialed = address
			return nil, nil
		},
		NowMS: fixedClock(testNowMS),
	})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !rep.Pong {
		t.Fatalf("pong not verified: %v", rep.PongErr)
	}
	if rep.RecoveryService != "ssh" {
		t.Fatalf("recovery service = %q, want ssh", rep.RecoveryService)
	}
	if dialed != "203.0.113.9:22" {
		t.Fatalf("recovery connect dialed %q, want 203.0.113.9:22", dialed)
	}
	if !rep.Healthy() {
		t.Fatal("both assertions passed but Healthy() is false")
	}
}

// The bug this file's split-path fixture exists for, seen on two real hosts
// minutes apart: with knock_addr set to the public address, `status` reported
// an i/o timeout and an unreachable recovery service against an agent that was
// armed, healthy, and answering. The agent had done nothing wrong, since a
// liveness ping that arrives anywhere but the always-allow interface is refused
// without a reply; the client had sent both assertions to the wrong address.
//
// Every existing test in this package used a fixture whose two addresses were
// the same address, which is why a green suite said nothing about this.
func TestClient_Status_SendsBothAssertionsToTheAlwaysAllowAddress(t *testing.T) {
	op := mustGenerate(t, "laptop-primary")
	host := mustGenerate(t, "web-01")
	h := testHostSplitPath(t, host.Public().Encryption, host.Public().Signing)

	var pinged netip.AddrPort
	var dialed string
	rep, err := client.Status(context.Background(), client.StatusOptions{
		Builder: client.Builder{Signer: op},
		Host:    h,
		Exchange: func(ctx context.Context, to netip.AddrPort, payload []byte, wait time.Duration) ([]byte, error) {
			pinged = to
			return answerPong(t, host, op.Public(), h.HostID, testNowMS, nil)(ctx, to, payload, wait)
		},
		Dial: func(_ context.Context, _, address string) (net.Conn, error) {
			dialed = address
			return nil, nil
		},
		NowMS: fixedClock(testNowMS),
	})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if pinged.String() != "198.51.100.4:62201" {
		t.Errorf("liveness ping went to %s, want 198.51.100.4:62201; a ping to knock_addr arrives on "+
			"the public interface and is refused in silence", pinged)
	}
	if dialed != "198.51.100.4:22" {
		t.Errorf("recovery connect dialed %q, want 198.51.100.4:22; both assertions have to traverse "+
			"the same path for the pair to be evidence about one path", dialed)
	}
	if rep.Addr.String() != "198.51.100.4" {
		t.Errorf("report address = %s, want 198.51.100.4", rep.Addr)
	}
}

// A rotation host's liveness ping has to land on the same current-window
// port `open` uses: the agent does not bind the fixed port at all once
// rotation is on, so a ping sent to SPAPort's fixed default times out
// against a perfectly healthy agent. This is confirm's own liveness
// pre-check (design section 7, I5) as much as it is `postern status`: both
// call this path, and an operator confirming a rotation host without
// --force from a genuinely healthy mesh would have failed here.
//
// Mutation verified: reverting pingOnce's `pingPort := o.Host.SPAPort()`
// override back to unconditional fails this on the port.
func TestClient_Status_PingsTheCurrentWindowPortOnARotationHost(t *testing.T) {
	op := mustGenerate(t, "laptop-primary")
	host := mustGenerate(t, "web-01")
	h := testHostRotation(t, host.Public().Encryption, host.Public().Signing)

	var pinged netip.AddrPort
	rep, err := client.Status(context.Background(), client.StatusOptions{
		Builder: client.Builder{Signer: op},
		Host:    h,
		Exchange: func(ctx context.Context, to netip.AddrPort, payload []byte, wait time.Duration) ([]byte, error) {
			pinged = to
			return answerPong(t, host, op.Public(), h.HostID, 600_000, nil)(ctx, to, payload, wait)
		},
		Dial: func(_ context.Context, _, address string) (net.Conn, error) {
			return nil, nil
		},
		NowMS: fixedClock(600_000), // unix 600 -> window 1 at the 10m default
	})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !rep.Pong {
		t.Fatalf("pong not verified: %v", rep.PongErr)
	}
	// Computed straight from knockport rather than through
	// h.CurrentKnockPort, the same reason the client's own rotation tests do
	// this: independent of that method's own correctness.
	wantWindow := knockport.Window(600, 10*time.Minute)
	wantPort := knockport.Port(rotationSecret(), wantWindow, 20000, 30000)
	if pinged.Addr() != h.KnockAddr || pinged.Port() != wantPort {
		t.Errorf("liveness ping went to %s, want %s:%d (the current-window port)", pinged, h.KnockAddr, wantPort)
	}
}

// The fallback that keeps standalone, loopback, and every entry written before
// always_allow_addr existed working exactly as they did. The client is the
// lenient side: an entry that says nothing about the always-allow path must
// still knock and still check, not become a host an operator cannot reach.
func TestClient_Status_FallsBackToKnockAddrWhenTheEntryRecordsNoAlwaysAllowAddr(t *testing.T) {
	op := mustGenerate(t, "laptop-primary")
	host := mustGenerate(t, "web-01")
	h := testHost(t, host.Public().Encryption, host.Public().Signing)

	var pinged netip.AddrPort
	var dialed string
	rep, err := client.Status(context.Background(), client.StatusOptions{
		Builder: client.Builder{Signer: op},
		Host:    h,
		Exchange: func(ctx context.Context, to netip.AddrPort, payload []byte, wait time.Duration) ([]byte, error) {
			pinged = to
			return answerPong(t, host, op.Public(), h.HostID, testNowMS, nil)(ctx, to, payload, wait)
		},
		Dial: func(_ context.Context, _, address string) (net.Conn, error) {
			dialed = address
			return nil, nil
		},
		NowMS: fixedClock(testNowMS),
	})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if pinged.String() != "203.0.113.9:62201" {
		t.Errorf("liveness ping went to %s, want knock_addr 203.0.113.9:62201", pinged)
	}
	if dialed != "203.0.113.9:22" {
		t.Errorf("recovery connect dialed %q, want knock_addr 203.0.113.9:22", dialed)
	}
	if rep.Addr.String() != "203.0.113.9" {
		t.Errorf("report address = %s, want 203.0.113.9", rep.Addr)
	}
}

// --via is for a host whose always-allow address moved after enrollment, and
// it has to move both assertions or it produces a report about two paths.
func TestClient_Status_ViaOverridesBothAssertions(t *testing.T) {
	op := mustGenerate(t, "laptop-primary")
	host := mustGenerate(t, "web-01")
	h := testHostSplitPath(t, host.Public().Encryption, host.Public().Signing)

	var pinged netip.AddrPort
	var dialed string
	rep, err := client.Status(context.Background(), client.StatusOptions{
		Builder: client.Builder{Signer: op},
		Host:    h,
		Via:     netip.MustParseAddr("100.64.7.7"),
		Exchange: func(ctx context.Context, to netip.AddrPort, payload []byte, wait time.Duration) ([]byte, error) {
			pinged = to
			return answerPong(t, host, op.Public(), h.HostID, testNowMS, nil)(ctx, to, payload, wait)
		},
		Dial: func(_ context.Context, _, address string) (net.Conn, error) {
			dialed = address
			return nil, nil
		},
		NowMS: fixedClock(testNowMS),
	})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if pinged.String() != "100.64.7.7:62201" {
		t.Errorf("liveness ping went to %s, want the --via address 100.64.7.7:62201", pinged)
	}
	if dialed != "100.64.7.7:22" {
		t.Errorf("recovery connect dialed %q, want the --via address 100.64.7.7:22", dialed)
	}
	if rep.Addr.String() != "100.64.7.7" {
		t.Errorf("report address = %s, want 100.64.7.7", rep.Addr)
	}
}

// The per-port case design section 7 spends a page on: mesh ACLs are
// routinely written per port, so a rule permitting UDP 62201 while dropping
// TCP 22 leaves the pong green with no shell available. A liveness result
// that reported only the pong would be green through exactly the outage it
// exists to catch.
//
// Mutation verified: making Healthy() return r.Pong alone fails this test.
func TestClient_Status_IsUnhealthyWhenThePongSucceedsButRecoveryIsUnreachable(t *testing.T) {
	op := mustGenerate(t, "laptop-primary")
	host := mustGenerate(t, "web-01")
	h := testHost(t, host.Public().Encryption, host.Public().Signing)

	rep, err := client.Status(context.Background(), client.StatusOptions{
		Builder:  client.Builder{Signer: op},
		Host:     h,
		Exchange: answerPong(t, host, op.Public(), h.HostID, testNowMS, nil),
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, context.DeadlineExceeded
		},
		NowMS: fixedClock(testNowMS),
	})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !rep.Pong {
		t.Fatalf("the pong should still verify: %v", rep.PongErr)
	}
	if rep.Recovery.Outcome != client.TimedOut {
		t.Fatalf("recovery outcome = %q, want timeout", rep.Recovery.Outcome)
	}
	if rep.Healthy() {
		t.Fatal("reported healthy with an unreachable recovery service; a fail-closed service armed " +
			"on that evidence leaves a host with no way in")
	}
}

// Echoing request_id and challenge_nonce together is what stops a captured
// pong answering a later ping. The client must verify against the values it
// minted for this exchange, not against whatever came back.
//
// Mutation verified: passing pong.Challenge (rather than the minted
// challenge) to Verify makes the "wrong challenge" row pass — and fail here.
func TestClient_Status_RejectsAPongThatDoesNotAnswerThePingItSent(t *testing.T) {
	op := mustGenerate(t, "laptop-primary")
	host := mustGenerate(t, "web-01")
	h := testHost(t, host.Public().Encryption, host.Public().Signing)

	for _, tc := range []struct {
		name   string
		mutate func(*spa.Pong)
	}{
		{"wrong challenge", func(p *spa.Pong) { p.Challenge = [16]byte{0xff} }},
		{"wrong request_id", func(p *spa.Pong) { p.RequestID = [16]byte{0xff} }},
		{"wrong host_id", func(p *spa.Pong) { p.HostID = [16]byte{0xff} }},
		{"stale timestamp", func(p *spa.Pong) { p.TimestampMS = testNowMS - 600_000 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep, err := client.Status(context.Background(), client.StatusOptions{
				Builder:  client.Builder{Signer: op},
				Host:     h,
				Exchange: answerPong(t, host, op.Public(), h.HostID, testNowMS, tc.mutate),
				Dial:     func(context.Context, string, string) (net.Conn, error) { return nil, nil },
				NowMS:    fixedClock(testNowMS),
			})
			if err != nil {
				t.Fatalf("Status: %v", err)
			}
			if rep.Pong {
				t.Fatal("a pong that does not answer this ping was accepted")
			}
			if !errors.Is(rep.PongErr, spa.ErrPongMismatch) {
				t.Fatalf("PongErr = %v, want ErrPongMismatch", rep.PongErr)
			}
		})
	}
}

// A pong signed by a key the client does not hold proves nothing. Refusing
// to check at all is better than reporting an unverified reply as liveness,
// which is the false green section 7 exists to remove.
func TestClient_Status_RefusesToVerifyAPongWithNoConfiguredHostSigningKey(t *testing.T) {
	op := mustGenerate(t, "laptop-primary")
	host := mustGenerate(t, "web-01")
	h := testHost(t, host.Public().Encryption, [32]byte{})

	rep, err := client.Status(context.Background(), client.StatusOptions{
		Builder:  client.Builder{Signer: op},
		Host:     h,
		Exchange: answerPong(t, host, op.Public(), h.HostID, testNowMS, nil),
		Dial:     func(context.Context, string, string) (net.Conn, error) { return nil, nil },
		NowMS:    fixedClock(testNowMS),
	})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if rep.Pong {
		t.Fatal("liveness reported without a key to verify it with")
	}
	if !errors.Is(rep.PongErr, client.ErrNoHostSigningKey) {
		t.Fatalf("PongErr = %v, want ErrNoHostSigningKey", rep.PongErr)
	}
}

// TestClient_Status_RefusesAHostWhoseSigningKeyIsTheOperatorsOwn is the
// operator-side half of keeping the two Ed25519 signing roles disjoint; the
// agent-side half is spa.NewOpenerFromSigner. A key that signs SPA requests
// as an operator and pongs as a host is a key whose signatures postern's
// domain tags, and nothing else, keep apart.
//
// The two rows differ in exactly one thing: whose key the host entry names as
// host_signing, and correspondingly who signs the reply. The host's
// encryption key is its own in both, so the ping is sealed and opened
// identically, and every other field the verifier checks is the one this
// exchange minted. The second row is what establishes that the first row's
// refusal comes from the key comparison rather than from the split-signer
// fixture: delete the comparison and the first row reports a healthy pong.
func TestClient_Status_RefusesAHostWhoseSigningKeyIsTheOperatorsOwn(t *testing.T) {
	for _, tc := range []struct {
		name         string
		operatorsOwn bool
	}{
		{"host_signing is the operator's own key", true},
		{"host_signing is a key of the host's own", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			op := mustGenerate(t, "laptop-primary")
			host := mustGenerate(t, "web-01")

			pongSigner := host
			if tc.operatorsOwn {
				pongSigner = op
			}
			h := testHost(t, host.Public().Encryption, pongSigner.Public().Signing)

			rep, err := client.Status(context.Background(), client.StatusOptions{
				Builder:  client.Builder{Signer: op},
				Host:     h,
				Exchange: answerPongSignedBy(t, host, pongSigner, op.Public(), h.HostID, testNowMS, nil),
				Dial:     func(context.Context, string, string) (net.Conn, error) { return nil, nil },
				NowMS:    fixedClock(testNowMS),
			})
			if err != nil {
				t.Fatalf("Status: %v", err)
			}
			if !tc.operatorsOwn {
				if !rep.Pong {
					t.Fatalf("pong not verified for a host with its own signing key: %v", rep.PongErr)
				}
				return
			}
			if rep.Pong {
				t.Fatal("reported liveness from a pong the operator's own key could have signed")
			}
			if !errors.Is(rep.PongErr, client.ErrHostKeyIsOperatorKey) {
				t.Fatalf("PongErr = %v, want ErrHostKeyIsOperatorKey", rep.PongErr)
			}
		})
	}
}

// TestClient_Status_ReportsAMissingOperatorIdentityRatherThanPanicking pins
// the guard on the role-reuse comparison above, which reads the operator's
// public key and so has a nil Signer within reach. The answer a caller
// without an identity loaded gets is the same one the Builder has always
// given, reached one step later.
func TestClient_Status_ReportsAMissingOperatorIdentityRatherThanPanicking(t *testing.T) {
	host := mustGenerate(t, "web-01")
	h := testHost(t, host.Public().Encryption, host.Public().Signing)

	rep, err := client.Status(context.Background(), client.StatusOptions{
		Host: h,
		Exchange: func(context.Context, netip.AddrPort, []byte, time.Duration) ([]byte, error) {
			t.Error("a ping was sent with no operator identity loaded")
			return nil, nil
		},
		Dial:  func(context.Context, string, string) (net.Conn, error) { return nil, nil },
		NowMS: fixedClock(testNowMS),
	})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if rep.Pong {
		t.Fatal("liveness reported with no operator identity loaded")
	}
	if rep.PongErr == nil {
		t.Fatal("PongErr = nil, want the Builder's missing-identity error")
	}
}

func TestClient_Status_ReportsSilenceOnTheAlwaysAllowPathAsAFailedPong(t *testing.T) {
	op := mustGenerate(t, "laptop-primary")
	host := mustGenerate(t, "web-01")
	h := testHost(t, host.Public().Encryption, host.Public().Signing)

	rep, err := client.Status(context.Background(), client.StatusOptions{
		Builder: client.Builder{Signer: op},
		Host:    h,
		Exchange: func(context.Context, netip.AddrPort, []byte, time.Duration) ([]byte, error) {
			return nil, syscall.ETIMEDOUT
		},
		Dial:  func(context.Context, string, string) (net.Conn, error) { return nil, nil },
		NowMS: fixedClock(testNowMS),
	})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if rep.Pong {
		t.Fatal("a silent path reported as live")
	}
	if rep.Healthy() {
		t.Fatal("Healthy() is true with no pong")
	}
}
