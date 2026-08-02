package client_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/jotra7/postern/internal/client"
	"github.com/jotra7/postern/internal/identity"
	"github.com/jotra7/postern/internal/knockport"
	"github.com/jotra7/postern/internal/spa"
)

// noSleep replaces the wait between copies, so a multi-send test finishes
// instantly and deterministically rather than depending on a real timer.
func noSleep(context.Context, time.Duration) {}

// A confirm is one UDP datagram and UDP does not guarantee delivery. On a
// live two-host fleet the first confirm to one host was lost and the second
// landed; the other took four attempts. The consequence of a lost confirm is
// not an error the operator sees — the SPA path never answers — it is an
// automatic revert ten minutes later, which is the expensive failure the
// command exists to prevent.
//
// Mutation verified: forcing sends to 1 in SendAction (`sends = 1`
// unconditionally) fails this on the count.
func TestClient_SendAction_SendsMoreThanOneDatagram(t *testing.T) {
	op := mustGenerate(t, "laptop-primary")
	host := mustGenerate(t, "web-01")
	h := testHost(t, host.Public().Encryption, host.Public().Signing)

	sender := &recordingSend{}
	b := client.Builder{Signer: op}
	rep, err := client.SendAction(context.Background(), client.ActionOptions{
		Builder: b,
		Host:    h,
		Send:    sender.send,
		Sends:   client.DefaultActionSends,
		Sleep:   noSleep,
		NowMS:   fixedClock(testNowMS),
	}, func(nowMS uint64) (*spa.Request, error) {
		return b.Confirm(h, 47, [16]byte{0xab}, nowMS)
	})
	if err != nil {
		t.Fatalf("SendAction: %v", err)
	}
	if client.DefaultActionSends < 2 {
		t.Fatal("DefaultActionSends is 1, so a lost confirm is still an automatic revert")
	}
	if len(sender.payload) != client.DefaultActionSends {
		t.Fatalf("sent %d datagrams, want %d", len(sender.payload), client.DefaultActionSends)
	}
	if rep.Sent != client.DefaultActionSends || rep.Attempted != client.DefaultActionSends {
		t.Fatalf("report says %d of %d sent, want %d of %d",
			rep.Sent, rep.Attempted, client.DefaultActionSends, client.DefaultActionSends)
	}
}

// Each copy is built fresh, so no two carry the same request_id. Resending
// one sealed datagram would be a replay of a single packet rather than
// several sends of one instruction: internal/replay reserves on request_id,
// so every copy after the first would be refused before it ever reached the
// confirm action — which would make the retry guarantee only that the FIRST
// attempt can land, the exact opposite of the point.
//
// The assertion is on request_id read back out of the sealed datagram by the
// host's own opener, not on the ciphertext: spa.Seal draws a fresh nonce per
// call, so byte-distinctness would hold even for three seals of one identical
// request and would prove nothing about replay.
//
// Mutation verified: hoisting the build and Seal out of SendAction's loop
// (sealing once, sending the same slice three times) fails this.
func TestClient_SendAction_EachCopyCarriesItsOwnRequestID(t *testing.T) {
	op := mustGenerate(t, "laptop-primary")
	host := mustGenerate(t, "web-01")
	h := testHost(t, host.Public().Encryption, host.Public().Signing)
	opener, _, err := spa.NewOpenerFromSigner(host, []identity.PublicIdentity{op.Public()})
	if err != nil {
		t.Fatalf("NewOpenerFromSigner: %v", err)
	}

	sender := &recordingSend{}
	b := client.Builder{Signer: op}
	if _, err := client.SendAction(context.Background(), client.ActionOptions{
		Builder: b,
		Host:    h,
		Send:    sender.send,
		Sends:   3,
		Sleep:   noSleep,
		NowMS:   fixedClock(testNowMS),
	}, func(nowMS uint64) (*spa.Request, error) {
		return b.Confirm(h, 47, [16]byte{0xab}, nowMS)
	}); err != nil {
		t.Fatalf("SendAction: %v", err)
	}

	seen := map[[16]byte]bool{}
	for i, p := range sender.payload {
		req, _, err := opener.TrialOpen(p)
		if err != nil {
			t.Fatalf("datagram %d does not open under the host's own key: %v", i, err)
		}
		if seen[req.RequestID] {
			t.Fatalf("datagram %d repeats request_id %x; the agent's replay store would refuse it, so "+
				"only the first copy could ever reach the confirm action", i, req.RequestID)
		}
		seen[req.RequestID] = true
	}
	if len(seen) != 3 {
		t.Fatalf("%d distinct request_ids, want 3", len(seen))
	}
}

// A confirm or disarm against a rotation host has to land on the same
// current-window port `open` uses: the agent does not bind the fixed port at
// all once rotation is on, so a confirm sent to KnockAddrPort's fixed default
// (Task 7 left this branch only in Open) is a datagram to a port nothing is
// listening on. The dead-man timer then reverts the very change the confirm
// was meant to ratify, silently, ten minutes later — that failure mode is
// what this guards.
//
// Mutation verified: reverting SendAction to `rep := ActionReport{To:
// o.Host.KnockAddrPort()}` with nothing after it fails this on the port.
func TestClient_SendAction_RotationSendsToTheCurrentWindowPort(t *testing.T) {
	op := mustGenerate(t, "laptop-primary")
	h := rotationHost(t)

	sender := &recordingSend{}
	b := client.Builder{Signer: op}
	rep, err := client.SendAction(context.Background(), client.ActionOptions{
		Builder: b,
		Host:    h,
		Send:    sender.send,
		Sends:   1,
		Sleep:   noSleep,
		NowMS:   fixedClock(600_000), // unix 600 -> window 1 at the 10m default
	}, func(nowMS uint64) (*spa.Request, error) {
		return b.Confirm(h, 47, [16]byte{0xab}, nowMS)
	})
	if err != nil {
		t.Fatalf("SendAction: %v", err)
	}
	// Computed straight from knockport, independent of CurrentKnockPort's own
	// correctness, the same reason TestClient_Open_RotationSendsOneDatagramToTheCurrentWindowPort does.
	wantWindow := knockport.Window(600, 10*time.Minute)
	wantPort := knockport.Port(rotationSecret(), wantWindow, 20000, 30000)
	if rep.To.Addr() != h.KnockAddr || rep.To.Port() != wantPort {
		t.Fatalf("action went to %s, want %s:%d (the current-window port)", rep.To, h.KnockAddr, wantPort)
	}
	if len(sender.to) != 1 || sender.to[0] != rep.To {
		t.Fatalf("datagram sent to %v, want it to match the reported destination %s", sender.to, rep.To)
	}
}

// A send that fails part-way through is not a failed command: one datagram on
// the wire is all a confirm has ever needed, and reporting an error would
// send an operator chasing a confirm that in fact landed.
//
// The pairing that makes this attributable: the same table drives a run where
// EVERY send fails, which must report the error. Without that row an
// implementation that swallowed every error would pass.
func TestClient_SendAction_ReportsAnErrorOnlyWhenNoCopyLeft(t *testing.T) {
	sendErr := errors.New("network is unreachable")
	for _, tc := range []struct {
		name     string
		failFrom int // the copy index (0-based) from which sends start failing
		wantSent int
		wantErr  bool
	}{
		{"all copies land", 3, 3, false},
		{"only the first lands", 1, 1, false},
		{"nothing leaves the machine", 0, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			op := mustGenerate(t, "laptop-primary")
			host := mustGenerate(t, "web-01")
			h := testHost(t, host.Public().Encryption, host.Public().Signing)

			n := 0
			send := func(context.Context, netip.AddrPort, []byte) error {
				defer func() { n++ }()
				if n >= tc.failFrom {
					return sendErr
				}
				return nil
			}
			b := client.Builder{Signer: op}
			rep, err := client.SendAction(context.Background(), client.ActionOptions{
				Builder: b,
				Host:    h,
				Send:    send,
				Sends:   3,
				Sleep:   noSleep,
				NowMS:   fixedClock(testNowMS),
			}, func(nowMS uint64) (*spa.Request, error) {
				return b.Confirm(h, 47, [16]byte{0xab}, nowMS)
			})
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if rep.Sent != tc.wantSent {
				t.Fatalf("report says %d sent, want %d", rep.Sent, tc.wantSent)
			}
			if rep.Attempted != 3 {
				t.Fatalf("report says %d attempted, want 3", rep.Attempted)
			}
		})
	}
}
