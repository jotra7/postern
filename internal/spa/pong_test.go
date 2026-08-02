package spa_test

import (
	"errors"
	"testing"

	"github.com/jotra7/postern/internal/identity"
	"github.com/jotra7/postern/internal/spa"
)

func TestSPA_Pong_RoundTripsAndVerifies(t *testing.T) {
	host, err := identity.Generate("web-01")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	p := &spa.Pong{Version: spa.Version1, Alg: spa.AlgEd25519X25519, TimestampMS: 1_700_000_000_000}
	for i := range p.HostID {
		p.HostID[i] = byte(i)
		p.RequestID[i] = byte(i + 40)
		p.Challenge[i] = byte(i + 80)
	}

	raw, err := spa.SignPong(p, host)
	if err != nil {
		t.Fatalf("SignPong: %v", err)
	}
	if len(raw) != spa.PongSize {
		t.Fatalf("pong = %d bytes, want %d", len(raw), spa.PongSize)
	}

	got, err := spa.ParsePong(raw)
	if err != nil {
		t.Fatalf("ParsePong: %v", err)
	}
	if err := got.Verify(host.Public().Signing, p.HostID, p.RequestID, p.Challenge, p.TimestampMS, 60_000); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestSPA_Pong_Verify_RejectsMismatchedFields(t *testing.T) {
	host, _ := identity.Generate("web-01")
	p := &spa.Pong{Version: spa.Version1, Alg: spa.AlgEd25519X25519, TimestampMS: 1_000_000}
	for i := range p.HostID {
		p.HostID[i] = 1
		p.RequestID[i] = 2
		p.Challenge[i] = 3
	}
	raw, _ := spa.SignPong(p, host)
	got, err := spa.ParsePong(raw)
	if err != nil {
		t.Fatalf("ParsePong: %v", err)
	}

	var wrong [16]byte
	wrong[0] = 0xff

	// Echoing both request_id and challenge_nonce is what stops a captured
	// pong answering a later ping, so each must be checked.
	if err := got.Verify(host.Public().Signing, wrong, p.RequestID, p.Challenge, p.TimestampMS, 60_000); err == nil {
		t.Error("Verify accepted a mismatched host_id")
	}
	if err := got.Verify(host.Public().Signing, p.HostID, wrong, p.Challenge, p.TimestampMS, 60_000); err == nil {
		t.Error("Verify accepted a mismatched request_id")
	}
	if err := got.Verify(host.Public().Signing, p.HostID, p.RequestID, wrong, p.TimestampMS, 60_000); err == nil {
		t.Error("Verify accepted a mismatched challenge nonce")
	}
}

func TestSPA_Pong_Verify_RejectsStaleTimestamp(t *testing.T) {
	host, _ := identity.Generate("web-01")
	p := &spa.Pong{Version: spa.Version1, Alg: spa.AlgEd25519X25519, TimestampMS: 1_000_000}
	raw, _ := spa.SignPong(p, host)
	got, _ := spa.ParsePong(raw)

	now := p.TimestampMS + 120_000
	if err := got.Verify(host.Public().Signing, p.HostID, p.RequestID, p.Challenge, now, 60_000); err == nil {
		t.Fatal("Verify accepted a pong outside the freshness window")
	}
}

func TestSPA_Pong_Verify_RejectsWrongSigningKey(t *testing.T) {
	host, _ := identity.Generate("web-01")
	impostor, _ := identity.Generate("not-web-01")

	p := &spa.Pong{Version: spa.Version1, Alg: spa.AlgEd25519X25519, TimestampMS: 1_000_000}
	raw, _ := spa.SignPong(p, impostor)
	got, _ := spa.ParsePong(raw)

	if err := got.Verify(host.Public().Signing, p.HostID, p.RequestID, p.Challenge, p.TimestampMS, 60_000); err == nil {
		t.Fatal("Verify accepted a pong signed by the wrong host")
	}
}

func TestSPA_ParsePong_RejectsLengthOutsideBounds(t *testing.T) {
	// Padding makes any length in [PongSize, MaxDatagram] legitimate, so only a
	// record shorter than PongSize or longer than MaxDatagram is rejected on
	// length. PongSize+1 is no longer wrong: it is a one-byte padded pong.
	for _, n := range []int{0, spa.PongSize - 1, spa.MaxDatagram + 1} {
		if _, err := spa.ParsePong(make([]byte, n)); !errors.Is(err, spa.ErrWrongSize) {
			t.Errorf("ParsePong(%d bytes) = %v, want ErrWrongSize", n, err)
		}
	}
}

func TestSPA_ParsePong_AcceptsPaddedPong(t *testing.T) {
	// A padded pong of several lengths verifies exactly as the unpadded record
	// does. Padding is appended directly so the boundary lengths (exactly the
	// record, mid-range, and MaxDatagram) are exercised deterministically.
	host, err := identity.Generate("web-01")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	p := &spa.Pong{Version: spa.Version1, Alg: spa.AlgEd25519X25519, TimestampMS: 1_700_000_000_000}
	for i := range p.HostID {
		p.HostID[i] = byte(i)
		p.RequestID[i] = byte(i + 40)
		p.Challenge[i] = byte(i + 80)
	}
	raw, err := spa.SignPong(p, host)
	if err != nil {
		t.Fatalf("SignPong: %v", err)
	}

	for _, total := range []int{spa.PongSize, spa.PongSize + 99, spa.MaxDatagram} {
		padded := make([]byte, total)
		copy(padded, raw)
		got, err := spa.ParsePong(padded)
		if err != nil {
			t.Fatalf("ParsePong(%d bytes): %v", total, err)
		}
		if err := got.Verify(host.Public().Signing, p.HostID, p.RequestID, p.Challenge, p.TimestampMS, 60_000); err != nil {
			t.Errorf("Verify after ParsePong(%d bytes): %v", total, err)
		}
	}
}
