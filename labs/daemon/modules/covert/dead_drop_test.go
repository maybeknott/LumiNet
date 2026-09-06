package covert

import (
	"bytes"
	"testing"
	"time"
)

func TestDeriveBlobKey_And_MuxLaneKey(t *testing.T) {
	secret := "test_master_secret_dead_drop"
	key, err := DeriveBlobKey(secret)
	if err != nil {
		t.Fatalf("DeriveBlobKey failed: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("Expected 32 bytes, got %d", len(key))
	}

	var sid [16]byte
	copy(sid[:], []byte("0123456789abcdef"))

	lane0, err := DeriveMuxLaneKeyV4(secret, sid, DirectionUp, "client-x", "run-y", 0)
	if err != nil {
		t.Fatalf("DeriveMuxLaneKeyV4 failed: %v", err)
	}
	lane1, err := DeriveMuxLaneKeyV4(secret, sid, DirectionUp, "client-x", "run-y", 1)
	if err != nil {
		t.Fatalf("DeriveMuxLaneKeyV4 failed: %v", err)
	}

	if bytes.Equal(lane0, lane1) {
		t.Errorf("Distinct lanes must yield distinct subkeys")
	}

	// Hex secret
	hexSecret := "hex:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	hexKey, err := DeriveBlobKey(hexSecret)
	if err != nil {
		t.Fatalf("DeriveBlobKey hex failed: %v", err)
	}
	if hexKey[0] != 0x01 || hexKey[31] != 0x20 {
		t.Errorf("Hex key decoded incorrectly")
	}
}

func TestSeal_And_OpenBlobEnvelope(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	var sid [16]byte
	copy(sid[:], []byte("dead_drop_sess_1"))
	seq := uint64(987654)
	plaintext := []byte("Sensitive Covert Stream Data Passing Through Dead-Drop Queue")

	sealed, err := SealBlobEnvelope(key, sid, DirectionUp, seq, plaintext, false)
	if err != nil {
		t.Fatalf("SealBlobEnvelope failed: %v", err)
	}

	if string(sealed[:4]) != EnvelopeMagic {
		t.Errorf("Magic mismatch: got %s", string(sealed[:4]))
	}

	env, decrypted, err := OpenBlobEnvelope(key, sealed)
	if err != nil {
		t.Fatalf("OpenBlobEnvelope failed: %v", err)
	}

	if env.SessionID != sid {
		t.Errorf("SessionID mismatch")
	}
	if env.Direction != DirectionUp {
		t.Errorf("Direction mismatch")
	}
	if env.Sequence != seq {
		t.Errorf("Sequence mismatch")
	}
	if env.Flags != FlagData {
		t.Errorf("Flags mismatch")
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted payload mismatch")
	}
}

func TestSeal_FinalEnvelope(t *testing.T) {
	key := make([]byte, 32)
	var sid [16]byte
	plaintext := []byte("EOF")

	sealed, err := SealBlobEnvelope(key, sid, DirectionDown, 1, plaintext, true)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	env, decrypted, err := OpenBlobEnvelope(key, sealed)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if env.Flags != FlagFinal {
		t.Errorf("Expected FlagFinal, got %d", env.Flags)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted payload mismatch")
	}
}

func TestAdaptiveCoalescer_Decisions(t *testing.T) {
	if EvaluateCoalesceTier(100) != TierInteractive {
		t.Errorf("Expected TierInteractive")
	}
	if EvaluateCoalesceTier(10*1024) != TierMedium {
		t.Errorf("Expected TierMedium")
	}
	if EvaluateCoalesceTier(100*1024) != TierBulk {
		t.Errorf("Expected TierBulk")
	}
	if EvaluateCoalesceTier(300*1024) != TierForcedBulk {
		t.Errorf("Expected TierForcedBulk")
	}

	if ShouldFlush(100, 2*time.Millisecond) {
		t.Errorf("Should not flush 100 bytes at 2ms")
	}
	if !ShouldFlush(100, 16*time.Millisecond) {
		t.Errorf("Should flush 100 bytes at 16ms (max age for interactive is 15ms)")
	}
	if !ShouldFlush(300*1024, 1*time.Millisecond) {
		t.Errorf("Should flush 300KB immediately (exceeds forced bulk threshold)")
	}
}
