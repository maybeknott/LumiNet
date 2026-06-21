package bridge

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestPadClientHello(t *testing.T) {
	// A minimal valid TLS ClientHello hex string:
	// TLS Record Header: 16 (handshake) 03 01 (TLS 1.0) 00 2d (length 45)
	// Handshake Header: 01 (ClientHello) 00 00 29 (length 41)
	// Client version: 03 03 (TLS 1.2)
	// Random: 32 bytes of zeros
	// Session ID: 00 (0 bytes)
	// Cipher Suites: 00 02 (length 2) 00 2f (TLS_RSA_WITH_AES_128_CBC_SHA)
	// Compression Methods: 01 (length 1) 00 (none)
	// (No extensions block)
	clientHelloHex := "160301002d010000290303" + strings.Repeat("00", 32) + "00" + "0002002f" + "0100"

	padLen := 10
	paddedHex, err := PadClientHello(clientHelloHex, padLen)
	if err != nil {
		t.Fatalf("PadClientHello failed: %v", err)
	}

	paddedBytes, err := hex.DecodeString(paddedHex)
	if err != nil {
		t.Fatalf("failed to decode padded hex: %v", err)
	}

	// The padded client hello should contain:
	// - Type 0x0015 (21) at some point
	// - The total length should increase by 2 (ext block length) + 4 (ext header) + padLen (zeros)
	expectedLen := len(clientHelloHex)/2 + 2 + 4 + padLen
	if len(paddedBytes) != expectedLen {
		t.Errorf("padded length mismatch: expected %d, got %d", expectedLen, len(paddedBytes))
	}

	// Verify that the record header length fields were updated correctly
	recLen := int(paddedBytes[3])<<8 | int(paddedBytes[4])
	if recLen != len(paddedBytes)-5 {
		t.Errorf("record length mismatch: header has %d, actual is %d", recLen, len(paddedBytes)-5)
	}

	hsLen := int(paddedBytes[6])<<16 | int(paddedBytes[7])<<8 | int(paddedBytes[8])
	if hsLen != len(paddedBytes)-9 {
		t.Errorf("handshake length mismatch: header has %d, actual is %d", hsLen, len(paddedBytes)-9)
	}
}
