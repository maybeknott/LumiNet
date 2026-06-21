package proxy

import (
	"bytes"
	"image"
	"io"
	"net"
	"testing"
)

func TestDeriveSecretFromJoinLink(t *testing.T) {
	tests := []struct {
		url      string
		expected []byte
	}{
		{"https://telemost.yandex.ru/j/1234567890?param=abc#anchor", []byte("1234567890")},
		{"https://telemost.yandex.ru/j/room-id-999/", []byte("room-id-999")},
		{"https://zoom.us/j/123?pwd=456", []byte("123")},
		{"", nil},
	}

	for _, tc := range tests {
		res := DeriveSecretFromJoinLink(tc.url)
		if !bytes.Equal(res, tc.expected) {
			t.Errorf("expected secret from URL %q to be %q, got %q", tc.url, tc.expected, res)
		}
	}
}

func TestWebRTCStegoHandshakeAndKeepalive(t *testing.T) {
	secret := []byte("session-shared-token")
	obf, err := NewWebRTCStegoObfuscator(secret)
	if err != nil {
		t.Fatalf("failed to create obfuscator: %v", err)
	}

	// Keepalive frame should be 24 bytes long
	frame := obf.EncodeKeepalive()
	if len(frame) != 24 {
		t.Errorf("expected keepalive frame size 24, got %d", len(frame))
	}
	if frame[0] != 0x30 {
		t.Errorf("expected first byte 0x30, got 0x%02x", frame[0])
	}

	// Decode keepalive on peer obfuscator
	peerObf, err := NewWebRTCStegoObfuscator(secret)
	if err != nil {
		t.Fatalf("failed to create peer obfuscator: %v", err)
	}

	res := peerObf.Decode(frame)
	if !res.HasFrame {
		t.Error("expected Decode to find a frame")
	}
	if !res.Keepalive {
		t.Error("expected decoded frame to be keepalive")
	}
	if res.SelfEcho {
		t.Error("expected self-echo to be false for different peer")
	}
	if res.PeerEpoch != obf.localEpoch {
		t.Errorf("expected peer epoch %d, got %d", obf.localEpoch, res.PeerEpoch)
	}
}

func TestWebRTCStegoDataEncryptionAndDecryption(t *testing.T) {
	secret := []byte("session-shared-token")
	obf, err := NewWebRTCStegoObfuscator(secret)
	if err != nil {
		t.Fatalf("failed to create obfuscator: %v", err)
	}

	payload := []byte("Steganographic SOCKS5/TCP data")
	frame, err := obf.EncodeData(payload)
	if err != nil {
		t.Fatalf("failed to encode data: %v", err)
	}

	// Header: 17 bytes VP8 interframe + 4 bytes epoch = 21 bytes
	// Nonce: 24 bytes
	// Ciphertext + Tag: len(payload) + 16 bytes
	// Total: 21 + 24 + len(payload) + 16 = 61 + len(payload)
	expectedLen := 61 + len(payload)
	if len(frame) != expectedLen {
		t.Errorf("expected frame size %d, got %d", expectedLen, len(frame))
	}
	if frame[0] != 0xb1 {
		t.Errorf("expected first byte 0xb1, got 0x%02x", frame[0])
	}

	// Decode with peer
	peerObf, err := NewWebRTCStegoObfuscator(secret)
	if err != nil {
		t.Fatalf("failed to create peer: %v", err)
	}

	res := peerObf.Decode(frame)
	if !res.HasFrame {
		t.Error("expected decoded result to have frame")
	}
	if res.Keepalive {
		t.Error("expected decoded result not to be keepalive")
	}
	if res.SelfEcho {
		t.Error("expected self-echo to be false")
	}
	if !bytes.Equal(res.Payload, payload) {
		t.Errorf("expected payload %q, got %q", payload, res.Payload)
	}
	if res.PeerEpoch != obf.localEpoch {
		t.Errorf("expected peer epoch %d, got %d", obf.localEpoch, res.PeerEpoch)
	}

	// Test self-echo detection
	resSelf := obf.Decode(frame)
	if !resSelf.HasFrame {
		t.Error("expected self decode to have frame")
	}
	if !resSelf.SelfEcho {
		t.Error("expected self-echo to be true")
	}
}

func TestPixelSteganography(t *testing.T) {
	// Create a mock transparent image (100x100 pixels = 10000 pixels capacity)
	img := image.NewRGBA(image.Rect(0, 0, 100, 100))
	payload := []byte("lumiNet intranet camouflage secret payload")

	// Hide data
	stegoImg, err := HideDataInImage(img, payload)
	if err != nil {
		t.Fatalf("failed to hide data in image: %v", err)
	}

	// Extract data
	extracted, err := ExtractDataFromImage(stegoImg)
	if err != nil {
		t.Fatalf("failed to extract data from image: %v", err)
	}

	if !bytes.Equal(payload, extracted) {
		t.Errorf("expected extracted payload %q, got %q", payload, extracted)
	}
}

func TestWebRTCStegoConn_ReadWrite(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	secret := []byte("shared-secret-key")

	stegoC1, err := NewWebRTCStegoConn(c1, secret)
	if err != nil {
		t.Fatalf("failed to create client stego conn: %v", err)
	}

	stegoC2, err := NewWebRTCStegoConn(c2, secret)
	if err != nil {
		t.Fatalf("failed to create server stego conn: %v", err)
	}

	payload := []byte("camouflaged connection payload over virtual pipe")

	errChan := make(chan error, 1)
	go func() {
		_, err := stegoC1.Write(payload)
		errChan <- err
	}()

	buf := make([]byte, len(payload))
	n, err := stegoC2.Read(buf)
	if err != nil {
		t.Fatalf("failed to read from stego conn: %v", err)
	}

	if err := <-errChan; err != nil {
		t.Fatalf("failed to write to stego conn: %v", err)
	}

	if n != len(payload) {
		t.Errorf("expected read length %d, got %d", len(payload), n)
	}

	if !bytes.Equal(buf, payload) {
		t.Errorf("expected payload %q, got %q", payload, buf)
	}
}

func TestPixelStegoConn_ReadWrite(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	// Use a non-existent path to test clean fallback
	stegoC1 := NewPixelStegoConn(c1, "missing_decoy_image.png")
	stegoC2 := NewPixelStegoConn(c2, "missing_decoy_image.png")

	payload := []byte("pixel steganography connection camouflage payload!")

	errChan := make(chan error, 1)
	go func() {
		_, err := stegoC1.Write(payload)
		errChan <- err
	}()

	// We read in two chunks to verify read buffering
	chunk1 := make([]byte, 10)
	n1, err := stegoC2.Read(chunk1)
	if err != nil {
		t.Fatalf("failed to read first chunk: %v", err)
	}

	chunk2 := make([]byte, len(payload)-10)
	n2, err := io.ReadFull(stegoC2, chunk2)
	if err != nil {
		t.Fatalf("failed to read second chunk: %v", err)
	}

	if err := <-errChan; err != nil {
		t.Fatalf("failed to write to stego conn: %v", err)
	}

	if n1+n2 != len(payload) {
		t.Errorf("expected total read length %d, got %d", len(payload), n1+n2)
	}

	fullRead := append(chunk1[:n1], chunk2...)
	if !bytes.Equal(fullRead, payload) {
		t.Errorf("expected payload %q, got %q", payload, fullRead)
	}
}

