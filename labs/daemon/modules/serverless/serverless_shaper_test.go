package serverless

import (
	"bytes"
	"net"
	"testing"
)

func TestServerlessDirectShaper_IsCensorshipSink(t *testing.T) {
	shaper := NewServerlessDirectShaper()

	sinkIPv4 := net.ParseIP("10.10.34.1")
	if !shaper.IsCensorshipSink(sinkIPv4) {
		t.Errorf("Expected 10.10.34.1 to be detected as censorship sink")
	}

	sinkIPv4Sub := net.ParseIP("10.10.34.254")
	if !shaper.IsCensorshipSink(sinkIPv4Sub) {
		t.Errorf("Expected 10.10.34.254 to be detected as censorship sink")
	}

	cleanIPv4 := net.ParseIP("1.1.1.1")
	if shaper.IsCensorshipSink(cleanIPv4) {
		t.Errorf("Did not expect 1.1.1.1 to be detected as censorship sink")
	}

	sinkIPv6 := net.ParseIP("2001:4188:2:600::1")
	if !shaper.IsCensorshipSink(sinkIPv6) {
		t.Errorf("Expected 2001:4188:2:600::1 to be detected as censorship sink")
	}

	cleanIPv6 := net.ParseIP("2606:4700:4700::1111")
	if shaper.IsCensorshipSink(cleanIPv6) {
		t.Errorf("Did not expect 2606:4700:4700::1111 to be detected as censorship sink")
	}
}

func TestServerlessDirectShaper_ShapeClientHello_LowDelay(t *testing.T) {
	shaper := NewServerlessDirectShaper()
	payload := make([]byte, 100)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	cfg := DefaultServerlessShaperConfig()
	cfg.Profile = ServerlessProfileLowDelay

	fragments := shaper.ShapeClientHello(payload, cfg)
	if len(fragments) < 3 {
		t.Fatalf("Expected at least 3 fragments, got %d", len(fragments))
	}

	if len(fragments[0].Payload) != 5 {
		t.Errorf("Expected record header chunk of length 5, got %d", len(fragments[0].Payload))
	}
	if fragments[0].DelayMs != 0 {
		t.Errorf("Expected 0ms delay for record header, got %d", fragments[0].DelayMs)
	}

	if len(fragments[1].Payload) != 38 {
		t.Errorf("Expected prefix chunk of length 38, got %d", len(fragments[1].Payload))
	}

	reconstructed := ReconstructFragments(fragments)
	if !bytes.Equal(reconstructed, payload) {
		t.Errorf("Reconstructed payload mismatch")
	}
}

func TestServerlessDirectShaper_ShapeClientHello_HighDelay(t *testing.T) {
	shaper := NewServerlessDirectShaper()
	payload := make([]byte, 80)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	cfg := DefaultServerlessShaperConfig()
	cfg.Profile = ServerlessProfileHighDelay

	fragments := shaper.ShapeClientHello(payload, cfg)

	hasStall := false
	for _, f := range fragments {
		if f.DelayMs == 400 {
			hasStall = true
			break
		}
	}
	if !hasStall {
		t.Errorf("Expected rhythmic 400ms stall in HighDelay profile")
	}

	reconstructed := ReconstructFragments(fragments)
	if !bytes.Equal(reconstructed, payload) {
		t.Errorf("Reconstructed payload mismatch")
	}
}

func TestServerlessDirectShaper_ShapeTCPStream(t *testing.T) {
	shaper := NewServerlessDirectShaper()
	data := []byte("GET / HTTP/1.1\r\nHost: target.org\r\n\r\n")

	cfg := DefaultServerlessShaperConfig()
	fragments := shaper.ShapeTCPStream(data, cfg)

	if len(fragments) != len(data) {
		t.Errorf("Expected 1-byte chunking for TCP stream, got %d vs %d", len(fragments), len(data))
	}

	reconstructed := ReconstructFragments(fragments)
	if !bytes.Equal(reconstructed, data) {
		t.Errorf("Reconstructed TCP stream mismatch")
	}
}

func TestServerlessDirectShaper_GenerateUDPNoise(t *testing.T) {
	shaper := NewServerlessDirectShaper()
	cfg := DefaultServerlessShaperConfig()

	noise := shaper.GenerateUDPNoise(3, cfg)
	if len(noise) < 1200 || len(noise) > 1230 {
		t.Errorf("Noise payload length out of bounds: %d", len(noise))
	}

	cfg.UDPNoiseEnabled = false
	if shaper.GenerateUDPNoise(3, cfg) != nil {
		t.Errorf("Expected nil when UDP noise is disabled")
	}
}
