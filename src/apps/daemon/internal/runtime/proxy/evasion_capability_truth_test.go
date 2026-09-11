package proxy

import (
	"strings"
	"testing"
)

func TestNormalizeEvasionConfigCanonicalizesPixelStego(t *testing.T) {
	cfg := normalizeEvasionConfig(EvasionConfig{StegoEnabled: true, StegoMode: "pixel_stego"})
	if cfg.StegoMode != "pixel" {
		t.Fatalf("StegoMode=%q want pixel", cfg.StegoMode)
	}
	if err := validateEvasionConfig(cfg); err != nil {
		t.Fatalf("canonical pixel mode rejected: %v", err)
	}
}

func TestValidateEvasionConfigRejectsUnknownStegoMode(t *testing.T) {
	cfg := DefaultEvasionConfig()
	cfg.StegoEnabled = true
	cfg.StegoMode = "pretend-mode"
	cfg.StegoWebRTCSDPSpoof = false
	if err := validateEvasionConfig(cfg); err == nil || !strings.Contains(err.Error(), "unsupported steganography mode") {
		t.Fatalf("err=%v, want unsupported steganography mode", err)
	}
}

func TestValidateEvasionConfigRejectsBehaviorlessSDPSpoof(t *testing.T) {
	cfg := DefaultEvasionConfig()
	cfg.StegoEnabled = true
	cfg.StegoMode = "webrtc_voip"
	cfg.StegoWebRTCSDPSpoof = true
	if err := validateEvasionConfig(cfg); err == nil || !strings.Contains(err.Error(), "not implemented") {
		t.Fatalf("err=%v, want fail-closed SDP spoof rejection", err)
	}
}

func TestValidateEvasionConfigRejectsDisconnectedAutoReconnect(t *testing.T) {
	cfg := DefaultEvasionConfig()
	cfg.AutoReconnectEnabled = true
	if err := validateEvasionConfig(cfg); err == nil || !strings.Contains(err.Error(), "not production-supported") {
		t.Fatalf("err=%v, want disconnected auto-reconnect rejection", err)
	}
}
