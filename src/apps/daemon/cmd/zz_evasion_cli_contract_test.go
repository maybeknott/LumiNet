package cmd

import (
	"strings"
	"testing"
)

func TestUnsupportedEvasionFlagsAreNotAdvertised(t *testing.T) {
	for _, name := range []string{"stego-webrtc-sdp", "upgen-quic-rate"} {
		flag := systemEvasionTunnelStartCmd.Flags().Lookup(name)
		if flag == nil {
			t.Fatalf("expected legacy compatibility flag %q", name)
		}
		if !flag.Hidden {
			t.Fatalf("legacy unsupported flag %q must be hidden from user-facing help", name)
		}
	}

	mode := systemEvasionTunnelStartCmd.Flags().Lookup("stego-mode")
	if mode == nil {
		t.Fatal("expected stego-mode flag")
	}
	if !strings.Contains(mode.Usage, "webrtc_voip or pixel") {
		t.Fatalf("stego-mode help must describe canonical runtime values, got %q", mode.Usage)
	}
}
