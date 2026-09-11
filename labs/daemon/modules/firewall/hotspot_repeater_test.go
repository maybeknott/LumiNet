package firewall

import (
	"strings"
	"testing"
)

func TestHotspotNatRepeater(t *testing.T) {
	repeater := NewHotspotNatRepeater(DefaultHotspotRepeaterConfig())
	cmds := repeater.GenerateIptablesCommands()

	foundMasq := false
	foundMss := false
	for _, c := range cmds {
		if strings.Contains(c, "-o tun0 -j MASQUERADE") {
			foundMasq = true
		}
		if strings.Contains(c, "TCPMSS --set-mss 1360") {
			foundMss = true
		}
	}

	if !foundMasq || !foundMss {
		t.Fatal("missing vital hotspot repeater rules")
	}
}
