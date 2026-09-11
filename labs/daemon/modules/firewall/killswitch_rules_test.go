package firewall

import (
	"net"
	"strings"
	"testing"
)

func TestKillswitchRuleGeneration(t *testing.T) {
	srv := net.ParseIP("198.51.100.50")
	ks := NewKillswitchRules("lumi0", 51820, srv)

	iptables := ks.GenerateIptables()
	foundDrop := false
	foundVpn := false
	for _, r := range iptables {
		if strings.Contains(r, "-P OUTPUT DROP") {
			foundDrop = true
		}
		if strings.Contains(r, "-o lumi0 -j ACCEPT") {
			foundVpn = true
		}
	}
	if !foundDrop || !foundVpn {
		t.Fatal("missing vital killswitch rules in iptables")
	}

	wfp := ks.GenerateWfpPowerShell()
	if !strings.Contains(wfp, "198.51.100.50") {
		t.Fatal("wfp missing server ip")
	}
}
