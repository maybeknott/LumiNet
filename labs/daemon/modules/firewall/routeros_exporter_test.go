package firewall

import (
	"strings"
	"testing"
)

func TestRouterOsExporter(t *testing.T) {
	exporter := NewRouterOsExporter()
	exporter.AddEntry("1.1.1.0/24")
	exporter.AddEntry("8.8.8.0/24")

	script := exporter.ExportAddressList("vpn_targets")
	if !strings.Contains(script, "/ip firewall address-list") {
		t.Errorf("missing address-list section")
	}
	if !strings.Contains(script, "add list=vpn_targets address=1.1.1.0/24") {
		t.Errorf("missing first entry")
	}

	mangle := exporter.ExportMangle("vpn_targets", "vpn_mark")
	if !strings.Contains(mangle, "action=mark-routing new-routing-mark=vpn_mark") {
		t.Errorf("missing mangle mark")
	}
}
