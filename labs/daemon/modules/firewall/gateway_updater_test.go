package firewall

import (
	"strings"
	"testing"
)

func TestDynamicGatewayUpdater(t *testing.T) {
	updater := NewDynamicGatewayUpdater()
	updater.SetDefaultGateway("10.0.0.1", "tun0")
	updater.AddRoute(GatewayRoute{
		DestinationCidr: "1.1.1.1/32",
		GatewayIP:       "10.0.0.1",
		InterfaceName:   "tun0",
		Metric:          10,
	})

	cmds := updater.CompileCommands("linux")
	if len(cmds) != 1 {
		t.Fatalf("expected 1 command")
	}
	if !strings.Contains(cmds[0], "ip route add 1.1.1.1/32 via 10.0.0.1 dev tun0 metric 10") {
		t.Errorf("unexpected linux route command: %s", cmds[0])
	}

	updater.RemoveRoute("1.1.1.1/32")
	if len(updater.CompileCommands("linux")) != 0 {
		t.Errorf("expected 0 commands after remove")
	}
}
