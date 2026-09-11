//go:build darwin

package system

import "testing"

func TestParseDefaultRouteInterface(t *testing.T) {
	out := `   route to: default
 destination: default
       mask: default
    gateway: 192.0.2.1
  interface: en0
`
	if got := parseDefaultRouteInterface(out); got != "en0" {
		t.Fatalf("parseDefaultRouteInterface() = %q, want en0", got)
	}
}

func TestParseNetworkServiceForDevice(t *testing.T) {
	out := `An asterisk (*) denotes that a network service is disabled.
(1) USB 10/100/1000 LAN
(Hardware Port: USB 10/100/1000 LAN, Device: en7)
(2) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)
(3) *Thunderbolt Bridge
(Hardware Port: Thunderbolt Bridge, Device: bridge0)
`
	if got := parseNetworkServiceForDevice(out, "en0"); got != "Wi-Fi" {
		t.Fatalf("parseNetworkServiceForDevice(en0) = %q, want Wi-Fi", got)
	}
	if got := parseNetworkServiceForDevice(out, "bridge0"); got != "" {
		t.Fatalf("disabled service should not be selected, got %q", got)
	}
	if got := parseNetworkServiceForDevice(out, "en9"); got != "" {
		t.Fatalf("unknown device should not resolve, got %q", got)
	}
}
