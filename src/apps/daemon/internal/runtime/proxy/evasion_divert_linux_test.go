//go:build linux

package proxy

import "testing"

func TestLinuxNetworkProtocol(t *testing.T) {
	tests := []struct {
		name string
		in   uint16
		want uint16
	}{
		{name: "IPv4", in: 0x0800, want: 0x0008},
		{name: "IPv6", in: 0x86dd, want: 0xdd86},
		{name: "ARP", in: 0x0806, want: 0x0608},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := linuxNetworkProtocol(tt.in); got != tt.want {
				t.Fatalf("linuxNetworkProtocol(%#04x) = %#04x, want %#04x", tt.in, got, tt.want)
			}
		})
	}
}
