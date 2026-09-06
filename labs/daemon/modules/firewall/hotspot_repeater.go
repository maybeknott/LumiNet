package firewall

import (
	"fmt"
)

type HotspotRepeaterConfig struct {
	DownstreamInterface string `json:"downstream_interface"`
	UpstreamVpnInterface string `json:"upstream_vpn_interface"`
	DownstreamSubnet     string `json:"downstream_subnet"`
	ClampMssBytes       uint16 `json:"clamp_mss_bytes"`
}

func DefaultHotspotRepeaterConfig() HotspotRepeaterConfig {
	return HotspotRepeaterConfig{
		DownstreamInterface:  "wlan1",
		UpstreamVpnInterface: "tun0",
		DownstreamSubnet:     "192.168.43.0/24",
		ClampMssBytes:        1360,
	}
}

type HotspotNatRepeater struct {
	config HotspotRepeaterConfig
}

func NewHotspotNatRepeater(cfg HotspotRepeaterConfig) *HotspotNatRepeater {
	return &HotspotNatRepeater{config: cfg}
}

func (r *HotspotNatRepeater) GenerateIptablesCommands() []string {
	return []string{
		"echo 1 > /proc/sys/net/ipv4/ip_forward",
		fmt.Sprintf("iptables -A FORWARD -i %s -o %s -j ACCEPT", r.config.DownstreamInterface, r.config.UpstreamVpnInterface),
		fmt.Sprintf("iptables -A FORWARD -i %s -o %s -m state --state RELATED,ESTABLISHED -j ACCEPT", r.config.UpstreamVpnInterface, r.config.DownstreamInterface),
		fmt.Sprintf("iptables -t nat -A POSTROUTING -s %s -o %s -j MASQUERADE", r.config.DownstreamSubnet, r.config.UpstreamVpnInterface),
		fmt.Sprintf("iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss %d", r.config.ClampMssBytes),
	}
}
