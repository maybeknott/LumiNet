package firewall

import (
	"fmt"
	"net"
	"strings"
)

type KillswitchRules struct {
	VpnInterface     string   `json:"vpn_interface"`
	VpnPort          uint16   `json:"vpn_port"`
	VpnServerIP      net.IP   `json:"vpn_server_ip"`
	AllowedSubnets   []string `json:"allowed_subnets"`
	BlockDnsLeaks    bool     `json:"block_dns_leaks"`
}

func NewKillswitchRules(vpnIface string, vpnPort uint16, vpnServer net.IP) *KillswitchRules {
	return &KillswitchRules{
		VpnInterface:   vpnIface,
		VpnPort:        vpnPort,
		VpnServerIP:    vpnServer,
		AllowedSubnets: []string{"127.0.0.1/8", "10.0.0.0/8", "192.168.0.0/16"},
		BlockDnsLeaks:  true,
	}
}

func (k *KillswitchRules) GenerateIptables() []string {
	rules := []string{
		"iptables -F OUTPUT",
		"iptables -P OUTPUT DROP",
		"iptables -A OUTPUT -o lo -j ACCEPT",
		fmt.Sprintf("iptables -A OUTPUT -o %s -j ACCEPT", k.VpnInterface),
		fmt.Sprintf("iptables -A OUTPUT -d %s -p udp --dport %d -j ACCEPT", k.VpnServerIP.String(), k.VpnPort),
		fmt.Sprintf("iptables -A OUTPUT -d %s -p tcp --dport %d -j ACCEPT", k.VpnServerIP.String(), k.VpnPort),
	}
	for _, subnet := range k.AllowedSubnets {
		rules = append(rules, fmt.Sprintf("iptables -A OUTPUT -d %s -j ACCEPT", subnet))
	}
	if k.BlockDnsLeaks {
		rules = append(rules, fmt.Sprintf("iptables -A OUTPUT -o ! %s -p udp --dport 53 -j REJECT", k.VpnInterface))
		rules = append(rules, fmt.Sprintf("iptables -A OUTPUT -o ! %s -p tcp --dport 53 -j REJECT", k.VpnInterface))
	}
	return rules
}

func (k *KillswitchRules) GenerateWfpPowerShell() string {
	var b strings.Builder
	b.WriteString("# Windows Filtering Platform (WFP) Killswitch\n")
	b.WriteString(fmt.Sprintf("New-NetFirewallRule -DisplayName 'LumiNet VPN Outbound' -Direction Outbound -InterfaceAlias '%s' -Action Allow\n", k.VpnInterface))
	b.WriteString(fmt.Sprintf("New-NetFirewallRule -DisplayName 'LumiNet Handshake Outbound' -Direction Outbound -RemoteAddress %s -RemotePort %d -Protocol UDP -Action Allow\n", k.VpnServerIP.String(), k.VpnPort))
	b.WriteString("New-NetFirewallRule -DisplayName 'LumiNet Block All Other Outbound' -Direction Outbound -Action Block -Priority 100\n")
	return b.String()
}
