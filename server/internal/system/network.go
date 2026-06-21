// Package system provides operating-system specific APIs for network adapter discovery, Windows Registry proxies, and DNS modifications.
package system

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/maybeknott/luminet/internal/utils"
)

// NetworkInterface represents detected metadata about a network interface card adapter.
type NetworkInterface struct {
	Name       string   `json:"name"`
	MAC        string   `json:"mac"`
	IPs        []string `json:"ips"`
	Gateway    string   `json:"gateway"`
	IsWireless bool     `json:"is_wireless"`
	SSID       string   `json:"ssid"` // Populated if IsWireless is true
}

// GetActiveInterfaces queries and parses operating system network adapters.
func GetActiveInterfaces(ctx context.Context) ([]*NetworkInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	gw, _ := GetDefaultGateway(ctx)
	ssid, _ := GetCurrentSSID(ctx)

	var active []*NetworkInterface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		var ips []string
		for _, addr := range addrs {
			ipStr := addr.String()
			if idx := strings.Index(ipStr, "/"); idx != -1 {
				ipStr = ipStr[:idx]
			}
			ips = append(ips, ipStr)
		}

		if len(ips) == 0 {
			continue
		}

		isWireless := strings.Contains(strings.ToLower(iface.Name), "wi-fi") ||
			strings.Contains(strings.ToLower(iface.Name), "wireless") ||
			(ssid != "" && strings.Contains(strings.ToLower(iface.Name), "wlan"))

		ifaceSSID := ""
		if isWireless {
			ifaceSSID = ssid
		}

		active = append(active, &NetworkInterface{
			Name:       iface.Name,
			MAC:        iface.HardwareAddr.String(),
			IPs:        ips,
			Gateway:    gw,
			IsWireless: isWireless,
			SSID:       ifaceSSID,
		})
	}

	return active, nil
}

// GetCurrentSSID attempts to resolve the connected WiFi network name (SSID), if any.
func GetCurrentSSID(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "netsh", "wlan", "show", "interfaces")
	cmd.SysProcAttr = utils.GetHideWindowSysProcAttr()
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "SSID") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1]), nil
			}
		}
	}
	return "", fmt.Errorf("no active wifi connection found")
}

// GetDefaultGateway resolves the IP address of the primary active internet gateway route.
func GetDefaultGateway(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		"(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1).NextHop")
	cmd.SysProcAttr = utils.GetHideWindowSysProcAttr()
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	gw := strings.TrimSpace(string(out))
	if gw == "" || gw == "0.0.0.0" {
		return "", fmt.Errorf("no default gateway found")
	}
	return gw, nil
}
