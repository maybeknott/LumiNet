//go:build windows

// Package system provides operating-system specific APIs for network adapter discovery, Windows Registry proxies, and DNS modifications.
package system

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
)

// psEscapeSingleQuoted escapes a value for safe interpolation inside a
// PowerShell single-quoted string literal. Inside single quotes PowerShell
// performs no expansion, so the only escape required is doubling embedded
// single quotes. This is defense-in-depth: callers must already have validated
// inputs via ValidateInterfaceAlias / ValidateDNSServers.
func psEscapeSingleQuoted(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// SetDNS configures target DNS servers on the specified network adapter using PowerShell cmdlets.
func SetDNS(ctx context.Context, adapterName string, dnsServers []string) error {
	if err := ValidateInterfaceAlias(adapterName); err != nil {
		return err
	}
	if err := ValidateDNSServers(dnsServers); err != nil {
		return err
	}

	serversStr := make([]string, 0, len(dnsServers))
	for _, s := range dnsServers {
		serversStr = append(serversStr, "'"+psEscapeSingleQuoted(strings.TrimSpace(s))+"'")
	}
	serversArg := strings.Join(serversStr, ",")

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		fmt.Sprintf("Set-DnsClientServerAddress -InterfaceAlias '%s' -ServerAddresses @(%s)", psEscapeSingleQuoted(adapterName), serversArg))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set DNS: %v, output: %s", err, string(output))
	}
	return nil
}

// ResetDNS resets the network adapter to dynamically inherit DNS servers via DHCP.
func ResetDNS(ctx context.Context, adapterName string) error {
	if err := ValidateInterfaceAlias(adapterName); err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		fmt.Sprintf("Set-DnsClientServerAddress -InterfaceAlias '%s' -ResetServerAddresses", psEscapeSingleQuoted(adapterName)))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to reset DNS: %v, output: %s", err, string(output))
	}
	return nil
}

// GetDNS returns the current custom DNS server IPs configured on the specified network adapter.
func GetDNS(ctx context.Context, adapterName string) ([]string, error) {
	if err := ValidateInterfaceAlias(adapterName); err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		fmt.Sprintf("(Get-DnsClientServerAddress -InterfaceAlias '%s' -AddressFamily IPv4).ServerAddresses", psEscapeSingleQuoted(adapterName)))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to get DNS: %v, output: %s", err, string(output))
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	var dnsServers []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			dnsServers = append(dnsServers, line)
		}
	}
	return dnsServers, nil
}

// ClearDNS resets the network adapter to dynamically inherit DNS servers via DHCP.
func ClearDNS(ctx context.Context, adapterName string) error {
	return ResetDNS(ctx, adapterName)
}
