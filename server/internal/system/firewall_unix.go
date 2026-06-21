//go:build !windows

package system

import (
	"context"
	"fmt"
	"os/exec"
)

// EnableLeakProtection stub.
func EnableLeakProtection(ctx context.Context, allowedPort int) error {
	return fmt.Errorf("leak protection is only supported on Windows in this version")
}

// DisableLeakProtection stub.
func DisableLeakProtection(ctx context.Context) error {
	return nil
}

// ApplyLeakProtection stub.
func ApplyLeakProtection(socksPort int) error {
	return fmt.Errorf("leak protection is only supported on Windows in this version")
}

// EnableDnsLeakProtection stub for non-Windows systems.
func EnableDnsLeakProtection(ctx context.Context, tunDeviceName string) error {
	return nil
}

// DisableDnsLeakProtection stub for non-Windows systems.
func DisableDnsLeakProtection(ctx context.Context) error {
	return nil
}

// EnableTProxyRules configures transparent proxy redirection rules using iptables and routing tables on Linux.
func EnableTProxyRules(ctx context.Context, localPort int, fwmark int) error {
	// Configure local routing table rules
	_ = exec.CommandContext(ctx, "ip", "rule", "add", "fwmark", fmt.Sprintf("0x%x/0xc0", fwmark), "table", "100").Run()
	_ = exec.CommandContext(ctx, "ip", "route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", "100").Run()

	// Configure iptables mangle rules for TPROXY redirection
	_ = exec.CommandContext(ctx, "iptables", "-t", "mangle", "-N", "LUMINET_TPROXY").Run()
	_ = exec.CommandContext(ctx, "iptables", "-t", "mangle", "-A", "PREROUTING", "-p", "tcp", "-j", "LUMINET_TPROXY").Run()
	_ = exec.CommandContext(ctx, "iptables", "-t", "mangle", "-A", "LUMINET_TPROXY", "-d", "127.0.0.0/8", "-j", "RETURN").Run()
	_ = exec.CommandContext(ctx, "iptables", "-t", "mangle", "-A", "LUMINET_TPROXY", "-p", "tcp", "-j", "TPROXY", "--on-port", fmt.Sprintf("%d", localPort), "--tproxy-mark", fmt.Sprintf("0x%x", fwmark)).Run()
	
	return nil
}

// DisableTProxyRules removes transparent proxy redirection rules.
func DisableTProxyRules(ctx context.Context, localPort int, fwmark int) error {
	_ = exec.CommandContext(ctx, "iptables", "-t", "mangle", "-D", "PREROUTING", "-p", "tcp", "-j", "LUMINET_TPROXY").Run()
	_ = exec.CommandContext(ctx, "iptables", "-t", "mangle", "-F", "LUMINET_TPROXY").Run()
	_ = exec.CommandContext(ctx, "iptables", "-t", "mangle", "-X", "LUMINET_TPROXY").Run()
	
	_ = exec.CommandContext(ctx, "ip", "rule", "del", "fwmark", fmt.Sprintf("0x%x/0xc0", fwmark), "table", "100").Run()
	_ = exec.CommandContext(ctx, "ip", "route", "del", "local", "0.0.0.0/0", "dev", "lo", "table", "100").Run()
	return nil
}
