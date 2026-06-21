//go:build windows

package system

/*
#cgo LDFLAGS: -lfwpuclnt
#include "wfp_leak_prevention.h"
*/
import "C"

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"syscall"
)

// EnableLeakProtection blocks all outbound traffic except traffic through the loopback interface
// or matching the proxy process itself, preventing leaks.
func EnableLeakProtection(ctx context.Context, allowedPort int) error {
	// Add netsh rule to block all outbound traffic by default
	cmd1 := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
		"name=LumiNet Leak Protection BlockAll", "dir=out", "action=block", "protocol=ANY")
	cmd1.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd1.Run(); err != nil {
		return fmt.Errorf("failed to add default block rule: %w", err)
	}

	// Add netsh rule to allow outbound traffic to the local proxy port (loopback)
	cmd2 := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
		"name=LumiNet Leak Protection AllowProxy", "dir=out", "action=allow", "protocol=TCP",
		fmt.Sprintf("localport=%d", allowedPort))
	cmd2.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd2.Run(); err != nil {
		// Clean up the first rule
		_ = DisableLeakProtection(ctx)
		return fmt.Errorf("failed to add proxy allow rule: %w", err)
	}

	return nil
}

// DisableLeakProtection removes the firewall rules added for leak protection.
func DisableLeakProtection(ctx context.Context) error {
	cmd1 := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "delete", "rule",
		"name=LumiNet Leak Protection BlockAll")
	cmd1.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd1.Run()

	cmd2 := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "delete", "rule",
		"name=LumiNet Leak Protection AllowProxy")
	cmd2.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd2.Run()

	return nil
}

// ApplyLeakProtection blocks all outbound traffic except through local SOCKS port using netsh.
func ApplyLeakProtection(socksPort int) error {
	return EnableLeakProtection(context.Background(), socksPort)
}

// EnableDnsLeakProtection blocks outbound UDP DNS (port 53) on all physical network interfaces except the TUN interface using WFP.
func EnableDnsLeakProtection(ctx context.Context, tunDeviceName string) error {
	iface, err := net.InterfaceByName(tunDeviceName)
	if err != nil {
		return fmt.Errorf("failed to get interface by name %s: %w", tunDeviceName, err)
	}

	res := C.InitializeDnsLeakPreventer(C.UINT32(iface.Index))
	if res != 0 {
		return fmt.Errorf("WFP InitializeDnsLeakPreventer failed with code: 0x%x", uint32(res))
	}

	return nil
}

// DisableDnsLeakProtection removes the block rules added for DNS leak protection.
func DisableDnsLeakProtection(ctx context.Context) error {
	res := C.DeinitializeDnsLeakPreventer()
	if res != 0 {
		return fmt.Errorf("WFP DeinitializeDnsLeakPreventer failed with code: 0x%x", uint32(res))
	}
	return nil
}


