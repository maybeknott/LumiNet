// Copyright 2024 LumiNet. Use of this source code is governed by the MIT license.
// Package windows provides system DNS adapter configuration and emergency reset
// capabilities for Windows platforms.
// Originates from RedCloud Windows core and adapted for LumiNet.

package windows

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// CommandExecutor abstracts OS command execution for testing and platform isolation.
type CommandExecutor interface {
	Execute(ctx context.Context, cmd string, args ...string) (string, error)
}

// PowerShellExecutor executes commands via Windows PowerShell.
type PowerShellExecutor struct{}

// Execute runs a powershell command with context.
func (p *PowerShellExecutor) Execute(ctx context.Context, cmd string, args ...string) (string, error) {
	allArgs := append([]string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", cmd}, args...)
	c := exec.CommandContext(ctx, "powershell.exe", allArgs...)
	out, err := c.CombinedOutput()
	return string(out), err
}

// SystemDNSManager manages network adapter DNS settings on Windows.
type SystemDNSManager struct {
	mu       sync.Mutex
	executor CommandExecutor
}

// NewSystemDNSManager creates a new SystemDNSManager.
func NewSystemDNSManager(executor CommandExecutor) *SystemDNSManager {
	if executor == nil {
		executor = &PowerShellExecutor{}
	}
	return &SystemDNSManager{
		executor: executor,
	}
}

// SetInterfaceDNS sets static DNS server addresses on the specified network adapter.
func (m *SystemDNSManager) SetInterfaceDNS(ctx context.Context, interfaceAlias string, dnsServers []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if strings.TrimSpace(interfaceAlias) == "" {
		return errors.New("interface alias cannot be empty")
	}
	if len(dnsServers) == 0 {
		return errors.New("at least one DNS server must be specified")
	}

	var formattedServers []string
	for _, s := range dnsServers {
		trimmed := strings.TrimSpace(s)
		if trimmed != "" {
			formattedServers = append(formattedServers, fmt.Sprintf("'%s'", trimmed))
		}
	}

	serverList := strings.Join(formattedServers, ",")
	cmd := fmt.Sprintf("Set-DnsClientServerAddress -InterfaceAlias '%s' -ServerAddresses @(%s)", interfaceAlias, serverList)

	out, err := m.executor.Execute(ctx, cmd)
	if err != nil {
		return fmt.Errorf("failed to set DNS on %s: %w, output: %s", interfaceAlias, err, strings.TrimSpace(out))
	}
	return nil
}

// ResetInterfaceDNS restores DHCP/automatic DNS resolution on the specified network adapter.
func (m *SystemDNSManager) ResetInterfaceDNS(ctx context.Context, interfaceAlias string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if strings.TrimSpace(interfaceAlias) == "" {
		return errors.New("interface alias cannot be empty")
	}

	cmd := fmt.Sprintf("Set-DnsClientServerAddress -InterfaceAlias '%s' -ResetServerAddresses", interfaceAlias)
	out, err := m.executor.Execute(ctx, cmd)
	if err != nil {
		return fmt.Errorf("failed to reset DNS on %s: %w, output: %s", interfaceAlias, err, strings.TrimSpace(out))
	}
	return nil
}

// FlushDNSCache executes ipconfig /flushdns to immediately clear local resolver cache.
func (m *SystemDNSManager) FlushDNSCache(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cmd := "Clear-DnsClientCache"
	out, err := m.executor.Execute(ctx, cmd)
	if err != nil {
		return fmt.Errorf("failed to clear DNS client cache: %w, output: %s", err, strings.TrimSpace(out))
	}
	return nil
}

// BuildBatchSetScript generates a script snippet to configure multiple adapters in parallel.
func BuildBatchSetScript(adapters []string, primaryDNS, secondaryDNS string) string {
	var lines []string
	servers := primaryDNS
	if secondaryDNS != "" {
		servers = fmt.Sprintf("'%s','%s'", primaryDNS, secondaryDNS)
	} else {
		servers = fmt.Sprintf("'%s'", primaryDNS)
	}

	for _, adapter := range adapters {
		lines = append(lines, fmt.Sprintf("Set-DnsClientServerAddress -InterfaceAlias '%s' -ServerAddresses @(%s) -ErrorAction SilentlyContinue", adapter, servers))
	}
	lines = append(lines, "Clear-DnsClientCache")
	return strings.Join(lines, "; ")
}
