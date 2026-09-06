package windows

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type mockExecutor struct {
	executedCommands []string
	returnErr        bool
}

func (m *mockExecutor) Execute(ctx context.Context, cmd string, args ...string) (string, error) {
	m.executedCommands = append(m.executedCommands, cmd)
	if m.returnErr {
		return "Access is denied", errors.New("exit status 1")
	}
	return "Success", nil
}

func TestSetInterfaceDNS(t *testing.T) {
	mock := &mockExecutor{}
	mgr := NewSystemDNSManager(mock)

	ctx := context.Background()
	err := mgr.SetInterfaceDNS(ctx, "Wi-Fi", []string{"1.1.1.1", "1.0.0.1"})
	if err != nil {
		t.Fatalf("SetInterfaceDNS failed: %v", err)
	}

	if len(mock.executedCommands) != 1 {
		t.Fatalf("Expected 1 command, got %d", len(mock.executedCommands))
	}

	cmd := mock.executedCommands[0]
	if !strings.Contains(cmd, "Set-DnsClientServerAddress") || !strings.Contains(cmd, "Wi-Fi") || !strings.Contains(cmd, "'1.1.1.1','1.0.0.1'") {
		t.Errorf("Unexpected command string: %s", cmd)
	}
}

func TestResetInterfaceDNS(t *testing.T) {
	mock := &mockExecutor{}
	mgr := NewSystemDNSManager(mock)

	ctx := context.Background()
	err := mgr.ResetInterfaceDNS(ctx, "Ethernet")
	if err != nil {
		t.Fatalf("ResetInterfaceDNS failed: %v", err)
	}

	if len(mock.executedCommands) != 1 {
		t.Fatalf("Expected 1 command, got %d", len(mock.executedCommands))
	}

	cmd := mock.executedCommands[0]
	if !strings.Contains(cmd, "-ResetServerAddresses") || !strings.Contains(cmd, "Ethernet") {
		t.Errorf("Unexpected command string: %s", cmd)
	}
}

func TestFlushDNSCache(t *testing.T) {
	mock := &mockExecutor{}
	mgr := NewSystemDNSManager(mock)

	ctx := context.Background()
	err := mgr.FlushDNSCache(ctx)
	if err != nil {
		t.Fatalf("FlushDNSCache failed: %v", err)
	}

	if len(mock.executedCommands) != 1 || mock.executedCommands[0] != "Clear-DnsClientCache" {
		t.Errorf("Unexpected command: %v", mock.executedCommands)
	}
}

func TestBuildBatchSetScript(t *testing.T) {
	script := BuildBatchSetScript([]string{"Wi-Fi", "Ethernet"}, "8.8.8.8", "8.8.4.4")
	if !strings.Contains(script, "Wi-Fi") || !strings.Contains(script, "Ethernet") {
		t.Errorf("Script missing adapter names: %s", script)
	}
	if !strings.Contains(script, "'8.8.8.8','8.8.4.4'") {
		t.Errorf("Script missing DNS servers: %s", script)
	}
	if !strings.Contains(script, "Clear-DnsClientCache") {
		t.Errorf("Script missing cache flush: %s", script)
	}
}
