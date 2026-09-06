package plugin

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestNativePluginDescriptor(t *testing.T) {
	desc := NewNativePluginDescriptor("com.luminet.plugin.matsuri", "Matsuri Bridge", "/system/bin/sh")
	if desc.ID != "com.luminet.plugin.matsuri" {
		t.Fatalf("expected ID com.luminet.plugin.matsuri, got %s", desc.ID)
	}
	if desc.FileMode != DefaultPluginFileMode {
		t.Fatalf("expected file mode %v, got %v", DefaultPluginFileMode, desc.FileMode)
	}
}

func TestPluginCommandConfigBuildArgs(t *testing.T) {
	cfg := &PluginCommandConfig{
		BindAddress: "127.0.0.1",
		BindPort:    10808,
		RemoteDNS:   "8.8.8.8",
		SNI:         "example.com",
		DoHURL:      "https://dns.google/dns-query",
		SplitSNI:    true,
		UDPMode:     true,
	}

	args := cfg.BuildArgs()

	expectedContains := []string{
		"-l", "127.0.0.1:10808",
		"-d", "8.8.8.8",
		"-s", "example.com",
		"--doh", "https://dns.google/dns-query",
		"--split-sni",
		"-u",
	}

	for _, exp := range expectedContains {
		found := false
		for _, a := range args {
			if a == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing expected arg %s in args: %v", exp, args)
		}
	}
}

func TestPluginProcessManagerValidationAndPrepare(t *testing.T) {
	mgr := NewPluginProcessManager()

	// Create a temporary dummy executable file
	tmpDir := t.TempDir()
	dummyExec := filepath.Join(tmpDir, "dummy_plugin")
	if err := os.WriteFile(dummyExec, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("failed to create dummy exec: %v", err)
	}

	if err := mgr.ValidateExecutable(dummyExec); err != nil {
		t.Fatalf("validation failed for valid file: %v", err)
	}

	nonExistent := filepath.Join(tmpDir, "non_existent")
	if err := mgr.ValidateExecutable(nonExistent); err == nil {
		t.Fatalf("expected error for non-existent executable")
	}

	desc := NewNativePluginDescriptor("test.plugin", "Test", dummyExec)
	cfg := &PluginCommandConfig{
		BindAddress: "127.0.0.1",
		BindPort:    2080,
	}

	cmd, err := mgr.PrepareCommand(context.Background(), desc, cfg)
	if err != nil {
		t.Fatalf("unexpected error from PrepareCommand: %v", err)
	}
	if cmd == nil || cmd.Path != dummyExec {
		t.Fatalf("unexpected command: %v", cmd)
	}
}
