//go:build !windows

package runtimecore

import (
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func fakeEngineBinary(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "engine")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTorEngineRejectsImmediateProcessExit(t *testing.T) {
	eng := newTorEngine(19050, 19051)
	eng.binaryPath = fakeEngineBinary(t, "exit 7")
	if err := eng.Start(); err == nil {
		t.Fatal("Tor Start succeeded after child exited immediately")
	}
	if eng.IsRunning() {
		t.Fatal("Tor reports running after immediate child exit")
	}
}

func TestPsiphonEngineRejectsImmediateProcessExit(t *testing.T) {
	eng := newPsiphonEngine(19090)
	eng.binaryPath = fakeEngineBinary(t, "exit 7")
	if err := eng.Start(); err == nil {
		t.Fatal("Psiphon Start succeeded after child exited immediately")
	}
	if eng.IsRunning() {
		t.Fatal("Psiphon reports running after immediate child exit")
	}
}

func TestTorEngineUsesUniqueInstanceConfig(t *testing.T) {
	binary := fakeEngineBinary(t, "sleep 5")
	first := newTorEngine(19150, 19151)
	first.binaryPath = binary
	first.bootstrapProbe = func(string, string) (int, error) { return 100, nil }
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	first.mu.Lock()
	firstPath := first.configPath
	first.mu.Unlock()
	first.Stop()
	second := newTorEngine(19150, 19151)
	second.binaryPath = binary
	second.bootstrapProbe = func(string, string) (int, error) { return 100, nil }
	if err := second.Start(); err != nil {
		t.Fatal(err)
	}
	defer second.Stop()
	second.mu.Lock()
	secondPath := second.configPath
	second.mu.Unlock()
	if firstPath == secondPath {
		t.Fatalf("Tor reused config path %q", firstPath)
	}
}

func TestTorEngineWaitsForFullBootstrap(t *testing.T) {
	eng := newTorEngine(19250, 19251)
	eng.binaryPath = fakeEngineBinary(t, "sleep 5")
	eng.startupTimeout = time.Second
	eng.startupPollInterval = 5 * time.Millisecond
	var probes atomic.Int32
	eng.bootstrapProbe = func(string, string) (int, error) {
		if probes.Add(1) < 3 {
			return 80, nil
		}
		return 100, nil
	}
	if err := eng.Start(); err != nil {
		t.Fatal(err)
	}
	defer eng.Stop()
	if got := probes.Load(); got < 3 {
		t.Fatalf("bootstrap probes=%d, want at least 3", got)
	}
	if !eng.IsRunning() {
		t.Fatal("Tor not running after bootstrap reached 100")
	}
}

func TestTorEngineRejectsLiveProcessThatNeverBootstraps(t *testing.T) {
	eng := newTorEngine(19350, 19351)
	eng.binaryPath = fakeEngineBinary(t, "sleep 5")
	eng.startupTimeout = 50 * time.Millisecond
	eng.startupPollInterval = 5 * time.Millisecond
	eng.bootstrapProbe = func(string, string) (int, error) { return 80, nil }
	if err := eng.Start(); err == nil {
		t.Fatal("Tor Start succeeded without full bootstrap")
	}
	if eng.IsRunning() {
		t.Fatal("Tor remained running after bootstrap timeout")
	}
}

func TestTorEngineRetriesTemporaryBootstrapProbeErrors(t *testing.T) {
	eng := newTorEngine(19450, 19451)
	eng.binaryPath = fakeEngineBinary(t, "sleep 5")
	eng.startupTimeout = time.Second
	eng.startupPollInterval = 5 * time.Millisecond
	var probes atomic.Int32
	eng.bootstrapProbe = func(string, string) (int, error) {
		if probes.Add(1) == 1 {
			return 0, errors.New("control cookie not ready")
		}
		return 100, nil
	}
	if err := eng.Start(); err != nil {
		t.Fatal(err)
	}
	eng.Stop()
}

func TestPsiphonEngineUsesUniqueInstanceConfig(t *testing.T) {
	binary := fakeEngineBinary(t, "sleep 5")
	first := newPsiphonEngine(19190)
	first.binaryPath = binary
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	first.mu.Lock()
	firstPath := first.configPath
	first.mu.Unlock()
	first.Stop()
	second := newPsiphonEngine(19190)
	second.binaryPath = binary
	if err := second.Start(); err != nil {
		t.Fatal(err)
	}
	defer second.Stop()
	second.mu.Lock()
	secondPath := second.configPath
	second.mu.Unlock()
	if firstPath == secondPath {
		t.Fatalf("Psiphon reused config path %q", firstPath)
	}
}
