package proxy

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var helperBin string

func TestMain(m *testing.M) {
	tmpDir := os.TempDir()
	helperBin = filepath.Join(tmpDir, "helper-sleep.exe")
	if filepath.Separator != '\\' {
		helperBin = filepath.Join(tmpDir, "helper-sleep")
	}

	srcFile := filepath.Join(tmpDir, "helper-sleep.go")
	srcCode := `package main
import "time"
func main() {
	time.Sleep(5 * time.Second)
}
`
	if err := os.WriteFile(srcFile, []byte(srcCode), 0644); err != nil {
		panic("failed to write helper source: " + err.Error())
	}
	defer os.Remove(srcFile)

	cmd := exec.Command("go", "build", "-o", helperBin, srcFile)
	if err := cmd.Run(); err != nil {
		panic("failed to build helper: " + err.Error())
	}

	code := m.Run()

	os.Remove(helperBin)
	os.Exit(code)
}

func TestPsiphonUpstreamChaining(t *testing.T) {
	socksPort := 12345
	engine := NewPsiphonEngine(socksPort)
	upstreamProxy := "socks5://127.0.0.1:1080"
	engine.SetUpstreamProxy(upstreamProxy)

	engine.binaryPath = helperBin

	// Start engine - it should succeed starting the mock helper in background
	err := engine.Start()
	if err != nil {
		t.Fatalf("Failed to start engine: %v", err)
	}
	defer engine.Stop()

	// Wait briefly for disk write
	time.Sleep(100 * time.Millisecond)

	tmpDir := os.TempDir()
	confPath := filepath.Join(tmpDir, "psiphon-12345.json")

	data, errRead := os.ReadFile(confPath)
	if errRead != nil {
		t.Fatalf("Expected config file to be written, got error: %v", errRead)
	}

	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatalf("Failed to parse written config JSON: %v", err)
	}

	if config["LocalSocksProxyPort"] != float64(socksPort) {
		t.Errorf("Expected LocalSocksProxyPort to be %d, got %v", socksPort, config["LocalSocksProxyPort"])
	}

	if config["UpstreamProxyURL"] != upstreamProxy {
		t.Errorf("Expected UpstreamProxyURL to be %s, got %v", upstreamProxy, config["UpstreamProxyURL"])
	}
}

func TestTorBridgeConfiguration(t *testing.T) {
	socksPort := 12346
	controlPort := 12347
	engine := NewTorEngine(socksPort, controlPort)
	bridges := []string{
		"obfs4 192.0.2.1:443 7A62C6E875560A57740263A3C9A0F0D8E9D0F7EC cert=Cq472+30VbQfQc6N1c/tL1k19U5296839P4/235773173 iat-mode=0",
	}
	obfs4Path := "/usr/bin/obfs4proxy"
	engine.ConfigureBridges(bridges, obfs4Path)

	engine.binaryPath = helperBin

	err := engine.Start()
	if err != nil {
		t.Fatalf("Failed to start engine: %v", err)
	}
	defer engine.Stop()

	// Wait briefly for disk write
	time.Sleep(100 * time.Millisecond)

	tmpDir := os.TempDir()
	confPath := filepath.Join(tmpDir, "torrc-12346")

	data, errRead := os.ReadFile(confPath)
	if errRead != nil {
		t.Fatalf("Expected torrc config to be written: %v", errRead)
	}

	content := string(data)
	if !strings.Contains(content, "UseBridges 1") {
		t.Errorf("Expected torrc to contain UseBridges 1, got:\n%s", content)
	}

	expectedPlugin := "ClientTransportPlugin obfs4 exec " + filepath.ToSlash(obfs4Path)
	if !strings.Contains(content, expectedPlugin) {
		t.Errorf("Expected torrc to contain '%s', got:\n%s", expectedPlugin, content)
	}

	if !strings.Contains(content, "Bridge obfs4 192.0.2.1:443") {
		t.Errorf("Expected torrc to contain Bridge obfs4 line, got:\n%s", content)
	}
}
