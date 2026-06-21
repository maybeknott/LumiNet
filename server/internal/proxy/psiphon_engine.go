package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/maybeknott/luminet/internal/utils"
)

// RealPsiphonEngine implements ProxyEngine for Psiphon.
type RealPsiphonEngine struct {
	mu            sync.Mutex
	isRunning     bool
	binaryPath    string
	socksPort     int
	upstreamProxy string
	cmd           *exec.Cmd
	cancel        context.CancelFunc
	configPath    string
}

// NewPsiphonEngine creates a new RealPsiphonEngine.
func NewPsiphonEngine(socksPort int) *RealPsiphonEngine {
	return &RealPsiphonEngine{
		socksPort: socksPort,
	}
}

// SetUpstreamProxy configures an upstream proxy URL (e.g., socks5://127.0.0.1:1080) for chaining.
func (e *RealPsiphonEngine) SetUpstreamProxy(proxyURL string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.upstreamProxy = proxyURL
}

// FindBinary searches for psiphon-tunnel-core.
func (e *RealPsiphonEngine) FindBinary() (string, error) {
	if e.binaryPath != "" {
		if _, err := os.Stat(e.binaryPath); err == nil {
			return e.binaryPath, nil
		}
	}

	binaries := []string{
		"psiphon-tunnel-core.exe", "psiphon-tunnel-core",
		`./bin/psiphon/psiphon-tunnel-core.exe`,
		`./bin/psiphon/psiphon-tunnel-core`,
		`C:\Users\ACER\Desktop\quranips\tools\Proxy tester\bin\psiphon\psiphon-tunnel-core.exe`,
	}

	for _, bin := range binaries {
		path, err := exec.LookPath(bin)
		if err == nil {
			e.binaryPath = path
			return path, nil
		}
		if _, err := os.Stat(bin); err == nil {
			abs, err := filepath.Abs(bin)
			if err == nil {
				e.binaryPath = abs
				return abs, nil
			}
			e.binaryPath = bin
			return bin, nil
		}
	}

	return "", fmt.Errorf("failed to locate psiphon-tunnel-core binary in PATH or common folders")
}

// Start launches the Psiphon process.
func (e *RealPsiphonEngine) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.isRunning {
		return nil
	}

	binary, err := e.FindBinary()
	if err != nil {
		return err
	}

	tmpDir := os.TempDir()
	confPath := filepath.Join(tmpDir, fmt.Sprintf("psiphon-%d.json", e.socksPort))

	configMap := map[string]interface{}{
		"LocalSocksProxyPort":    e.socksPort,
		"PropagationChannelId":   "LUMINET_DESKTOP",
		"SponsorId":              "LUMINET",
		"TunnelWholeDevice":      false,
		"NetworkConnectivityCheckerEnabled": false,
	}

	if e.upstreamProxy != "" {
		configMap["UpstreamProxyURL"] = e.upstreamProxy
	}

	configData, err := json.Marshal(configMap)
	if err != nil {
		return fmt.Errorf("failed to marshal psiphon config: %w", err)
	}

	if err := os.WriteFile(confPath, configData, 0644); err != nil {
		return fmt.Errorf("failed to write psiphon config: %w", err)
	}
	e.configPath = confPath

	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel

	cmd := exec.CommandContext(ctx, binary, "-config", confPath)
	cmd.SysProcAttr = utils.GetDaemonSysProcAttr()

	if err := cmd.Start(); err != nil {
		cancel()
		os.Remove(confPath)
		return fmt.Errorf("failed to start Psiphon core: %w", err)
	}

	e.cmd = cmd
	e.isRunning = true

	go func() {
		_ = cmd.Wait()
		e.mu.Lock()
		e.isRunning = false
		e.cmd = nil
		_ = os.Remove(e.configPath)
		e.mu.Unlock()
	}()

	time.Sleep(300 * time.Millisecond)
	return nil
}

// Stop terminates the Psiphon process.
func (e *RealPsiphonEngine) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.isRunning {
		return
	}

	if e.cancel != nil {
		e.cancel()
		e.cancel = nil
	}

	if e.cmd != nil && e.cmd.Process != nil {
		_ = e.cmd.Process.Kill()
	}

	if e.configPath != "" {
		_ = os.Remove(e.configPath)
	}

	e.isRunning = false
	e.cmd = nil
}

// IsRunning returns status of Psiphon.
func (e *RealPsiphonEngine) IsRunning() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.isRunning
}
