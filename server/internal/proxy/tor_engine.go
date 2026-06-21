package proxy

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/maybeknott/luminet/internal/utils"
)

// TorEngine implements ProxyEngine for Tor.
type TorEngine struct {
	mu             sync.Mutex
	isRunning      bool
	binaryPath     string
	socksPort      int
	controlPort    int
	bridges        []string
	obfs4ProxyPath string
	cmd            *exec.Cmd
	cancel         context.CancelFunc
	configPath     string
}

// NewTorEngine creates a new TorEngine instance.
func NewTorEngine(socksPort, controlPort int) *TorEngine {
	return &TorEngine{
		socksPort:   socksPort,
		controlPort: controlPort,
	}
}

// ConfigureBridges sets Tor bridges and pluggable transport plugin path.
func (e *TorEngine) ConfigureBridges(bridges []string, obfs4ProxyPath string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.bridges = bridges
	e.obfs4ProxyPath = obfs4ProxyPath
}

// FindBinary searches paths for the tor executable.
func (e *TorEngine) FindBinary() (string, error) {
	if e.binaryPath != "" {
		if _, err := os.Stat(e.binaryPath); err == nil {
			return e.binaryPath, nil
		}
	}

	binaries := []string{
		"tor.exe", "tor",
		`./bin/tor/tor.exe`,
		`./bin/tor/tor`,
		`C:\Users\ACER\Desktop\quranips\tools\Proxy tester\bin\tor\tor.exe`,
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

	return "", fmt.Errorf("failed to locate tor binary in PATH or common directories")
}

// Start launches the Tor process.
func (e *TorEngine) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.isRunning {
		return nil
	}

	binary, err := e.FindBinary()
	if err != nil {
		return err
	}

	// Create temp torrc config file
	tmpDir := os.TempDir()
	confPath := filepath.Join(tmpDir, fmt.Sprintf("torrc-%d", e.socksPort))
	dataDir := filepath.Join(tmpDir, fmt.Sprintf("tordata-%d", e.socksPort))
	_ = os.MkdirAll(dataDir, 0700)

	torrcContent := fmt.Sprintf(`SocksPort 127.0.0.1:%d
ControlPort 127.0.0.1:%d
DataDirectory %s
GeoIPFile %s
GeoIPv6File %s
AvoidDiscoveredRendezvousPoints 1
`, e.socksPort, e.controlPort, dataDir, filepath.Join(dataDir, "geoip"), filepath.Join(dataDir, "geoip6"))

	if len(e.bridges) > 0 {
		torrcContent += "UseBridges 1\n"
		if e.obfs4ProxyPath != "" {
			torrcContent += fmt.Sprintf("ClientTransportPlugin obfs4 exec %s\n", filepath.ToSlash(e.obfs4ProxyPath))
		}
		for _, b := range e.bridges {
			torrcContent += fmt.Sprintf("Bridge %s\n", b)
		}
	}

	// Write torrc
	if err := os.WriteFile(confPath, []byte(torrcContent), 0644); err != nil {
		return fmt.Errorf("failed to create torrc: %w", err)
	}
	e.configPath = confPath

	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel

	cmd := exec.CommandContext(ctx, binary, "-f", confPath)
	cmd.SysProcAttr = utils.GetDaemonSysProcAttr()

	if err := cmd.Start(); err != nil {
		cancel()
		os.Remove(confPath)
		return fmt.Errorf("failed to start Tor process: %w", err)
	}

	e.cmd = cmd
	e.isRunning = true

	// Spin a monitor goroutine to clean up on process exit
	go func() {
		_ = cmd.Wait()
		e.mu.Lock()
		e.isRunning = false
		e.cmd = nil
		_ = os.Remove(e.configPath)
		e.mu.Unlock()
	}()

	// Wait briefly to check if it crashed instantly
	time.Sleep(300 * time.Millisecond)
	return nil
}

// Stop terminates the Tor process.
func (e *TorEngine) Stop() {
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

// IsRunning returns status of Tor.
func (e *TorEngine) IsRunning() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.isRunning
}
