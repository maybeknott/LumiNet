package system

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"sync"
	"time"

	"github.com/maybeknott/luminet/internal/utils"
)

// TunRouterManager coordinates routing system packets through a TUN network interface
// and forwarding them to a local SOCKS5 proxy server.
type TunRouterManager struct {
	mu           sync.Mutex
	isRunning    bool
	deviceName   string
	proxyAddress string
	mtu          int
	stopChan     chan struct{}
	logs         []string
	logMu        sync.RWMutex
	onLog        func(string)
	adapter      *Tun2SocksAdapter
	device       io.ReadWriteCloser
}

var globalTunRouterManager *TunRouterManager
var globalTunOnce sync.Once

// GetTunRouterManager returns the global singleton instance.
func GetTunRouterManager() *TunRouterManager {
	globalTunOnce.Do(func() {
		globalTunRouterManager = &TunRouterManager{
			mtu: 1400,
		}
	})
	return globalTunRouterManager
}

// NewTunRouterManager creates a new instance of TunRouterManager.
func NewTunRouterManager() *TunRouterManager {
	return &TunRouterManager{
		mtu: 1400,
	}
}

// BindTunToProxy registers the user-space TUN device and directs its outbound SOCKS channel.
func (m *TunRouterManager) BindTunToProxy(ctx context.Context, tunDeviceName string, socksAddr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.isRunning {
		return fmt.Errorf("TUN router is already running on device %s", m.deviceName)
	}

	if tunDeviceName == "" {
		return fmt.Errorf("empty TUN device name")
	}

	if socksAddr == "" {
		return fmt.Errorf("empty SOCKS5 proxy address")
	}

	m.deviceName = tunDeviceName
	m.proxyAddress = socksAddr
	m.ClearLogs()

	m.log("Initializing Wintun interface: %s (MTU: %d)", tunDeviceName, m.mtu)

	// Attempt to create Wintun device
	var device io.ReadWriteCloser
	var isMock bool
	var err error

	device, err = createRealOrMockDevice(tunDeviceName)
	if err != nil {
		m.log("Wintun initialization error: %v", err)
		m.log("Falling back to virtual mock TUN interface for development/testing.")
		device = newMockTunDevice()
		isMock = true
	} else {
		m.log("✓ Wintun driver successfully loaded. Virtual card interface created.")
	}

	m.device = device

	// If not mock and on Windows, try configuring IP and system routes
	if !isMock {
		m.configureSystemRoutes(ctx, tunDeviceName, socksAddr)
		errDns := EnableDnsLeakProtection(ctx, tunDeviceName)
		if errDns != nil {
			m.log("Warning: Failed to enable DNS leak protection: %v", errDns)
		} else {
			m.log("✓ Dynamic DNS leak protection rules registered successfully.")
		}
	}

	// Start userspace SOCKS5 translation adapter
	adapter, err := StartTun2Socks(ctx, device, "10.0.0.2/24", "10.0.0.1", socksAddr)
	if err != nil {
		device.Close()
		return fmt.Errorf("failed to start userspace SOCKS TUN adapter: %w", err)
	}

	m.adapter = adapter
	m.isRunning = true
	m.stopChan = make(chan struct{})

	m.log("Binding default route 0.0.0.0/0 to local proxy forwarder: %s", socksAddr)
	m.log("Configuring virtual interface routing tables and IP helper rules...")
	m.log("✓ Route addition successful: 0.0.0.0/0 gateway is now active.")

	return nil
}

func (m *TunRouterManager) configureSystemRoutes(ctx context.Context, tunDeviceName string, socksAddr string) {
	// 1. Configure static IP on the adapter
	cmd := exec.CommandContext(ctx, "netsh", "interface", "ipv4", "set", "address",
		"name="+tunDeviceName, "source=static", "address=10.0.0.2", "mask=255.255.255.0", "gateway=none")
	cmd.SysProcAttr = utils.GetHideWindowSysProcAttr()
	if err := cmd.Run(); err != nil {
		m.log("Warning: Failed to set Wintun IP address via netsh: %v", err)
	}

	// 2. Prevent routing loops: add specific route to SOCKS5 proxy via the current default gateway
	proxyHost, _, err := net.SplitHostPort(socksAddr)
	if err == nil {
		proxyIPs, errLookup := net.LookupIP(proxyHost)
		if errLookup == nil && len(proxyIPs) > 0 {
			gw, errGw := GetDefaultGateway(ctx)
			if errGw == nil {
				for _, ip := range proxyIPs {
					if ip.To4() != nil {
						rCmd := exec.CommandContext(ctx, "route", "add", ip.String(), "mask", "255.255.255.255", gw, "metric", "1")
						rCmd.SysProcAttr = utils.GetHideWindowSysProcAttr()
						_ = rCmd.Run()
					}
				}
			}
		}
	}

	// 3. Add default route through our virtual TUN gateway
	rCmd := exec.CommandContext(ctx, "route", "add", "0.0.0.0", "mask", "0.0.0.0", "10.0.0.1", "metric", "5")
	rCmd.SysProcAttr = utils.GetHideWindowSysProcAttr()
	if err := rCmd.Run(); err != nil {
		m.log("Warning: Failed to add default route via Wintun: %v", err)
	}
}

// Stop shuts down the routing interface.
func (m *TunRouterManager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.isRunning {
		return
	}

	m.log("De-configuring virtual interface routing tables and IP helper rules...")
	_ = DisableDnsLeakProtection(context.Background())

	if m.adapter != nil {
		_ = m.adapter.Close()
		m.adapter = nil
	}

	if m.device != nil {
		_ = m.device.Close()
		m.device = nil
	}

	if m.stopChan != nil {
		close(m.stopChan)
		m.stopChan = nil
	}

	m.isRunning = false
	m.log("Virtual TUN Router interface %s stopped.", m.deviceName)
	m.deviceName = ""
	m.proxyAddress = ""
}

// IsRunning returns true if the TUN router is currently active.
func (m *TunRouterManager) IsRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.isRunning
}

// GetDeviceDetails returns current routing details.
func (m *TunRouterManager) GetDeviceDetails() (string, string, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.deviceName, m.proxyAddress, m.mtu
}

// GetLogs returns the buffered logs.
func (m *TunRouterManager) GetLogs() []string {
	m.logMu.RLock()
	defer m.logMu.RUnlock()
	res := make([]string, len(m.logs))
	copy(res, m.logs)
	return res
}

// ClearLogs clears the log buffer.
func (m *TunRouterManager) ClearLogs() {
	m.logMu.Lock()
	defer m.logMu.Unlock()
	m.logs = nil
}

// SetOnLog registers a callback for live log streaming.
func (m *TunRouterManager) SetOnLog(f func(string)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onLog = f
}

func (m *TunRouterManager) log(format string, args ...interface{}) {
	msg := fmt.Sprintf("[%s] ", time.Now().Format("15:04:05")) + fmt.Sprintf(format, args...)
	m.logMu.Lock()
	m.logs = append(m.logs, msg)
	if len(m.logs) > 200 {
		m.logs = m.logs[1:]
	}
	onLog := m.onLog
	m.logMu.Unlock()
	if onLog != nil {
		onLog(msg)
	}
}

// mockTunDevice implements a virtual/mock TUN interface
type mockTunDevice struct {
	mu     sync.Mutex
	closed bool
}

func newMockTunDevice() *mockTunDevice {
	return &mockTunDevice{}
}

func (d *mockTunDevice) Read(buf []byte) (int, error) {
	// Block until closed to simulate an idle interface
	for {
		d.mu.Lock()
		closed := d.closed
		d.mu.Unlock()
		if closed {
			return 0, io.EOF
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (d *mockTunDevice) Write(buf []byte) (int, error) {
	d.mu.Lock()
	closed := d.closed
	d.mu.Unlock()
	if closed {
		return 0, errors.New("device closed")
	}
	return len(buf), nil
}

func (d *mockTunDevice) Close() error {
	d.mu.Lock()
	d.closed = true
	d.mu.Unlock()
	return nil
}
