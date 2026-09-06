package firewall

import (
	"fmt"
	"sync"
	"time"
)

// SslVpnAdapterConfig defines SSL VPN tunnel parameters.
type SslVpnAdapterConfig struct {
	GatewayIP       string        `json:"gateway_ip"`
	VirtualIP       string        `json:"virtual_ip"`
	HeartbeatPeriod time.Duration `json:"heartbeat_period"`
	SessionCookie   string        `json:"session_cookie"`
}

// SslVpnVirtualAdapter manages SSL VPN tunnel state and heartbeats.
type SslVpnVirtualAdapter struct {
	mu            sync.Mutex
	cfg           SslVpnAdapterConfig
	isActive      bool
	lastHeartbeat time.Time
	rxBytes       uint64
	txBytes       uint64
}

// NewSslVpnVirtualAdapter creates a virtual adapter.
func NewSslVpnVirtualAdapter(cfg SslVpnAdapterConfig) (*SslVpnVirtualAdapter, error) {
	if cfg.GatewayIP == "" || cfg.VirtualIP == "" {
		return nil, fmt.Errorf("gateway IP and virtual IP must be configured")
	}
	if cfg.HeartbeatPeriod == 0 {
		cfg.HeartbeatPeriod = 30 * time.Second
	}
	return &SslVpnVirtualAdapter{
		cfg:      cfg,
		isActive: false,
	}, nil
}

// Activate establishes the virtual interface tunnel.
func (a *SslVpnVirtualAdapter) Activate() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.isActive {
		return fmt.Errorf("adapter already active")
	}
	a.isActive = true
	a.lastHeartbeat = time.Now()
	return nil
}

// ProcessHeartbeat verifies and updates the keepalive timestamp.
func (a *SslVpnVirtualAdapter) ProcessHeartbeat() bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.isActive {
		return false
	}
	a.lastHeartbeat = time.Now()
	return true
}

// RecordTraffic increments byte counters.
func (a *SslVpnVirtualAdapter) RecordTraffic(rx, tx uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rxBytes += rx
	a.txBytes += tx
}

// Stats returns current counters and active status.
func (a *SslVpnVirtualAdapter) Stats() (bool, uint64, uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.isActive, a.rxBytes, a.txBytes
}
