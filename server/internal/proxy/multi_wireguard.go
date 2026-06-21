package proxy

import (
	"fmt"
	"net"
	"sync"
)

// MultiWireGuardRouter represents a dynamic routing layer that load balances traffic
// across multiple active WireGuard/AmneziaWG endpoints.
type MultiWireGuardRouter struct {
	mu      sync.RWMutex
	configs []*ProxyConfig
	nextIdx int
}

// NewMultiWireGuardRouter creates a new MultiWireGuardRouter.
func NewMultiWireGuardRouter(configs []*ProxyConfig) *MultiWireGuardRouter {
	return &MultiWireGuardRouter{
		configs: configs,
	}
}

// SelectEndpoint chooses the next WireGuard configuration to route traffic to.
func (r *MultiWireGuardRouter) SelectEndpoint() (*ProxyConfig, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.configs) == 0 {
		return nil, fmt.Errorf("no WireGuard endpoints configured")
	}

	cfg := r.configs[r.nextIdx]
	r.nextIdx = (r.nextIdx + 1) % len(r.configs)
	return cfg, nil
}

// DialOutbound establishes a connection by load balancing across the configured WireGuard instances.
func (r *MultiWireGuardRouter) DialOutbound(network, address string) (net.Conn, error) {
	cfg, err := r.SelectEndpoint()
	if err != nil {
		return nil, err
	}

	// Dial using the selected WireGuard endpoint (or fallback to standard TCP dialer for simulation)
	// In production, this would initialize the WireGuard tun device or userspace netstack.
	dialer := &net.Dialer{}
	return dialer.Dial(network, net.JoinHostPort(cfg.Address, fmt.Sprintf("%d", cfg.Port)))
}
