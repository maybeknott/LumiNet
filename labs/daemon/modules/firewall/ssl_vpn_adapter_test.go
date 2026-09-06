package firewall

import (
	"testing"
	"time"
)

func TestSslVpnVirtualAdapterLifecycle(t *testing.T) {
	cfg := SslVpnAdapterConfig{
		GatewayIP:       "10.200.0.1",
		VirtualIP:       "10.200.0.50",
		HeartbeatPeriod: 10 * time.Second,
		SessionCookie:   "test-session",
	}

	adapter, err := NewSslVpnVirtualAdapter(cfg)
	if err != nil {
		t.Fatalf("failed to create adapter: %v", err)
	}

	if err := adapter.Activate(); err != nil {
		t.Fatalf("failed to activate: %v", err)
	}

	if !adapter.ProcessHeartbeat() {
		t.Errorf("heartbeat should succeed on active adapter")
	}

	adapter.RecordTraffic(1024, 2048)
	active, rx, tx := adapter.Stats()
	if !active || rx != 1024 || tx != 2048 {
		t.Errorf("stats mismatch: active=%v, rx=%d, tx=%d", active, rx, tx)
	}
}
