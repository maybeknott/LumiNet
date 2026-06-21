package system

import (
	"context"
	"testing"
	"time"
)

func TestTunRouterManager(t *testing.T) {
	mgr := NewTunRouterManager()

	if mgr.IsRunning() {
		t.Errorf("Expected TUN router manager to be idle initially")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := mgr.BindTunToProxy(ctx, "wintun0", "127.0.0.1:1080")
	if err != nil {
		t.Fatalf("Failed to bind TUN device: %v", err)
	}

	if !mgr.IsRunning() {
		t.Errorf("Expected TUN router manager to be running after Bind")
	}

	dev, proxy, mtu := mgr.GetDeviceDetails()
	if dev != "wintun0" {
		t.Errorf("Expected device name 'wintun0', got %q", dev)
	}
	if proxy != "127.0.0.1:1080" {
		t.Errorf("Expected proxy address '127.0.0.1:1080', got %q", proxy)
	}
	if mtu != 1400 {
		t.Errorf("Expected MTU 1400, got %d", mtu)
	}

	// Test double bind prevention
	err = mgr.BindTunToProxy(ctx, "wintun1", "127.0.0.1:1080")
	if err == nil {
		t.Errorf("Expected error when binding already running router, got nil")
	}

	mgr.Stop()
	time.Sleep(10 * time.Millisecond)

	if mgr.IsRunning() {
		t.Errorf("Expected TUN router manager to be idle after Stop")
	}
}
