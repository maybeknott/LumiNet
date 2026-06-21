//go:build linux

package proxy

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

func TestNamespaceAndInterfaceSetup(t *testing.T) {
	// Skip if not running as root, since creating network namespaces requires root privileges.
	if os.Getuid() != 0 {
		t.Skip("Skipping test because it requires root privileges (running on Linux as root)")
	}

	nsName := "testns_luminet"
	vethHost := "veth_test_h"
	vethPeer := "veth_test_p"
	hostCIDR := "10.250.0.1/24"
	peerCIDR := "10.250.0.2/24"
	gateway := "10.250.0.1"

	// 1. Create Namespace
	err := CreateNamespace(nsName)
	if err != nil {
		t.Fatalf("failed to create namespace: %v", err)
	}
	defer func() {
		_ = DeleteNamespace(nsName)
	}()

	// 2. Setup namespace interface
	err = SetupNamespaceInterface(nsName, vethHost, vethPeer, hostCIDR, peerCIDR, gateway)
	if err != nil {
		t.Fatalf("failed to setup namespace interface: %v", err)
	}

	// 3. Test loopback redirect rules (setup and clear)
	err = SetupRedirectRules(nsName, 8080, 10880)
	if err != nil {
		t.Logf("Warning: redirect rules setup failed (might not have nftables/iptables binary): %v", err)
	} else {
		err = ClearRedirectRules(nsName, 8080, 10880)
		if err != nil {
			t.Errorf("failed to clear redirect rules: %v", err)
		}
	}

	// 4. Test Wormhole Forwarder inside the namespace
	forwarder := NewWormholeForwarder(nsName, "127.0.0.1:8080", "127.0.0.1:9090")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = forwarder.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start wormhole forwarder in namespace: %v", err)
	}

	// Verify listener is created inside the namespace
	err = ExecuteInNamespace(nsName, func() error {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:8080", 1*time.Second)
		if err != nil {
			return fmt.Errorf("failed to connect to wormhole listener inside namespace: %w", err)
		}
		conn.Close()
		return nil
	})
	if err != nil {
		t.Errorf("wormhole verification failed: %v", err)
	}

	err = forwarder.Stop()
	if err != nil {
		t.Errorf("failed to stop wormhole forwarder: %v", err)
	}
}
