package proxy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTailscaleAdapterLifecycle(t *testing.T) {
	// Setup a temporary state directory inside temporary folder
	tmpDir, err := os.MkdirTemp("", "tailscale-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	authKey := "ts-auth-mock-12345"
	hostname := "test-node-1"

	adapter := NewTailscaleAdapter(authKey, hostname, tmpDir)

	// Assert start succeeds
	if err := adapter.Start(); err != nil {
		t.Fatalf("failed to start adapter: %v", err)
	}

	if !adapter.IsRunning() {
		t.Errorf("adapter should be running")
	}

	// Verify that state directory has node_creds.json
	credsPath := filepath.Join(tmpDir, "node_creds.json")
	if _, err := os.Stat(credsPath); os.IsNotExist(err) {
		t.Errorf("expected credentials file to exist at %s", credsPath)
	}

	// Assert load credentials matches
	if adapter.creds.AuthKey != authKey || adapter.creds.Hostname != hostname {
		t.Errorf("unexpected loaded credentials: %+v", adapter.creds)
	}

	// Stop the adapter
	adapter.Stop()

	if adapter.IsRunning() {
		t.Errorf("adapter should not be running after Stop")
	}
}

func TestTailscaleAdapterDerpFallbackRouting(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tailscale-test-derp-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	adapter := NewTailscaleAdapter("mock-key", "test-node", tmpDir)
	adapter.SetUDPBlocked(true)

	if err := adapter.Start(); err != nil {
		t.Fatalf("failed to start adapter: %v", err)
	}
	defer adapter.Stop()

	// Simulate sending a packet over the netstack
	testDst := "100.64.0.10"
	testPayload := []byte("hello tailscale mesh vpn")

	adapter.netstack.QueuePacket(testDst, testPayload)

	// Give the packet routing loop some time to process the packet
	time.Sleep(300 * time.Millisecond)

	// Since we echo everything back on the mock DERP server, we should check if
	// the inbound channel of our derpClient received the packet.
	select {
	case echoed := <-adapter.derpClient.inboundCh:
		if string(echoed) != string(testPayload) {
			t.Errorf("expected echoed payload to match: %q, got: %q", string(testPayload), string(echoed))
		}
	case <-time.After(2 * time.Second):
		t.Errorf("timed out waiting for echoed packet via DERP relay")
	}
}

func TestTailscaleEngineWrapperWithSwitcher(t *testing.T) {
	engine, err := GetProxyEngine(EngineTailscale)
	if err != nil {
		t.Fatalf("failed to resolve EngineTailscale via switcher: %v", err)
	}

	if engine.IsRunning() {
		t.Errorf("engine should not be running initially")
	}

	// Wrapper Start
	if err := engine.Start(); err != nil {
		t.Fatalf("failed to start TailscaleEngine wrapper: %v", err)
	}
	defer engine.Stop()

	if !engine.IsRunning() {
		t.Errorf("engine wrapper should be running after Start")
	}

	// Wrapper Stop
	engine.Stop()
	if engine.IsRunning() {
		t.Errorf("engine wrapper should be stopped after Stop")
	}
}
