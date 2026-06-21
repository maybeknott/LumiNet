package proxy

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestUdpForwarder(t *testing.T) {
	// Setup a mock remote UDP listener
	remoteAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to resolve: %v", err)
	}
	remoteConn, err := net.ListenUDP("udp", remoteAddr)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer remoteConn.Close()

	// Spin up UdpForwarder pointing to the mock remote listener port
	forwarderPort := 21000
	forwarder := NewUdpForwarder(forwarderPort, remoteConn.LocalAddr().String())
	err = forwarder.Start()
	if err != nil {
		t.Fatalf("failed to start forwarder: %v", err)
	}
	defer forwarder.Close()

	// Dial mock client sending packets to forwarder
	clientConn, err := net.Dial("udp", "127.0.0.1:21000")
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer clientConn.Close()

	// Write payload
	expectedPayload := []byte("hello double hop")
	_, err = clientConn.Write(expectedPayload)
	if err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	// Read from remote target connection
	_ = remoteConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 100)
	n, clientUDPAddr, err := remoteConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("failed to read from remote connection: %v", err)
	}

	if string(buf[:n]) != string(expectedPayload) {
		t.Errorf("expected %q, got %q", string(expectedPayload), string(buf[:n]))
	}

	// Write response back to the client
	_, err = remoteConn.WriteToUDP([]byte("reply double hop"), clientUDPAddr)
	if err != nil {
		t.Fatalf("failed to write response: %v", err)
	}

	// Read reply on client side
	_ = clientConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, err = clientConn.Read(buf)
	if err != nil {
		t.Fatalf("client failed to read response: %v", err)
	}

	if string(buf[:n]) != "reply double hop" {
		t.Errorf("expected 'reply double hop', got %q", string(buf[:n]))
	}
}

func TestSetupWarpInWarp(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	forwarder, err := SetupWarpInWarp(ctx, "mock-outer-config", "mock-inner-config")
	if err != nil {
		t.Fatalf("failed to setup Warp-in-Warp: %v", err)
	}
	defer forwarder.Close()

	if forwarder.localPort != 20000 {
		t.Errorf("expected forwarder local port 20000, got %d", forwarder.localPort)
	}
}

func TestSetupPsiphonOverWarp(t *testing.T) {
	upstream, err := SetupPsiphonOverWarp("127.0.0.1:10086", "mock-psiphon-config")
	if err != nil {
		t.Fatalf("failed to setup Psiphon-over-WARP: %v", err)
	}

	expectedUpstream := "socks5://127.0.0.1:10086"
	if upstream != expectedUpstream {
		t.Errorf("expected upstream proxy url %q, got %q", expectedUpstream, upstream)
	}
}
