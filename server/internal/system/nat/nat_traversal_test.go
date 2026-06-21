package nat

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestUDPPunchHole(t *testing.T) {
	lAddr, err := net.ResolveUDPAddr("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to resolve local address: %v", err)
	}

	conn, err := net.ListenUDP("udp4", lAddr)
	if err != nil {
		t.Fatalf("failed to listen local UDP: %v", err)
	}
	defer conn.Close()

	rAddr, err := net.ResolveUDPAddr("udp4", "127.0.0.1:9999")
	if err != nil {
		t.Fatalf("failed to resolve remote address: %v", err)
	}

	err = UDPPunchHole(conn, rAddr, 200*time.Millisecond)
	if err != nil {
		t.Errorf("unexpected error during UDP punch-hole: %v", err)
	}
}

func TestTCPSimultaneousOpen(t *testing.T) {
	// Setup a local TCP listener to accept the incoming dial
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer listener.Close()

	lPort := listener.Addr().(*net.TCPAddr).Port

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Launch acceptor loop
	acceptDone := make(chan bool)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			conn.Close()
			acceptDone <- true
		} else {
			acceptDone <- false
		}
	}()

	// Simulating dial
	conn, err := TCPSimultaneousOpen(ctx, 0, "127.0.0.1", lPort, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("simultaneous open failed: %v", err)
	}
	defer conn.Close()

	ok := <-acceptDone
	if !ok {
		t.Error("accept loop failed to receive the connection")
	}
}
