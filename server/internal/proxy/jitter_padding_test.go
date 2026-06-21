package proxy

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestPsiphonJitterConn(t *testing.T) {
	// Start local TCP server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	var receivedData bytes.Buffer
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(&receivedData, conn)
	}()

	// Dial and wrap connection
	rawConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	jitterConn := NewPsiphonJitterConn(rawConn)

	// Perform writes
	payload1 := []byte("Hello")
	payload2 := []byte("World")

	_, err = jitterConn.Write(payload1)
	if err != nil {
		t.Fatalf("Write 1 failed: %v", err)
	}

	_, err = jitterConn.Write(payload2)
	if err != nil {
		t.Fatalf("Write 2 failed: %v", err)
	}

	jitterConn.Close()

	// Wait briefly for server data accumulation
	time.Sleep(50 * time.Millisecond)

	data := receivedData.Bytes()
	// Total data must contain padding (written twice) + payload1 + payload2
	minExpectedLen := len(payload1) + len(payload2) + 64 // 32 * 2 padding min
	if len(data) < minExpectedLen {
		t.Errorf("Expected at least %d bytes of received data, got %d", minExpectedLen, len(data))
	}
}
