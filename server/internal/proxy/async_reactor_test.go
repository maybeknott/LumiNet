package proxy

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestAsyncReactorForwarding(t *testing.T) {
	// 1. Start a local mock echo destination server
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock echo server: %v", err)
	}
	defer echoListener.Close()

	go func() {
		for {
			conn, err := echoListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c) // echo back
			}(conn)
		}
	}()

	// 2. Start a local proxy mock server
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock proxy listener: %v", err)
	}
	defer proxyListener.Close()

	reactor, err := NewAsyncReactor()
	if err != nil {
		t.Fatalf("failed to create async reactor: %v", err)
	}
	defer reactor.Close()

	go func() {
		clientConn, err := proxyListener.Accept()
		if err != nil {
			return
		}

		targetConn, err := net.Dial("tcp", echoListener.Addr().String())
		if err != nil {
			clientConn.Close()
			return
		}

		if err := reactor.Register(clientConn, targetConn); err != nil {
			clientConn.Close()
			targetConn.Close()
		}
	}()

	// 3. Dial proxy mock server as client, send payload, and receive echo response
	client, err := net.Dial("tcp", proxyListener.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial proxy server: %v", err)
	}
	defer client.Close()

	payload := []byte("hello reactor async forwarding")
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("failed to write payload: %v", err)
	}

	buf := make([]byte, 100)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	if !bytes.Equal(buf[:n], payload) {
		t.Errorf("got response %q, want %q", string(buf[:n]), string(payload))
	}

	// Send a second payload to ensure reactor continues to forward subsequent reads
	payload2 := []byte("chunk two of forwarding test")
	if _, err := client.Write(payload2); err != nil {
		t.Fatalf("failed to write second payload: %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err = client.Read(buf)
	if err != nil {
		t.Fatalf("failed to read second response: %v", err)
	}

	if !bytes.Equal(buf[:n], payload2) {
		t.Errorf("got second response %q, want %q", string(buf[:n]), string(payload2))
	}
}

func TestAsyncReactorForwarding_NoEcho(t *testing.T) {
	var received bytes.Buffer
	var mu sync.Mutex

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock listener: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			mu.Lock()
			received.Write(buf[:n])
			mu.Unlock()
		}
	}()

	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start proxy listener: %v", err)
	}
	defer proxyListener.Close()

	reactor, err := NewAsyncReactor()
	if err != nil {
		t.Fatalf("failed to create async reactor: %v", err)
	}
	defer reactor.Close()

	go func() {
		clientConn, err := proxyListener.Accept()
		if err != nil {
			return
		}
		targetConn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			clientConn.Close()
			return
		}
		_ = reactor.Register(clientConn, targetConn)
	}()

	client, err := net.Dial("tcp", proxyListener.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial proxy: %v", err)
	}
	defer client.Close()

	// Write first chunk
	if _, err := client.Write([]byte("chunk1")); err != nil {
		t.Fatalf("write 1 failed: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// Write second chunk
	if _, err := client.Write([]byte("chunk2")); err != nil {
		t.Fatalf("write 2 failed: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	got := received.String()
	mu.Unlock()

	expected := "chunk1chunk2"
	if got != expected {
		t.Errorf("received %q, want %q", got, expected)
	}
}

