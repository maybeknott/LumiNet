package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
)

func TestKcpSmuxStability(t *testing.T) {
	// Configure test config
	cfg := &ProxyConfig{
		Protocol:         ProtocolKCP,
		Address:          "127.0.0.1",
		Port:             29900,
		Password:         "testpassword",
		Method:           "aes-128",
		KCPNoDelay:       1,
		KCPInterval:      10,
		KCPResend:        2,
		KCPNoCongestion:  1,
		KCPSendWindow:    128,
		KCPReceiveWindow: 128,
	}

	// Listen on KCP
	listener, err := ListenKcp("127.0.0.1:29900", cfg)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	// Accept loop (server echo)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					_, _ = c.Write(buf[:n])
				}
			}(conn)
		}
	}()

	// Dial using KcpTransportManager
	mgr := NewKcpTransportManager()
	clientStream, err := mgr.Dial(cfg)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer clientStream.Close()

	// Write data
	msg := []byte("hello KCP + SMUX multiplexing!")
	_, err = clientStream.Write(msg)
	if err != nil {
		t.Fatalf("Failed to write to KCP stream: %v", err)
	}

	// Read data back
	buf := make([]byte, len(msg))
	_, err = io.ReadFull(clientStream, buf)
	if err != nil {
		t.Fatalf("Failed to read from KCP stream: %v", err)
	}

	if !bytes.Equal(buf, msg) {
		t.Errorf("expected %s, got %s", msg, buf)
	}
}

func TestKcpSmuxMultiplexing(t *testing.T) {
	// Configure test config
	cfg := &ProxyConfig{
		Protocol:         ProtocolKCP,
		Address:          "127.0.0.1",
		Port:             29901,
		Password:         "testpassword2",
		Method:           "tea",
		KCPNoDelay:       1,
		KCPInterval:      10,
		KCPResend:        2,
		KCPNoCongestion:  1,
		KCPSendWindow:    128,
		KCPReceiveWindow: 128,
	}

	listener, err := ListenKcp("127.0.0.1:29901", cfg)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					_, _ = c.Write(buf[:n])
				}
			}(conn)
		}
	}()

	mgr := NewKcpTransportManager()

	var wg sync.WaitGroup
	// Launch 10 concurrent streams
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			stream, err := mgr.Dial(cfg)
			if err != nil {
				t.Errorf("Stream %d failed to dial: %v", id, err)
				return
			}
			defer stream.Close()

			msg := []byte(fmt.Sprintf("stream msg %d", id))
			_, err = stream.Write(msg)
			if err != nil {
				t.Errorf("Stream %d failed to write: %v", id, err)
				return
			}

			buf := make([]byte, len(msg))
			_, err = io.ReadFull(stream, buf)
			if err != nil {
				t.Errorf("Stream %d failed to read: %v", id, err)
				return
			}

			if !bytes.Equal(buf, msg) {
				t.Errorf("Stream %d data mismatch: expected %s, got %s", id, msg, buf)
			}
		}(i)
	}
	wg.Wait()
}
