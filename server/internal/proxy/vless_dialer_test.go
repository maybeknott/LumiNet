package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestVLESSDialer_TCP(t *testing.T) {
	testUUID := "9de78a2e-4b7b-4171-ba47-19ad0d7f9503"
	
	// Create mock VLESS TCP server
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	localAddr := listener.Addr().(*net.TCPAddr)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read VLESS handshake header
		buf := make([]byte, 1024)
		_, err = io.ReadAtLeast(conn, buf, 22)
		if err != nil {
			return
		}

		// Validate VLESS version, command, port
		if buf[0] != 0 {
			t.Errorf("expected version 0, got %d", buf[0])
		}
		if buf[18] != 1 {
			t.Errorf("expected command 1 (TCP Dial), got %d", buf[18])
		}

		// Send VLESS validation response header (version 0 + addons length 0)
		_, _ = conn.Write([]byte{0, 0})
		
		// Echo loop instead of io.Copy
		echoBuf := make([]byte, 512)
		for {
			n, err := conn.Read(echoBuf)
			if err != nil {
				return
			}
			_, err = conn.Write(echoBuf[:n])
			if err != nil {
				return
			}
		}
	}()

	cfg := &ProxyConfig{
		Protocol:  ProtocolVLESS,
		Address:   localAddr.IP.String(),
		Port:      localAddr.Port,
		UUID:      testUUID,
		Transport: "tcp",
		TLS:       false,
	}

	dialer := NewVLESSDialer(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := dialer.DialTarget(ctx, "example.com", 80)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	testMsg := []byte("Hello VLESS")
	if _, err := conn.Write(testMsg); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	resp := make([]byte, len(testMsg))
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read failed: %v", err)
	}

	if string(resp) != string(testMsg) {
		t.Errorf("expected %q, got %q", string(testMsg), string(resp))
	}
}

func TestVLESSDialer_WS(t *testing.T) {
	testUUID := "9de78a2e-4b7b-4171-ba47-19ad0d7f9503"
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	// Create mock VLESS WebSocket server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()

		// Read first frame (VLESS Header)
		mType, data, err := ws.ReadMessage()
		if err != nil || mType != websocket.BinaryMessage {
			return
		}

		// Validate command type (TCP Dial = 1)
		if len(data) < 22 || data[18] != 1 {
			return
		}

		// Send success response (version 0 + addons length 0)
		err = ws.WriteMessage(websocket.BinaryMessage, []byte{0, 0})
		if err != nil {
			return
		}

		// Relay echo loop
		for {
			mType, data, err = ws.ReadMessage()
			if err != nil {
				break
			}
			_ = ws.WriteMessage(mType, data)
		}
	}))
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("failed to parse test server URL: %v", err)
	}

	host, portStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portStr)

	cfg := &ProxyConfig{
		Protocol:  ProtocolVLESS,
		Address:   host,
		Port:      port,
		UUID:      testUUID,
		Transport: "ws",
		TLS:       false,
		Path:      "/ray",
	}

	dialer := NewVLESSDialer(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := dialer.DialTarget(ctx, "example.com", 80)
	if err != nil {
		t.Fatalf("WS dial failed: %v", err)
	}
	defer conn.Close()

	testMsg := []byte("WS Handshake Check")
	if _, err := conn.Write(testMsg); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	resp := make([]byte, len(testMsg))
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read failed: %v", err)
	}

	if string(resp) != string(testMsg) {
		t.Errorf("expected %q, got %q", string(testMsg), string(resp))
	}
}
