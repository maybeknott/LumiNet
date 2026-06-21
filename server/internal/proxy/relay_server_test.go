package proxy

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestEvasionRelayServer(t *testing.T) {
	// Create target echo server
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen on target port: %v", err)
	}
	defer targetListener.Close()

	go func() {
		for {
			conn, err := targetListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c) // Echo payload back
			}(conn)
		}
	}()

	// Start EvasionRelayServer
	relay := NewEvasionRelayServer("127.0.0.1:0")
	err = relay.Start()
	if err != nil {
		t.Fatalf("Failed to start relay server: %v", err)
	}
	defer relay.Stop()

	// Wait briefly for listener to boot
	time.Sleep(50 * time.Millisecond)

	// Dial the relay server manually
	relayAddr := relay.listener.Addr().String()
	conn, err := net.Dial("tcp", relayAddr)
	if err != nil {
		t.Fatalf("Failed to dial relay server: %v", err)
	}
	defer conn.Close()

	// Send HTTP request to establish tunnel
	reqStr := "GET / HTTP/1.1\r\nHost: localhost\r\nX-Actual-Host: " + targetListener.Addr().String() + "\r\n\r\n"
	_, err = conn.Write([]byte(reqStr))
	if err != nil {
		t.Fatalf("Failed to send tunnel request: %v", err)
	}

	// Verify handshake response
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read handshake response: %v", err)
	}
	if line != "HTTP/1.1 200 Connection Established\r\n" {
		t.Errorf("Unexpected handshake response line: %q", line)
	}

	// Read empty line
	_, _ = reader.ReadString('\n')

	// Send payload and test echo
	payload := []byte("Hello hijacked tunnel!\n")
	_, err = conn.Write(payload)
	if err != nil {
		t.Fatalf("Failed to send payload: %v", err)
	}

	respLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read echo response: %v", err)
	}
	if respLine != string(payload) {
		t.Errorf("Expected echo %q, got %q", string(payload), respLine)
	}
}

func TestStartEvasionRelayServer(t *testing.T) {
	errChan := make(chan error, 1)
	// We run it on a random free port (127.0.0.1:0 is not supported directly by http.Serve in some contexts, but net.Listen handles it)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close() // free the port to allow StartEvasionRelayServer to bind to it

	go func() {
		errChan <- StartEvasionRelayServer(addr)
	}()

	select {
	case err := <-errChan:
		if err != nil {
			t.Logf("StartEvasionRelayServer exited early with: %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		// Running successfully
	}
}

func TestEvasionRelayServerWithDecoy(t *testing.T) {
	// Create decoy listener
	decoyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen on decoy: %v", err)
	}
	defer decoyListener.Close()

	go func() {
		for {
			conn, err := decoyListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				_, _ = c.Read(buf) // Drain incoming request buffer to prevent RST on Windows
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello Decoy!"))
			}(conn)
		}
	}()

	// Start EvasionRelayServer with Decoy enabled
	relay := NewEvasionRelayServer("127.0.0.1:0")
	relay.DecoyTarget = decoyListener.Addr().String()
	relay.SecretPaths = []string{"/tunnel"}
	err = relay.Start()
	if err != nil {
		t.Fatalf("Failed to start relay server: %v", err)
	}
	defer relay.Stop()

	// Wait briefly for listener to boot
	time.Sleep(50 * time.Millisecond)

	// Case 1: Dial and send non-matching probe data (should redirect to decoy)
	probeConn, err := net.Dial("tcp", relay.listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial relay: %v", err)
	}
	defer probeConn.Close()

	_, _ = probeConn.Write([]byte("GET /random-censor-probe HTTP/1.1\r\nHost: target\r\n\r\n"))
	respBuf := make([]byte, 1024)
	n, err := probeConn.Read(respBuf)
	if err != nil {
		t.Fatalf("Failed to read from redirect: %v", err)
	}
	
	resp := string(respBuf[:n])
	if !strings.Contains(resp, "Hello Decoy!") {
		t.Errorf("Expected response from decoy, got: %q", resp)
	}
}



