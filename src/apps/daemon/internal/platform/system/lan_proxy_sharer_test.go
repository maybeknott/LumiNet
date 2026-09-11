package system

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/maybeknott/luminet/internal/foundation/boundedio"
)

// startEchoCarrier starts a minimal SOCKS5 echo server for testing.
func startEchoCarrier(t *testing.T) (string, func()) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on carrier: %v", err)
	}

	stopChan := make(chan struct{})

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				select {
				case <-stopChan:
					return
				default:
					return
				}
			}

			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))

				// SOCKS5 handshake
				var verMethods [2]byte
				if _, err := io.ReadFull(c, verMethods[:]); err != nil {
					return
				}
				methods := make([]byte, verMethods[1])
				if _, err := io.ReadFull(c, methods); err != nil {
					return
				}
				// Accept NO_AUTH
				_, _ = c.Write([]byte{0x05, 0x00})

				// SOCKS5 request
				var head [4]byte
				if _, err := io.ReadFull(c, head[:]); err != nil {
					return
				}
				// Drain target addr
				switch head[3] {
				case 0x01:
					var b [4 + 2]byte
					_, _ = io.ReadFull(c, b[:])
				case 0x03:
					var l [1]byte
					_, _ = io.ReadFull(c, l[:])
					b := make([]byte, int(l[0])+2)
					_, _ = io.ReadFull(c, b)
				case 0x04:
					var b [16 + 2]byte
					_, _ = io.ReadFull(c, b[:])
				}
				// Reply SUCCESS
				_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 80})

				// Echo loop
				_ = c.SetDeadline(time.Time{})
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	return l.Addr().String(), func() {
		close(stopChan)
		_ = l.Close()
	}
}

func TestLanProxySharerSocks5Open(t *testing.T) {
	carrierAddr, closeCarrier := startEchoCarrier(t)
	defer closeCarrier()

	sharer := NewLanProxySharer()
	status, err := sharer.Start(carrierAddr, LanSettings{
		Enabled: true,
		Port:    0, // Random available port
	})
	if err != nil {
		t.Fatalf("failed to start sharer: %v", err)
	}
	defer sharer.Stop()

	if !status.Running || !status.Open {
		t.Fatalf("expected running open status, got %+v", status)
	}

	// Dial LAN sharer as SOCKS5 client
	client, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sharer.port))
	if err != nil {
		t.Fatalf("failed to dial sharer: %v", err)
	}
	defer client.Close()

	// SOCKS5 handshake (NO_AUTH)
	_, _ = client.Write([]byte{0x05, 0x01, 0x00})
	var rep [2]byte
	if _, err := io.ReadFull(client, rep[:]); err != nil || rep[0] != 0x05 || rep[1] != 0x00 {
		t.Fatalf("handshake failed: %v, rep: %v", err, rep)
	}

	// SOCKS5 CONNECT to example.com:80
	target := "example.com"
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(target))}
	req = append(req, []byte(target)...)
	req = append(req, 0x00, 0x50) // port 80
	_, _ = client.Write(req)

	var connRep [10]byte
	if _, err := io.ReadFull(client, connRep[:]); err != nil || connRep[1] != 0x00 {
		t.Fatalf("connect failed: %v, rep: %v", err, connRep)
	}

	// Send echo payload
	msg := []byte("hello-luminet-socks5")
	_, _ = client.Write(msg)
	recv := make([]byte, len(msg))
	if _, err := io.ReadFull(client, recv); err != nil {
		t.Fatalf("failed to receive echo: %v", err)
	}
	if string(recv) != string(msg) {
		t.Fatalf("expected %s, got %s", msg, recv)
	}
}

func TestLanProxySharerSocks5Auth(t *testing.T) {
	carrierAddr, closeCarrier := startEchoCarrier(t)
	defer closeCarrier()

	sharer := NewLanProxySharer()
	_, err := sharer.Start(carrierAddr, LanSettings{
		Enabled:  true,
		Port:     0,
		Username: "alice",
		Password: "secretpassword",
	})
	if err != nil {
		t.Fatalf("failed to start sharer: %v", err)
	}
	defer sharer.Stop()

	// Test 1: Fail without auth method
	c1, _ := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sharer.port))
	_, _ = c1.Write([]byte{0x05, 0x01, 0x00}) // Only NO_AUTH offered
	var r1 [2]byte
	_, _ = io.ReadFull(c1, r1[:])
	if r1[1] != 0xFF {
		t.Fatalf("expected 0xFF rejection, got %v", r1)
	}
	c1.Close()

	// Test 2: Success with valid RFC 1929 auth
	c2, _ := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sharer.port))
	defer c2.Close()
	_, _ = c2.Write([]byte{0x05, 0x01, 0x02}) // USER_PASS offered
	var r2 [2]byte
	_, _ = io.ReadFull(c2, r2[:])
	if r2[1] != 0x02 {
		t.Fatalf("expected 0x02 accept, got %v", r2)
	}

	// Send user/pass: version 0x01, ulen 5, alice, plen 14, secretpassword
	authBuf := []byte{0x01, 0x05}
	authBuf = append(authBuf, []byte("alice")...)
	authBuf = append(authBuf, byte(len("secretpassword")))
	authBuf = append(authBuf, []byte("secretpassword")...)
	_, _ = c2.Write(authBuf)

	var authRep [2]byte
	_, _ = io.ReadFull(c2, authRep[:])
	if authRep[1] != 0x00 {
		t.Fatalf("expected auth success 0x00, got %v", authRep)
	}
}

func TestLanProxySharerHttpConnect(t *testing.T) {
	carrierAddr, closeCarrier := startEchoCarrier(t)
	defer closeCarrier()

	sharer := NewLanProxySharer()
	_, err := sharer.Start(carrierAddr, LanSettings{
		Enabled:  true,
		Port:     0,
		Username: "bob",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("failed to start sharer: %v", err)
	}
	defer sharer.Stop()

	// 1. Without credentials -> 407
	c1, _ := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sharer.port))
	_, _ = c1.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"))
	reader1 := bufio.NewReader(c1)
	line1, _ := boundedio.ReadLine(reader1, maxLanHTTPLineBytes)
	if !strings.Contains(line1, "407 Proxy Authentication Required") {
		t.Fatalf("expected 407, got %s", line1)
	}
	c1.Close()

	// 2. With credentials -> 200 Connection established
	c2, _ := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sharer.port))
	defer c2.Close()
	authHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte("bob:password123"))
	req := fmt.Sprintf("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: %s\r\n\r\n", authHeader)
	_, _ = c2.Write([]byte(req))

	reader2 := bufio.NewReader(c2)
	line2, _ := boundedio.ReadLine(reader2, maxLanHTTPLineBytes)
	if !strings.Contains(line2, "200 Connection established") {
		t.Fatalf("expected 200, got %s", line2)
	}
	// Read empty line
	_, _ = boundedio.ReadLine(reader2, maxLanHTTPLineBytes)

	// Test echo data through CONNECT tunnel
	payload := []byte("secure-tls-handshake-bytes")
	_, _ = c2.Write(payload)
	echoBuf := make([]byte, len(payload))
	if _, err := io.ReadFull(reader2, echoBuf); err != nil {
		t.Fatalf("failed reading echo from HTTP CONNECT tunnel: %v", err)
	}
	if string(echoBuf) != string(payload) {
		t.Fatalf("expected %s, got %s", payload, echoBuf)
	}
}
