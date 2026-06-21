package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func TestKdf(t *testing.T) {
	key := Kdf("foobar", 16)
	if len(key) != 16 {
		t.Fatalf("expected key length 16, got %d", len(key))
	}

	key32 := Kdf("secretpassword", 32)
	if len(key32) != 32 {
		t.Fatalf("expected key length 32, got %d", len(key32))
	}
}

func TestReplayCache(t *testing.T) {
	cache := NewReplayCache(5)

	salt1 := []byte("salt1-sixteen-b")
	salt2 := []byte("salt2-sixteen-b")
	salt3 := []byte("salt3-sixteen-b")
	salt4 := []byte("salt4-sixteen-b")
	salt5 := []byte("salt5-sixteen-b")
	salt6 := []byte("salt6-sixteen-b")

	if !cache.CheckAndAdd(salt1) {
		t.Fatal("expected salt1 to be accepted")
	}
	if cache.CheckAndAdd(salt1) {
		t.Fatal("expected salt1 to be rejected as replay")
	}

	// Add up to capacity
	if !cache.CheckAndAdd(salt2) || !cache.CheckAndAdd(salt3) || !cache.CheckAndAdd(salt4) || !cache.CheckAndAdd(salt5) {
		t.Fatal("expected salts 2-5 to be accepted")
	}

	// salt6 will cause salt1 to be evicted
	if !cache.CheckAndAdd(salt6) {
		t.Fatal("expected salt6 to be accepted")
	}

	// salt1 should now be evicted and accepted again
	if !cache.CheckAndAdd(salt1) {
		t.Fatal("expected evicted salt1 to be accepted again")
	}
}

func TestAEADConn(t *testing.T) {
	ciphers := []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"}

	for _, method := range ciphers {
		t.Run(method, func(t *testing.T) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("failed to listen: %v", err)
			}
			defer l.Close()

			password := "testpassword"
			cache := NewReplayCache(100)

			// Start server goroutine
			go func() {
				rawConn, err := l.Accept()
				if err != nil {
					return
				}
				defer rawConn.Close()

				serverConn, err := NewAEADConn(rawConn, method, password, cache)
				if err != nil {
					t.Errorf("failed to create server AEAD conn: %v", err)
					return
				}

				buf := make([]byte, 100)
				n, err := serverConn.Read(buf)
				if err != nil {
					t.Errorf("server read failed: %v", err)
					return
				}

				// Echo back
				_, _ = serverConn.Write(buf[:n])
			}()

			// Client connect
			rawClient, err := net.Dial("tcp", l.Addr().String())
			if err != nil {
				t.Fatalf("failed to dial: %v", err)
			}
			defer rawClient.Close()

			clientConn, err := NewAEADConn(rawClient, method, password, cache)
			if err != nil {
				t.Fatalf("failed to create client AEAD conn: %v", err)
			}

			msg := []byte("Hello Shadowsocks!")
			if _, err := clientConn.Write(msg); err != nil {
				t.Fatalf("client write failed: %v", err)
			}

			reply := make([]byte, len(msg))
			if _, err := io.ReadFull(clientConn, reply); err != nil {
				t.Fatalf("client read reply failed: %v", err)
			}

			if !bytes.Equal(msg, reply) {
				t.Fatalf("expected echo %s, got %s", msg, reply)
			}
		})
	}
}

func TestObfsConn(t *testing.T) {
	modes := []string{"http", "http_simple", "tls"}

	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("failed to listen: %v", err)
			}
			defer l.Close()

			host := "example.com"

			// Server mock
			go func() {
				rawConn, err := l.Accept()
				if err != nil {
					return
				}
				defer rawConn.Close()

				serverObfs := NewObfsConn(rawConn, mode, host, "", false)
				buf := make([]byte, 100)
				n, err := serverObfs.Read(buf)
				if err != nil {
					t.Errorf("server read failed: %v", err)
					return
				}

				_, _ = serverObfs.Write(buf[:n])
			}()

			// Client mock
			rawClient, err := net.Dial("tcp", l.Addr().String())
			if err != nil {
				t.Fatalf("failed to dial: %v", err)
			}
			defer rawClient.Close()

			clientObfs := NewObfsConn(rawClient, mode, host, "", true)

			msg := make([]byte, 32)
			rand.Read(msg) // Salt-like payload
			
			if _, err := clientObfs.Write(msg); err != nil {
				t.Fatalf("client write failed: %v", err)
			}

			reply := make([]byte, len(msg))
			if _, err := io.ReadFull(clientObfs, reply); err != nil {
				t.Fatalf("client read reply failed: %v", err)
			}

			if !bytes.Equal(msg, reply) {
				t.Fatalf("data mismatch for mode %s", mode)
			}
		})
	}
}

func TestDialShadowsocks(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()

	password := "verysecret"
	method := "aes-256-gcm"

	// Mock server listening and replying
	go func() {
		rawConn, err := l.Accept()
		if err != nil {
			return
		}
		defer rawConn.Close()

		ssServer, err := NewAEADConn(rawConn, method, password, nil)
		if err != nil {
			t.Errorf("failed to create server AEAD conn: %v", err)
			return
		}

		buf := make([]byte, 200)
		n, err := ssServer.Read(buf)
		if err != nil {
			t.Errorf("server read failed: %v", err)
			return
		}

		_, _ = ssServer.Write(buf[:n])
	}()

	host, portStr, _ := net.SplitHostPort(l.Addr().String())
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	cfg := &ProxyConfig{
		Protocol: ProtocolShadowsocks,
		Address:  host,
		Port:     port,
		Method:   method,
		Password: password,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cache := NewReplayCache(10)
	conn, err := DialShadowsocks(ctx, cfg, cache)
	if err != nil {
		t.Fatalf("DialShadowsocks failed: %v", err)
	}
	defer conn.Close()

	msg := []byte("Hello DialShadowsocks!")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	reply := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read reply failed: %v", err)
	}

	if !bytes.Equal(msg, reply) {
		t.Fatalf("expected echo %s, got %s", msg, reply)
	}
}
