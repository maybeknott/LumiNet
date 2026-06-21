package proxy

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func TestFallbackProxyRouting(t *testing.T) {
	// Start a mock local target server
	localListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on local: %v", err)
	}
	defer localListener.Close()

	localRecv := make(chan string, 1)
	go func() {
		conn, err := localListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 100)
		n, _ := conn.Read(buf)
		localRecv <- string(buf[:n])
	}()

	// Start a mock decoy target server
	decoyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on decoy: %v", err)
	}
	defer decoyListener.Close()

	decoyRecv := make(chan string, 1)
	go func() {
		conn, err := decoyListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 100)
		n, _ := conn.Read(buf)
		decoyRecv <- string(buf[:n])
	}()

	// Setup FallbackProxy
	proxyPort := "127.0.0.1:0"
	secretPaths := []string{"/secret-proxy-inbound", "GET /tunnel"}
	proxy := NewFallbackProxy(proxyPort, localListener.Addr().String(), decoyListener.Addr().String(), secretPaths)

	if err := proxy.Start(); err != nil {
		t.Fatalf("failed to start fallback proxy: %v", err)
	}
	defer proxy.Stop()

	// 1. Test Match (Local target routing)
	clientConn1, err := net.Dial("tcp", proxy.listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial proxy: %v", err)
	}
	payload1 := "GET /tunnel HTTP/1.1\r\n\r\n"
	_, _ = clientConn1.Write([]byte(payload1))
	clientConn1.Close()

	select {
	case msg := <-localRecv:
		if msg != payload1 {
			t.Errorf("expected local target to receive '%s', got '%s'", payload1, msg)
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("timeout waiting for local target message")
	}

	// Restart local accept goroutine
	go func() {
		conn, err := localListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 100)
		n, _ := conn.Read(buf)
		localRecv <- string(buf[:n])
	}()

	// 2. Test Decoy (Fallback routing)
	clientConn2, err := net.Dial("tcp", proxy.listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial proxy: %v", err)
	}
	payload2 := "GET /index.html HTTP/1.1\r\n\r\n"
	_, _ = clientConn2.Write([]byte(payload2))
	clientConn2.Close()

	select {
	case msg := <-decoyRecv:
		if msg != payload2 {
			t.Errorf("expected decoy target to receive '%s', got '%s'", payload2, msg)
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("timeout waiting for decoy target message")
	}

	// 3. Test Blocked IP
	_, cidr, _ := net.ParseCIDR("127.0.0.0/8")
	proxy.SetBlockedCIDRs([]*net.IPNet{cidr})

	clientConn3, err := net.Dial("tcp", proxy.listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial proxy: %v", err)
	}
	defer clientConn3.Close()

	// Wait briefly to allow processing and close
	time.Sleep(50 * time.Millisecond)

	buf := make([]byte, 10)
	_ = clientConn3.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	_, err = clientConn3.Read(buf)
	if err != io.EOF && err == nil {
		t.Error("expected connection to be reset or closed by country filter, but it remained open")
	}
}

func TestFallbackProxyNginx404(t *testing.T) {
	// Start FallbackProxy with empty decoyAddress (triggers nginx404)
	proxy := NewFallbackProxy("127.0.0.1:0", "127.0.0.1:9999", "", []string{"/secret"})
	if err := proxy.Start(); err != nil {
		t.Fatalf("failed to start fallback proxy: %v", err)
	}
	defer proxy.Stop()

	clientConn, err := net.Dial("tcp", proxy.listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer clientConn.Close()

	// Send non-matching request
	_, _ = clientConn.Write([]byte("GET /index.html HTTP/1.1\r\n\r\n"))

	buf := make([]byte, 1024)
	_ = clientConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read: %v", err)
	}

	response := string(buf[:n])
	if !strings.Contains(response, "nginx/1.22.1") || !strings.Contains(response, "404 Not Found") {
		t.Errorf("expected Nginx 404 response headers, got: %s", response)
	}
}

func TestFallbackProxyWithReality(t *testing.T) {
	// 1. Setup Server/Client keys and Verifier
	serverPriv := make([]byte, 32)
	_, _ = rand.Read(serverPriv)
	serverPriv[0] &= 248
	serverPriv[31] &= 127
	serverPriv[31] |= 64
	serverPub, _ := curve25519.X25519(serverPriv, curve25519.Basepoint)

	clientPriv := make([]byte, 32)
	_, _ = rand.Read(clientPriv)
	clientPriv[0] &= 248
	clientPriv[31] &= 127
	clientPriv[31] |= 64
	clientPub, _ := curve25519.X25519(clientPriv, curve25519.Basepoint)

	// Start local target
	localL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("local listen failed: %v", err)
	}
	defer localL.Close()

	localChan := make(chan []byte, 1)
	go func() {
		c, err := localL.Accept()
		if err == nil {
			defer c.Close()
			buf := make([]byte, 512)
			n, _ := io.ReadAtLeast(c, buf, 10)
			localChan <- buf[:n]
		}
	}()

	// Start decoy target
	decoyL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("decoy listen failed: %v", err)
	}
	defer decoyL.Close()

	decoyChan := make(chan []byte, 1)
	go func() {
		c, err := decoyL.Accept()
		if err == nil {
			defer c.Close()
			buf := make([]byte, 512)
			n, _ := io.ReadAtLeast(c, buf, 10)
			decoyChan <- buf[:n]
		}
	}()

	verifier, err := NewRealityVerifierWithParams(
		[]byte("dummy_auth_key_32_bytes_long_12"),
		decoyL.Addr().String(),
		serverPriv,
		[]string{"73686f72745f6964"},
		5*time.Second,
	)
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	proxy := NewFallbackProxy("127.0.0.1:0", localL.Addr().String(), decoyL.Addr().String(), nil)
	proxy.RealityVerifier = verifier
	if err := proxy.Start(); err != nil {
		t.Fatalf("failed to start proxy: %v", err)
	}
	defer proxy.Stop()

	// 2. Test valid client
	hello := make([]byte, 126)
	hello[0] = 0x16
	hello[1] = 0x03
	hello[2] = 0x03
	binary.BigEndian.PutUint16(hello[3:5], 121)
	hello[5] = 0x01
	hello[6] = 0
	binary.BigEndian.PutUint16(hello[7:9], 117)
	hello[9] = 0x03
	hello[10] = 0x03
	for i := 0; i < 32; i++ {
		hello[11+i] = byte(i + 10)
	}
	clientRandom := hello[11:43]
	hello[43] = 32

	hello[76] = 0
	hello[77] = 2
	hello[78] = 0x13
	hello[79] = 0x01
	hello[80] = 1
	hello[81] = 0
	binary.BigEndian.PutUint16(hello[82:84], 42)
	binary.BigEndian.PutUint16(hello[84:86], 51)
	binary.BigEndian.PutUint16(hello[86:88], 38)
	binary.BigEndian.PutUint16(hello[88:90], 36)
	binary.BigEndian.PutUint16(hello[90:92], 29)
	binary.BigEndian.PutUint16(hello[92:94], 32)
	copy(hello[94:126], clientPub)

	sharedSecret, _ := curve25519.X25519(clientPriv, serverPub)
	realityKey := make([]byte, 32)
	hkdfReader := hkdf.New(sha256.New, sharedSecret, clientRandom[:20], []byte("REALITY"))
	_, _ = io.ReadFull(hkdfReader, realityKey)
	block, _ := aes.NewCipher(realityKey)
	aead, _ := cipher.NewGCM(block)

	aad := make([]byte, len(hello))
	copy(aad, hello)
	for i := 0; i < 32; i++ {
		aad[44+i] = 0
	}

	plaintext := make([]byte, 16)
	binary.BigEndian.PutUint32(plaintext[0:4], 0x00000001)
	binary.BigEndian.PutUint32(plaintext[4:8], uint32(time.Now().Unix()))
	copy(plaintext[8:16], []byte("short_id"))

	ciphertext := aead.Seal(nil, clientRandom[20:], plaintext, aad)
	copy(hello[44:76], ciphertext)

	c1, err := net.Dial("tcp", proxy.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	_, _ = c1.Write(hello)
	c1.Close()

	select {
	case data := <-localChan:
		if !bytes.Equal(data[:len(hello)], hello) {
			t.Errorf("local target received mismatch bytes")
		}
	case <-time.After(1 * time.Second):
		t.Errorf("timeout waiting for local target")
	}

	// 3. Test invalid client Hello
	c2, err := net.Dial("tcp", proxy.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	invalidHello := make([]byte, 126)
	copy(invalidHello, hello)
	invalidHello[44] ^= 0xFF // corrupt ciphertext
	_, _ = c2.Write(invalidHello)
	c2.Close()

	select {
	case data := <-decoyChan:
		if !bytes.Equal(data[:len(invalidHello)], invalidHello) {
			t.Errorf("decoy target received mismatch bytes")
		}
	case <-time.After(1 * time.Second):
		t.Errorf("timeout waiting for decoy target deflection")
	}
}

