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
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func TestRealityVerifier_Verify(t *testing.T) {
	authKey := []byte("reality_test_auth_key_32_bytes_!")
	decoyAddress := "127.0.0.1:8080" // mock decoy

	verifier, err := NewRealityVerifier(authKey, decoyAddress)
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	// 1. Construct a valid mock TLS ClientHello with a valid ticket
	hello := make([]byte, 100)
	hello[0] = 0x16 // TLS Handshake
	hello[1] = 0x03 // Version
	hello[2] = 0x03
	// Random bytes start at offset 11. Length is 32.
	randomOffset := 11
	for i := 0; i < 32; i++ {
		hello[randomOffset+i] = byte(i)
	}

	// Session ID length and offset
	sessionIDOffset := 43
	hello[sessionIDOffset] = 32 // Length 32

	// Setup client key for encryption
	block, _ := aes.NewCipher(authKey)
	aead, _ := cipher.NewGCM(block)
	nonce := hello[randomOffset+20 : randomOffset+32]

	plaintext := []byte("authenticticket1") // 16 bytes
	ciphertext := aead.Seal(nil, nonce, plaintext, hello[:sessionIDOffset])

	copy(hello[sessionIDOffset+1:], ciphertext)

	// Mock connection
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		_, _ = clientConn.Write(hello)
	}()

	wrapped, ok, err := verifier.InterceptAndVerify(serverConn)
	if err != nil {
		t.Fatalf("failed to intercept and verify: %v", err)
	}

	if !ok {
		t.Fatal("expected authentication verification to succeed")
	}

	if wrapped == nil {
		t.Fatal("expected wrapped connection to be returned")
	}

	// Read from wrapped connection to verify replay buffer
	readBuf := make([]byte, 100)
	n, err := wrapped.Read(readBuf)
	if err != nil {
		t.Fatalf("failed to read from wrapped connection: %v", err)
	}
	if n != len(hello) {
		t.Fatalf("expected to read %d bytes, got %d", len(hello), n)
	}
}

func TestRealityVerifier_Fallback(t *testing.T) {
	authKey := []byte("reality_test_auth_key_32_bytes_!")
	
	// Start a local mock decoy server
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock decoy server: %v", err)
	}
	defer l.Close()

	decoyAddress := l.Addr().String()
	verifier, err := NewRealityVerifier(authKey, decoyAddress)
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	// Flag for decoy access
	decoyReached := make(chan bool, 1)

	go func() {
		conn, err := l.Accept()
		if err == nil {
			decoyReached <- true
			conn.Close()
		}
	}()

	// Construct an invalid ClientHello (bad signature/ticket)
	hello := make([]byte, 100)
	hello[0] = 0x16
	hello[43] = 32 // session ID length

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		_, _ = clientConn.Write(hello)
		_, _ = clientConn.Write([]byte("some data"))
	}()

	wrapped, ok, err := verifier.InterceptAndVerify(serverConn)
	if ok || wrapped != nil {
		t.Fatal("expected verification to fail and return ok=false, wrapped=nil")
	}

	select {
	case <-decoyReached:
		// Succeeded in routing to decoy!
	case <-time.After(2 * time.Second):
		t.Fatal("expected connection to fallback and connect to decoy target")
	}
}

func TestRealityVerifier_VerifyFull(t *testing.T) {
	// 1. Generate Server X25519 private & public keys
	serverPriv := make([]byte, 32)
	_, _ = rand.Read(serverPriv)
	serverPriv[0] &= 248
	serverPriv[31] &= 127
	serverPriv[31] |= 64
	serverPub, _ := curve25519.X25519(serverPriv, curve25519.Basepoint)

	// 2. Generate Client X25519 private & public keys
	clientPriv := make([]byte, 32)
	_, _ = rand.Read(clientPriv)
	clientPriv[0] &= 248
	clientPriv[31] &= 127
	clientPriv[31] |= 64
	clientPub, _ := curve25519.X25519(clientPriv, curve25519.Basepoint)

	// 3. Construct mock TLS 1.3 ClientHello record with X25519 Key Share
	hello := make([]byte, 126)
	hello[0] = 0x16 // Handshake Record
	hello[1] = 0x03 // TLS 1.0 (Record Version)
	hello[2] = 0x03
	// Record length is 121 (126 - 5)
	binary.BigEndian.PutUint16(hello[3:5], 121)

	hello[5] = 0x01 // Handshake Type: ClientHello
	// Handshake length is 117 (126 - 9)
	hello[6] = 0
	binary.BigEndian.PutUint16(hello[7:9], 117)

	hello[9] = 0x03 // Handshake version (TLS 1.2 / 0x0303)
	hello[10] = 0x03

	// Client random bytes at offset 11 (32 bytes)
	for i := 0; i < 32; i++ {
		hello[11+i] = byte(i + 10)
	}
	clientRandom := hello[11:43]

	// Session ID length = 32 at offset 43
	hello[43] = 32
	// Session ID placeholder bytes at offset 44 (ciphertext)

	// Cipher Suites length = 2, value = 0x1301 (TLS_AES_128_GCM_SHA256)
	hello[76] = 0
	hello[77] = 2
	hello[78] = 0x13
	hello[79] = 0x01

	// Compression Methods length = 1, value = 0x00
	hello[80] = 1
	hello[81] = 0

	// Extensions length = 42
	binary.BigEndian.PutUint16(hello[82:84], 42)

	// Extension: Key Share (Type = 51)
	binary.BigEndian.PutUint16(hello[84:86], 51)
	// Ext length = 38
	binary.BigEndian.PutUint16(hello[86:88], 38)
	// Shares length = 36
	binary.BigEndian.PutUint16(hello[88:90], 36)
	// Group X25519 = 29
	binary.BigEndian.PutUint16(hello[90:92], 29)
	// Key length = 32
	binary.BigEndian.PutUint16(hello[92:94], 32)
	// Write client public key bytes
	copy(hello[94:126], clientPub)

	// 4. Derive GCM key on client-side
	sharedSecret, err := curve25519.X25519(clientPriv, serverPub)
	if err != nil {
		t.Fatalf("failed to calculate X25519: %v", err)
	}

	realityKey := make([]byte, 32)
	hkdfReader := hkdf.New(sha256.New, sharedSecret, clientRandom[:20], []byte("REALITY"))
	if _, err := io.ReadFull(hkdfReader, realityKey); err != nil {
		t.Fatalf("failed to derive HKDF key: %v", err)
	}

	block, _ := aes.NewCipher(realityKey)
	aead, _ := cipher.NewGCM(block)

	// Prepare AAD (Session ID field zeroed out)
	aad := make([]byte, len(hello))
	copy(aad, hello)
	for i := 0; i < 32; i++ {
		aad[44+i] = 0
	}

	// Plaintext payload: version (4 bytes), time (4 bytes), short ID (8 bytes)
	plaintext := make([]byte, 16)
	binary.BigEndian.PutUint32(plaintext[0:4], 0x00000001) // Version
	nowSec := uint32(time.Now().Unix())
	binary.BigEndian.PutUint32(plaintext[4:8], nowSec) // Current time
	copy(plaintext[8:16], []byte("short_id"))         // Short ID

	ciphertext := aead.Seal(nil, clientRandom[20:], plaintext, aad)
	copy(hello[44:76], ciphertext)

	// 5. Initialize Server RealityVerifier
	shortIDs := []string{"73686f72745f6964"} // hex of "short_id"
	verifier, err := NewRealityVerifierWithParams(
		[]byte("dummy_auth_key_32_bytes_long_12"),
		"127.0.0.1:8080",
		serverPriv,
		shortIDs,
		5*time.Second,
	)
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		_, _ = clientConn.Write(hello)
	}()

	wrapped, ok, err := verifier.InterceptAndVerify(serverConn)
	if err != nil {
		t.Fatalf("InterceptAndVerify failed: %v", err)
	}

	if !ok {
		t.Fatal("expected full cryptographic verification to succeed, but failed")
	}

	if wrapped == nil {
		t.Fatal("expected wrapped connection but got nil")
	}

	// Verify replay buffer matches
	readBuf := make([]byte, len(hello))
	n, err := io.ReadFull(wrapped, readBuf)
	if err != nil {
		t.Fatalf("failed to read from wrapped connection: %v", err)
	}

	if !bytes.Equal(readBuf[:n], hello) {
		t.Error("replayed handshake bytes do not match original ClientHello")
	}
}
