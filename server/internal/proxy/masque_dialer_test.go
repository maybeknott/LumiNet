package proxy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"LumiNet Testing"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, nil
}

func TestMasqueDialerSimulated(t *testing.T) {
	// Generate self-signed cert for mock TLS server
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("failed to generate self-signed cert: %v", err)
	}

	config := &tls.Config{Certificates: []tls.Certificate{cert}}

	// Start a mock MASQUE TLS server
	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock server: %v", err)
	}
	defer rawListener.Close()

	l := tls.NewListener(rawListener, config)
	defer l.Close()

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read request
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)

		// Respond with HTTP 200 OK
		resp := "HTTP/1.1 200 OK\r\nConnection: Keep-Alive\r\n\r\n"
		_, _ = conn.Write([]byte(resp))

		// Loop/echo traffic
		_, _ = conn.Write([]byte("hello from masque"))
	}()

	dialer := NewMasqueDialer(fmt.Sprintf("https://%s/tunnel", l.Addr().String()), false)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := dialer.DialTarget(ctx, "target.example.com", 443)
	if err != nil {
		t.Fatalf("failed to dial target via MASQUE: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 100)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read from MASQUE connection: %v", err)
	}

	res := string(buf[:n])
	if res != "hello from masque" {
		t.Errorf("expected 'hello from masque', got '%s'", res)
	}
}

func TestVarintEncoding(t *testing.T) {
	testCases := []uint64{0, 37, 63, 64, 16383, 16384, 1073741823, 1073741824, 4611686018427387903}
	for _, tc := range testCases {
		buf := &sliceReader{buf: make([]byte, 16), offset: 0}
		// Write
		w := &sliceWriter{buf: buf.buf, offset: 0}
		err := WriteVarint(w, tc)
		if err != nil {
			t.Fatalf("failed to write varint for %d: %v", tc, err)
		}
		// Read
		buf.buf = w.buf[:w.offset]
		buf.offset = 0
		val, err := ReadVarint(buf)
		if err != nil {
			t.Fatalf("failed to read varint for %d: %v", tc, err)
		}
		if val != tc {
			t.Errorf("expected %d, got %d", tc, val)
		}
	}
}

func TestCapsuleFraming(t *testing.T) {
	originalCapsule := &Capsule{
		Type:  CapsuleTypeAddressAssign,
		Value: []byte{0x01, 0xc0, 0xa8, 0x01, 0x01, 0x18}, // Assigned address: IPv4 192.168.1.1/24
	}

	buf := &sliceReader{buf: make([]byte, 100), offset: 0}
	w := &sliceWriter{buf: buf.buf, offset: 0}

	err := WriteCapsule(w, originalCapsule)
	if err != nil {
		t.Fatalf("failed to write capsule: %v", err)
	}

	buf.buf = w.buf[:w.offset]
	buf.offset = 0

	decoded, err := ReadCapsule(buf)
	if err != nil {
		t.Fatalf("failed to read capsule: %v", err)
	}

	if decoded.Type != originalCapsule.Type {
		t.Errorf("expected type %d, got %d", originalCapsule.Type, decoded.Type)
	}

	addrs, err := ParseAddressAssign(decoded.Value)
	if err != nil {
		t.Fatalf("failed to parse AddressAssign capsule payload: %v", err)
	}

	if len(addrs) != 1 {
		t.Fatalf("expected 1 address, got %d", len(addrs))
	}

	ip := addrs[0].IP
	if !ip.Equal(net.IPv4(192, 168, 1, 1)) {
		t.Errorf("expected IP 192.168.1.1, got %v", ip)
	}
	if addrs[0].PrefixLen != 24 {
		t.Errorf("expected prefix 24, got %d", addrs[0].PrefixLen)
	}
}

type sliceWriter struct {
	buf    []byte
	offset int
}

func (s *sliceWriter) Write(p []byte) (n int, err error) {
	if s.offset+len(p) > len(s.buf) {
		return 0, io.ErrShortWrite
	}
	n = copy(s.buf[s.offset:], p)
	s.offset += n
	return n, nil
}

