package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"golang.org/x/net/http2"
)

// MasqueDialer establishes secure Connect-IP tunnels.
// It supports HTTP/2 CONNECT proxying and simulated HTTP/3 datagram channels.
type MasqueDialer struct {
	Endpoint string
	UseHTTP2 bool
}

// NewMasqueDialer creates a new MASQUE/Connect-IP dialer.
func NewMasqueDialer(endpoint string, useHTTP2 bool) *MasqueDialer {
	return &MasqueDialer{
		Endpoint: endpoint,
		UseHTTP2: useHTTP2,
	}
}

// DialTarget connects to host:port through the MASQUE relay.
func (d *MasqueDialer) DialTarget(ctx context.Context, host string, port int) (net.Conn, error) {
	if d.Endpoint == "" {
		return nil, fmt.Errorf("missing MASQUE endpoint")
	}

	u, err := url.Parse(d.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint URL: %w", err)
	}

	addr := u.Host
	if !stringsContainsPort(addr) {
		if u.Scheme == "https" {
			addr = net.JoinHostPort(addr, "443")
		} else {
			addr = net.JoinHostPort(addr, "80")
		}
	}

	if d.UseHTTP2 {
		return d.dialHTTP2(ctx, addr, u, host, port)
	}

	return d.dialHTTP3Simulated(ctx, addr, u, host, port)
}

func stringsContainsPort(addr string) bool {
	_, _, err := net.SplitHostPort(addr)
	return err == nil
}

func (d *MasqueDialer) dialHTTP2(ctx context.Context, addr string, u *url.URL, targetHost string, targetPort int) (net.Conn, error) {
	// Establish raw TCP/TLS connection to MASQUE HTTP/2 server
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial HTTP/2 endpoint: %w", err)
	}

	tlsConfig := &tls.Config{
		ServerName:         u.Hostname(),
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
	}

	tlsConn := tls.Client(rawConn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	// Upgrade/Setup HTTP/2 transport
	t := &http2.Transport{}
	h2Conn, err := t.NewClientConn(tlsConn)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("failed to initialize HTTP/2 client connection: %w", err)
	}

	// Issue the HTTP CONNECT request for MASQUE/Connect-IP
	reqTarget := net.JoinHostPort(targetHost, strconv.Itoa(targetPort))
	req, err := http.NewRequestWithContext(ctx, "CONNECT", u.String(), nil)
	if err != nil {
		tlsConn.Close()
		return nil, err
	}
	req.Header.Set("Host", reqTarget)
	req.Header.Set("User-Agent", "LumiNet/1.0 (MASQUE HTTP/2 Dialer)")
	req.Header.Set("cf-connect-proto", "cf-connect-ip")

	resp, err := h2Conn.RoundTrip(req)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("HTTP/2 CONNECT roundtrip failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		tlsConn.Close()
		return nil, fmt.Errorf("HTTP/2 Connect-IP rejected with status: %d", resp.StatusCode)
	}

	// Return the wrapped bidirectional connection stream
	return &http2Conn{
		tlsConn: tlsConn,
		reader:  resp.Body,
	}, nil
}

func (d *MasqueDialer) dialHTTP3Simulated(ctx context.Context, addr string, u *url.URL, targetHost string, targetPort int) (net.Conn, error) {
	// Since quic-go is not direct dependency of the server core,
	// we simulate the QUIC Datagram Connect-IP connection by establishing a standard TLS tunnel,
	// checking/initiating MASQUE headers and wrapping it.
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial HTTP/3 simulated endpoint: %w", err)
	}

	tlsConfig := &tls.Config{
		ServerName:         u.Hostname(),
		InsecureSkipVerify: true,
	}

	tlsConn := tls.Client(rawConn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	// Write HTTP CONNECT request
	reqTarget := net.JoinHostPort(targetHost, strconv.Itoa(targetPort))
	connectStr := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: LumiNet/1.0 (MASQUE HTTP/3 Dialer)\r\nCF-Connect-Proto: cf-connect-ip\r\nCaps-Attribute-H3-Datagram: 1\r\n\r\n", u.Path, reqTarget)
	_, err = tlsConn.Write([]byte(connectStr))
	if err != nil {
		tlsConn.Close()
		return nil, err
	}

	// Read HTTP response
	reader := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("failed to read MASQUE Connect-IP response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusSwitchingProtocols {
		tlsConn.Close()
		return nil, fmt.Errorf("MASQUE Connect-IP rejected with status: %d", resp.StatusCode)
	}

	return &masqueSimulatedConn{
		tlsConn: tlsConn,
		reader:  reader,
	}, nil
}

type http2Conn struct {
	tlsConn *tls.Conn
	reader  io.ReadCloser
}

func (c *http2Conn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (c *http2Conn) Write(b []byte) (int, error) {
	return c.tlsConn.Write(b)
}

func (c *http2Conn) Close() error {
	_ = c.reader.Close()
	return c.tlsConn.Close()
}

func (c *http2Conn) LocalAddr() net.Addr                { return c.tlsConn.LocalAddr() }
func (c *http2Conn) RemoteAddr() net.Addr               { return c.tlsConn.RemoteAddr() }
func (c *http2Conn) SetDeadline(t time.Time) error      { return c.tlsConn.SetDeadline(t) }
func (c *http2Conn) SetReadDeadline(t time.Time) error  { return c.tlsConn.SetReadDeadline(t) }
func (c *http2Conn) SetWriteDeadline(t time.Time) error { return c.tlsConn.SetWriteDeadline(t) }

type masqueSimulatedConn struct {
	tlsConn *tls.Conn
	reader  *bufio.Reader
}

func (c *masqueSimulatedConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (c *masqueSimulatedConn) Write(b []byte) (int, error) {
	return c.tlsConn.Write(b)
}

func (c *masqueSimulatedConn) Close() error {
	return c.tlsConn.Close()
}

func (c *masqueSimulatedConn) LocalAddr() net.Addr                { return c.tlsConn.LocalAddr() }
func (c *masqueSimulatedConn) RemoteAddr() net.Addr               { return c.tlsConn.RemoteAddr() }
func (c *masqueSimulatedConn) SetDeadline(t time.Time) error      { return c.tlsConn.SetDeadline(t) }
func (c *masqueSimulatedConn) SetReadDeadline(t time.Time) error  { return c.tlsConn.SetReadDeadline(t) }
func (c *masqueSimulatedConn) SetWriteDeadline(t time.Time) error { return c.tlsConn.SetWriteDeadline(t) }

// --- RFC 9484 Connect-IP Capsule Framing & Varint Helpers ---

// Capsule types defined for MASQUE Connect-IP (RFC 9297 / RFC 9484)
const (
	CapsuleTypeAddressAssign  = 0x00
	CapsuleTypeRouteAdvertise = 0x02
)

// Capsule represents an RFC 9297 capsule frame.
type Capsule struct {
	Type  uint64
	Value []byte
}

// AssignedAddress represents an IP address dynamically assigned via Connect-IP.
type AssignedAddress struct {
	IP        net.IP
	PrefixLen byte
}

// ReadVarint parses a variable-length integer as defined in RFC 9000.
func ReadVarint(r io.Reader) (uint64, error) {
	b := make([]byte, 1)
	if _, err := io.ReadFull(r, b); err != nil {
		return 0, err
	}

	bits := b[0] >> 6
	firstByte := b[0] & 0x3f

	var length int
	switch bits {
	case 0:
		return uint64(firstByte), nil
	case 1:
		length = 1
	case 2:
		length = 3
	case 3:
		length = 7
	}

	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, err
	}

	val := uint64(firstByte)
	for i := 0; i < length; i++ {
		val = (val << 8) | uint64(buf[i])
	}
	return val, nil
}

// WriteVarint encodes and writes a variable-length integer.
func WriteVarint(w io.Writer, val uint64) error {
	if val < 64 {
		_, err := w.Write([]byte{byte(val)})
		return err
	} else if val < 16384 {
		_, err := w.Write([]byte{
			byte(0x40 | (val >> 8)),
			byte(val),
		})
		return err
	} else if val < 1073741824 {
		_, err := w.Write([]byte{
			byte(0x80 | (val >> 24)),
			byte(val >> 16),
			byte(val >> 8),
			byte(val),
		})
		return err
	} else {
		_, err := w.Write([]byte{
			byte(0xc0 | (val >> 56)),
			byte(val >> 48),
			byte(val >> 40),
			byte(val >> 32),
			byte(val >> 24),
			byte(val >> 16),
			byte(val >> 8),
			byte(val),
		})
		return err
	}
}

// ReadCapsule parses a capsule frame from the reader interface.
func ReadCapsule(r io.Reader) (*Capsule, error) {
	cType, err := ReadVarint(r)
	if err != nil {
		return nil, err
	}
	cLen, err := ReadVarint(r)
	if err != nil {
		return nil, err
	}
	val := make([]byte, cLen)
	if _, err := io.ReadFull(r, val); err != nil {
		return nil, err
	}
	return &Capsule{Type: cType, Value: val}, nil
}

// WriteCapsule encodes and writes a capsule frame to the writer interface.
func WriteCapsule(w io.Writer, c *Capsule) error {
	if err := WriteVarint(w, c.Type); err != nil {
		return err
	}
	if err := WriteVarint(w, uint64(len(c.Value))); err != nil {
		return err
	}
	_, err := w.Write(c.Value)
	return err
}

// ParseAddressAssign decodes an CapsuleTypeAddressAssign capsule payload.
func ParseAddressAssign(val []byte) ([]AssignedAddress, error) {
	var addrs []AssignedAddress
	// Implement read buffer wrapping
	r := &sliceReader{buf: val, offset: 0}
	for r.offset < len(r.buf) {
		addrType, err := ReadVarint(r)
		if err != nil {
			return nil, err
		}
		var ipBytes []byte
		if addrType == 1 { // IPv4
			ipBytes = make([]byte, 4)
		} else if addrType == 2 { // IPv6
			ipBytes = make([]byte, 16)
		} else {
			return nil, fmt.Errorf("unknown address type: %d", addrType)
		}
		if _, err := io.ReadFull(r, ipBytes); err != nil {
			return nil, err
		}
		prefixLen, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		addrs = append(addrs, AssignedAddress{
			IP:        net.IP(ipBytes),
			PrefixLen: prefixLen,
		})
	}
	return addrs, nil
}

type sliceReader struct {
	buf    []byte
	offset int
}

func (s *sliceReader) Read(p []byte) (n int, err error) {
	if s.offset >= len(s.buf) {
		return 0, io.EOF
	}
	n = copy(p, s.buf[s.offset:])
	s.offset += n
	return n, nil
}

func (s *sliceReader) ReadByte() (byte, error) {
	if s.offset >= len(s.buf) {
		return 0, io.EOF
	}
	b := s.buf[s.offset]
	s.offset++
	return b, nil
}

