package proxy

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// VLESSDialer implements client-side tunneling to VLESS servers.
type VLESSDialer struct {
	Config *ProxyConfig
}

// NewVLESSDialer creates a dialer for VLESS configurations.
func NewVLESSDialer(cfg *ProxyConfig) *VLESSDialer {
	return &VLESSDialer{Config: cfg}
}

// DialTarget dials the VLESS server, executes the handshake, and returns the tunnel connection.
func (vd *VLESSDialer) DialTarget(ctx context.Context, targetHost string, targetPort int) (net.Conn, error) {
	serverAddr := net.JoinHostPort(vd.Config.Address, strconv.Itoa(vd.Config.Port))
	
	var conn net.Conn
	var err error
	
	dialer := net.Dialer{Timeout: 10 * time.Second}
	
	if vd.Config.Transport == "ws" {
		conn, err = vd.dialWebSocket(ctx, targetHost, targetPort)
		if err != nil {
			return nil, err
		}
		return conn, nil
	}

	// Default TCP/TLS dial
	conn, err = dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial VLESS host: %w", err)
	}

	if vd.Config.TLS {
		conn = &jitterConn{Conn: conn, firstWrite: true}

		sni := vd.Config.SNI
		if sni == "" {
			sni = vd.Config.Address
		}
		tlsConfig := &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: vd.Config.SkipCertVerify,
		}
		if len(vd.Config.ALPN) > 0 {
			tlsConfig.NextProtos = vd.Config.ALPN
		}
		
		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS handshake failed: %w", err)
		}
		conn = tlsConn
	}

	// Write VLESS Header
	header, err := vd.buildVLESSHeader(targetHost, targetPort)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if _, err := conn.Write(header); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send VLESS handshake header: %w", err)
	}

	// Read VLESS server response header (1 byte version + 1 byte addons length)
	respHeader := make([]byte, 2)
	if _, err := io.ReadFull(conn, respHeader); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read VLESS response header: %w", err)
	}
	if respHeader[0] != 0 {
		conn.Close()
		return nil, fmt.Errorf("unsupported VLESS response version: %d", respHeader[0])
	}
	addonsLen := int(respHeader[1])
	if addonsLen > 0 {
		addons := make([]byte, addonsLen)
		if _, err := io.ReadFull(conn, addons); err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to read VLESS response addons: %w", err)
		}
	}

	return conn, nil
}

func (vd *VLESSDialer) dialWebSocket(ctx context.Context, targetHost string, targetPort int) (net.Conn, error) {
	scheme := "ws"
	if vd.Config.TLS {
		scheme = "wss"
	}

	hostName := vd.Config.Host
	if hostName == "" {
		hostName = vd.Config.Address
	}

	path := vd.Config.Path
	if path == "" {
		path = "/"
	} else if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	u := url.URL{
		Scheme: scheme,
		Host:   net.JoinHostPort(vd.Config.Address, strconv.Itoa(vd.Config.Port)),
		Path:   path,
	}

	header := make(http.Header)
	header.Set("Host", hostName)
	header.Set("User-Agent", "LumiNet/1.0 (VLESS WS Dialer)")

	dialer := websocket.Dialer{
		HandshakeTimeout: 5 * time.Second,
	}

	if vd.Config.TLS {
		sni := vd.Config.SNI
		if sni == "" {
			sni = vd.Config.Address
		}
		dialer.TLSClientConfig = &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: vd.Config.SkipCertVerify,
		}
		if len(vd.Config.ALPN) > 0 {
			dialer.TLSClientConfig.NextProtos = vd.Config.ALPN
		}
	}

	wsConn, _, err := dialer.DialContext(ctx, u.String(), header)
	if err != nil {
		return nil, fmt.Errorf("VLESS websocket dial failed: %w", err)
	}

	// Build handshake header and write as first binary frame
	vlessHeader, err := vd.buildVLESSHeader(targetHost, targetPort)
	if err != nil {
		wsConn.Close()
		return nil, err
	}

	err = wsConn.WriteMessage(websocket.BinaryMessage, vlessHeader)
	if err != nil {
		wsConn.Close()
		return nil, fmt.Errorf("failed to write VLESS WS header: %w", err)
	}

	return &vlessWSConn{
		Conn: wsConn,
	}, nil
}

func (vd *VLESSDialer) buildVLESSHeader(targetHost string, targetPort int) ([]byte, error) {
	// Remove hyphens and decode hex
	cleanUUID := strings.ReplaceAll(vd.Config.UUID, "-", "")
	uuidBytes, err := hex.DecodeString(cleanUUID)
	if err != nil || len(uuidBytes) != 16 {
		return nil, fmt.Errorf("invalid UUID parameter: %w", err)
	}
	
	var addrType byte
	var addrVal []byte

	if ip := net.ParseIP(targetHost); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			addrType = 1 // IPv4
			addrVal = ip4
		} else {
			addrType = 3 // IPv6
			addrVal = ip
		}
	} else {
		addrType = 2 // Domain name
		addrVal = append([]byte{byte(len(targetHost))}, []byte(targetHost)...)
	}

	// Buffer allocation
	// VLESS Header: Version (1) + UUID (16) + AddonsLength (1) + Command (1, Dial) + Port (2) + AddressType (1) + AddressValue + Payload
	buf := make([]byte, 1+16+1+1+2+1+len(addrVal))
	buf[0] = 0 // VLESS version 0
	copy(buf[1:17], uuidBytes)
	buf[17] = 0 // Addons length: 0
	buf[18] = 1 // Command: 1 (TCP Dial)
	
	binary.BigEndian.PutUint16(buf[19:21], uint16(targetPort))
	buf[21] = addrType
	copy(buf[22:], addrVal)

	return buf, nil
}

type vlessWSConn struct {
	*websocket.Conn
	readBuf []byte
}

func (c *vlessWSConn) Read(b []byte) (int, error) {
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	messageType, msg, err := c.ReadMessage()
	if err != nil {
		return 0, err
	}

	if messageType != websocket.BinaryMessage {
		return 0, fmt.Errorf("unexpected websocket message type: %d", messageType)
	}

	// First server response frame contains VLESS Version (1) + Addons Length (1), total 2 bytes
	if len(msg) >= 2 && msg[0] == 0 {
		// Strip the VLESS server validation header (2 bytes)
		addonsLen := msg[1]
		headerLen := 2 + int(addonsLen)
		if len(msg) > headerLen {
			msg = msg[headerLen:]
		} else {
			// recursively call read again
			return c.Read(b)
		}
	}

	n := copy(b, msg)
	if n < len(msg) {
		c.readBuf = msg[n:]
	}
	return n, nil
}

func (c *vlessWSConn) Write(b []byte) (int, error) {
	err := c.WriteMessage(websocket.BinaryMessage, b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *vlessWSConn) LocalAddr() net.Addr { return nil }
func (c *vlessWSConn) RemoteAddr() net.Addr { return nil }
func (c *vlessWSConn) SetDeadline(t time.Time) error { return nil }
func (c *vlessWSConn) SetReadDeadline(t time.Time) error { return c.Conn.SetReadDeadline(t) }
func (c *vlessWSConn) SetWriteDeadline(t time.Time) error { return c.Conn.SetWriteDeadline(t) }

type jitterConn struct {
	net.Conn
	firstWrite bool
}

func (jc *jitterConn) Write(b []byte) (int, error) {
	if jc.firstWrite {
		jc.firstWrite = false

		// Check if it's a TLS ClientHello (starts with 0x16 0x03 0x01 or similar)
		if len(b) > 5 && b[0] == 0x16 && b[1] == 0x03 {
			// Disable Nagle's algorithm (TCP_NODELAY)
			if tcpConn, ok := jc.Conn.(*net.TCPConn); ok {
				_ = tcpConn.SetNoDelay(true)
			}

			// Write in 10 to 47 random chunks
			totalChunks := 10 + mrand.Intn(38)
			offset := 0
			chunkLen := len(b) / totalChunks
			if chunkLen < 1 {
				chunkLen = 1
			}

			for i := 0; i < totalChunks && offset < len(b); i++ {
				end := offset + chunkLen
				if i == totalChunks-1 || end > len(b) {
					end = len(b)
				}

				_, err := jc.Conn.Write(b[offset:end])
				if err != nil {
					return offset, err
				}

				offset = end

				// sleep 1ms to 10ms
				sleepMs := 1.0 + mrand.Float64()*9.0
				time.Sleep(time.Duration(sleepMs * float64(time.Millisecond)))
			}
			return len(b), nil
		}
	}
	return jc.Conn.Write(b)
}

