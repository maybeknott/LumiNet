package proxy

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// EdgeDialer establishes TCP connections by proxying over an Edge Worker via VLESS, Trojan, or SOCKS5.
type EdgeDialer struct {
	Config *ProxyConfig
}

// NewEdgeDialer creates a new dialer for Edge Worker relays.
func NewEdgeDialer(cfg *ProxyConfig) *EdgeDialer {
	return &EdgeDialer{Config: cfg}
}

// DialTarget dials the Edge Worker, executes the selected protocol handshake, and returns the connection.
func (ed *EdgeDialer) DialTarget(ctx context.Context, targetHost string, targetPort int) (net.Conn, error) {
	if ed.Config.Transport == "ws" {
		return ed.dialWebSocket(ctx, targetHost, targetPort)
	}

	// Direct TCP/TLS dial
	serverAddr := net.JoinHostPort(ed.Config.Address, strconv.Itoa(ed.Config.Port))
	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial edge server: %w", err)
	}

	if ed.Config.TLS {
		sni := ed.Config.SNI
		if sni == "" {
			sni = ed.Config.Address
		}
		tlsConfig := &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: ed.Config.SkipCertVerify,
		}
		if len(ed.Config.ALPN) > 0 {
			tlsConfig.NextProtos = ed.Config.ALPN
		}
		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS handshake failed: %w", err)
		}
		conn = tlsConn
	}

	// Perform handshake based on the configured protocol
	switch ed.Config.Protocol {
	case ProtocolVLESS:
		header, err := ed.buildVLESSHeader(targetHost, targetPort)
		if err != nil {
			conn.Close()
			return nil, err
		}
		if _, err := conn.Write(header); err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to write VLESS header: %w", err)
		}
		// Read response
		respHeader := make([]byte, 2)
		if _, err := io.ReadFull(conn, respHeader); err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to read VLESS response: %w", err)
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
				return nil, fmt.Errorf("failed to read VLESS addons: %w", err)
			}
		}

	case ProtocolTrojan:
		header, err := ed.buildTrojanHeader(targetHost, targetPort)
		if err != nil {
			conn.Close()
			return nil, err
		}
		if _, err := conn.Write(header); err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to write Trojan header: %w", err)
		}

	case ProtocolSOCKS5:
		if err := ed.handshakeSOCKS5(conn, targetHost, targetPort); err != nil {
			conn.Close()
			return nil, fmt.Errorf("SOCKS5 handshake failed: %w", err)
		}

	default:
		conn.Close()
		return nil, fmt.Errorf("unsupported protocol for edge dialer: %s", ed.Config.Protocol)
	}

	return conn, nil
}

func (ed *EdgeDialer) dialWebSocket(ctx context.Context, targetHost string, targetPort int) (net.Conn, error) {
	scheme := "ws"
	if ed.Config.TLS {
		scheme = "wss"
	}

	hostName := ed.Config.Host
	if hostName == "" {
		hostName = ed.Config.Address
	}

	path := ed.Config.Path
	if path == "" {
		path = "/"
	} else if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	u := url.URL{
		Scheme: scheme,
		Host:   net.JoinHostPort(ed.Config.Address, strconv.Itoa(ed.Config.Port)),
		Path:   path,
	}

	header := make(http.Header)
	header.Set("Host", hostName)
	header.Set("User-Agent", "LumiNet/1.0 (Edge WS Dialer)")

	dialer := websocket.Dialer{
		HandshakeTimeout: 5 * time.Second,
	}

	if ed.Config.TLS {
		sni := ed.Config.SNI
		if sni == "" {
			sni = ed.Config.Address
		}
		dialer.TLSClientConfig = &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: ed.Config.SkipCertVerify,
		}
		if len(ed.Config.ALPN) > 0 {
			dialer.TLSClientConfig.NextProtos = ed.Config.ALPN
		}
	}

	wsConn, _, err := dialer.DialContext(ctx, u.String(), header)
	if err != nil {
		return nil, fmt.Errorf("edge websocket dial failed: %w", err)
	}

	// Build handshake header and write as first binary frame
	var handshakeBytes []byte
	isVLESS := false

	switch ed.Config.Protocol {
	case ProtocolVLESS:
		isVLESS = true
		handshakeBytes, err = ed.buildVLESSHeader(targetHost, targetPort)
	case ProtocolTrojan:
		handshakeBytes, err = ed.buildTrojanHeader(targetHost, targetPort)
	case ProtocolSOCKS5:
		// SOCKS5 over WebSocket requires initial handshake sequence over WS frames.
		// Wrap first and execute standard handshake
		wrappedConn := &edgeWSConn{Conn: wsConn}
		if err := ed.handshakeSOCKS5(wrappedConn, targetHost, targetPort); err != nil {
			wsConn.Close()
			return nil, fmt.Errorf("SOCKS5 WS handshake failed: %w", err)
		}
		return wrappedConn, nil
	default:
		wsConn.Close()
		return nil, fmt.Errorf("unsupported protocol for edge WS dialer: %s", ed.Config.Protocol)
	}

	if err != nil {
		wsConn.Close()
		return nil, err
	}

	if err := wsConn.WriteMessage(websocket.BinaryMessage, handshakeBytes); err != nil {
		wsConn.Close()
		return nil, fmt.Errorf("failed to write WS handshake header: %w", err)
	}

	return &edgeWSConn{
		Conn:    wsConn,
		isVLESS: isVLESS,
	}, nil
}

func (ed *EdgeDialer) buildVLESSHeader(targetHost string, targetPort int) ([]byte, error) {
	cleanUUID := strings.ReplaceAll(ed.Config.UUID, "-", "")
	uuidBytes, err := hex.DecodeString(cleanUUID)
	if err != nil || len(uuidBytes) != 16 {
		return nil, fmt.Errorf("invalid VLESS UUID: %w", err)
	}

	var addrType byte
	var addrVal []byte
	if ip := net.ParseIP(targetHost); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			addrType = 1
			addrVal = ip4
		} else {
			addrType = 3
			addrVal = ip
		}
	} else {
		addrType = 2
		addrVal = append([]byte{byte(len(targetHost))}, []byte(targetHost)...)
	}

	buf := make([]byte, 1+16+1+1+2+1+len(addrVal))
	buf[0] = 0 // version 0
	copy(buf[1:17], uuidBytes)
	buf[17] = 0 // addons len
	buf[18] = 1 // command: connect
	binary.BigEndian.PutUint16(buf[19:21], uint16(targetPort))
	buf[21] = addrType
	copy(buf[22:], addrVal)

	return buf, nil
}

func (ed *EdgeDialer) buildTrojanHeader(targetHost string, targetPort int) ([]byte, error) {
	// hash password using sha224
	h := sha256.New224()
	h.Write([]byte(ed.Config.Password))
	hexPass := hex.EncodeToString(h.Sum(nil))

	var addrType byte
	var addrVal []byte
	if ip := net.ParseIP(targetHost); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			addrType = 1
			addrVal = ip4
		} else {
			addrType = 4
			addrVal = ip
		}
	} else {
		addrType = 3
		addrVal = append([]byte{byte(len(targetHost))}, []byte(targetHost)...)
	}

	buf := make([]byte, 56+2+1+1+len(addrVal)+2+2)
	copy(buf[0:56], []byte(hexPass))
	buf[56] = '\r'
	buf[57] = '\n'
	buf[58] = 1 // command: connect
	buf[59] = addrType
	copy(buf[60:], addrVal)

	portOffset := 60 + len(addrVal)
	binary.BigEndian.PutUint16(buf[portOffset:portOffset+2], uint16(targetPort))
	buf[portOffset+2] = '\r'
	buf[portOffset+3] = '\n'

	return buf, nil
}

func (ed *EdgeDialer) handshakeSOCKS5(conn net.Conn, targetHost string, targetPort int) error {
	// Greeting
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return fmt.Errorf("write socks5 greeting: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("read socks5 greeting response: %w", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		return fmt.Errorf("unsupported socks5 auth: version %d, method %d", resp[0], resp[1])
	}

	// Request
	var addrType byte
	var addrVal []byte
	if ip := net.ParseIP(targetHost); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			addrType = 1
			addrVal = ip4
		} else {
			addrType = 4
			addrVal = ip
		}
	} else {
		addrType = 3
		addrVal = append([]byte{byte(len(targetHost))}, []byte(targetHost)...)
	}

	req := make([]byte, 4+len(addrVal)+2)
	req[0] = 0x05
	req[1] = 0x01
	req[2] = 0x00
	req[3] = addrType
	copy(req[4:], addrVal)

	portOffset := 4 + len(addrVal)
	binary.BigEndian.PutUint16(req[portOffset:portOffset+2], uint16(targetPort))

	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("write socks5 request: %w", err)
	}

	// Reply
	repHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, repHeader); err != nil {
		return fmt.Errorf("read socks5 reply header: %w", err)
	}
	if repHeader[0] != 0x05 {
		return fmt.Errorf("invalid socks5 version in reply: %d", repHeader[0])
	}
	if repHeader[1] != 0x00 {
		return fmt.Errorf("socks5 connection failed: %d", repHeader[1])
	}

	var repAddrLen int
	switch repHeader[3] {
	case 1:
		repAddrLen = 4
	case 3:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenByte); err != nil {
			return fmt.Errorf("read domain length: %w", err)
		}
		repAddrLen = int(lenByte[0])
	case 4:
		repAddrLen = 16
	default:
		return fmt.Errorf("unknown address type in socks5 reply: %d", repHeader[3])
	}

	discardBuf := make([]byte, repAddrLen+2)
	if _, err := io.ReadFull(conn, discardBuf); err != nil {
		return fmt.Errorf("read socks5 reply address/port: %w", err)
	}

	return nil
}

type edgeWSConn struct {
	*websocket.Conn
	readBuf             []byte
	isVLESS             bool
	vlessHeaderStripped bool
}

func (c *edgeWSConn) Read(b []byte) (int, error) {
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

	if c.isVLESS && !c.vlessHeaderStripped {
		c.vlessHeaderStripped = true
		if len(msg) >= 2 && msg[0] == 0 {
			addonsLen := msg[1]
			headerLen := 2 + int(addonsLen)
			if len(msg) > headerLen {
				msg = msg[headerLen:]
			} else {
				return c.Read(b)
			}
		}
	}

	n := copy(b, msg)
	if n < len(msg) {
		c.readBuf = msg[n:]
	}
	return n, nil
}

func (c *edgeWSConn) Write(b []byte) (int, error) {
	err := c.WriteMessage(websocket.BinaryMessage, b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *edgeWSConn) LocalAddr() net.Addr                { return nil }
func (c *edgeWSConn) RemoteAddr() net.Addr               { return nil }
func (c *edgeWSConn) SetDeadline(t time.Time) error      { return nil }
func (c *edgeWSConn) SetReadDeadline(t time.Time) error  { return c.Conn.SetReadDeadline(t) }
func (c *edgeWSConn) SetWriteDeadline(t time.Time) error { return c.Conn.SetWriteDeadline(t) }
