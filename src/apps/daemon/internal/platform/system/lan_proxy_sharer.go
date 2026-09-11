package system

import (
	"bufio"
	"encoding/base64"

	"github.com/maybeknott/luminet/internal/foundation/boundedio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// maxLanHTTPLineBytes bounds a single HTTP request/header line read from a LAN
// peer. Longer lines are rejected so a peer that never terminates a line
// cannot grow the reader without bound.
const maxLanHTTPLineBytes = 16 << 10

// LanSettings specifies parameters for sharing proxy access on local network.
type LanSettings struct {
	Enabled  bool   `json:"enabled"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// LanStatus reports the runtime status of the LAN sharing listener.
type LanStatus struct {
	Running bool   `json:"running"`
	Address string `json:"address"`
	Open    bool   `json:"open"`
}

// LanProxySharer provides a dual HTTP & SOCKS5 listener on a single port for LAN devices.
type LanProxySharer struct {
	mu          sync.RWMutex
	listener    net.Listener
	port        int
	carrierAddr string
	settings    LanSettings
	stopChan    chan struct{}
	running     bool
}

func NewLanProxySharer() *LanProxySharer {
	return &LanProxySharer{}
}

func (s *LanProxySharer) Start(carrierAddr string, settings LanSettings) (LanStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		s.stopLocked()
	}

	addr := fmt.Sprintf("0.0.0.0:%d", settings.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return LanStatus{Running: false}, fmt.Errorf("cannot bind LAN share listener on %s: %w", addr, err)
	}

	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		listener.Close()
		return LanStatus{Running: false}, errors.New("failed to get TCP listener address")
	}

	s.listener = listener
	s.port = tcpAddr.Port
	s.carrierAddr = carrierAddr
	s.settings = settings
	s.stopChan = make(chan struct{})
	s.running = true

	isOpen := strings.TrimSpace(settings.Username) == "" || strings.TrimSpace(settings.Password) == ""

	go s.acceptLoop(listener, s.stopChan)

	return LanStatus{
		Running: true,
		Address: fmt.Sprintf("%s:%d", getOutboundIP(), s.port),
		Open:    isOpen,
	}, nil
}

func (s *LanProxySharer) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopLocked()
}

func (s *LanProxySharer) stopLocked() {
	if !s.running {
		return
	}
	s.running = false
	close(s.stopChan)
	if s.listener != nil {
		s.listener.Close()
		s.listener = nil
	}
}

func (s *LanProxySharer) Retarget(carrierAddr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.carrierAddr = carrierAddr
}

func (s *LanProxySharer) Status() LanStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.running {
		return LanStatus{Running: false}
	}
	isOpen := strings.TrimSpace(s.settings.Username) == "" || strings.TrimSpace(s.settings.Password) == ""
	return LanStatus{
		Running: true,
		Address: fmt.Sprintf("%s:%d", getOutboundIP(), s.port),
		Open:    isOpen,
	}
}

func (s *LanProxySharer) acceptLoop(l net.Listener, stopChan chan struct{}) {
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

		go s.handleConnection(conn)
	}
}

func (s *LanProxySharer) handleConnection(client net.Conn) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(30 * time.Second))

	var firstByte [1]byte
	if _, err := io.ReadFull(client, firstByte[:]); err != nil {
		return
	}

	s.mu.RLock()
	carrier := s.carrierAddr
	settings := s.settings
	s.mu.RUnlock()

	hasAuth := strings.TrimSpace(settings.Username) != "" && strings.TrimSpace(settings.Password) != ""

	if firstByte[0] == 0x05 {
		// SOCKS5 protocol
		s.handleSocks5(client, carrier, settings, hasAuth)
	} else {
		// HTTP proxy protocol
		s.handleHTTP(client, carrier, settings, hasAuth, firstByte[0])
	}
}

func (s *LanProxySharer) handleSocks5(client net.Conn, carrier string, settings LanSettings, hasAuth bool) {
	var count [1]byte
	if _, err := io.ReadFull(client, count[:]); err != nil {
		return
	}
	methods := make([]byte, count[0])
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}

	wanted := byte(0x00) // NO_AUTH
	if hasAuth {
		wanted = 0x02 // USER_PASS
	}

	matched := false
	for _, m := range methods {
		if m == wanted {
			matched = true
			break
		}
	}

	if !matched {
		_, _ = client.Write([]byte{0x05, 0xFF}) // NO_ACCEPTABLE
		return
	}

	if _, err := client.Write([]byte{0x05, wanted}); err != nil {
		return
	}

	if hasAuth {
		if !s.socks5Auth(client, settings.Username, settings.Password) {
			return
		}
	}

	var head [4]byte
	if _, err := io.ReadFull(client, head[:]); err != nil {
		return
	}

	if head[1] != 0x01 { // Only CONNECT supported
		_, _ = client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var targetHost string
	switch head[3] {
	case 0x01: // IPv4
		var ip [4]byte
		if _, err := io.ReadFull(client, ip[:]); err != nil {
			return
		}
		targetHost = net.IP(ip[:]).String()
	case 0x03: // Domain
		var length [1]byte
		if _, err := io.ReadFull(client, length[:]); err != nil {
			return
		}
		domainBytes := make([]byte, length[0])
		if _, err := io.ReadFull(client, domainBytes); err != nil {
			return
		}
		targetHost = string(domainBytes)
	case 0x04: // IPv6
		var ip [16]byte
		if _, err := io.ReadFull(client, ip[:]); err != nil {
			return
		}
		targetHost = net.IP(ip[:]).String()
	default:
		_, _ = client.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var portBytes [2]byte
	if _, err := io.ReadFull(client, portBytes[:]); err != nil {
		return
	}
	targetPort := binary.BigEndian.Uint16(portBytes[:])

	upstream, err := net.DialTimeout("tcp", carrier, 10*time.Second)
	if err != nil {
		_, _ = client.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer upstream.Close()

	// Negotiate with upstream SOCKS5 carrier
	if err := socks5UpstreamConnect(upstream, targetHost, targetPort); err != nil {
		_, _ = client.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// SOCKS5 success reply
	if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	_ = client.SetDeadline(time.Time{})
	_ = upstream.SetDeadline(time.Time{})
	splice(client, upstream)
}

func (s *LanProxySharer) socks5Auth(client net.Conn, user, pass string) bool {
	var ver [1]byte
	if _, err := io.ReadFull(client, ver[:]); err != nil || ver[0] != 0x01 {
		_, _ = client.Write([]byte{0x01, 0x01})
		return false
	}
	var ulen [1]byte
	if _, err := io.ReadFull(client, ulen[:]); err != nil {
		return false
	}
	offeredUser := make([]byte, ulen[0])
	if _, err := io.ReadFull(client, offeredUser); err != nil {
		return false
	}
	var plen [1]byte
	if _, err := io.ReadFull(client, plen[:]); err != nil {
		return false
	}
	offeredPass := make([]byte, plen[0])
	if _, err := io.ReadFull(client, offeredPass); err != nil {
		return false
	}

	ok := string(offeredUser) == user && string(offeredPass) == pass
	if ok {
		_, _ = client.Write([]byte{0x01, 0x00})
	} else {
		_, _ = client.Write([]byte{0x01, 0x01})
	}
	return ok
}

func (s *LanProxySharer) handleHTTP(client net.Conn, carrier string, settings LanSettings, hasAuth bool, firstByte byte) {
	reader := bufio.NewReader(io.MultiReader(strings.NewReader(string(firstByte)), client))
	reqLine, err := boundedio.ReadLine(reader, maxLanHTTPLineBytes)
	if err != nil {
		if errors.Is(err, boundedio.ErrLineTooLong) {
			_, _ = client.Write([]byte("HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\n\r\n"))
		}
		return
	}
	parts := strings.Fields(reqLine)
	if len(parts) < 2 {
		_, _ = client.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
		return
	}
	method := parts[0]
	target := parts[1]

	var headers []string
	authOk := !hasAuth
	expectedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(settings.Username+":"+settings.Password))

	for {
		line, err := boundedio.ReadLine(reader, maxLanHTTPLineBytes)
		if errors.Is(err, boundedio.ErrLineTooLong) {
			_, _ = client.Write([]byte("HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\n\r\n"))
			return
		}
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
		if hasAuth && strings.HasPrefix(strings.ToLower(line), "proxy-authorization:") {
			val := strings.TrimSpace(line[len("proxy-authorization:"):])
			if val == expectedAuth {
				authOk = true
			}
		}
		headers = append(headers, line)
	}

	if !authOk {
		_, _ = client.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"LumiNet\"\r\nContent-Length: 0\r\n\r\n"))
		return
	}

	if strings.EqualFold(method, "CONNECT") {
		hostPort := target
		if !strings.Contains(hostPort, ":") {
			hostPort += ":443"
		}
		host, portStr, err := net.SplitHostPort(hostPort)
		if err != nil {
			_, _ = client.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
			return
		}
		port := 443
		fmt.Sscanf(portStr, "%d", &port)

		upstream, err := net.DialTimeout("tcp", carrier, 10*time.Second)
		if err != nil {
			_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
			return
		}
		defer upstream.Close()

		if err := socks5UpstreamConnect(upstream, host, uint16(port)); err != nil {
			_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
			return
		}

		if _, err := client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
			return
		}
		_ = client.SetDeadline(time.Time{})
		_ = upstream.SetDeadline(time.Time{})
		splice(client, upstream)
		return
	}

	// Normal HTTP request: rewrite target URI to path
	host, port, path := parseAbsoluteURI(target)
	if host == "" {
		_, _ = client.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
		return
	}

	upstream, err := net.DialTimeout("tcp", carrier, 10*time.Second)
	if err != nil {
		_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
		return
	}
	defer upstream.Close()

	if err := socks5UpstreamConnect(upstream, host, port); err != nil {
		_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
		return
	}

	// Write origin request line and headers
	originReq := fmt.Sprintf("%s %s HTTP/1.1\r\n", method, path)
	_, _ = upstream.Write([]byte(originReq))
	for _, h := range headers {
		lowered := strings.ToLower(h)
		if strings.HasPrefix(lowered, "proxy-connection:") || strings.HasPrefix(lowered, "proxy-authorization:") {
			continue
		}
		_, _ = upstream.Write([]byte(h))
	}
	_, _ = upstream.Write([]byte("\r\n"))

	_ = client.SetDeadline(time.Time{})
	_ = upstream.SetDeadline(time.Time{})
	splice(client, upstream)
}

func parseAbsoluteURI(raw string) (host string, port uint16, path string) {
	trimmed := raw
	if strings.HasPrefix(strings.ToLower(trimmed), "http://") {
		trimmed = trimmed[7:]
	}
	slashIdx := strings.Index(trimmed, "/")
	authority := trimmed
	path = "/"
	if slashIdx != -1 {
		authority = trimmed[:slashIdx]
		path = trimmed[slashIdx:]
	}

	port = 80
	if strings.Contains(authority, ":") {
		h, p, err := net.SplitHostPort(authority)
		if err == nil {
			host = h
			var parsedPort int
			fmt.Sscanf(p, "%d", &parsedPort)
			if parsedPort > 0 && parsedPort <= 65535 {
				port = uint16(parsedPort)
			}
			return
		}
	}
	host = authority
	return
}

func socks5UpstreamConnect(conn net.Conn, targetHost string, targetPort uint16) error {
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	// Greeting: NO_AUTH
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil || resp[0] != 0x05 || resp[1] != 0x00 {
		return errors.New("upstream socks5 rejected no-auth")
	}

	// CONNECT
	buf := []byte{0x05, 0x01, 0x00, 0x03, byte(len(targetHost))}
	buf = append(buf, []byte(targetHost)...)
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], targetPort)
	buf = append(buf, p[:]...)

	if _, err := conn.Write(buf); err != nil {
		return err
	}

	var rep [4]byte
	if _, err := io.ReadFull(conn, rep[:]); err != nil || rep[1] != 0x00 {
		return errors.New("upstream socks5 connect failed")
	}

	// Discard bound addr
	switch rep[3] {
	case 0x01:
		var b [4 + 2]byte
		_, _ = io.ReadFull(conn, b[:])
	case 0x03:
		var l [1]byte
		_, _ = io.ReadFull(conn, l[:])
		b := make([]byte, int(l[0])+2)
		_, _ = io.ReadFull(conn, b)
	case 0x04:
		var b [16 + 2]byte
		_, _ = io.ReadFull(conn, b[:])
	}

	return nil
}

func splice(c1, c2 net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(c1, c2)
		if tc, ok := c1.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(c2, c1)
		if tc, ok := c2.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	wg.Wait()
}

func getOutboundIP() string {
	conn, err := net.Dial("udp", "1.1.1.1:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}
