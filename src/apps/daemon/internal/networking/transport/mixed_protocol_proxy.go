package transport

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"github.com/maybeknott/luminet/internal/foundation/boundedio"
)

// Protocol kind constants.
type ProxyProtocolKind int

const (
	ProtoHTTP ProxyProtocolKind = iota
	ProtoSOCKS4
	ProtoSOCKS5
)

func (k ProxyProtocolKind) String() string {
	switch k {
	case ProtoSOCKS5:
		return "SOCKS5"
	case ProtoSOCKS4:
		return "SOCKS4"
	default:
		return "HTTP"
	}
}

// DetectProxyProtocol classifies protocol from the opening byte.
func DetectProxyProtocol(firstByte byte) ProxyProtocolKind {
	switch firstByte {
	case 0x05:
		return ProtoSOCKS5
	case 0x04:
		return ProtoSOCKS4
	default:
		return ProtoHTTP
	}
}

// ---------------------------------------------------------------------------
// SOCKS4 / SOCKS4a Framing & Handshake
// ---------------------------------------------------------------------------

const (
	Socks4Version    byte = 0x04
	Socks4CmdConnect byte = 0x01
	Socks4CmdBind    byte = 0x02

	Socks4Granted     byte = 0x5a
	Socks4Rejected    byte = 0x5b
	Socks4NoIdentd    byte = 0x5c
	Socks4InvalidUser byte = 0x5d
)

// Socks4Request encapsulates a SOCKS4 or SOCKS4a connection request.
type Socks4Request struct {
	Command byte
	Port    int
	IP      net.IP
	UserID  string
	Domain  string
}

func (r *Socks4Request) TargetHost() string {
	if r.Domain != "" {
		return r.Domain
	}
	return r.IP.String()
}

func (r *Socks4Request) IsSocks4a() bool {
	ip4 := r.IP.To4()
	if ip4 == nil {
		return false
	}
	return ip4[0] == 0 && ip4[1] == 0 && ip4[2] == 0 && ip4[3] != 0
}

// ParseSocks4Request parses SOCKS4/4a request frame from reader.
func ParseSocks4Request(r io.Reader) (*Socks4Request, error) {
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	if hdr[0] != Socks4Version {
		return nil, fmt.Errorf("socks4: unsupported version 0x%02x", hdr[0])
	}

	command := hdr[1]
	port := int(binary.BigEndian.Uint16(hdr[2:4]))
	ip := net.IPv4(hdr[4], hdr[5], hdr[6], hdr[7])

	// Read null-terminated UserID
	br := bufio.NewReader(r)
	userBytes, err := br.ReadBytes(0x00)
	if err != nil {
		return nil, err
	}
	userID := string(userBytes[:len(userBytes)-1])

	req := &Socks4Request{
		Command: command,
		Port:    port,
		IP:      ip,
		UserID:  userID,
	}

	// SOCKS4a domain extension: 0.0.0.x with x != 0
	if req.IsSocks4a() {
		domainBytes, err := br.ReadBytes(0x00)
		if err != nil {
			return nil, err
		}
		req.Domain = string(domainBytes[:len(domainBytes)-1])
	}

	return req, nil
}

// BuildSocks4Reply builds 8-byte response frame: [0x00, STATUS, PORT(2B), IP(4B)].
func BuildSocks4Reply(status byte, bndPort int, bndIP net.IP) []byte {
	resp := make([]byte, 8)
	resp[0] = 0x00
	resp[1] = status
	binary.BigEndian.PutUint16(resp[2:4], uint16(bndPort))
	ip4 := bndIP.To4()
	if ip4 != nil {
		copy(resp[4:8], ip4)
	}
	return resp
}

// ---------------------------------------------------------------------------
// SOCKS5 Framing & Handshake
// ---------------------------------------------------------------------------

const (
	Socks5Version           byte = 0x05
	Socks5AuthNone          byte = 0x00
	Socks5AuthNoAcceptable  byte = 0xff

	Socks5CmdConnect      byte = 0x01
	Socks5CmdBind         byte = 0x02
	Socks5CmdUDPAssociate byte = 0x03

	Socks5AtypIPv4   byte = 0x01
	Socks5AtypDomain byte = 0x03
	Socks5AtypIPv6   byte = 0x04

	Socks5RepSuccess              byte = 0x00
	Socks5RepGeneralFailure       byte = 0x01
	Socks5RepConnectionNotAllowed byte = 0x02
	Socks5RepNetworkUnreachable   byte = 0x03
	Socks5RepHostUnreachable      byte = 0x04
	Socks5RepConnectionRefused    byte = 0x05
	Socks5RepTTLExpired           byte = 0x06
	Socks5RepCmdNotSupported      byte = 0x07
	Socks5RepAddrNotSupported     byte = 0x08
)

// Socks5Greeting holds methods offered by the client.
type Socks5Greeting struct {
	Methods []byte
}

// ParseSocks5Greeting parses initial method negotiation frame.
func ParseSocks5Greeting(r io.Reader) (*Socks5Greeting, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	if hdr[0] != Socks5Version {
		return nil, fmt.Errorf("socks5: unsupported version 0x%02x", hdr[0])
	}
	nmethods := int(hdr[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(r, methods); err != nil {
		return nil, err
	}
	return &Socks5Greeting{Methods: methods}, nil
}

// BuildSocks5GreetingReply creates greeting response: [0x05, METHOD].
func BuildSocks5GreetingReply(method byte) []byte {
	return []byte{Socks5Version, method}
}

// Socks5Request encapsulates a SOCKS5 command frame.
type Socks5Request struct {
	Command     byte
	TargetHost  string
	TargetPort  int
	AddressType byte
}

// ParseSocks5Request parses command request: [0x05, CMD, 0x00, ATYP, ADDR, PORT(2B)].
func ParseSocks5Request(r io.Reader) (*Socks5Request, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	if hdr[0] != Socks5Version {
		return nil, fmt.Errorf("socks5: invalid version 0x%02x", hdr[0])
	}
	command := hdr[1]
	atyp := hdr[3]

	var targetHost string
	switch atyp {
	case Socks5AtypIPv4:
		ipBuf := make([]byte, 4)
		if _, err := io.ReadFull(r, ipBuf); err != nil {
			return nil, err
		}
		targetHost = net.IP(ipBuf).String()

	case Socks5AtypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return nil, err
		}
		dlen := int(lenBuf[0])
		domainBuf := make([]byte, dlen)
		if _, err := io.ReadFull(r, domainBuf); err != nil {
			return nil, err
		}
		targetHost = string(domainBuf)

	case Socks5AtypIPv6:
		ipBuf := make([]byte, 16)
		if _, err := io.ReadFull(r, ipBuf); err != nil {
			return nil, err
		}
		targetHost = net.IP(ipBuf).String()

	default:
		return nil, fmt.Errorf("socks5: unsupported address type 0x%02x", atyp)
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, portBuf); err != nil {
		return nil, err
	}
	targetPort := int(binary.BigEndian.Uint16(portBuf))

	return &Socks5Request{
		Command:     command,
		TargetHost:  targetHost,
		TargetPort:  targetPort,
		AddressType: atyp,
	}, nil
}

// BuildSocks5Reply creates standard IPv4 SOCKS5 command response.
func BuildSocks5Reply(rep byte, bndPort int, bndIP net.IP) []byte {
	resp := make([]byte, 10)
	resp[0] = Socks5Version
	resp[1] = rep
	resp[2] = 0x00
	resp[3] = Socks5AtypIPv4
	ip4 := bndIP.To4()
	if ip4 != nil {
		copy(resp[4:8], ip4)
	}
	binary.BigEndian.PutUint16(resp[8:10], uint16(bndPort))
	return resp
}

// ---------------------------------------------------------------------------
// HTTP Proxy & HTTPS CONNECT
// ---------------------------------------------------------------------------

// HTTPProxyRequest encapsulates a parsed HTTP proxy or CONNECT request.
type HTTPProxyRequest struct {
	Method    string
	Host      string
	Port      int
	Path      string
	IsConnect bool
}

// maxHTTPRequestLineBytes bounds the initial HTTP request line; longer lines
// are rejected so a peer that never terminates the line cannot grow the
// reader without bound.
const maxHTTPRequestLineBytes = 16 << 10

// ParseHTTPProxyRequest parses the initial HTTP request line.
func ParseHTTPProxyRequest(reader *bufio.Reader) (*HTTPProxyRequest, error) {
	line, err := boundedio.ReadLine(reader, maxHTTPRequestLineBytes)
	if err != nil {
		if errors.Is(err, boundedio.ErrLineTooLong) {
			return nil, errors.New("http: request line too long")
		}
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return nil, errors.New("http: malformed request line")
	}

	method := strings.ToUpper(parts[0])
	rawURI := parts[1]

	if method == "CONNECT" {
		host, port, err := parseHostPort(rawURI, 443)
		if err != nil {
			return nil, err
		}
		return &HTTPProxyRequest{
			Method:    method,
			Host:      host,
			Port:      port,
			IsConnect: true,
		}, nil
	}

	// Standard HTTP GET/POST/etc.
	clean := strings.TrimPrefix(rawURI, "http://")
	clean = strings.TrimPrefix(clean, "https://")
	slashIdx := strings.Index(clean, "/")
	var hostPart, pathPart string
	if slashIdx >= 0 {
		hostPart = clean[:slashIdx]
		pathPart = clean[slashIdx:]
	} else {
		hostPart = clean
		pathPart = "/"
	}

	host, port, err := parseHostPort(hostPart, 80)
	if err != nil {
		return nil, err
	}

	return &HTTPProxyRequest{
		Method:    method,
		Host:      host,
		Port:      port,
		Path:      pathPart,
		IsConnect: false,
	}, nil
}

// BuildHTTPConnectOK returns 200 OK response bytes.
func BuildHTTPConnectOK() []byte {
	return []byte("HTTP/1.1 200 Connection Established\r\nProxy-Agent: LumiNet-Mixed-Proxy/1.0\r\n\r\n")
}

func parseHostPort(s string, defaultPort int) (string, int, error) {
	if strings.Contains(s, ":") {
		host, portStr, err := net.SplitHostPort(s)
		if err != nil {
			// Try fallback for ipv6 without brackets
			idx := strings.LastIndex(s, ":")
			host = s[:idx]
			portStr = s[idx+1:]
		}
		p, err := strconv.Atoi(portStr)
		if err != nil {
			return "", 0, fmt.Errorf("invalid port %q", portStr)
		}
		return host, p, nil
	}
	return s, defaultPort, nil
}
