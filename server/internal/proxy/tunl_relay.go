package proxy

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// Network represents the connection protocol in V2 headers.
type Network uint32

const (
	NetworkTCP Network = 0
	NetworkUDP Network = 1
)

func (n Network) String() string {
	switch n {
	case NetworkTCP:
		return "tcp"
	case NetworkUDP:
		return "udp"
	default:
		return "unknown"
	}
}

// Version represents the protocol version in V2 headers.
type Version uint32

const (
	VersionV2 Version = 0
)

// Header represents the parsed connection target metadata.
type Header struct {
	Ver  Version
	Net  Network
	Addr net.IP
	Port uint16
}

// parseV2Payload deserializes the bincode-compatible header payload.
func parseV2Payload(payload []byte) (*Header, error) {
	if len(payload) < 18 {
		return nil, errors.New("v2 payload too short")
	}
	r := bytes.NewReader(payload)

	var ver uint32
	if err := binary.Read(r, binary.LittleEndian, &ver); err != nil {
		return nil, fmt.Errorf("read version failed: %w", err)
	}
	if ver != 0 {
		return nil, fmt.Errorf("unsupported version: %d", ver)
	}

	var netType uint32
	if err := binary.Read(r, binary.LittleEndian, &netType); err != nil {
		return nil, fmt.Errorf("read network type failed: %w", err)
	}
	if netType != 0 && netType != 1 {
		return nil, fmt.Errorf("unsupported network type: %d", netType)
	}

	var addrFamily uint32
	if err := binary.Read(r, binary.LittleEndian, &addrFamily); err != nil {
		return nil, fmt.Errorf("read address family failed: %w", err)
	}

	var ip net.IP
	if addrFamily == 0 { // IPv4
		ipBytes := make([]byte, 4)
		if _, err := io.ReadFull(r, ipBytes); err != nil {
			return nil, fmt.Errorf("read ipv4 failed: %w", err)
		}
		ip = net.IP(ipBytes)
	} else if addrFamily == 1 { // IPv6
		ipBytes := make([]byte, 16)
		if _, err := io.ReadFull(r, ipBytes); err != nil {
			return nil, fmt.Errorf("read ipv6 failed: %w", err)
		}
		ip = net.IP(ipBytes)
	} else {
		return nil, fmt.Errorf("unsupported address family variant: %d", addrFamily)
	}

	var port uint16
	if err := binary.Read(r, binary.LittleEndian, &port); err != nil {
		return nil, fmt.Errorf("read port failed: %w", err)
	}

	return &Header{
		Ver:  Version(ver),
		Net:  Network(netType),
		Addr: ip,
		Port: port,
	}, nil
}

// ParseV1Header parses a V1 plaintext ASCII header line (excluding the trailing newline).
func ParseV1Header(line string) (*Header, error) {
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")

	// format: protocol@host$port
	atIdx := strings.Index(line, "@")
	if atIdx == -1 {
		return nil, fmt.Errorf("invalid V1 header: missing '@'")
	}
	proto := line[:atIdx]

	rest := line[atIdx+1:]
	dollarIdx := strings.Index(rest, "$")
	if dollarIdx == -1 {
		return nil, fmt.Errorf("invalid V1 header: missing '$'")
	}
	host := rest[:dollarIdx]
	portStr := rest[dollarIdx+1:]

	var netType Network
	switch strings.ToLower(proto) {
	case "tcp":
		netType = NetworkTCP
	case "udp":
		netType = NetworkUDP
	default:
		return nil, fmt.Errorf("invalid protocol: %s", proto)
	}

	portVal, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}

	ip := net.ParseIP(host)
	if ip == nil {
		// It's a domain name, resolve it
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("failed to resolve host %s: %w", host, err)
		}
		ip = ips[0]
	}

	return &Header{
		Ver:  0,
		Net:  netType,
		Addr: ip,
		Port: uint16(portVal),
	}, nil
}

// ReadHeader peeks at the stream to determine V1 or V2, then reads and parses the header.
func ReadHeader(br *bufio.Reader) (*Header, error) {
	firstByte, err := br.Peek(1)
	if err != nil {
		return nil, err
	}

	if firstByte[0] == 0x00 {
		// V2 Header
		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(br, lenBuf); err != nil {
			return nil, err
		}
		headerLen := binary.BigEndian.Uint16(lenBuf)

		payload := make([]byte, headerLen)
		if _, err := io.ReadFull(br, payload); err != nil {
			return nil, err
		}

		return parseV2Payload(payload)
	}

	// V1 Header (ASCII)
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	return ParseV1Header(line)
}

// RelayConnection reads the V1/V2 header from clientConn and relays the traffic to the target destination.
func RelayConnection(clientConn net.Conn) error {
	defer clientConn.Close()

	br := bufio.NewReader(clientConn)
	header, err := ReadHeader(br)
	if err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}

	if header.Net == NetworkTCP {
		return HandleTCPRelay(clientConn, br, header)
	} else if header.Net == NetworkUDP {
		return HandleUDPRelay(clientConn, br, header)
	}

	return fmt.Errorf("unsupported network type: %v", header.Net)
}

// HandleTCPRelay proxies raw TCP traffic bidirectionally.
func HandleTCPRelay(clientConn net.Conn, br *bufio.Reader, header *Header) error {
	targetAddr := net.JoinHostPort(header.Addr.String(), strconv.Itoa(int(header.Port)))
	targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("failed to dial target %s: %w", targetAddr, err)
	}
	defer targetConn.Close()

	// Wrap clientConn with a MultiReader to include any buffered bytes from bufio.Reader
	clientReader := io.MultiReader(br, clientConn)

	errChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(targetConn, clientReader)
		errChan <- err
	}()
	go func() {
		_, err := io.Copy(clientConn, targetConn)
		errChan <- err
	}()

	err = <-errChan
	return err
}

// HandleUDPRelay proxies raw UDP traffic mapping TCP chunks to UDP packets.
func HandleUDPRelay(clientConn net.Conn, br *bufio.Reader, header *Header) error {
	targetAddr := net.JoinHostPort(header.Addr.String(), strconv.Itoa(int(header.Port)))
	udpConn, err := net.Dial("udp", targetAddr)
	if err != nil {
		return fmt.Errorf("failed to dial UDP target %s: %w", targetAddr, err)
	}
	defer udpConn.Close()

	// Wrap clientConn with a MultiReader to include any buffered bytes from bufio.Reader
	clientReader := io.MultiReader(br, clientConn)

	errChan := make(chan error, 2)

	// TCP to UDP loop
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := clientReader.Read(buf)
			if n > 0 {
				_, writeErr := udpConn.Write(buf[:n])
				if writeErr != nil {
					errChan <- writeErr
					return
				}
			}
			if err != nil {
				errChan <- err
				return
			}
		}
	}()

	// UDP to TCP loop
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := udpConn.Read(buf)
			if n > 0 {
				_, writeErr := clientConn.Write(buf[:n])
				if writeErr != nil {
					errChan <- writeErr
					return
				}
			}
			if err != nil {
				errChan <- err
				return
			}
		}
	}()

	err = <-errChan
	if err == io.EOF {
		return nil
	}
	return err
}
