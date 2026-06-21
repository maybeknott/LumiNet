package proxy

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
)

// SerializeV2Header serializes a Header into standard Rust bincode-compatible V2 header format.
func SerializeV2Header(h *Header) ([]byte, error) {
	var buf bytes.Buffer

	// ver: Version (u32)
	if err := binary.Write(&buf, binary.LittleEndian, uint32(h.Ver)); err != nil {
		return nil, err
	}

	// net: Network (u32)
	if err := binary.Write(&buf, binary.LittleEndian, uint32(h.Net)); err != nil {
		return nil, err
	}

	// addr: IpAddr (enum u32 index + bytes)
	if ip4 := h.Addr.To4(); ip4 != nil {
		// variant 0 (IPv4)
		if err := binary.Write(&buf, binary.LittleEndian, uint32(0)); err != nil {
			return nil, err
		}
		if _, err := buf.Write(ip4); err != nil {
			return nil, err
		}
	} else {
		// variant 1 (IPv6)
		if err := binary.Write(&buf, binary.LittleEndian, uint32(1)); err != nil {
			return nil, err
		}
		if _, err := buf.Write(h.Addr.To16()); err != nil {
			return nil, err
		}
	}

	// port: u16
	if err := binary.Write(&buf, binary.LittleEndian, h.Port); err != nil {
		return nil, err
	}

	payloadBytes := buf.Bytes()
	headerLen := len(payloadBytes)

	finalBuf := make([]byte, 2+headerLen)
	binary.BigEndian.PutUint16(finalBuf[0:2], uint16(headerLen))
	copy(finalBuf[2:], payloadBytes)

	return finalBuf, nil
}

func TestParseV1Header(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		wantNet Network
		wantIP  string
		wantPort uint16
		wantErr bool
	}{
		{
			name:    "valid tcp ipv4",
			line:    "tcp@8.8.8.8$53\n",
			wantNet: NetworkTCP,
			wantIP:  "8.8.8.8",
			wantPort: 53,
			wantErr: false,
		},
		{
			name:    "valid udp ipv4",
			line:    "udp@127.0.0.1$1234\r\n",
			wantNet: NetworkUDP,
			wantIP:  "127.0.0.1",
			wantPort: 1234,
			wantErr: false,
		},
		{
			name:    "valid domain localhost",
			line:    "tcp@localhost$80\n",
			wantNet: NetworkTCP,
			wantIP:  "127.0.0.1",
			wantPort: 80,
			wantErr: false,
		},
		{
			name:    "missing @",
			line:    "tcp8.8.8.8$53\n",
			wantErr: true,
		},
		{
			name:    "missing $",
			line:    "tcp@8.8.8.8:53\n",
			wantErr: true,
		},
		{
			name:    "invalid protocol",
			line:    "http@8.8.8.8$53\n",
			wantErr: true,
		},
		{
			name:    "invalid port",
			line:    "tcp@8.8.8.8$abc\n",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := ParseV1Header(tt.line)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseV1Header() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if h.Net != tt.wantNet {
					t.Errorf("got Net = %v, want %v", h.Net, tt.wantNet)
				}
				if tt.name == "valid domain localhost" {
					if !h.Addr.IsLoopback() {
						t.Errorf("got IP = %v, want loopback IP", h.Addr.String())
					}
				} else {
					if h.Addr.String() != tt.wantIP {
						t.Errorf("got IP = %v, want %v", h.Addr.String(), tt.wantIP)
					}
				}
				if h.Port != tt.wantPort {
					t.Errorf("got Port = %v, want %v", h.Port, tt.wantPort)
				}
			}
		})
	}
}

func TestReadHeader_V2(t *testing.T) {
	tests := []struct {
		name    string
		header  Header
		wantErr bool
	}{
		{
			name: "valid v2 tcp ipv4",
			header: Header{
				Ver:  VersionV2,
				Net:  NetworkTCP,
				Addr: net.ParseIP("192.168.1.1"),
				Port: 8080,
			},
			wantErr: false,
		},
		{
			name: "valid v2 udp ipv4",
			header: Header{
				Ver:  VersionV2,
				Net:  NetworkUDP,
				Addr: net.ParseIP("8.8.4.4"),
				Port: 53,
			},
			wantErr: false,
		},
		{
			name: "valid v2 tcp ipv6",
			header: Header{
				Ver:  VersionV2,
				Net:  NetworkTCP,
				Addr: net.ParseIP("2001:db8::1"),
				Port: 443,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serialized, err := SerializeV2Header(&tt.header)
			if err != nil {
				t.Fatalf("SerializeV2Header failed: %v", err)
			}

			br := bufio.NewReader(bytes.NewReader(serialized))
			h, err := ReadHeader(br)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ReadHeader() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr {
				if h.Ver != tt.header.Ver {
					t.Errorf("got Ver = %v, want %v", h.Ver, tt.header.Ver)
				}
				if h.Net != tt.header.Net {
					t.Errorf("got Net = %v, want %v", h.Net, tt.header.Net)
				}
				if !h.Addr.Equal(tt.header.Addr) {
					t.Errorf("got Addr = %v, want %v", h.Addr, tt.header.Addr)
				}
				if h.Port != tt.header.Port {
					t.Errorf("got Port = %v, want %v", h.Port, tt.header.Port)
				}
			}
		})
	}
}

func TestReadHeader_InvalidV2(t *testing.T) {
	// 1. Payload too short
	badData := []byte{0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05} // len=5, but minimum is 18
	br := bufio.NewReader(bytes.NewReader(badData))
	_, err := ReadHeader(br)
	if err == nil {
		t.Error("expected error for too short payload")
	}

	// 2. Unsupported version
	h := Header{
		Ver:  1, // bad version
		Net:  NetworkTCP,
		Addr: net.ParseIP("127.0.0.1"),
		Port: 80,
	}
	serialized, _ := SerializeV2Header(&h)
	br = bufio.NewReader(bytes.NewReader(serialized))
	_, err = ReadHeader(br)
	if err == nil {
		t.Error("expected error for unsupported version")
	}

	// 3. Unsupported network
	h = Header{
		Ver:  VersionV2,
		Net:  2, // bad network
		Addr: net.ParseIP("127.0.0.1"),
		Port: 80,
	}
	serialized, _ = SerializeV2Header(&h)
	br = bufio.NewReader(bytes.NewReader(serialized))
	_, err = ReadHeader(br)
	if err == nil {
		t.Error("expected error for unsupported network")
	}
}

func TestRelayTCP(t *testing.T) {
	// Start target TCP Echo Server
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start target listener: %v", err)
	}
	defer targetListener.Close()

	go func() {
		conn, err := targetListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err == nil {
			_, _ = conn.Write(buf[:n])
		}
	}()

	// Start client and relay
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	targetAddr := targetListener.Addr().(*net.TCPAddr)
	h := Header{
		Ver:  VersionV2,
		Net:  NetworkTCP,
		Addr: targetAddr.IP,
		Port: uint16(targetAddr.Port),
	}

	serializedHeader, err := SerializeV2Header(&h)
	if err != nil {
		t.Fatalf("failed to serialize header: %v", err)
	}

	// Write header + payload to client connection
	go func() {
		_, _ = clientConn.Write(serializedHeader)
		_, _ = clientConn.Write([]byte("hello tcp relay"))
	}()

	relayErrChan := make(chan error, 1)
	go func() {
		relayErrChan <- RelayConnection(serverConn)
	}()

	// Read response on client side
	respBuf := make([]byte, 1024)
	n, err := clientConn.Read(respBuf)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	if string(respBuf[:n]) != "hello tcp relay" {
		t.Errorf("expected 'hello tcp relay', got '%s'", string(respBuf[:n]))
	}

	_ = clientConn.Close()

	// Make sure no unexpected error from relay
	relayErr := <-relayErrChan
	if relayErr != nil && relayErr != io.EOF {
		t.Logf("relay connection closed with: %v", relayErr)
	}
}

func TestRelayUDP(t *testing.T) {
	// Start target UDP Echo Server
	targetConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to start target UDP listener: %v", err)
	}
	defer targetConn.Close()

	go func() {
		buf := make([]byte, 1024)
		n, addr, err := targetConn.ReadFrom(buf)
		if err == nil {
			_, _ = targetConn.WriteTo(buf[:n], addr)
		}
	}()

	// Start client and relay
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	targetAddr := targetConn.LocalAddr().(*net.UDPAddr)
	h := Header{
		Ver:  VersionV2,
		Net:  NetworkUDP,
		Addr: targetAddr.IP,
		Port: uint16(targetAddr.Port),
	}

	serializedHeader, err := SerializeV2Header(&h)
	if err != nil {
		t.Fatalf("failed to serialize header: %v", err)
	}

	// Write header + payload to client connection
	go func() {
		_, _ = clientConn.Write(serializedHeader)
		_, _ = clientConn.Write([]byte("hello udp relay"))
	}()

	relayErrChan := make(chan error, 1)
	go func() {
		relayErrChan <- RelayConnection(serverConn)
	}()

	// Read response on client side
	respBuf := make([]byte, 1024)
	n, err := clientConn.Read(respBuf)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	if string(respBuf[:n]) != "hello udp relay" {
		t.Errorf("expected 'hello udp relay', got '%s'", string(respBuf[:n]))
	}

	_ = clientConn.Close()

	// Make sure no unexpected error from relay
	relayErr := <-relayErrChan
	if relayErr != nil && relayErr != io.EOF {
		t.Logf("relay connection closed with: %v", relayErr)
	}
}
