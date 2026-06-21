package proxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

// TUIC version and command types
const (
	TuicVersion            = 0x05
	TuicCmdAuthenticate    = 0x00
	TuicCmdConnect         = 0x01
	TuicCmdPacket          = 0x02
	TuicCmdDissociate      = 0x03
	TuicCmdHeartbeat       = 0x04
)

// Target address types
const (
	TuicAddrTypeDomain = 0x00
	TuicAddrTypeIPv4   = 0x01
	TuicAddrTypeIPv6   = 0x02
	TuicAddrTypeNone   = 0xff
)

// TuicSession represents an authenticated TUIC connection multiplexer session.
type TuicSession struct {
	mu           sync.Mutex
	conn         net.Conn
	uuid         [16]byte
	token        [32]byte
	authenticated bool
}

// NewTuicSession creates a new TUIC connection wrapper.
func NewTuicSession(conn net.Conn, uuid [16]byte, token [32]byte) *TuicSession {
	return &TuicSession{
		conn:  conn,
		uuid:  uuid,
		token: token,
	}
}

// WriteAuthenticate writes the initial Authenticate frame over the stream.
func (s *TuicSession) WriteAuthenticate() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	buf := new(bytes.Buffer)
	buf.WriteByte(TuicVersion)
	buf.WriteByte(TuicCmdAuthenticate)
	buf.Write(s.uuid[:])
	buf.Write(s.token[:])

	_, err := s.conn.Write(buf.Bytes())
	if err == nil {
		s.authenticated = true
	}
	return err
}

// WriteConnect writes a target TCP connection request connect frame.
func (s *TuicSession) WriteConnect(addrType byte, host string, port uint16) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	buf := new(bytes.Buffer)
	buf.WriteByte(TuicVersion)
	buf.WriteByte(TuicCmdConnect)

	// Encode Address
	buf.WriteByte(addrType)
	switch addrType {
	case TuicAddrTypeDomain:
		buf.WriteByte(byte(len(host)))
		buf.WriteString(host)
	case TuicAddrTypeIPv4:
		ip := net.ParseIP(host).To4()
		if ip == nil {
			return errors.New("invalid IPv4 address")
		}
		buf.Write(ip)
	case TuicAddrTypeIPv6:
		ip := net.ParseIP(host).To16()
		if ip == nil {
			return errors.New("invalid IPv6 address")
		}
		buf.Write(ip)
	default:
		return fmt.Errorf("unsupported address type: %d", addrType)
	}

	_ = binary.Write(buf, binary.BigEndian, port)

	_, err := s.conn.Write(buf.Bytes())
	return err
}

// WritePacket writes a UDP payload fragment command frame.
func (s *TuicSession) WritePacket(assocID, pktID uint16, fragTotal, fragID byte, targetHost string, targetPort uint16, payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	buf := new(bytes.Buffer)
	buf.WriteByte(TuicVersion)
	buf.WriteByte(TuicCmdPacket)

	_ = binary.Write(buf, binary.BigEndian, assocID)
	_ = binary.Write(buf, binary.BigEndian, pktID)
	buf.WriteByte(fragTotal)
	buf.WriteByte(fragID)
	_ = binary.Write(buf, binary.BigEndian, uint16(len(payload)))

	// For first fragment, specify address
	if fragID == 0 {
		buf.WriteByte(TuicAddrTypeDomain)
		buf.WriteByte(byte(len(targetHost)))
		buf.WriteString(targetHost)
		_ = binary.Write(buf, binary.BigEndian, targetPort)
	} else {
		buf.WriteByte(TuicAddrTypeNone)
	}

	buf.Write(payload)

	_, err := s.conn.Write(buf.Bytes())
	return err
}

// ReadCommandHeader reads the prefix header of a TUIC command.
func ReadCommandHeader(r io.Reader) (ver, cmdType byte, err error) {
	buf := make([]byte, 2)
	_, err = io.ReadFull(r, buf)
	if err != nil {
		return 0, 0, err
	}
	return buf[0], buf[1], nil
}
