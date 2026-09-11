package relay

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
)

type ProxyProtocolVersion int

const (
	ProxyProtoNone ProxyProtocolVersion = iota
	ProxyProtoV1
	ProxyProtoV2
)

type RelayEndpoint struct {
	TargetAddr           *net.TCPAddr
	Weight               uint32
	IsAlive              bool
	ActiveConnections    int
	TotalBytesForwarded  uint64
}

type ZeroCopyRelaySupervisor struct {
	ListenAddr      *net.TCPAddr
	ProxyProtocol   ProxyProtocolVersion
	endpoints       []*RelayEndpoint
	endpointIndex   int
	sessions        map[uint64]*RelayEndpoint
	nextSessionID   uint64
	mu              sync.Mutex
}

func NewZeroCopyRelaySupervisor(listen *net.TCPAddr, proto ProxyProtocolVersion) *ZeroCopyRelaySupervisor {
	return &ZeroCopyRelaySupervisor{
		ListenAddr:    listen,
		ProxyProtocol: proto,
		sessions:      make(map[uint64]*RelayEndpoint),
		nextSessionID: 1,
	}
}

func (s *ZeroCopyRelaySupervisor) AddEndpoint(addr *net.TCPAddr, weight uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if weight == 0 {
		weight = 1
	}
	s.endpoints = append(s.endpoints, &RelayEndpoint{
		TargetAddr: addr,
		Weight:     weight,
		IsAlive:    true,
	})
}

func (s *ZeroCopyRelaySupervisor) OpenSession(clientAddr *net.TCPAddr) (uint64, *net.TCPAddr, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var healthy []*RelayEndpoint
	for _, ep := range s.endpoints {
		if ep.IsAlive {
			healthy = append(healthy, ep)
		}
	}
	if len(healthy) == 0 {
		return 0, nil, errors.New("no healthy endpoints")
	}

	chosen := healthy[s.endpointIndex%len(healthy)]
	s.endpointIndex++
	chosen.ActiveConnections++

	sid := s.nextSessionID
	s.nextSessionID++
	s.sessions[sid] = chosen
	return sid, chosen.TargetAddr, nil
}

func (s *ZeroCopyRelaySupervisor) CloseSession(sessionID uint64, bytesRelayed uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ep, ok := s.sessions[sessionID]; ok {
		if ep.ActiveConnections > 0 {
			ep.ActiveConnections--
		}
		ep.TotalBytesForwarded += bytesRelayed
		delete(s.sessions, sessionID)
	}
}

func (s *ZeroCopyRelaySupervisor) GenerateProxyHeader(clientAddr, serverAddr *net.TCPAddr) []byte {
	switch s.ProxyProtocol {
	case ProxyProtoV1:
		family := "TCP4"
		if clientAddr.IP.To4() == nil {
			family = "TCP6"
		}
		str := fmt.Sprintf("PROXY %s %s %s %d %d\r\n", family, clientAddr.IP.String(), serverAddr.IP.String(), clientAddr.Port, serverAddr.Port)
		return []byte(str)
	case ProxyProtoV2:
		// 12-byte signature + version command (0x21) + family AF_INET/STREAM (0x11) + length (12)
		sig := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x11}
		buf := make([]byte, 16+12)
		copy(buf[0:14], sig)
		binary.BigEndian.PutUint16(buf[14:16], 12)
		c4 := clientAddr.IP.To4()
		s4 := serverAddr.IP.To4()
		if c4 != nil && s4 != nil {
			copy(buf[16:20], c4)
			copy(buf[20:24], s4)
		}
		binary.BigEndian.PutUint16(buf[24:26], uint16(clientAddr.Port))
		binary.BigEndian.PutUint16(buf[26:28], uint16(serverAddr.Port))
		return buf
	default:
		return nil
	}
}
