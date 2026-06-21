//go:build !windows && !linux

package proxy

import (
	"context"
	"errors"
	"net"
)

type StubPacketInjector struct{}

func NewPacketInjector() PacketInjector {
	return &StubPacketInjector{}
}

func (s *StubPacketInjector) Start(ctx context.Context, listenPort int) error {
	return nil
}

func (s *StubPacketInjector) Stop() error {
	return nil
}

func (s *StubPacketInjector) IsRunning() bool {
	return false
}

func InjectTCPDecoy(destIP string, destPort uint16, synSeq uint32, ttl uint32, payloadHex string, payloadLen int) error {
	return errors.New("packet injection not supported on this platform")
}

// InjectWindowsDivertPacket is a stub for unsupported platforms
func InjectWindowsDivertPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, ttl uint32, flags uint8, seq, ack uint32, payload []byte) error {
	return errors.New("packet injection not supported on this platform")
}

// InstallRstDropRule stub
func InstallRstDropRule(destination string) error {
	return nil
}

// RemoveRstDropRule stub
func RemoveRstDropRule(destination string) error {
	return nil
}

// StartBypassSniffer stub
func StartBypassSniffer(conn *rawBypassConn) {
}
