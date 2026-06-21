package proxy

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
)

func TestParseTUIC_Valid(t *testing.T) {
	uri := "tuic://b51759f2-2ea9-42b7-86c6-99cf59ad0d7f:pass123@127.0.0.1:443?sni=google.com&congestion_control=bbr&udp_relay_mode=native#TuicTest"
	cfg, err := parseTUIC(uri)
	if err != nil {
		t.Fatalf("failed to parse TUIC URI: %v", err)
	}

	if cfg.Protocol != ProtocolTUIC {
		t.Errorf("expected ProtocolTUIC, got %v", cfg.Protocol)
	}
	if cfg.UUID != "b51759f2-2ea9-42b7-86c6-99cf59ad0d7f" {
		t.Errorf("expected UUID, got %s", cfg.UUID)
	}
	if cfg.Password != "pass123" {
		t.Errorf("expected Password, got %s", cfg.Password)
	}
	if cfg.Address != "127.0.0.1" || cfg.Port != 443 {
		t.Errorf("expected address and port, got %s:%d", cfg.Address, cfg.Port)
	}
	if cfg.SNI != "google.com" || cfg.CongestionControl != "bbr" || cfg.UDPRelayMode != "native" {
		t.Errorf("unexpected query properties: %+v", cfg)
	}
	if cfg.Name != "TuicTest" {
		t.Errorf("expected remark, got %s", cfg.Name)
	}
}

func TestTuicSession_Serialization(t *testing.T) {
	// Mock net.Conn pipe
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	uuid := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	token := [32]byte{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
	}

	session := NewTuicSession(clientConn, uuid, token)

	// WriteAuthenticate
	go func() {
		err := session.WriteAuthenticate()
		if err != nil {
			t.Errorf("WriteAuthenticate error: %v", err)
		}
	}()

	ver, cmdType, err := ReadCommandHeader(serverConn)
	if err != nil {
		t.Fatalf("ReadCommandHeader failed: %v", err)
	}
	if ver != TuicVersion || cmdType != TuicCmdAuthenticate {
		t.Errorf("expected version 0x05 and type 0x00, got version 0x%02x type 0x%02x", ver, cmdType)
	}

	uuidBuf := make([]byte, 16)
	_, _ = io.ReadFull(serverConn, uuidBuf)
	if !bytes.Equal(uuidBuf, uuid[:]) {
		t.Errorf("expected uuid %v, got %v", uuid, uuidBuf)
	}

	tokenBuf := make([]byte, 32)
	_, _ = io.ReadFull(serverConn, tokenBuf)
	if !bytes.Equal(tokenBuf, token[:]) {
		t.Errorf("expected token %v, got %v", token, tokenBuf)
	}

	// WriteConnect
	go func() {
		err := session.WriteConnect(TuicAddrTypeDomain, "google.com", 443)
		if err != nil {
			t.Errorf("WriteConnect error: %v", err)
		}
	}()

	ver, cmdType, err = ReadCommandHeader(serverConn)
	if err != nil {
		t.Fatalf("ReadCommandHeader failed: %v", err)
	}
	if ver != TuicVersion || cmdType != TuicCmdConnect {
		t.Errorf("expected type Connect, got ver %d type %d", ver, cmdType)
	}

	addrTypeBuf := make([]byte, 1)
	_, _ = io.ReadFull(serverConn, addrTypeBuf)
	if addrTypeBuf[0] != TuicAddrTypeDomain {
		t.Errorf("expected addr type domain, got %d", addrTypeBuf[0])
	}

	lenBuf := make([]byte, 1)
	_, _ = io.ReadFull(serverConn, lenBuf)
	domainLen := int(lenBuf[0])
	if domainLen != len("google.com") {
		t.Errorf("expected domain length %d, got %d", len("google.com"), domainLen)
	}

	domainBuf := make([]byte, domainLen)
	_, _ = io.ReadFull(serverConn, domainBuf)
	if string(domainBuf) != "google.com" {
		t.Errorf("expected domain google.com, got %s", string(domainBuf))
	}

	var port uint16
	_ = binary.Read(serverConn, binary.BigEndian, &port)
	if port != 443 {
		t.Errorf("expected port 443, got %d", port)
	}
}
