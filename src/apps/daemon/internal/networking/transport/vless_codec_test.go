package transport

import (
	"bytes"
	"net"
	"testing"
)

func TestVLESSRequestHeaderSerializationIPv4(t *testing.T) {
	uuid := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	ip := net.ParseIP("192.168.1.100").To4()

	req := &VLESSRequestHeader{
		Version: 0,
		UUID:    uuid,
		Command: VLESSCommandTCP,
		Port:    443,
		Address: VLESSAddress{
			Type: VLESSAddressTypeIPv4,
			IP:   ip,
		},
		Addons: []byte{0x0a, 0x0b},
	}

	serialized, err := req.Serialize()
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	deserialized, consumed, err := DeserializeVLESSRequestHeader(serialized)
	if err != nil {
		t.Fatalf("Deserialize failed: %v", err)
	}

	if consumed != len(serialized) {
		t.Errorf("expected consumed %d, got %d", len(serialized), consumed)
	}
	if deserialized.Version != req.Version {
		t.Errorf("version mismatch: expected %d, got %d", req.Version, deserialized.Version)
	}
	if deserialized.UUID != req.UUID {
		t.Errorf("uuid mismatch")
	}
	if deserialized.Command != req.Command {
		t.Errorf("command mismatch: expected %d, got %d", req.Command, deserialized.Command)
	}
	if deserialized.Port != req.Port {
		t.Errorf("port mismatch: expected %d, got %d", req.Port, deserialized.Port)
	}
	if !bytes.Equal(deserialized.Address.IP.To4(), ip) {
		t.Errorf("IP mismatch: expected %v, got %v", ip, deserialized.Address.IP)
	}
	if !bytes.Equal(deserialized.Addons, req.Addons) {
		t.Errorf("addons mismatch")
	}
}

func TestVLESSRequestHeaderSerializationDomain(t *testing.T) {
	uuid := [16]byte{0xaa, 0xbb, 0xcc, 0xdd, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	domain := "example.com"

	req := &VLESSRequestHeader{
		Version: 0,
		UUID:    uuid,
		Command: VLESSCommandUDP,
		Port:    53,
		Address: VLESSAddress{
			Type:   VLESSAddressTypeDomain,
			Domain: domain,
		},
	}

	serialized, err := req.Serialize()
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	deserialized, consumed, err := DeserializeVLESSRequestHeader(serialized)
	if err != nil {
		t.Fatalf("Deserialize failed: %v", err)
	}

	if consumed != len(serialized) {
		t.Errorf("expected consumed %d, got %d", len(serialized), consumed)
	}
	if deserialized.Address.Domain != domain {
		t.Errorf("domain mismatch: expected %s, got %s", domain, deserialized.Address.Domain)
	}
}

func TestVLESSResponseHeaderCodec(t *testing.T) {
	addons := []byte("vless-addons-test")
	resp := &VLESSResponseHeader{
		Version: 0,
		Addons:  addons,
	}

	serialized, err := resp.Serialize()
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	deserialized, consumed, err := DeserializeVLESSResponseHeader(serialized)
	if err != nil {
		t.Fatalf("Deserialize failed: %v", err)
	}

	if consumed != len(serialized) {
		t.Errorf("consumed %d != len %d", consumed, len(serialized))
	}
	if deserialized.Version != resp.Version {
		t.Errorf("version mismatch: %d != %d", deserialized.Version, resp.Version)
	}
	if !bytes.Equal(deserialized.Addons, addons) {
		t.Errorf("addons mismatch")
	}
}
