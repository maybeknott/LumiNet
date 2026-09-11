package transport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// VLESSCommand defines the requested target transport command.
type VLESSCommand byte

const (
	VLESSCommandTCP VLESSCommand = 1
	VLESSCommandUDP VLESSCommand = 2
	VLESSCommandMux VLESSCommand = 3
)

// VLESSAddressType represents the network address family.
type VLESSAddressType byte

const (
	VLESSAddressTypeIPv4   VLESSAddressType = 1
	VLESSAddressTypeDomain VLESSAddressType = 2
	VLESSAddressTypeIPv6   VLESSAddressType = 3
)

// VLESSAddress encapsulates a destination address.
type VLESSAddress struct {
	Type   VLESSAddressType
	IP     net.IP
	Domain string
}

func (a VLESSAddress) String() string {
	if a.Type == VLESSAddressTypeDomain {
		return a.Domain
	}
	if a.IP != nil {
		return a.IP.String()
	}
	return ""
}

// VLESSRequestHeader models the binary VLESS handshake header.
type VLESSRequestHeader struct {
	Version byte
	UUID    [16]byte
	Addons  []byte
	Command VLESSCommand
	Port    uint16
	Address VLESSAddress
}

// VLESSResponseHeader models the binary VLESS server response header.
type VLESSResponseHeader struct {
	Version byte
	Addons  []byte
}

// Serialize encodes the VLESS request header into a binary buffer.
func (h *VLESSRequestHeader) Serialize() ([]byte, error) {
	if len(h.Addons) > 255 {
		return nil, errors.New("vless: addons length exceeds 255 bytes")
	}

	var addrBytes []byte
	switch h.Address.Type {
	case VLESSAddressTypeIPv4:
		ipv4 := h.Address.IP.To4()
		if ipv4 == nil {
			return nil, errors.New("vless: invalid IPv4 address")
		}
		addrBytes = append([]byte{byte(VLESSAddressTypeIPv4)}, ipv4...)
	case VLESSAddressTypeDomain:
		dBytes := []byte(h.Address.Domain)
		if len(dBytes) == 0 || len(dBytes) > 255 {
			return nil, fmt.Errorf("vless: domain length %d out of bounds (1..255)", len(dBytes))
		}
		addrBytes = append([]byte{byte(VLESSAddressTypeDomain), byte(len(dBytes))}, dBytes...)
	case VLESSAddressTypeIPv6:
		ipv6 := h.Address.IP.To16()
		if ipv6 == nil {
			return nil, errors.New("vless: invalid IPv6 address")
		}
		addrBytes = append([]byte{byte(VLESSAddressTypeIPv6)}, ipv6...)
	default:
		return nil, fmt.Errorf("vless: unsupported address type %d", h.Address.Type)
	}

	// Layout:
	// Version: 1 byte
	// UUID: 16 bytes
	// Addons length: 1 byte
	// Addons: N bytes
	// Command: 1 byte
	// Port: 2 bytes (Big Endian)
	// Address: Type (1 byte) + [Len (1 byte)] + Address
	totalLen := 1 + 16 + 1 + len(h.Addons) + 1 + 2 + len(addrBytes)
	buf := make([]byte, totalLen)

	idx := 0
	buf[idx] = h.Version
	idx++

	copy(buf[idx:idx+16], h.UUID[:])
	idx += 16

	buf[idx] = byte(len(h.Addons))
	idx++
	if len(h.Addons) > 0 {
		copy(buf[idx:idx+len(h.Addons)], h.Addons)
		idx += len(h.Addons)
	}

	buf[idx] = byte(h.Command)
	idx++

	binary.BigEndian.PutUint16(buf[idx:idx+2], h.Port)
	idx += 2

	copy(buf[idx:], addrBytes)

	return buf, nil
}

// DeserializeVLESSRequestHeader parses a VLESS request header and returns the header and bytes consumed.
func DeserializeVLESSRequestHeader(data []byte) (*VLESSRequestHeader, int, error) {
	if len(data) < 19 {
		return nil, 0, errors.New("vless: buffer too short for request header")
	}

	idx := 0
	version := data[idx]
	idx++

	var uuid [16]byte
	copy(uuid[:], data[idx:idx+16])
	idx += 16

	addonsLen := int(data[idx])
	idx++

	if len(data) < idx+addonsLen+3 {
		return nil, 0, errors.New("vless: buffer truncated before command and port")
	}

	var addons []byte
	if addonsLen > 0 {
		addons = make([]byte, addonsLen)
		copy(addons, data[idx:idx+addonsLen])
		idx += addonsLen
	}

	cmdByte := data[idx]
	idx++
	cmd := VLESSCommand(cmdByte)
	if cmd != VLESSCommandTCP && cmd != VLESSCommandUDP && cmd != VLESSCommandMux {
		return nil, 0, fmt.Errorf("vless: invalid command %d", cmdByte)
	}

	port := binary.BigEndian.Uint16(data[idx : idx+2])
	idx += 2

	if len(data) < idx+1 {
		return nil, 0, errors.New("vless: buffer truncated before address type")
	}

	addrType := VLESSAddressType(data[idx])
	idx++

	var address VLESSAddress
	address.Type = addrType

	switch addrType {
	case VLESSAddressTypeIPv4:
		if len(data) < idx+4 {
			return nil, 0, errors.New("vless: buffer truncated for IPv4 address")
		}
		ip := make(net.IP, 4)
		copy(ip, data[idx:idx+4])
		idx += 4
		address.IP = ip

	case VLESSAddressTypeDomain:
		if len(data) < idx+1 {
			return nil, 0, errors.New("vless: buffer truncated for domain length")
		}
		dLen := int(data[idx])
		idx++
		if len(data) < idx+dLen {
			return nil, 0, errors.New("vless: buffer truncated for domain string")
		}
		address.Domain = string(data[idx : idx+dLen])
		idx += dLen

	case VLESSAddressTypeIPv6:
		if len(data) < idx+16 {
			return nil, 0, errors.New("vless: buffer truncated for IPv6 address")
		}
		ip := make(net.IP, 16)
		copy(ip, data[idx:idx+16])
		idx += 16
		address.IP = ip

	default:
		return nil, 0, fmt.Errorf("vless: unsupported address type %d", addrType)
	}

	return &VLESSRequestHeader{
		Version: version,
		UUID:    uuid,
		Addons:  addons,
		Command: cmd,
		Port:    port,
		Address: address,
	}, idx, nil
}

// Serialize encodes the VLESS response header.
func (r *VLESSResponseHeader) Serialize() ([]byte, error) {
	if len(r.Addons) > 255 {
		return nil, errors.New("vless: response addons length exceeds 255 bytes")
	}
	buf := make([]byte, 2+len(r.Addons))
	buf[0] = r.Version
	buf[1] = byte(len(r.Addons))
	if len(r.Addons) > 0 {
		copy(buf[2:], r.Addons)
	}
	return buf, nil
}

// DeserializeVLESSResponseHeader decodes a VLESS response header.
func DeserializeVLESSResponseHeader(data []byte) (*VLESSResponseHeader, int, error) {
	if len(data) < 2 {
		return nil, 0, errors.New("vless: response buffer too short")
	}
	version := data[0]
	addonsLen := int(data[1])
	if len(data) < 2+addonsLen {
		return nil, 0, errors.New("vless: response buffer truncated for addons")
	}

	var addons []byte
	if addonsLen > 0 {
		addons = make([]byte, addonsLen)
		copy(addons, data[2:2+addonsLen])
	}

	return &VLESSResponseHeader{
		Version: version,
		Addons:  addons,
	}, 2 + addonsLen, nil
}
