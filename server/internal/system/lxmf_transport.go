package system

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"
)

// LXMFMessage represents a serialized message in the Lightweight Extensible Message Format.
type LXMFMessage struct {
	Sender    [32]byte
	Recipient [32]byte
	Timestamp time.Time
	Content   []byte
}

// SerializeLXMF serializes the message into a binary format.
// Header format:
// [32 bytes Sender] [32 bytes Recipient] [8 bytes Big-Endian Nanoseconds Timestamp] [Remaining bytes Payload]
func SerializeLXMF(msg *LXMFMessage) ([]byte, error) {
	var buf bytes.Buffer
	_, _ = buf.Write(msg.Sender[:])
	_, _ = buf.Write(msg.Recipient[:])

	tsNanos := msg.Timestamp.UnixNano()
	if err := binary.Write(&buf, binary.BigEndian, tsNanos); err != nil {
		return nil, fmt.Errorf("failed to serialize timestamp: %w", err)
	}

	_, _ = buf.Write(msg.Content)
	return buf.Bytes(), nil
}

// DeserializeLXMF parses a raw binary payload back into a LXMFMessage.
func DeserializeLXMF(payload []byte) (*LXMFMessage, error) {
	if len(payload) < 72 {
		return nil, fmt.Errorf("payload too short for LXMF message")
	}

	msg := &LXMFMessage{}
	copy(msg.Sender[:], payload[0:32])
	copy(msg.Recipient[:], payload[32:64])

	tsNanos := int64(binary.BigEndian.Uint64(payload[64:72]))
	msg.Timestamp = time.Unix(0, tsNanos)

	msg.Content = make([]byte, len(payload)-72)
	copy(msg.Content, payload[72:])

	return msg, nil
}

// GenerateEphemeralAddress creates a random 32-byte mesh endpoint address.
func GenerateEphemeralAddress() [32]byte {
	var addr [32]byte
	_, _ = rand.Read(addr[:])
	return addr
}
