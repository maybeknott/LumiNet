package multipath

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	TypeHello    byte = 0x01
	TypeHelloAck byte = 0x02
	TypeData     byte = 0x03
	TypeClose    byte = 0x04
	TypePing     byte = 0x05
	TypePong     byte = 0x06
)

const HeaderSize = 1 + 16 + 8 + 4 // 29 bytes
const MaxPayload = 1 << 20        // 1 MiB

var (
	ErrFrameTooShort   = errors.New("frame data too short for header")
	ErrPayloadTooLarge = errors.New("payload exceeds maximum size")
)

type SessionID [16]byte

type Frame struct {
	Type    byte
	Session SessionID
	Seq     uint64
	Payload []byte
}

func (f *Frame) Encode() []byte {
	buf := make([]byte, HeaderSize+len(f.Payload))
	buf[0] = f.Type
	copy(buf[1:17], f.Session[:])
	binary.BigEndian.PutUint64(buf[17:25], f.Seq)
	binary.BigEndian.PutUint32(buf[25:29], uint32(len(f.Payload)))
	copy(buf[29:], f.Payload)
	return buf
}

func (f *Frame) WriteTo(w io.Writer) (int64, error) {
	b := f.Encode()
	n, err := w.Write(b)
	return int64(n), err
}

func DecodeFrame(data []byte) (*Frame, error) {
	if len(data) < HeaderSize {
		return nil, ErrFrameTooShort
	}
	f := &Frame{
		Type: data[0],
	}
	copy(f.Session[:], data[1:17])
	f.Seq = binary.BigEndian.Uint64(data[17:25])
	payloadLen := binary.BigEndian.Uint32(data[25:29])
	if payloadLen > MaxPayload {
		return nil, fmt.Errorf("%w: %d", ErrPayloadTooLarge, payloadLen)
	}
	if len(data) < HeaderSize+int(payloadLen) {
		return nil, fmt.Errorf("insufficient data for payload: need %d, have %d", HeaderSize+payloadLen, len(data))
	}
	f.Payload = make([]byte, payloadLen)
	copy(f.Payload, data[HeaderSize:HeaderSize+int(payloadLen)])
	return f, nil
}

func ReadFrame(r io.Reader) (*Frame, error) {
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	payloadLen := binary.BigEndian.Uint32(header[25:29])
	if payloadLen > MaxPayload {
		return nil, fmt.Errorf("%w: %d", ErrPayloadTooLarge, payloadLen)
	}
	buf := make([]byte, HeaderSize+int(payloadLen))
	copy(buf[:HeaderSize], header)
	if payloadLen > 0 {
		if _, err := io.ReadFull(r, buf[HeaderSize:]); err != nil {
			return nil, err
		}
	}
	return DecodeFrame(buf)
}
