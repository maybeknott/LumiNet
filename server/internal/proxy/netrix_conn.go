package proxy

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
)

// NetrixConn wraps a net.Conn with a custom compression and timing jitter layer.
// This matches Netrix's anti-DPI capabilities by compressing streams using LZ4 or Zstd
// and introducing packet delays.
type NetrixConn struct {
	net.Conn
	compression   string
	jitterEnabled bool
	jitterMin     int
	jitterMax     int
	readBuf       []byte
}

// NewNetrixConn wraps a connection with Netrix style compression and jitter features.
func NewNetrixConn(c net.Conn, compression string, jitterEnabled bool, jitterMin, jitterMax int) *NetrixConn {
	return &NetrixConn{
		Conn:          c,
		compression:   strings.ToLower(compression),
		jitterEnabled: jitterEnabled,
		jitterMin:     jitterMin,
		jitterMax:     jitterMax,
	}
}

// compressPayload compresses the write data if it meets the minimum size threshold (1024 bytes).
func (c *NetrixConn) compressPayload(data []byte) (byte, []byte) {
	if len(data) < 1024 {
		return 0x00, data
	}

	switch c.compression {
	case "lz4":
		bound := lz4.CompressBlockBound(len(data))
		buf := make([]byte, bound)
		n, err := lz4.CompressBlock(data, buf, nil)
		if err == nil && n > 0 && n < len(data) {
			return 0x01, buf[:n]
		}
	case "zstd":
		compressed := zstd.EncodeTo(nil, data)
		if len(compressed) < len(data) {
			return 0x02, compressed
		}
	}

	return 0x00, data
}

// Write compresses the data frame and prefixes a custom 9-byte header:
// [Compressed Length (4 bytes)] [Uncompressed Length (4 bytes)] [Compression Flag (1 byte)]
// It also applies timing jitter if configured.
func (c *NetrixConn) Write(b []byte) (int, error) {
	if c.jitterEnabled {
		minMs := c.jitterMin
		maxMs := c.jitterMax
		if minMs <= 0 {
			minMs = 5
		}
		if maxMs < minMs {
			maxMs = minMs + 15
		}
		diff := maxMs - minMs
		var delay int
		if diff > 0 {
			n, err := rand.Int(rand.Reader, big.NewInt(int64(diff)))
			if err == nil {
				delay = minMs + int(n.Int64())
			} else {
				delay = minMs
			}
		} else {
			delay = minMs
		}
		time.Sleep(time.Duration(delay) * time.Millisecond)
	}

	flag, payload := c.compressPayload(b)

	header := make([]byte, 9)
	binary.BigEndian.PutUint32(header[0:4], uint32(len(payload)))
	binary.BigEndian.PutUint32(header[4:8], uint32(len(b)))
	header[8] = flag

	_, err := c.Conn.Write(header)
	if err != nil {
		return 0, err
	}

	_, err = c.Conn.Write(payload)
	if err != nil {
		return 0, err
	}

	return len(b), nil
}

// Read reads a framed payload, decompresses it if necessary, and serves it to the reader.
func (c *NetrixConn) Read(b []byte) (int, error) {
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	header := make([]byte, 9)
	_, err := io.ReadFull(c.Conn, header)
	if err != nil {
		return 0, err
	}

	compLen := binary.BigEndian.Uint32(header[0:4])
	uncompLen := binary.BigEndian.Uint32(header[4:8])
	flag := header[8]

	payload := make([]byte, compLen)
	_, err = io.ReadFull(c.Conn, payload)
	if err != nil {
		return 0, err
	}

	var decompressed []byte
	switch flag {
	case 0x00:
		decompressed = payload
	case 0x01:
		decompressed = make([]byte, uncompLen)
		n, err := lz4.UncompressBlock(payload, decompressed)
		if err != nil {
			return 0, fmt.Errorf("lz4 decompression failed: %w", err)
		}
		decompressed = decompressed[:n]
	case 0x02:
		decompressed, err = zstd.DecodeTo(nil, payload)
		if err != nil {
			return 0, fmt.Errorf("zstd decompression failed: %w", err)
		}
	default:
		return 0, fmt.Errorf("unknown compression flag: 0x%02x", flag)
	}

	n := copy(b, decompressed)
	if n < len(decompressed) {
		c.readBuf = append([]byte(nil), decompressed[n:]...)
	}

	return n, nil
}
