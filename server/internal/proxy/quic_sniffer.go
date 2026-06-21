package proxy

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/hkdf"
)

const (
	quicVersion1 = 0x1
	quicVersion2 = 0x6b3343cf

	hkdfLabelKeyV1 = "quic key"
	hkdfLabelKeyV2 = "quicv2 key"
	hkdfLabelIVV1  = "quic iv"
	hkdfLabelIVV2  = "quicv2 iv"
	hkdfLabelHPV1  = "quic hp"
	hkdfLabelHPV2  = "quicv2 hp"

	cryptoFrameType = 0x06
	paddingFrameType = 0x00
)

var (
	quicSaltOld = []byte{0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99}
	quicSaltV1  = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	quicSaltV2  = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
)

func getSalt(v uint32) []byte {
	switch v {
	case quicVersion1:
		return quicSaltV1
	case quicVersion2:
		return quicSaltV2
	}
	return quicSaltOld
}

func keyLabel(v uint32) string {
	if v == quicVersion2 {
		return hkdfLabelKeyV2
	}
	return hkdfLabelKeyV1
}

func ivLabel(v uint32) string {
	if v == quicVersion2 {
		return hkdfLabelIVV2
	}
	return hkdfLabelIVV1
}

func hpLabel(v uint32) string {
	if v == quicVersion2 {
		return hkdfLabelHPV2
	}
	return hkdfLabelHPV1
}

// SniffQuicInitialSNI extracts the SNI domain name from an outbound QUIC Initial packet.
func SniffQuicInitialSNI(packet []byte) (string, error) {
	if len(packet) < 40 {
		return "", errors.New("packet too short")
	}
	// Check if it's a long header packet
	if packet[0]&0x80 == 0 {
		return "", errors.New("not a long header packet")
	}

	br := bytes.NewReader(packet)
	typeByte, _ := br.ReadByte()

	// Version
	verBytes := make([]byte, 4)
	if _, err := br.Read(verBytes); err != nil {
		return "", err
	}
	version := binary.BigEndian.Uint32(verBytes)

	if version != 0 && typeByte&0x40 == 0 {
		return "", errors.New("not a valid QUIC packet")
	}

	// Destination Connection ID
	destLen, err := br.ReadByte()
	if err != nil {
		return "", err
	}
	destConnID := make([]byte, int(destLen))
	if _, err := br.Read(destConnID); err != nil {
		return "", err
	}

	// Source Connection ID
	srcLen, err := br.ReadByte()
	if err != nil {
		return "", err
	}
	srcConnID := make([]byte, int(srcLen))
	if _, err := br.Read(srcConnID); err != nil {
		return "", err
	}

	// Verify it's an Initial packet
	expectedType := byte(0b00)
	if version == quicVersion2 {
		expectedType = 0b01
	}
	if (typeByte >> 4 & 0b11) != expectedType {
		return "", errors.New("not an initial packet")
	}

	// Read Token Length and Token
	tokenLen, err := readVarint(br)
	if err != nil {
		return "", err
	}
	if tokenLen > 0 {
		if tokenLen > int64(br.Len()) {
			return "", errors.New("token length exceeds packet size")
		}
		// Skip token
		_, _ = br.Seek(tokenLen, io.SeekCurrent)
	}

	// Read Length of payload
	payloadLen, err := readVarint(br)
	if err != nil {
		return "", err
	}

	headerLen := int64(len(packet) - br.Len())

	// Secrets derivation
	initialSecret := hkdf.Extract(sha256.New, destConnID, getSalt(version))
	clientSecret := hkdfExpandLabel(sha256.New, initialSecret, "client in", []byte{}, 32)

	key := hkdfExpandLabel(sha256.New, clientSecret, keyLabel(version), nil, 16)
	iv := hkdfExpandLabel(sha256.New, clientSecret, ivLabel(version), nil, 12)
	hpKey := hkdfExpandLabel(sha256.New, clientSecret, hpLabel(version), nil, 16)

	// AEAD setup
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Header protection setup
	hpBlock, err := aes.NewCipher(hpKey)
	if err != nil {
		return "", err
	}

	// Make a mutable copy of packet
	pktCopy := make([]byte, len(packet))
	copy(pktCopy, packet)

	pnOffset := headerLen
	if pnOffset+4+16 > int64(len(pktCopy)) {
		return "", errors.New("packet too small for header unprotection")
	}

	// Sample offset
	sampleOffset := pnOffset + 4
	sample := pktCopy[sampleOffset : sampleOffset+16]

	mask := make([]byte, hpBlock.BlockSize())
	hpBlock.Encrypt(mask, sample)

	// Unmask first byte
	pktCopy[0] ^= mask[0] & 0x0f

	pnLen := int64(pktCopy[0]&0x03 + 1)
	pnBytes := make([]byte, pnLen)
	for i := int64(0); i < pnLen; i++ {
		pktCopy[pnOffset+i] ^= mask[1+i]
		pnBytes[i] = pktCopy[pnOffset+i]
	}

	// Reconstruct packet number
	var pn int64
	for _, b := range pnBytes {
		pn = (pn << 8) | int64(b)
	}
	pn = decodePacketNumber(2, pn, uint8(pnLen))

	// Re-construct auth header and payload
	authHeader := pktCopy[:pnOffset+pnLen]
	encryptedPayload := pktCopy[pnOffset+pnLen : pnOffset+pnLen+payloadLen-pnLen]

	// Nonce setup
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], uint64(pn))
	for i := range iv {
		nonce[i] ^= iv[i]
	}

	decrypted, err := aead.Open(nil, nonce, encryptedPayload, authHeader)
	if err != nil {
		return "", fmt.Errorf("QUIC Initial decryption failed: %w", err)
	}

	// Parse CRYPTO frames
	cryptoData, err := extractCryptoFrameData(decrypted)
	if err != nil {
		return "", err
	}

	// Parse SNI from ClientHello handshake message
	return parseSNFromClientHello(cryptoData)
}

func readVarint(br *bytes.Reader) (int64, error) {
	b, err := br.ReadByte()
	if err != nil {
		return 0, err
	}
	ver := b >> 6
	val := int64(b & 0x3f)
	var count int
	switch ver {
	case 0:
		return val, nil
	case 1:
		count = 1
	case 2:
		count = 3
	case 3:
		count = 7
	}
	for i := 0; i < count; i++ {
		next, err := br.ReadByte()
		if err != nil {
			return 0, err
		}
		val = (val << 8) | int64(next)
	}
	return val, nil
}

func decodePacketNumber(largest, truncated int64, nbits uint8) int64 {
	expected := largest + 1
	win := int64(1 << (nbits * 8))
	hwin := win / 2
	mask := win - 1
	candidate := (expected &^ mask) | truncated
	switch {
	case candidate <= expected-hwin && candidate < (1<<62)-win:
		return candidate + win
	case candidate > expected+hwin && candidate >= win:
		return candidate - win
	}
	return candidate
}

func hkdfExpandLabel(hash func() hash.Hash, secret []byte, label string, context []byte, length int) []byte {
	var hkdfLabel cryptobyte.Builder
	hkdfLabel.AddUint16(uint16(length))
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte("tls13 "))
		b.AddBytes([]byte(label))
	})
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(context)
	})
	out := make([]byte, length)
	n, err := hkdf.Expand(hash, secret, hkdfLabel.BytesOrPanic()).Read(out)
	if err != nil || n != length {
		panic("quic: HKDF-Expand-Label failed")
	}
	return out
}

func extractCryptoFrameData(payload []byte) ([]byte, error) {
	br := bytes.NewReader(payload)
	for br.Len() > 0 {
		frameType, err := readVarint(br)
		if err != nil {
			return nil, err
		}
		if frameType == paddingFrameType {
			continue
		}
		if frameType != cryptoFrameType {
			return nil, errors.New("not a crypto frame")
		}
		// Read Offset
		_, err = readVarint(br)
		if err != nil {
			return nil, err
		}
		// Read Length
		length, err := readVarint(br)
		if err != nil {
			return nil, err
		}
		if length > int64(br.Len()) {
			return nil, errors.New("crypto frame length exceeds payload size")
		}
		data := make([]byte, length)
		if _, err := br.Read(data); err != nil {
			return nil, err
		}
		return data, nil
	}
	return nil, errors.New("no crypto frame found")
}

func parseSNFromClientHello(data []byte) (string, error) {
	if len(data) < 42 {
		return "", errors.New("handshake message too short")
	}
	if data[0] != 0x01 {
		return "", errors.New("handshake message is not ClientHello")
	}

	offset := 38
	sessionIDLen := int(data[offset])
	offset += 1 + sessionIDLen

	if offset+2 > len(data) {
		return "", errors.New("malformed ClientHello: cipher suites bounds")
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2 + cipherSuitesLen

	if offset+1 > len(data) {
		return "", errors.New("malformed ClientHello: compression methods bounds")
	}
	compressionLen := int(data[offset])
	offset += 1 + compressionLen

	if offset+2 > len(data) {
		return "", errors.New("no extensions in ClientHello")
	}
	extensionsLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	if offset+extensionsLen > len(data) {
		return "", errors.New("malformed ClientHello: extensions bounds")
	}

	end := offset + extensionsLen
	for offset+4 <= end {
		extType := binary.BigEndian.Uint16(data[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4

		if offset+extLen > end {
			break
		}

		if extType == 0 { // Server Name Indication (SNI)
			sniData := data[offset : offset+extLen]
			if len(sniData) < 5 {
				return "", errors.New("SNI extension too short")
			}
			serverNameListLen := int(binary.BigEndian.Uint16(sniData[0:2]))
			if serverNameListLen+2 > len(sniData) {
				return "", errors.New("malformed SNI extension")
			}
			
			nameOffset := 2
			for nameOffset+3 <= len(sniData) {
				nameType := sniData[nameOffset]
				nameLen := int(binary.BigEndian.Uint16(sniData[nameOffset+1 : nameOffset+3]))
				nameOffset += 3
				if nameOffset+nameLen > len(sniData) {
					break
				}
				if nameType == 0 { // host_name
					return string(sniData[nameOffset : nameOffset+nameLen]), nil
				}
				nameOffset += nameLen
			}
			return "", errors.New("no host_name SNI in extension")
		}
		offset += extLen
	}

	return "", errors.New("SNI extension not found in ClientHello")
}
