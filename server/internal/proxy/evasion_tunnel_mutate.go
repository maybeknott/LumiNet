package proxy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"strings"
)

func findEvasionSNIOffset(data []byte) int {
	if len(data) < 47 {
		return -1
	}
	if data[0] != 0x16 || data[1] != 0x03 {
		return -1
	}
	if data[5] != 0x01 {
		return -1
	}

	sidLen := int(data[43])
	if 44+sidLen+2 > len(data) {
		return -1
	}

	csLenOffset := 44 + sidLen
	if csLenOffset+2 > len(data) {
		return -1
	}
	csLen := int(binary.BigEndian.Uint16(data[csLenOffset : csLenOffset+2]))
	if csLenOffset+2+csLen+1 > len(data) {
		return -1
	}

	cmLenOffset := 46 + sidLen + csLen
	cmLen := int(data[cmLenOffset])
	if cmLenOffset+1+cmLen+2 > len(data) {
		return -1
	}

	extsLenOffset := 47 + sidLen + csLen + cmLen
	extsLen := int(binary.BigEndian.Uint16(data[extsLenOffset : extsLenOffset+2]))
	extStart := extsLenOffset + 2
	if extStart+extsLen > len(data) {
		return -1
	}

	idx := extStart
	for idx+4 <= len(data) {
		extType := binary.BigEndian.Uint16(data[idx : idx+2])
		extLen := int(binary.BigEndian.Uint16(data[idx+2 : idx+4]))
		if idx+4+extLen > len(data) {
			break
		}
		if extType == 0 {
			return idx
		}
		idx += 4 + extLen
	}

	return -1
}

func normalizeHttpHeaders(b []byte, customUserAgent string, mutateMethod bool, mutateAbsoluteUri bool, httpPadding int) []byte {
	if len(b) < 16 {
		return b
	}
	isHttp := false
	for _, verb := range []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH "} {
		if strings.HasPrefix(string(b), verb) {
			isHttp = true
			break
		}
	}
	if !isHttp {
		return b
	}

	parts := strings.SplitN(string(b), "\r\n\r\n", 2)
	if len(parts) < 2 {
		return b
	}

	headerPart := parts[0]
	bodyPart := parts[1]

	headerLines := strings.Split(headerPart, "\r\n")
	if len(headerLines) < 2 {
		return b
	}

	requestLine := headerLines[0]
	headers := make(map[string][]string)

	for _, line := range headerLines[1:] {
		if line == "" {
			continue
		}
		kv := strings.SplitN(line, ":", 2)
		if len(kv) == 2 {
			key := strings.TrimSpace(kv[0])
			val := strings.TrimSpace(kv[1])
			headers[key] = append(headers[key], val)
		}
	}

	if customUserAgent != "" {
		headers["User-Agent"] = []string{customUserAgent}
	}

	// Apply HTTP Absolute URI mutation if enabled
	if mutateAbsoluteUri {
		// Find Host header
		var hostHeader string
		if hostVals, found := headers["Host"]; found && len(hostVals) > 0 {
			hostHeader = hostVals[0]
		}
		if hostHeader != "" {
			reqParts := strings.SplitN(requestLine, " ", 3)
			if len(reqParts) == 3 {
				method := reqParts[0]
				path := reqParts[1]
				version := reqParts[2]
				if !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://") {
					requestLine = method + " http://" + hostHeader + path + " " + version
				}
			}
		}
	}

	// Apply HTTP Method Casing Mutation if enabled
	if mutateMethod {
		reqParts := strings.SplitN(requestLine, " ", 2)
		if len(reqParts) == 2 {
			mutatedMethod := mutateStringCasing(reqParts[0])
			requestLine = mutatedMethod + " " + reqParts[1]
		}
	}

	var reassembled strings.Builder
	reassembled.WriteString(requestLine + "\r\n")

	// Apply HTTP Header Padding if enabled
	if httpPadding > 0 {
		for i := 0; i < httpPadding; i++ {
			paddingKey := fmt.Sprintf("X-Evasion-Padding-%03d", i)
			paddingVal := fmt.Sprintf("padding-content-offset-%d-length-%d", i, 50+rand.Intn(50))
			reassembled.WriteString(paddingKey + ": " + paddingVal + "\r\n")
		}
	}

	// Standard order list
	stdOrder := []string{"Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding", "Connection"}
	for _, key := range stdOrder {
		if vals, found := headers[key]; found {
			for _, val := range vals {
				reassembled.WriteString(key + ": " + val + "\r\n")
			}
			delete(headers, key)
		}
	}

	for key, vals := range headers {
		for _, val := range vals {
			reassembled.WriteString(key + ": " + val + "\r\n")
		}
	}

	reassembled.WriteString("\r\n")
	reassembled.WriteString(bodyPart)

	return []byte(reassembled.String())
}

// MutateSniCaseInHello parses a ClientHello packet, extracts the SNI hostname, mutates its casing and replaces it.
func MutateSniCaseInHello(packet []byte) []byte {
	sniIdx := findEvasionSNIOffset(packet)
	if sniIdx == -1 {
		return packet
	}
	if sniIdx+9 > len(packet) {
		return packet
	}
	hostLen := int(binary.BigEndian.Uint16(packet[sniIdx+7 : sniIdx+9]))
	if sniIdx+9+hostLen > len(packet) {
		return packet
	}
	originalHost := string(packet[sniIdx+9 : sniIdx+9+hostLen])
	
	mutatedHost := mutateStringCasing(originalHost)
	
	return ReplaceSniInHello(packet, mutatedHost)
}

func mutateStringCasing(s string) string {
	runes := []rune(s)
	for i, r := range runes {
		if r >= 'a' && r <= 'z' {
			if i%2 == 0 {
				runes[i] = r - 'a' + 'A'
			}
		} else if r >= 'A' && r <= 'Z' {
			if i%2 != 0 {
				runes[i] = r - 'A' + 'a'
			}
		}
	}
	return string(runes)
}

// ReplaceSniInHello parses a ClientHello packet, locates the SNI extension, and replaces the SNI domain name.
// It updates the length fields in the TLS record, handshake layer, and extensions block.
func ReplaceSniInHello(packet []byte, newSni string) []byte {
	if len(packet) < 47 {
		return packet
	}
	if packet[0] != 0x16 || packet[1] != 0x03 {
		return packet
	}
	sniIdx := findEvasionSNIOffset(packet)
	if sniIdx == -1 {
		// As a fallback, look for type bytes directly
		idx := bytes.Index(packet, []byte{0x00, 0x00})
		if idx == -1 {
			return packet
		}
		sniIdx = idx
	}

	// Reconstruct the handshake packet with the modified SNI string
	// Split before extension
	beforeSni := packet[:sniIdx]

	extLen := int(binary.BigEndian.Uint16(packet[sniIdx+2 : sniIdx+4]))
	afterSniOffset := sniIdx + 4 + extLen
	if afterSniOffset > len(packet) {
		return packet
	}
	afterSni := packet[afterSniOffset:]

	sniBytes := []byte(newSni)
	sniLen := len(sniBytes)

	newExtLen := sniLen + 5
	newExt := make([]byte, 4+newExtLen)

	binary.BigEndian.PutUint16(newExt[0:2], 0)
	binary.BigEndian.PutUint16(newExt[2:4], uint16(newExtLen))
	binary.BigEndian.PutUint16(newExt[4:6], uint16(sniLen+3))
	newExt[6] = 0
	binary.BigEndian.PutUint16(newExt[7:9], uint16(sniLen))
	copy(newExt[9:], sniBytes)

	newPacket := append([]byte{}, beforeSni...)
	newPacket = append(newPacket, newExt...)
	newPacket = append(newPacket, afterSni...)

	// Recalculate and update the length fields
	sidLen := int(packet[43])
	csLenOffset := 44 + sidLen
	if csLenOffset+2 > len(packet) {
		return newPacket
	}
	csLen := int(binary.BigEndian.Uint16(packet[csLenOffset : csLenOffset+2]))
	cmLenOffset := 46 + sidLen + csLen
	if cmLenOffset >= len(packet) {
		return newPacket
	}
	cmLen := int(packet[cmLenOffset])
	extsLenOffset := 47 + sidLen + csLen + cmLen
	if extsLenOffset+2 > len(packet) {
		return newPacket
	}

	diff := len(newPacket) - len(packet)

	oldExtsLen := int(binary.BigEndian.Uint16(newPacket[extsLenOffset : extsLenOffset+2]))
	newExtsLen := oldExtsLen + diff
	binary.BigEndian.PutUint16(newPacket[extsLenOffset:extsLenOffset+2], uint16(newExtsLen))

	oldHandshakeLen := int(newPacket[6])<<16 | int(newPacket[7])<<8 | int(newPacket[8])
	newHandshakeLen := oldHandshakeLen + diff
	newPacket[6] = byte((newHandshakeLen >> 16) & 0xff)
	newPacket[7] = byte((newHandshakeLen >> 8) & 0xff)
	newPacket[8] = byte(newHandshakeLen & 0xff)

	oldRecordLen := int(binary.BigEndian.Uint16(newPacket[3:5]))
	newRecordLen := oldRecordLen + diff
	binary.BigEndian.PutUint16(newPacket[3:5], uint16(newRecordLen))

	return newPacket
}

func padClientHelloBytes(raw []byte, padLen int) ([]byte, error) {
	if len(raw) < 43 {
		return nil, fmt.Errorf("ClientHello too short")
	}
	if raw[0] != 0x16 {
		return nil, fmt.Errorf("Not a handshake record")
	}
	if raw[5] != 0x01 {
		return nil, fmt.Errorf("Not a ClientHello handshake")
	}

	offset := 43
	sessionIDLen := int(raw[offset])
	offset += 1 + sessionIDLen
	if offset+2 > len(raw) {
		return nil, fmt.Errorf("Malformed ClientHello: session ID bounds")
	}

	cipherSuitesLen := int(raw[offset])<<8 | int(raw[offset+1])
	offset += 2 + cipherSuitesLen
	if offset+1 > len(raw) {
		return nil, fmt.Errorf("Malformed ClientHello: cipher suites bounds")
	}

	compressionLen := int(raw[offset])
	offset += 1 + compressionLen

	hasExtensions := offset+2 <= len(raw)

	var result []byte
	extBlockAddedLen := 4 + padLen // 2 bytes type + 2 bytes len + padLen zeros

	if hasExtensions {
		extensionsLen := int(raw[offset])<<8 | int(raw[offset+1])
		if offset+2+extensionsLen > len(raw) {
			return nil, fmt.Errorf("Malformed ClientHello: extensions bounds")
		}

		result = append(result, raw[0:3]...)
		oldRecLen := int(raw[3])<<8 | int(raw[4])
		newRecLen := oldRecLen + extBlockAddedLen
		result = append(result, byte(newRecLen>>8), byte(newRecLen&0xff))

		result = append(result, raw[5]) // Handshake type

		oldHsLen := int(raw[6])<<16 | int(raw[7])<<8 | int(raw[8])
		newHsLen := oldHsLen + extBlockAddedLen
		result = append(result, byte(newHsLen>>16), byte((newHsLen>>8)&0xff), byte(newHsLen&0xff))

		result = append(result, raw[9:offset]...)

		newExtLen := extensionsLen + extBlockAddedLen
		result = append(result, byte(newExtLen>>8), byte(newExtLen&0xff))

		result = append(result, raw[offset+2:offset+2+extensionsLen]...)

		// Append padding extension: type 0x0015 (21), length padLen, then padLen zeros
		result = append(result, 0x00, 0x15)
		result = append(result, byte(padLen>>8), byte(padLen&0xff))
		result = append(result, make([]byte, padLen)...)

		result = append(result, raw[offset+2+extensionsLen:]...)
	} else {
		result = append(result, raw[0:3]...)
		oldRecLen := int(raw[3])<<8 | int(raw[4])
		newRecLen := oldRecLen + 2 + extBlockAddedLen
		result = append(result, byte(newRecLen>>8), byte(newRecLen&0xff))

		result = append(result, raw[5])

		oldHsLen := int(raw[6])<<16 | int(raw[7])<<8 | int(raw[8])
		newHsLen := oldHsLen + 2 + extBlockAddedLen
		result = append(result, byte(newHsLen>>16), byte((newHsLen>>8)&0xff), byte(newHsLen&0xff))

		result = append(result, raw[9:offset]...)

		result = append(result, byte(extBlockAddedLen>>8), byte(extBlockAddedLen&0xff))

		// Append padding extension
		result = append(result, 0x00, 0x15)
		result = append(result, byte(padLen>>8), byte(padLen&0xff))
		result = append(result, make([]byte, padLen)...)
	}

	return result, nil
}

// TlsSNIHostRange parses a raw TLS ClientHello and returns the byte range [start, end)
// of the SNI hostname within the data slice. Returns (0, 0) on any parse failure.
func TlsSNIHostRange(data []byte) (int, int) {
	if len(data) < 5 || data[0] != 0x16 {
		return 0, 0
	}
	i := 5
	if len(data) < i+4 || data[i] != 0x01 {
		return 0, 0
	}
	i += 4
	if len(data) < i+2+32+1 {
		return 0, 0
	}
	i += 2 + 32
	sessionLen := int(data[i])
	i++
	if len(data) < i+sessionLen+2 {
		return 0, 0
	}
	i += sessionLen
	cipherLen := int(data[i])<<8 | int(data[i+1])
	i += 2
	if len(data) < i+cipherLen+1 {
		return 0, 0
	}
	i += cipherLen
	compressionLen := int(data[i])
	i++
	if len(data) < i+compressionLen+2 {
		return 0, 0
	}
	i += compressionLen
	extLen := int(data[i])<<8 | int(data[i+1])
	i += 2
	extEnd := i + extLen
	if len(data) < extEnd {
		return 0, 0
	}
	for i+4 <= extEnd {
		typ := int(data[i])<<8 | int(data[i+1])
		l := int(data[i+2])<<8 | int(data[i+3])
		i += 4
		if i+l > extEnd {
			return 0, 0
		}
		if typ == 0x0000 {
			return sniHostRangeInExtension(data, i, i+l)
		}
		i += l
	}
	return 0, 0
}

// SniSplits returns split points around the SNI hostname in a TLS ClientHello,
// plus fixed points at bytes 1 and 5 to split the record/handshake headers.
// Falls back to nil if the SNI cannot be located.
func SniSplits(data []byte) []int {
	hostStart, hostEnd := TlsSNIHostRange(data)
	if hostStart <= 0 || hostEnd <= hostStart {
		return nil
	}
	candidates := []int{1, 5, hostStart - 8, hostStart - 1, hostStart + 1, hostStart + 7, hostEnd}
	out := make([]int, 0, len(candidates))
	seen := map[int]bool{}
	for _, p := range candidates {
		if p > 0 && p < len(data) && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sortInts(out)
	return out
}

func sortInts(a []int) {
	for i := 1; i < len(a); i++ {
		v := a[i]
		j := i - 1
		for j >= 0 && a[j] > v {
			a[j+1] = a[j]
			j--
		}
		a[j+1] = v
	}
}

func sniHostRangeInExtension(data []byte, start, end int) (int, int) {
	i := start
	if i+2 > end {
		return 0, 0
	}
	listLen := int(data[i])<<8 | int(data[i+1])
	i += 2
	if i+listLen > end {
		return 0, 0
	}
	for i+3 <= end {
		nameType := data[i]
		nameLen := int(data[i+1])<<8 | int(data[i+2])
		i += 3
		if i+nameLen > end {
			return 0, 0
		}
		if nameType == 0 {
			return i, i + nameLen
		}
		i += nameLen
	}
	return 0, 0
}

