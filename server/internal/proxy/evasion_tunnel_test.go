package proxy

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFindEvasionSNIOffset_NonTLS(t *testing.T) {
	data := []byte("GET / HTTP/1.1\r\nHost: google.com\r\n\r\n")
	offset := findEvasionSNIOffset(data)
	if offset != -1 {
		t.Errorf("Expected offset -1 for non-TLS traffic, got %d", offset)
	}
}

func TestFindEvasionSNIOffset_ShortData(t *testing.T) {
	data := []byte{0x16, 0x03, 0x01, 0x00}
	offset := findEvasionSNIOffset(data)
	if offset != -1 {
		t.Errorf("Expected offset -1 for short packet, got %d", offset)
	}
}

func TestFindEvasionSNIOffset_ValidClientHello(t *testing.T) {
	data := make([]byte, 200)

	// TLS Record Header
	data[0] = 0x16 // Handshake record
	data[1] = 0x03 // TLS 1.0/1.2/1.3
	data[2] = 0x01
	binary.BigEndian.PutUint16(data[3:5], 195) // Length of record

	// Handshake Header
	data[5] = 0x01 // Client Hello
	data[6] = 0x00
	data[7] = 0x00
	data[8] = 191
	data[9] = 0x03 // TLS 1.2 Version
	data[10] = 0x03

	// Session ID length (0) at offset 43
	data[43] = 0x00

	// Cipher Suites length (2 bytes) at offset 44
	binary.BigEndian.PutUint16(data[44:46], 2)
	data[46] = 0x00
	data[47] = 0x2f // TLS_RSA_WITH_AES_128_CBC_SHA

	// Compression methods length (1 byte) at offset 48
	data[48] = 0x01
	data[49] = 0x00 // null compression

	// Extensions Length (2 bytes) at offset 50
	binary.BigEndian.PutUint16(data[50:52], 141)

	// Extension 1: SNI (Type 0x0000) at offset 52
	binary.BigEndian.PutUint16(data[52:54], 0)  // Type: SNI
	binary.BigEndian.PutUint16(data[54:56], 20) // Extension Length
	binary.BigEndian.PutUint16(data[56:58], 18)
	data[58] = 0x00 // Name Type: host_name
	binary.BigEndian.PutUint16(data[59:61], 15)
	copy(data[61:76], []byte("example.website"))

	offset := findEvasionSNIOffset(data)
	if offset != 52 {
		t.Errorf("Expected SNI extension start offset 52, got %d", offset)
	}
}

func TestEvasionTunnelConn_Write_Range(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	conn := &evasionTunnelConn{
		Conn:       c1,
		splitBytes: 0,
		delayMs:    1,
		mutateHost: false,
		autoSni:    false,
		packets:    "all",
		minLength:  5,
		maxLength:  10,
		firstWrite: true,
	}

	payload := []byte("This is a test payload that should be fragmented into smaller chunks.")

	readChan := make(chan []byte, 1)
	go func() {
		buf := make([]byte, len(payload))
		_, err := io.ReadFull(c2, buf)
		if err != nil {
			readChan <- nil
		} else {
			readChan <- buf
		}
	}()

	n, err := conn.Write(payload)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(payload) {
		t.Errorf("Expected to write %d bytes, wrote %d", len(payload), n)
	}

	received := <-readChan
	if received == nil {
		t.Fatalf("Failed to read expected bytes from c2")
	}
	if string(received) != string(payload) {
		t.Errorf("Expected received data %q, got %q", string(payload), string(received))
	}
}

func TestEvasionTunnel_ForwardDNSQuery_UDP(t *testing.T) {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to resolve UDP addr: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("Failed to listen UDP: %v", err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().String()

	go func() {
		buf := make([]byte, 512)
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		resp := make([]byte, n+4)
		copy(resp, buf[:n])
		resp[7] = 1
		_, _ = conn.WriteToUDP(resp, clientAddr)
	}()

	mgr := GetEvasionManager()
	query := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	resp, err := mgr.forwardDNSQuery(query, localAddr)
	if err != nil {
		t.Fatalf("forwardDNSQuery failed: %v", err)
	}

	if len(resp) < 12 {
		t.Errorf("Response too short: %d", len(resp))
	}
	if resp[0] != 0x12 || resp[1] != 0x34 {
		t.Errorf("Expected Transaction ID 0x1234, got %x%x", resp[0], resp[1])
	}
}

func TestEvasionTunnel_ForwardDNSQuery_DoH(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Content-Type") != "application/dns-message" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		resp := make([]byte, len(body))
		copy(resp, body)
		resp[0] = 0x00
		resp[1] = 0x00
		w.Write(resp)
	}))
	defer ts.Close()

	mgr := GetEvasionManager()
	query := []byte{0x56, 0x78, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	resp, err := mgr.forwardDNSQuery(query, ts.URL)
	if err != nil {
		t.Fatalf("forwardDNSQuery DoH failed: %v", err)
	}

	if len(resp) < 12 {
		t.Errorf("Response too short: %d", len(resp))
	}
	if resp[0] != 0x56 || resp[1] != 0x78 {
		t.Errorf("Expected Transaction ID 0x5678, got %x%x (overwrite check failed)", resp[0], resp[1])
	}
}

func TestEvasionTunnelConn_Write_SNISplitOffset(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	conn := &evasionTunnelConn{
		Conn:           c1,
		splitBytes:     0,
		delayMs:        1,
		mutateHost:     false,
		autoSni:        true,
		sniSplitOffset: 3, // Split 3 bytes inside the SNI hostname "example.website"
		packets:        "tlshello",
		minLength:      0,
		maxLength:      0,
		firstWrite:     true,
	}

	// Build a valid ClientHello
	data := make([]byte, 200)
	data[0] = 0x16 // Handshake record
	data[1] = 0x03 // TLS
	data[2] = 0x01
	binary.BigEndian.PutUint16(data[3:5], 195)
	data[5] = 0x01 // Client Hello
	data[6] = 0x00
	data[7] = 0x00
	data[8] = 191
	data[9] = 0x03
	data[10] = 0x03
	data[43] = 0x00 // Session ID length
	binary.BigEndian.PutUint16(data[44:46], 2) // Cipher suites
	data[46] = 0x00
	data[47] = 0x2f
	data[48] = 0x01 // Compression
	data[49] = 0x00
	binary.BigEndian.PutUint16(data[50:52], 141) // Extensions length
	binary.BigEndian.PutUint16(data[52:54], 0)   // SNI extension type
	binary.BigEndian.PutUint16(data[54:56], 20)  // SNI extension length
	binary.BigEndian.PutUint16(data[56:58], 18)
	data[58] = 0x00 // Name type: host_name
	binary.BigEndian.PutUint16(data[59:61], 15)  // Name length: 15
	copy(data[61:76], []byte("example.website"))

	// SNI extension header is at index 52.
	// Hostname starts at index 52 + 9 = 61.
	// Split offset is 3, so splitAt = 61 + 3 = 64.
	expectedSplitAt := 64

	var writeBuf []byte
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		// Read the first chunk (expected size: expectedSplitAt = 64)
		chunk1 := make([]byte, expectedSplitAt)
		n, err := io.ReadFull(c2, chunk1)
		if err != nil {
			t.Errorf("Failed to read chunk 1: %v", err)
			return
		}
		writeBuf = append(writeBuf, chunk1[:n]...)

		// Read the remaining chunk
		chunk2 := make([]byte, len(data)-expectedSplitAt)
		n, err = io.ReadFull(c2, chunk2)
		if err != nil {
			t.Errorf("Failed to read chunk 2: %v", err)
			return
		}
		writeBuf = append(writeBuf, chunk2[:n]...)
	}()

	n, err := conn.Write(data)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(data) {
		t.Errorf("Expected to write %d bytes, wrote %d", len(data), n)
	}

	<-readDone

	if len(writeBuf) != len(data) {
		t.Fatalf("Expected reassembled write buffer size %d, got %d", len(data), len(writeBuf))
	}
	for i := range data {
		if writeBuf[i] != data[i] {
			t.Errorf("Mismatch at index %d: expected %x, got %x", i, data[i], writeBuf[i])
		}
	}
}

func TestReplaceSniInHello(t *testing.T) {
	// Build a valid ClientHello
	data := make([]byte, 200)
	data[0] = 0x16 // Handshake record
	data[1] = 0x03 // TLS
	data[2] = 0x01
	binary.BigEndian.PutUint16(data[3:5], 195)
	data[5] = 0x01 // Client Hello
	data[6] = 0x00
	data[7] = 0x00
	data[8] = 191
	data[9] = 0x03
	data[10] = 0x03
	data[43] = 0x00 // Session ID length
	binary.BigEndian.PutUint16(data[44:46], 2) // Cipher suites
	data[46] = 0x00
	data[47] = 0x2f
	data[48] = 0x01 // Compression
	data[49] = 0x00
	binary.BigEndian.PutUint16(data[50:52], 141) // Extensions length
	binary.BigEndian.PutUint16(data[52:54], 0)   // SNI extension type
	binary.BigEndian.PutUint16(data[54:56], 20)  // SNI extension length
	binary.BigEndian.PutUint16(data[56:58], 18)
	data[58] = 0x00 // Name type: host_name
	binary.BigEndian.PutUint16(data[59:61], 15)  // Name length: 15
	copy(data[61:76], []byte("example.website"))

	newSni := "google.com"
	replaced := ReplaceSniInHello(data, newSni)

	if len(replaced) == 0 {
		t.Fatalf("Replaced packet is empty")
	}

	// Find SNI offset of replaced packet
	newOffset := findEvasionSNIOffset(replaced)
	if newOffset == -1 {
		t.Fatalf("Could not find SNI offset in replaced packet")
	}

	nameLen := binary.BigEndian.Uint16(replaced[newOffset+7 : newOffset+9])
	if int(nameLen) != len(newSni) {
		t.Errorf("Expected name length %d, got %d", len(newSni), nameLen)
	}

	name := string(replaced[newOffset+9 : newOffset+9+int(nameLen)])
	if name != newSni {
		t.Errorf("Expected name %q, got %q", newSni, name)
	}
}

func TestEvasionTunnelConn_Write_SniSpoof(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	conn := &evasionTunnelConn{
		Conn:           c1,
		splitBytes:     0,
		delayMs:        1,
		mutateHost:     false,
		autoSni:        false,
		sniSpoof:       "spoofed.domain",
		packets:        "tlshello",
		firstWrite:     true,
	}

	// Build a valid ClientHello
	data := make([]byte, 200)
	data[0] = 0x16 // Handshake record
	data[1] = 0x03 // TLS
	data[2] = 0x01
	binary.BigEndian.PutUint16(data[3:5], 195)
	data[5] = 0x01 // Client Hello
	data[6] = 0x00
	data[7] = 0x00
	data[8] = 191
	data[9] = 0x03
	data[10] = 0x03
	data[43] = 0x00 // Session ID length
	binary.BigEndian.PutUint16(data[44:46], 2) // Cipher suites
	data[46] = 0x00
	data[47] = 0x2f
	data[48] = 0x01 // Compression
	data[49] = 0x00
	binary.BigEndian.PutUint16(data[50:52], 141) // Extensions length
	binary.BigEndian.PutUint16(data[52:54], 0)   // SNI extension type
	binary.BigEndian.PutUint16(data[54:56], 20)  // SNI extension length
	binary.BigEndian.PutUint16(data[56:58], 18)
	data[58] = 0x00 // Name type: host_name
	binary.BigEndian.PutUint16(data[59:61], 15)  // Name length: 15
	copy(data[61:76], []byte("example.website"))

	var writeBuf []byte
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, 500)
		n, err := c2.Read(buf)
		if err == nil {
			writeBuf = append(writeBuf, buf[:n]...)
		}
	}()

	_, err := conn.Write(data)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	<-readDone

	if len(writeBuf) == 0 {
		t.Fatalf("Read zero bytes from pipe")
	}

	newOffset := findEvasionSNIOffset(writeBuf)
	if newOffset == -1 {
		t.Fatalf("Could not find SNI offset in written packet")
	}

	nameLen := binary.BigEndian.Uint16(writeBuf[newOffset+7 : newOffset+9])
	if int(nameLen) != len("spoofed.domain") {
		t.Errorf("Expected name length %d, got %d", len("spoofed.domain"), nameLen)
	}

	name := string(writeBuf[newOffset+9 : newOffset+9+int(nameLen)])
	if name != "spoofed.domain" {
		t.Errorf("Expected name %q, got %q", "spoofed.domain", name)
	}
}

func TestEvasionTunnelConn_Write_Padding(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	conn := &evasionTunnelConn{
		Conn:               c1,
		splitBytes:         0,
		delayMs:            1,
		mutateHost:         false,
		autoSni:            false,
		clientHelloPadding: 100,
		packets:            "tlshello",
		firstWrite:         true,
	}

	// Build a valid ClientHello
	data := make([]byte, 200)
	data[0] = 0x16 // Handshake record
	data[1] = 0x03 // TLS
	data[2] = 0x01
	binary.BigEndian.PutUint16(data[3:5], 195)
	data[5] = 0x01 // Client Hello
	data[6] = 0x00
	data[7] = 0x00
	data[8] = 191
	data[9] = 0x03
	data[10] = 0x03
	data[43] = 0x00 // Session ID length
	binary.BigEndian.PutUint16(data[44:46], 2) // Cipher suites
	data[46] = 0x00
	data[47] = 0x2f
	data[48] = 0x01 // Compression
	data[49] = 0x00
	binary.BigEndian.PutUint16(data[50:52], 141) // Extensions length
	binary.BigEndian.PutUint16(data[52:54], 0)   // SNI extension type
	binary.BigEndian.PutUint16(data[54:56], 20)  // SNI extension length
	binary.BigEndian.PutUint16(data[56:58], 18)
	data[58] = 0x00 // Name type: host_name
	binary.BigEndian.PutUint16(data[59:61], 15)  // Name length: 15
	copy(data[61:76], []byte("example.website"))

	var writeBuf []byte
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, 500)
		n, err := c2.Read(buf)
		if err == nil {
			writeBuf = append(writeBuf, buf[:n]...)
		}
	}()

	_, err := conn.Write(data)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	<-readDone

	if len(writeBuf) == 0 {
		t.Fatalf("Read zero bytes from pipe")
	}

	// The written packet must be padded by 104 bytes (100 zeros + 4 bytes extension header)
	expectedLen := len(data) + 104
	if len(writeBuf) != expectedLen {
		t.Errorf("Expected padded packet length %d, got %d", expectedLen, len(writeBuf))
	}
}

func TestEvasionTunnelConn_Write_JitterAndUA(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	conn := &evasionTunnelConn{
		Conn:            c1,
		splitBytes:      5,
		delayMs:         2,
		mutateHost:      true,
		autoSni:         false,
		delayJitter:     true,
		customUserAgent: "Mozilla/TestSpoof",
		packets:         "all",
		firstWrite:      true,
	}

	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Go-http-client/1.1\r\n\r\n")

	readChan := make(chan []byte, 1)
	go func() {
		receivedData := make([]byte, 0, 500)
		buf := make([]byte, 256)
		for !strings.HasSuffix(string(receivedData), "\r\n\r\n") {
			n, err := c2.Read(buf)
			if err != nil {
				break
			}
			receivedData = append(receivedData, buf[:n]...)
		}
		readChan <- receivedData
	}()

	n, err := conn.Write(payload)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	received := <-readChan
	if received == nil {
		t.Fatalf("Failed to read from pipe")
	}

	recStr := string(received)
	if !strings.Contains(recStr, "hOsT:") {
		t.Errorf("Expected mutated host header to contain 'hOsT:', got: %q", recStr)
	}
	if !strings.Contains(recStr, "User-Agent: Mozilla/TestSpoof") {
		t.Errorf("Expected User-Agent to be spoofed with 'Mozilla/TestSpoof', got: %q", recStr)
	}
	if n != len(received) {
		t.Errorf("Expected conn.Write to return written bytes %d, got %d", len(received), n)
	}
}

func TestEvasionTunnelConn_Write_MutateHeaderSpace(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	conn := &evasionTunnelConn{
		Conn:              c1,
		splitBytes:        0,
		delayMs:           1,
		mutateHost:        false,
		mutateHeaderSpace: true,
		packets:           "all",
		firstWrite:        true,
	}

	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	readChan := make(chan []byte, 1)
	go func() {
		receivedData := make([]byte, 0, 500)
		buf := make([]byte, 256)
		for !strings.HasSuffix(string(receivedData), "\r\n\r\n") {
			n, err := c2.Read(buf)
			if err != nil {
				break
			}
			receivedData = append(receivedData, buf[:n]...)
		}
		readChan <- receivedData
	}()

	_, err := conn.Write(payload)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	received := <-readChan
	if received == nil {
		t.Fatalf("Failed to read from pipe")
	}

	recStr := string(received)
	if !strings.Contains(recStr, "Host :") {
		t.Errorf("Expected mutated header to contain 'Host :', got: %q", recStr)
	}
}

func TestEvasionTunnelConn_Write_TcpWindowClamp(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	conn := &evasionTunnelConn{
		Conn:           c1,
		splitBytes:     0,
		delayMs:        1,
		tcpWindowClamp: 4,
		packets:        "all",
		firstWrite:     true,
	}

	payload := []byte("ABCDEFGHIJ") // 10 bytes

	readChan := make(chan [][]byte, 1)
	go func() {
		var chunks [][]byte
		buf := make([]byte, 256)
		total := 0
		for total < len(payload) {
			n, err := c2.Read(buf)
			if err != nil {
				break
			}
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			chunks = append(chunks, chunk)
			total += n
		}
		readChan <- chunks
	}()

	_, err := conn.Write(payload)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	chunks := <-readChan
	if len(chunks) < 3 {
		t.Errorf("Expected payload to be fragmented into at least 3 chunks with clamp=4, got: %d chunks", len(chunks))
	}

	for _, chunk := range chunks {
		if len(chunk) > 4 {
			t.Errorf("Expected chunk size <= 4, got chunk of size %d: %q", len(chunk), string(chunk))
		}
	}
}

func TestParseCPSPacket(t *testing.T) {
	// 1. Static hex bytes
	res, err := parseCPSPacket("<b 0a0b 0c>")
	if err != nil {
		t.Fatalf("Failed to parse static bytes: %v", err)
	}
	expected := []byte{0x0a, 0x0b, 0x0c}
	if !bytes.Equal(res, expected) {
		t.Errorf("Expected %x, got %x", expected, res)
	}

	// 2. Timestamp and Counter
	res, err = parseCPSPacket("<t><c>")
	if err != nil {
		t.Fatalf("Failed to parse timestamp/counter: %v", err)
	}
	if len(res) != 8 {
		t.Errorf("Expected 8 bytes for timestamp+counter, got %d", len(res))
	}

	// 3. Random bytes
	res, err = parseCPSPacket("<r 16>")
	if err != nil {
		t.Fatalf("Failed to parse random bytes: %v", err)
	}
	if len(res) != 16 {
		t.Errorf("Expected 16 random bytes, got %d", len(res))
	}

	// 4. Nonce
	res, err = parseCPSPacket("<n>")
	if err != nil {
		t.Fatalf("Failed to parse nonce: %v", err)
	}
	if len(res) != 8 {
		t.Errorf("Expected 8 bytes for nonce, got %d", len(res))
	}

	// 5. XOR obfuscation
	res, err = parseCPSPacket("<b 55aa><x 255>")
	if err != nil {
		t.Fatalf("Failed to parse XOR key: %v", err)
	}
	expectedXor := []byte{0x55 ^ 0xff, 0xaa ^ 0xff}
	if !bytes.Equal(res, expectedXor) {
		t.Errorf("Expected XORed %x, got %x", expectedXor, res)
	}
}

func TestEvasionTunnelConn_Write_PreflightSignature(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	conn := &evasionTunnelConn{
		Conn:               c1,
		splitBytes:         0,
		delayMs:            1,
		packets:            "all",
		firstWrite:         true,
		preflightSignature: "<b aa bb cc>",
		preflightDelayMs:   5,
	}

	payload := []byte("payload")

	readChan := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 10)
		_, err := io.ReadFull(c2, buf)
		if err != nil {
			readChan <- nil
		} else {
			readChan <- buf
		}
	}()

	_, err := conn.Write(payload)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	received := <-readChan
	if received == nil {
		t.Fatalf("Failed to read from pipe")
	}

	// Expected output is signature bytes followed by payload
	expected := []byte{0xaa, 0xbb, 0xcc, 'p', 'a', 'y', 'l', 'o', 'a', 'd'}
	if !bytes.Equal(received, expected) {
		t.Errorf("Expected received data %x, got %x", expected, received)
	}
}

func TestEvasionTunnelConn_Write_SessionFragmentation(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	conn := &evasionTunnelConn{
		Conn:                  c1,
		firstWrite:            true,
		sessionFrag:           true,
		sessionFragProb:       1.0,
		sessionFragMinTotal:   15,
		sessionFragMaxTotal:   20,
		sessionFragMinChunk:   2,
		sessionFragMaxChunk:   5,
		sessionFragMinDelayMs: 1,
		sessionFragMaxDelayMs: 2,
	}

	payload := []byte("123456789012345678901234567890")

	readChan := make(chan []byte, 1)
	go func() {
		buf := make([]byte, len(payload))
		_, err := io.ReadFull(c2, buf)
		if err != nil {
			readChan <- nil
		} else {
			readChan <- buf
		}
	}()

	n, err := conn.Write(payload)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(payload) {
		t.Errorf("Expected to write %d bytes, wrote %d", len(payload), n)
	}

	received := <-readChan
	if received == nil {
		t.Fatalf("Failed to read from pipe")
	}

	if !bytes.Equal(received, payload) {
		t.Errorf("Expected received data %s, got %s", string(payload), string(received))
	}

	if !conn.sessionFragDetermined {
		t.Errorf("Expected session fragmentation decision to be made")
	}
	if conn.sessionFragTotalBytes < 15 || conn.sessionFragTotalBytes > 20 {
		t.Errorf("Expected total bytes to fragment to be between 15 and 20, got %d", conn.sessionFragTotalBytes)
	}
	if conn.sessionFragBytesCount < conn.sessionFragTotalBytes {
		t.Errorf("Expected fragmented bytes count (%d) to reach or exceed total bytes to fragment (%d)", conn.sessionFragBytesCount, conn.sessionFragTotalBytes)
	}
}



