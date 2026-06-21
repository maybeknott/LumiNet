package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
)

type NipoObfuscatedConn struct {
	net.Conn
	isClient     bool
	fakeHost     string
	userAgent    string
	reader       *bufio.Reader
	readBuf      bytes.Buffer
	readMu       sync.Mutex
	writeMu      sync.Mutex
	methods      []string
	endpoints    []string
}

func NewNipoClientConn(conn net.Conn, fakeHost, userAgent string) *NipoObfuscatedConn {
	if fakeHost == "" {
		fakeHost = "google.com"
	}
	if userAgent == "" {
		userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	}
	return &NipoObfuscatedConn{
		Conn:      conn,
		isClient:  true,
		fakeHost:  fakeHost,
		userAgent: userAgent,
		reader:    bufio.NewReader(conn),
		methods:   []string{"GET", "POST", "PUT", "DELETE"},
		endpoints: []string{"api", "login", "user", "update"},
	}
}

func NewNipoServerConn(conn net.Conn) *NipoObfuscatedConn {
	return &NipoObfuscatedConn{
		Conn:     conn,
		isClient: false,
		reader:   bufio.NewReader(conn),
	}
}

func (c *NipoObfuscatedConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	var envelope string
	if c.isClient {
		method := c.methods[rand.Intn(len(c.methods))]
		endpoint := c.endpoints[rand.Intn(len(c.endpoints))]
		envelope = fmt.Sprintf("%s /%s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: %s\r\n"+
			"Accept: */*\r\n"+
			"Connection: keep-alive\r\n"+
			"Content-Length: %d\r\n"+
			"Content-Type: application/x-www-form-urlencoded\r\n\r\n"+
			"%sCOMP\r\n\r\n", method, endpoint, c.fakeHost, c.userAgent, len(b), string(b))
	} else {
		envelope = fmt.Sprintf("HTTP/1.1 200 OK\r\n"+
			"Content-Type: application/x-www-form-urlencoded\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: keep-alive\r\n"+
			"Cache-Control: no-cache\r\n"+
			"Pragma: no-cache\r\n\r\n"+
			"%sCOMP\r\n\r\n", len(b), string(b))
	}

	_, err := c.Conn.Write([]byte(envelope))
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *NipoObfuscatedConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if c.readBuf.Len() > 0 {
		return c.readBuf.Read(b)
	}

	headerBytes, err := readHeaders(c.reader)
	if err != nil {
		return 0, err
	}

	contentLength, err := parseContentLength(headerBytes)
	if err != nil {
		// If there is no content-length, try to parse status/request line boundaries or fallback
		return 0, fmt.Errorf("failed to parse content-length: %w", err)
	}

	body := make([]byte, contentLength)
	_, err = io.ReadFull(c.reader, body)
	if err != nil {
		return 0, err
	}

	// Read and discard trailing COMP\r\n\r\n (8 bytes)
	compBuf := make([]byte, 8)
	_, _ = io.ReadFull(c.reader, compBuf)

	c.readBuf.Write(body)
	return c.readBuf.Read(b)
}

func readHeaders(r *bufio.Reader) ([]byte, error) {
	var headerBuf bytes.Buffer
	for {
		b, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		headerBuf.WriteByte(b)
		data := headerBuf.Bytes()
		if len(data) >= 4 && bytes.Equal(data[len(data)-4:], []byte("\r\n\r\n")) {
			break
		}
	}
	return headerBuf.Bytes(), nil
}

func parseContentLength(headerBytes []byte) (int, error) {
	lines := strings.Split(string(headerBytes), "\r\n")
	for _, line := range lines {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 && strings.EqualFold(strings.TrimSpace(parts[0]), "content-length") {
			val, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil {
				return 0, err
			}
			return val, nil
		}
	}
	return 0, fmt.Errorf("Content-Length header not found")
}
