package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	utls "github.com/refraction-networking/utls"
)

// ServerlessDialer establishes TCP connections by proxying over a WebSocket or HTTP Serverless Relay.
type ServerlessDialer struct {
	RelayURL string
}

// NewServerlessDialer creates a new dialer for serverless relays.
func NewServerlessDialer(relayURL string) *ServerlessDialer {
	return &ServerlessDialer{
		RelayURL: relayURL,
	}
}

// DialTarget establishes a virtual TCP connection to host:port via the Serverless Relay.
func (d *ServerlessDialer) DialTarget(ctx context.Context, host string, port int) (net.Conn, error) {
	if d.RelayURL == "" {
		return nil, fmt.Errorf("missing relay URL")
	}

	u, err := url.Parse(d.RelayURL)
	if err != nil {
		return nil, fmt.Errorf("invalid relay URL: %w", err)
	}

	if u.Scheme == "http" || u.Scheme == "https" {
		targetAddr := net.JoinHostPort(host, strconv.Itoa(port))
		return NewHttpServerlessConn(d.RelayURL, targetAddr), nil
	}

	dialer := &websocket.Dialer{
		HandshakeTimeout: 5 * time.Second,
		NetDialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			rawConn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			host, _, _ := net.SplitHostPort(addr)
			tlsConfig := &utls.Config{
				ServerName:         host,
				InsecureSkipVerify: true,
			}
			tlsConn := utls.UClient(rawConn, tlsConfig, utls.HelloChrome_Auto)
			if err := tlsConn.Handshake(); err != nil {
				rawConn.Close()
				return nil, err
			}
			return tlsConn, nil
		},
	}

	header := http.Header{}
	header.Set("User-Agent", "LumiNet/1.0 (Serverless Dialer)")

	wsConn, _, err := dialer.DialContext(ctx, d.RelayURL, header)
	if err != nil {
		return nil, fmt.Errorf("websocket dial failed: %w", err)
	}

	// Send connection metadata first
	meta := map[string]interface{}{
		"host": host,
		"port": port,
	}
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		wsConn.Close()
		return nil, fmt.Errorf("failed to marshal metadata: %w", err)
	}

	err = wsConn.WriteMessage(websocket.TextMessage, metaBytes)
	if err != nil {
		wsConn.Close()
		return nil, fmt.Errorf("failed to send metadata: %w", err)
	}

	// Wait for connection confirmation response from the relay server
	_, msg, err := wsConn.ReadMessage()
	if err != nil {
		wsConn.Close()
		return nil, fmt.Errorf("failed to read relay confirmation: %w", err)
	}

	var status map[string]string
	if err := json.Unmarshal(msg, &status); err != nil || status["status"] != "connected" {
		wsConn.Close()
		return nil, fmt.Errorf("relay connection confirmation failed: %s", string(msg))
	}

	return &serverlessConn{
		Conn: wsConn,
	}, nil
}


type serverlessConn struct {
	*websocket.Conn
	readBuf []byte
}

func (s *serverlessConn) Read(b []byte) (int, error) {
	if len(s.readBuf) > 0 {
		n := copy(b, s.readBuf)
		s.readBuf = s.readBuf[n:]
		return n, nil
	}

	_, msg, err := s.ReadMessage()
	if err != nil {
		return 0, err
	}

	n := copy(b, msg)
	if n < len(msg) {
		s.readBuf = msg[n:]
	}
	return n, nil
}

func (s *serverlessConn) Write(b []byte) (int, error) {
	err := s.WriteMessage(websocket.BinaryMessage, b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (s *serverlessConn) LocalAddr() net.Addr {
	return nil
}

func (s *serverlessConn) RemoteAddr() net.Addr {
	return nil
}

func (s *serverlessConn) SetDeadline(t time.Time) error {
	return nil
}

func (s *serverlessConn) SetReadDeadline(t time.Time) error {
	return s.Conn.SetReadDeadline(t)
}

func (s *serverlessConn) SetWriteDeadline(t time.Time) error {
	return s.Conn.SetWriteDeadline(t)
}

type httpServerlessConn struct {
	relayURL   string
	realDst    string
	sessionID  string
	client     *http.Client
	readBuf    bytes.Buffer
	bufMu      sync.Mutex
	txBuf      bytes.Buffer
	txMu       sync.Mutex
	txSignal   chan struct{}
	closed     bool
	pollCtx    context.Context
	pollCancel context.CancelFunc

	// Sequence ordering variables
	writeSeq   uint64
	querySeq   uint64
}

// NewHttpServerlessConn creates a virtual connection executing base64 polling over HTTP POST streams.
func NewHttpServerlessConn(relayURL, realDst string) net.Conn {
	sessBytes := make([]byte, 8)
	_, _ = rand.Read(sessBytes)
	sessID := fmt.Sprintf("sess-%x", sessBytes)

	ctx, cancel := context.WithCancel(context.Background())

	c := &httpServerlessConn{
		relayURL:   relayURL,
		realDst:    realDst,
		sessionID:  sessID,
		client:     &http.Client{Timeout: 10 * time.Second},
		txSignal:   make(chan struct{}, 1),
		pollCtx:    ctx,
		pollCancel: cancel,
	}

	go c.startPollingLoop()
	return c
}

func (c *httpServerlessConn) startPollingLoop() {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-c.pollCtx.Done():
			return
		case <-ticker.C:
		case <-c.txSignal:
		}

		c.txMu.Lock()
		if c.txBuf.Len() == 0 {
			c.txMu.Unlock()
			c.bufMu.Lock()
			bufLen := c.readBuf.Len()
			c.bufMu.Unlock()

			if bufLen == 0 {
				_ = c.sendRequest(nil)
			}
			continue
		}

		// Snapshot data for transaction
		data := make([]byte, c.txBuf.Len())
		copy(data, c.txBuf.Bytes())
		c.txBuf.Reset()
		c.txMu.Unlock()

		err := c.sendRequest(data)
		if err != nil {
			// Transactional Rollback: Prepend failed data back to txBuf
			c.txMu.Lock()
			newData := c.txBuf.Bytes()
			c.txBuf.Reset()
			c.txBuf.Write(data)
			c.txBuf.Write(newData)
			c.txMu.Unlock()

			// Simple backoff
			time.Sleep(1 * time.Second)
		}
	}
}

func (c *httpServerlessConn) sendRequest(data []byte) error {
	c.txMu.Lock()
	qseq := c.querySeq
	c.querySeq++
	var wseqVal *uint64
	if len(data) > 0 {
		w := c.writeSeq
		wseqVal = &w
		c.writeSeq++
	}
	c.txMu.Unlock()

	payload := TunnelPayload{
		SessionID: c.sessionID,
		Target:    c.realDst,
		Data:      data,
		Seq:       &qseq,
		Wseq:      wseqVal,
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		if wseqVal != nil {
			c.txMu.Lock()
			c.writeSeq--
			c.txMu.Unlock()
		}
		return err
	}

	req, err := http.NewRequestWithContext(c.pollCtx, "POST", c.relayURL, bytes.NewReader(bodyBytes))
	if err != nil {
		if wseqVal != nil {
			c.txMu.Lock()
			c.writeSeq--
			c.txMu.Unlock()
		}
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "LumiNet/1.0 (Serverless HTTP Dialer)")

	resp, err := c.client.Do(req)
	if err != nil {
		if wseqVal != nil {
			c.txMu.Lock()
			c.writeSeq--
			c.txMu.Unlock()
		}
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if wseqVal != nil {
			c.txMu.Lock()
			c.writeSeq--
			c.txMu.Unlock()
		}
		return fmt.Errorf("relay returned non-200 status: %d", resp.StatusCode)
	}

	var tunnelResp TunnelResponse
	if err := json.NewDecoder(resp.Body).Decode(&tunnelResp); err != nil {
		if wseqVal != nil {
			c.txMu.Lock()
			c.writeSeq--
			c.txMu.Unlock()
		}
		return err
	}

	if tunnelResp.Error != "" {
		if wseqVal != nil {
			c.txMu.Lock()
			c.writeSeq--
			c.txMu.Unlock()
		}
		return fmt.Errorf("tunnel error: %s", tunnelResp.Error)
	}

	if len(tunnelResp.Data) > 0 {
		c.bufMu.Lock()
		c.readBuf.Write(tunnelResp.Data)
		c.bufMu.Unlock()
	}

	return nil
}


func (c *httpServerlessConn) Read(b []byte) (int, error) {
	for {
		c.bufMu.Lock()
		if c.readBuf.Len() > 0 {
			n, err := c.readBuf.Read(b)
			c.bufMu.Unlock()
			return n, err
		}
		c.bufMu.Unlock()

		if c.closed {
			return 0, io.EOF
		}

		time.Sleep(50 * time.Millisecond)
	}
}

func (c *httpServerlessConn) Write(b []byte) (int, error) {
	if c.closed {
		return 0, fmt.Errorf("connection closed")
	}

	c.txMu.Lock()
	c.txBuf.Write(b)
	c.txMu.Unlock()

	select {
	case c.txSignal <- struct{}{}:
	default:
	}

	return len(b), nil
}

func (c *httpServerlessConn) Close() error {
	c.closed = true
	c.pollCancel()
	return nil
}

func (c *httpServerlessConn) LocalAddr() net.Addr                { return nil }
func (c *httpServerlessConn) RemoteAddr() net.Addr               { return nil }
func (c *httpServerlessConn) SetDeadline(t time.Time) error      { return nil }
func (c *httpServerlessConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *httpServerlessConn) SetWriteDeadline(t time.Time) error { return nil }

