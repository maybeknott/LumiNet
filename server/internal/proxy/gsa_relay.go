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
	"sync"
	"time"
)

type GsaTunnelConn struct {
	scriptURL  string
	authKey    string
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
}

func NewGsaTunnelConn(scriptURL, authKey, realDst string) *GsaTunnelConn {
	sessBytes := make([]byte, 8)
	_, _ = rand.Read(sessBytes)
	sessID := fmt.Sprintf("sess-%x", sessBytes)

	ctx, cancel := context.WithCancel(context.Background())

	c := &GsaTunnelConn{
		scriptURL:  scriptURL,
		authKey:    authKey,
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

func (c *GsaTunnelConn) startPollingLoop() {
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

func (c *GsaTunnelConn) sendRequest(data []byte) error {
	payload := TunnelPayload{
		SessionID: c.sessionID,
		Target:    c.realDst,
		Data:      data,
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(c.pollCtx, "POST", c.scriptURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.authKey != "" {
		req.Header.Set("X-GSA-Auth-Key", c.authKey)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GSA returned non-200 status: %d", resp.StatusCode)
	}

	var tunnelResp TunnelResponse
	if err := json.NewDecoder(resp.Body).Decode(&tunnelResp); err != nil {
		return err
	}

	if tunnelResp.Error != "" {
		return fmt.Errorf("tunnel error: %s", tunnelResp.Error)
	}

	if len(tunnelResp.Data) > 0 {
		c.bufMu.Lock()
		c.readBuf.Write(tunnelResp.Data)
		c.bufMu.Unlock()
	}

	return nil
}

func (c *GsaTunnelConn) Read(b []byte) (int, error) {
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

func (c *GsaTunnelConn) Write(b []byte) (int, error) {
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

func (c *GsaTunnelConn) Close() error {
	c.closed = true
	c.pollCancel()
	return nil
}

func (c *GsaTunnelConn) LocalAddr() net.Addr                { return nil }
func (c *GsaTunnelConn) RemoteAddr() net.Addr               { return nil }
func (c *GsaTunnelConn) SetDeadline(t time.Time) error      { return nil }
func (c *GsaTunnelConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *GsaTunnelConn) SetWriteDeadline(t time.Time) error { return nil }
