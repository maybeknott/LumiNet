package proxy

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// GDriveMailbox represents the Google Drive shared folder SOCKS5 mailbox transport.
// It integrates the Zephyr SOCKS5 over Google Drive API transport design.
type GDriveMailbox struct {
	mu             sync.Mutex
	FolderID       string
	SessionID      string
	AccessToken    string
	UseSimulator   bool
	WrapInEnvelope bool
	HTTPClient     *http.Client
}

// NewGDriveMailbox creates a new instance of GDriveMailbox.
func NewGDriveMailbox(folderID, sessionID string) *GDriveMailbox {
	return &GDriveMailbox{
		FolderID:       folderID,
		SessionID:      sessionID,
		UseSimulator:   true, // Default to simulator; caller can set AccessToken and disable simulator
		WrapInEnvelope: true,
		HTTPClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// SendChunk uploads a base64-encoded chunk file to Google Drive.
func (m *GDriveMailbox) SendChunk(ctx context.Context, chunkIdx int, data []byte) error {
	if len(data) == 0 {
		return nil
	}

	var dataToEncode []byte = data
	if m.WrapInEnvelope {
		env := &ZephyrEnvelope{
			SessionID: m.SessionID,
			Seq:       uint64(chunkIdx),
			Payload:   data,
		}
		var err error
		dataToEncode, err = env.Encode()
		if err != nil {
			return err
		}
	}

	payloadB64 := base64.StdEncoding.EncodeToString(dataToEncode)
	fileName := fmt.Sprintf("gdrive_%s_chunk_%d.bin", m.SessionID, chunkIdx)

	if m.UseSimulator {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
		return nil
	}

	// Production Mode: Perform direct HTTP REST API call to Google Drive API v3
	apiUrl := "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id"
	boundary := "gdrive_zephyr_boundary"

	body := fmt.Sprintf(
		"--%s\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{\r\n  \"name\": \"%s\",\r\n  \"parents\": [\"%s\"]\r\n}\r\n"+
			"--%s\r\nContent-Type: application/octet-stream\r\n\r\n%s\r\n--%s--\r\n",
		boundary, fileName, m.FolderID, boundary, payloadB64, boundary,
	)

	req, err := http.NewRequestWithContext(ctx, "POST", apiUrl, strings.NewReader(body))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+m.AccessToken)
	req.Header.Set("Content-Type", "multipart/related; boundary="+boundary)

	resp, err := m.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("google drive API returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// ReadChunk downloads a specific base64-encoded chunk from Google Drive.
func (m *GDriveMailbox) ReadChunk(ctx context.Context, chunkIdx int) ([]byte, error) {
	if m.UseSimulator {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
		return nil, io.EOF
	}

	fileName := fmt.Sprintf("gdrive_%s_chunk_%d.bin", m.SessionID, chunkIdx)
	query := fmt.Sprintf("name = '%s' and '%s' in parents and trashed = false", fileName, m.FolderID)
	listURL := fmt.Sprintf("https://www.googleapis.com/drive/v3/files?q=%s&fields=files(id,name)", url.QueryEscape(query))

	req, err := http.NewRequestWithContext(ctx, "GET", listURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+m.AccessToken)

	resp, err := m.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("google drive list returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var listResp struct {
		Files []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"files"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return nil, err
	}

	if len(listResp.Files) == 0 {
		return nil, nil // Not found yet, poll again
	}

	fileID := listResp.Files[0].ID
	downloadURL := fmt.Sprintf("https://www.googleapis.com/drive/v3/files/%s?alt=media", fileID)
	downloadReq, err := http.NewRequestWithContext(ctx, "GET", downloadURL, nil)
	if err != nil {
		return nil, err
	}
	downloadReq.Header.Set("Authorization", "Bearer "+m.AccessToken)

	downloadResp, err := m.HTTPClient.Do(downloadReq)
	if err != nil {
		return nil, err
	}
	defer downloadResp.Body.Close()

	if downloadResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google drive download returned status %d", downloadResp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(downloadResp.Body)
	if err != nil {
		return nil, err
	}

	decodedBytes, err := base64.StdEncoding.DecodeString(string(bodyBytes))
	if err != nil {
		return nil, err
	}

	// Clean up downloaded file asynchronously
	go func() {
		delReq, _ := http.NewRequest(http.MethodDelete, "https://www.googleapis.com/drive/v3/files/"+fileID, nil)
		delReq.Header.Set("Authorization", "Bearer "+m.AccessToken)
		delResp, err := m.HTTPClient.Do(delReq)
		if err == nil {
			delResp.Body.Close()
		}
	}()

	if m.WrapInEnvelope {
		env, err := DecodeZephyrEnvelope(decodedBytes)
		if err != nil {
			return nil, err
		}
		return env.Payload, nil
	}

	return decodedBytes, nil
}

// VirtualConnection creates a net.Conn wrapper that routes reads and writes via Google Drive API calls.
func (m *GDriveMailbox) VirtualConnection() net.Conn {
	return &gdriveConn{
		mailbox:  m,
		readBuf:  nil,
		chunkIdx: 0,
		writeIdx: 0,
		ctx:      context.Background(),
	}
}

type gdriveConn struct {
	mailbox  *GDriveMailbox
	readBuf  []byte
	chunkIdx int
	writeIdx int
	ctx      context.Context
}

func (c *gdriveConn) Read(b []byte) (int, error) {
	if len(c.readBuf) == 0 {
		for {
			data, err := c.mailbox.ReadChunk(c.ctx, c.chunkIdx)
			if err != nil {
				return 0, err
			}
			if data != nil {
				c.readBuf = data
				c.chunkIdx++
				break
			}
			select {
			case <-c.ctx.Done():
				return 0, c.ctx.Err()
			case <-time.After(150 * time.Millisecond):
			}
		}
	}

	n := copy(b, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *gdriveConn) Write(b []byte) (int, error) {
	err := c.mailbox.SendChunk(c.ctx, c.writeIdx, b)
	if err != nil {
		return 0, err
	}
	c.writeIdx++
	return len(b), nil
}

func (c *gdriveConn) Close() error                       { return nil }
func (c *gdriveConn) LocalAddr() net.Addr                { return nil }
func (c *gdriveConn) RemoteAddr() net.Addr               { return nil }
func (c *gdriveConn) SetDeadline(t time.Time) error      { return nil }
func (c *gdriveConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *gdriveConn) SetWriteDeadline(t time.Time) error { return nil }

// ZephyrEnvelope represents the binary structured envelope from Mralimoh/Zephyr.
type ZephyrEnvelope struct {
	SessionID  string `json:"session_id"`
	Seq        uint64 `json:"seq"`
	TargetAddr string `json:"target_addr,omitempty"`
	Payload    []byte `json:"payload,omitempty"`
	Close      bool   `json:"close,omitempty"`
}

const (
	ZephyrMagicByte     = 0x1F
	ZephyrMaxPayloadLen = 10 * 1024 * 1024
)

func (e *ZephyrEnvelope) Encode() ([]byte, error) {
	metaSize := 1 + 1 + len(e.SessionID) + 8 + 1 + len(e.TargetAddr) + 1 + 4
	buf := make([]byte, 2 + metaSize + len(e.Payload))
	binary.BigEndian.PutUint16(buf[0:2], uint16(metaSize))
	
	offset := 2
	buf[offset] = ZephyrMagicByte
	buf[offset+1] = uint8(len(e.SessionID))
	offset += 2
	copy(buf[offset:], e.SessionID)
	offset += len(e.SessionID)

	binary.BigEndian.PutUint64(buf[offset:], e.Seq)
	offset += 8

	buf[offset] = uint8(len(e.TargetAddr))
	offset++
	copy(buf[offset:], e.TargetAddr)
	offset += len(e.TargetAddr)

	if e.Close {
		buf[offset] = 1
	} else {
		buf[offset] = 0
	}
	offset++

	binary.BigEndian.PutUint32(buf[offset:], uint32(len(e.Payload)))
	offset += 4

	copy(buf[offset:], e.Payload)
	return buf, nil
}

func DecodeZephyrEnvelope(data []byte) (*ZephyrEnvelope, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("data too short for size header")
	}
	metaSize := int(binary.BigEndian.Uint16(data[0:2]))
	if len(data) < 2+metaSize {
		return nil, fmt.Errorf("data too short for meta header")
	}

	buf := data[2 : 2+metaSize]
	if buf[0] != ZephyrMagicByte {
		return nil, fmt.Errorf("invalid magic byte: expected 0x%02X, got 0x%02X", ZephyrMagicByte, buf[0])
	}

	sidLen := int(buf[1])
	if len(buf) < 2+sidLen {
		return nil, fmt.Errorf("metadata buffer too short for session ID")
	}
	sessionID := string(buf[2 : 2+sidLen])
	
	offset := 2 + sidLen
	if len(buf) < offset+8 {
		return nil, fmt.Errorf("metadata buffer too short for sequence")
	}
	seq := binary.BigEndian.Uint64(buf[offset : offset+8])
	offset += 8
	
	if len(buf) < offset+1 {
		return nil, fmt.Errorf("metadata buffer too short for target address length")
	}
	addrLen := int(buf[offset])
	offset++
	var targetAddr string
	if addrLen > 0 {
		if len(buf) < offset+addrLen {
			return nil, fmt.Errorf("metadata buffer too short for target address")
		}
		targetAddr = string(buf[offset : offset+addrLen])
		offset += addrLen
	}

	if len(buf) < offset+1 {
		return nil, fmt.Errorf("metadata buffer too short for close flag")
	}
	isClose := buf[offset] == 1
	offset++

	if len(buf) < offset+4 {
		return nil, fmt.Errorf("metadata buffer too short for payload length")
	}
	payLen := binary.BigEndian.Uint32(buf[offset : offset+4])

	e := &ZephyrEnvelope{
		SessionID:  sessionID,
		Seq:        seq,
		TargetAddr: targetAddr,
		Close:      isClose,
	}

	if payLen > 0 {
		if int(payLen) > len(data)-(2+metaSize) {
			return nil, fmt.Errorf("payload length %d exceeds available data %d", payLen, len(data)-(2+metaSize))
		}
		e.Payload = make([]byte, payLen)
		copy(e.Payload, data[2+metaSize:2+metaSize+int(payLen)])
	}
	return e, nil
}
