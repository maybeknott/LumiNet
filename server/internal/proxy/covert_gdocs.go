package proxy

import (
	"context"
	"encoding/base64"
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

// GDocsTransport represents a covert transport using Google Docs or Google Drive API.
// It operates in real REST mode when provided an AccessToken, and mock/simulation mode otherwise.
type GDocsTransport struct {
	mu           sync.Mutex
	FolderID     string
	AccessToken  string // OAuth2 access token for real API calls
	UseSimulator bool   // Force simulator mode
	HTTPClient   *http.Client
}

// NewGDocsTransport creates a new Google Docs covert transport.
func NewGDocsTransport(folderID, accessToken string) *GDocsTransport {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	useSim := accessToken == ""
	return &GDocsTransport{
		FolderID:     folderID,
		AccessToken:  accessToken,
		UseSimulator: useSim,
		HTTPClient:   client,
	}
}

// SendChunk uploads a chunk of SOCKS5 data to Google Drive as a file or document revision.
func (t *GDocsTransport) SendChunk(ctx context.Context, sessionID string, chunkIdx int, data []byte) error {
	if len(data) == 0 {
		return nil
	}

	payloadB64 := base64.StdEncoding.EncodeToString(data)
	fileName := fmt.Sprintf("%s_chunk_%d.txt", sessionID, chunkIdx)

	if t.UseSimulator {
		// Simulation Mode: Sleep to mimic roundtrip network latency
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(150 * time.Millisecond):
		}
		return nil
	}

	// Production Mode: Perform direct HTTP REST API call to Google Drive API v3
	apiUrl := "https://www.googleapis.com/drive/v3/files?uploadType=multipart"
	
	// Create multipart body containing file metadata and the base64 payload
	boundary := "gdocs_evasion_boundary"
	body := fmt.Sprintf(
		"--%s\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{\r\n  \"name\": \"%s\",\r\n  \"parents\": [\"%s\"]\r\n}\r\n"+
			"--%s\r\nContent-Type: text/plain\r\n\r\n%s\r\n--%s--\r\n",
		boundary, fileName, t.FolderID, boundary, payloadB64, boundary,
	)

	req, err := http.NewRequestWithContext(ctx, "POST", apiUrl, strings.NewReader(body))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+t.AccessToken)
	req.Header.Set("Content-Type", "multipart/related; boundary="+boundary)

	resp, err := t.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("google api returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// ReadChunk downloads a specific chunk of data from the shared Google Drive folder.
func (t *GDocsTransport) ReadChunk(ctx context.Context, sessionID string, chunkIdx int) ([]byte, error) {
	if t.UseSimulator {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(150 * time.Millisecond):
		}
		// Return empty / EOF simulation
		return nil, io.EOF
	}

	// Production Mode: Query Google Drive API for the specific file name
	fileName := fmt.Sprintf("%s_chunk_%d.txt", sessionID, chunkIdx)
	query := fmt.Sprintf("name = '%s' and '%s' in parents and trashed = false", fileName, t.FolderID)
	
	// Escape the query for URL
	queryEscaped := url.QueryEscape(query)
	listURL := fmt.Sprintf("https://www.googleapis.com/drive/v3/files?q=%s&fields=files(id,name)", queryEscaped)

	req, err := http.NewRequestWithContext(ctx, "GET", listURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+t.AccessToken)

	resp, err := t.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("google api list returned status %d: %s", resp.StatusCode, string(respBody))
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

	// Download file media content
	downloadURL := fmt.Sprintf("https://www.googleapis.com/drive/v3/files/%s?alt=media", fileID)
	downloadReq, err := http.NewRequestWithContext(ctx, "GET", downloadURL, nil)
	if err != nil {
		return nil, err
	}
	downloadReq.Header.Set("Authorization", "Bearer "+t.AccessToken)

	downloadResp, err := t.HTTPClient.Do(downloadReq)
	if err != nil {
		return nil, err
	}
	defer downloadResp.Body.Close()

	if downloadResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google api download returned status %d", downloadResp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(downloadResp.Body)
	if err != nil {
		return nil, err
	}

	decodedBytes, err := base64.StdEncoding.DecodeString(string(bodyBytes))
	if err != nil {
		return nil, err
	}

	// Delete file asynchronously to clean up storage
	go func() {
		delReq, _ := http.NewRequest(http.MethodDelete, "https://www.googleapis.com/drive/v3/files/"+fileID, nil)
		delReq.Header.Set("Authorization", "Bearer "+t.AccessToken)
		delResp, err := t.HTTPClient.Do(delReq)
		if err == nil {
			delResp.Body.Close()
		}
	}()

	return decodedBytes, nil
}

// VirtualConnection creates a net.Conn wrapper that routes reads and writes via Google Docs API calls.
func (t *GDocsTransport) VirtualConnection(sessionID string) net.Conn {
	return &gdocsConn{
		transport: t,
		sessionID: sessionID,
		readBuf:   nil,
		chunkIdx:  0,
		writeIdx:  0,
		ctx:       context.Background(),
	}
}

type gdocsConn struct {
	transport *GDocsTransport
	sessionID string
	readBuf   []byte
	chunkIdx  int
	writeIdx  int
	ctx       context.Context
}

func (c *gdocsConn) Read(b []byte) (int, error) {
	if len(c.readBuf) == 0 {
		// Polling for the next chunk
		for {
			data, err := c.transport.ReadChunk(c.ctx, c.sessionID, c.chunkIdx)
			if err != nil {
				return 0, err // might be io.EOF or other errors
			}
			if data != nil {
				c.readBuf = data
				c.chunkIdx++
				break
			}
			// If data is nil, it means the file wasn't found yet or is empty. Poll again.
			select {
			case <-c.ctx.Done():
				return 0, c.ctx.Err()
			case <-time.After(200 * time.Millisecond):
			}
		}
	}

	n := copy(b, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *gdocsConn) Write(b []byte) (int, error) {
	err := c.transport.SendChunk(c.ctx, c.sessionID, c.writeIdx, b)
	if err != nil {
		return 0, err
	}
	c.writeIdx++
	return len(b), nil
}

func (c *gdocsConn) Close() error                       { return nil }
func (c *gdocsConn) LocalAddr() net.Addr                { return nil }
func (c *gdocsConn) RemoteAddr() net.Addr               { return nil }
func (c *gdocsConn) SetDeadline(t time.Time) error      { return nil }
func (c *gdocsConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *gdocsConn) SetWriteDeadline(t time.Time) error { return nil }

