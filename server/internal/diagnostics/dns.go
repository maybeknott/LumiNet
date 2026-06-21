package diagnostics

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"
)

// QueryDoH performs secure DNS-over-HTTPS resolution.
func QueryDoH(resolverURL string, dnsMsg []byte) ([]byte, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("POST", resolverURL, bytes.NewReader(dnsMsg))
	if err != nil {
		return nil, fmt.Errorf("failed to create DoH request: %w", err)
	}

	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH query failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read DoH response: %w", err)
	}

	return body, nil
}
