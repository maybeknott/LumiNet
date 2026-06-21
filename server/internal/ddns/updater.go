// Package ddns manages dynamic DNS record updates for various providers.
package ddns

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ErrProviderNotSupported is returned when the configured DDNS provider is not implemented.
var ErrProviderNotSupported = fmt.Errorf("ddns provider not supported")

// UpdateResult details the outcome of a DDNS update attempt.
type UpdateResult struct {
	Domain     string `json:"domain"`
	IP         string `json:"ip"`
	Updated    bool   `json:"updated"`
	StatusText string `json:"status_text"`
}

// Updater handles dynamic DNS record reconciliation with a remote DNS provider.
type Updater struct {
	provider   string
	token      string
	domain     string
	httpClient *http.Client
}

// NewUpdater initializes a new DDNS updater for a given provider, credentials, and domain name.
func NewUpdater(provider, token, domain string) *Updater {
	return &Updater{
		provider: strings.ToLower(provider),
		token:    token,
		domain:   domain,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// GetPublicIP fetches the current public IP address using an external service.
func (u *Updater) GetPublicIP(ctx context.Context) (string, error) {
	services := []string{
		"https://api.ipify.org",
		"https://icanhazip.com",
		"https://checkip.amazonaws.com",
	}

	for _, svc := range services {
		req, err := http.NewRequestWithContext(ctx, "GET", svc, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "LumiNet/1.0")

		resp, err := u.httpClient.Do(req)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		ip := strings.TrimSpace(string(body))
		if ip != "" {
			return ip, nil
		}
	}
	return "", fmt.Errorf("failed to determine public IP from all services")
}

// UpdateIP contacts the DDNS provider and updates the A/AAAA record if the public IP has changed.
func (u *Updater) UpdateIP(ctx context.Context, currentIP string) (*UpdateResult, error) {
	switch u.provider {
	case "cloudflare":
		return u.updateCloudflare(ctx, currentIP)
	case "duckdns":
		return u.updateDuckDNS(ctx, currentIP)
	case "noip":
		return u.updateNoIP(ctx, currentIP)
	case "dynu":
		return u.updateDynu(ctx, currentIP)
	default:
		return nil, fmt.Errorf("%w: %s", ErrProviderNotSupported, u.provider)
	}
}

// updateDuckDNS updates a DuckDNS record.
// Token is the DuckDNS token; domain is the subdomain (without .duckdns.org).
func (u *Updater) updateDuckDNS(ctx context.Context, ip string) (*UpdateResult, error) {
	url := fmt.Sprintf("https://www.duckdns.org/update?domains=%s&token=%s&ip=%s",
		u.domain, u.token, ip)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "LumiNet/1.0")

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("duckdns update failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	status := strings.TrimSpace(string(body))

	updated := status == "OK"
	return &UpdateResult{
		Domain:     u.domain + ".duckdns.org",
		IP:         ip,
		Updated:    updated,
		StatusText: status,
	}, nil
}

// updateNoIP updates a No-IP record using their HTTP API.
// Token should be "username:password" base64 encoded or plain "user:pass".
func (u *Updater) updateNoIP(ctx context.Context, ip string) (*UpdateResult, error) {
	url := fmt.Sprintf("https://dynupdate.no-ip.com/nic/update?hostname=%s&myip=%s", u.domain, ip)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	// token is "username:password"
	parts := strings.SplitN(u.token, ":", 2)
	if len(parts) == 2 {
		req.SetBasicAuth(parts[0], parts[1])
	}
	req.Header.Set("User-Agent", "LumiNet/1.0 luminet@example.com")

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("no-ip update failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	status := strings.TrimSpace(string(body))
	updated := strings.HasPrefix(status, "good") || strings.HasPrefix(status, "nochg")

	return &UpdateResult{
		Domain:     u.domain,
		IP:         ip,
		Updated:    updated,
		StatusText: status,
	}, nil
}

// updateDynu updates a Dynu record.
func (u *Updater) updateDynu(ctx context.Context, ip string) (*UpdateResult, error) {
	url := fmt.Sprintf("https://api.dynu.com/nic/update?hostname=%s&myip=%s&password=%s",
		u.domain, ip, u.token)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "LumiNet/1.0")

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dynu update failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	status := strings.TrimSpace(string(body))
	updated := strings.HasPrefix(status, "good") || strings.HasPrefix(status, "nochg")

	return &UpdateResult{
		Domain:     u.domain,
		IP:         ip,
		Updated:    updated,
		StatusText: status,
	}, nil
}

// updateCloudflare updates a Cloudflare DNS A record via the Cloudflare API v4.
// Token is the Cloudflare API token; domain is "zone_id:record_name" or just the record name
// if zone_id can be looked up.
func (u *Updater) updateCloudflare(ctx context.Context, ip string) (*UpdateResult, error) {
	// Parse token as "zone_id:api_token" or just "api_token"
	parts := strings.SplitN(u.token, ":", 2)
	var zoneID, apiToken string
	if len(parts) == 2 {
		zoneID = parts[0]
		apiToken = parts[1]
	} else {
		apiToken = u.token
	}

	if zoneID == "" {
		// Try to look up zone ID from domain
		var err error
		zoneID, err = u.cloudflareGetZoneID(ctx, apiToken, u.domain)
		if err != nil {
			return nil, fmt.Errorf("cloudflare zone lookup failed: %w", err)
		}
	}

	// Get existing DNS record ID
	recordID, currentIP, err := u.cloudflareGetRecord(ctx, apiToken, zoneID, u.domain)
	if err != nil {
		return nil, fmt.Errorf("cloudflare record lookup failed: %w", err)
	}

	if currentIP == ip {
		return &UpdateResult{
			Domain:     u.domain,
			IP:         ip,
			Updated:    false,
			StatusText: "IP unchanged, no update needed",
		}, nil
	}

	// Update the record
	updateURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", zoneID, recordID)
	body := map[string]interface{}{
		"type":    "A",
		"name":    u.domain,
		"content": ip,
		"ttl":     120,
		"proxied": false,
	}
	bodyJSON, _ := json.Marshal(body)

	req, err := http.NewRequestWithContext(ctx, "PUT", updateURL, strings.NewReader(string(bodyJSON)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cloudflare update request failed: %w", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	success, _ := result["success"].(bool)
	return &UpdateResult{
		Domain:     u.domain,
		IP:         ip,
		Updated:    success,
		StatusText: fmt.Sprintf("Cloudflare API response: success=%v", success),
	}, nil
}

func (u *Updater) cloudflareGetZoneID(ctx context.Context, token, domain string) (string, error) {
	// Extract root domain (last two parts)
	parts := strings.Split(domain, ".")
	rootDomain := domain
	if len(parts) >= 2 {
		rootDomain = strings.Join(parts[len(parts)-2:], ".")
	}

	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones?name=%s", rootDomain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		Result []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if len(result.Result) == 0 {
		return "", fmt.Errorf("no zone found for domain %s", rootDomain)
	}
	return result.Result[0].ID, nil
}

func (u *Updater) cloudflareGetRecord(ctx context.Context, token, zoneID, name string) (id, ip string, err error) {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records?type=A&name=%s", zoneID, name)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	var result struct {
		Result []struct {
			ID      string `json:"id"`
			Content string `json:"content"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", err
	}
	if len(result.Result) == 0 {
		return "", "", fmt.Errorf("no A record found for %s", name)
	}
	return result.Result[0].ID, result.Result[0].Content, nil
}
