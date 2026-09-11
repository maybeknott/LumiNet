package scanner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/maybeknott/luminet/internal/foundation/remoteaction"
)

const maxCloudflareWorkerReadback = 2 << 20

// CloudflareDeployer handles API deployment of generic scripts to Cloudflare Workers.
// It intentionally does not claim that an uploaded script implements any particular
// application protocol.
type CloudflareDeployer struct {
	client *http.Client
}

// NewCloudflareDeployer initializes the deployer.
func NewCloudflareDeployer() *CloudflareDeployer {
	return &CloudflareDeployer{
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

func cloudflareWorkerURL(accountID, scriptName string) string {
	return fmt.Sprintf(
		"https://api.cloudflare.com/client/v4/accounts/%s/workers/scripts/%s",
		url.PathEscape(accountID),
		url.PathEscape(scriptName),
	)
}

func applyCloudflareAuth(req *http.Request, email, apiToken string) {
	if email != "" {
		req.Header.Set("X-Auth-Email", email)
	}
	req.Header.Set("Authorization", "Bearer "+apiToken)
}

func (d *CloudflareDeployer) fetchWorkerScript(ctx context.Context, email, apiToken, accountID, scriptName string) ([]byte, bool, error) {
	endpoint := cloudflareWorkerURL(accountID, scriptName)
	policy := remoteaction.DefaultPolicy("cloudflare.scanner-worker.read", remoteaction.Idempotent)
	policy.RateLimitScope = "provider.cloudflare"
	outcome, err := remoteaction.Do(ctx, d.client, policy, func(ctx context.Context, _ int) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create worker read request: %w", err)
		}
		applyCloudflareAuth(req, email, apiToken)
		return req, nil
	}, nil)
	if err != nil {
		return nil, false, fmt.Errorf("failed to execute worker read request: %w", err)
	}
	resp := outcome.Response
	if resp == nil {
		return nil, false, fmt.Errorf("Cloudflare worker read completed without response")
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		return nil, false, fmt.Errorf("Cloudflare API read error (status %d): %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCloudflareWorkerReadback+1))
	if err != nil {
		return nil, false, fmt.Errorf("failed to read Cloudflare worker content: %w", err)
	}
	if len(body) > maxCloudflareWorkerReadback {
		return nil, false, fmt.Errorf("Cloudflare worker content exceeds %d-byte verification limit", maxCloudflareWorkerReadback)
	}
	return body, true, nil
}

// DeployWorkerScript creates a generic JavaScript Worker and verifies exact readback.
// Existing Workers are never replaced through this compatibility API; replacement
// requires a separate, explicit operator workflow with destructive confirmation.
func (d *CloudflareDeployer) DeployWorkerScript(ctx context.Context, email, apiToken, accountID, scriptName, scriptBody string) error {
	if accountID == "" || scriptName == "" || apiToken == "" {
		return fmt.Errorf("account_id, name, and token are required")
	}
	if len(scriptBody) == 0 {
		return fmt.Errorf("worker script must not be empty")
	}
	if len(scriptBody) > maxCloudflareWorkerReadback {
		return fmt.Errorf("worker script exceeds %d-byte verification limit", maxCloudflareWorkerReadback)
	}

	if _, exists, err := d.fetchWorkerScript(ctx, email, apiToken, accountID, scriptName); err != nil {
		return fmt.Errorf("failed to check existing Worker before deployment: %w", err)
	} else if exists {
		return fmt.Errorf("worker %q already exists; refusing implicit replacement", scriptName)
	}

	endpoint := cloudflareWorkerURL(accountID, scriptName)
	policy := remoteaction.DefaultPolicy("cloudflare.scanner-worker.upload", remoteaction.Idempotent)
	policy.RateLimitScope = "provider.cloudflare"
	outcome, err := remoteaction.Do(ctx, d.client, policy, func(ctx context.Context, _ int) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewBufferString(scriptBody))
		if err != nil {
			return nil, fmt.Errorf("failed to create worker request: %w", err)
		}
		applyCloudflareAuth(req, email, apiToken)
		req.Header.Set("Content-Type", "application/javascript")
		return req, nil
	}, nil)
	if err != nil {
		return fmt.Errorf("failed to execute worker request: %w", err)
	}
	resp := outcome.Response
	if resp == nil {
		return fmt.Errorf("Cloudflare worker upload completed without response")
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		return fmt.Errorf("Cloudflare API error (status %d): %s", resp.StatusCode, string(body))
	}

	published, exists, err := d.fetchWorkerScript(ctx, email, apiToken, accountID, scriptName)
	if err != nil {
		return fmt.Errorf("worker uploaded but readback verification failed: %w", err)
	}
	if !exists {
		return fmt.Errorf("worker uploaded but was not visible during readback verification")
	}
	if !bytes.Equal(published, []byte(scriptBody)) {
		return fmt.Errorf("worker uploaded but readback did not match submitted script")
	}

	return nil
}
