package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// CaptchaSolver handles communication with the solvecaptcha / 2captcha service.
type CaptchaSolver struct {
	APIKey          string
	EndpointURL     string
	HTTPClient      *http.Client
	PollingInterval time.Duration
	Timeout         time.Duration
}

// NewCaptchaSolver creates a new CaptchaSolver instance.
func NewCaptchaSolver(apiKey, endpointURL string) *CaptchaSolver {
	if endpointURL == "" {
		endpointURL = "https://api.solvecaptcha.com"
	}
	if !strings.HasPrefix(endpointURL, "http://") && !strings.HasPrefix(endpointURL, "https://") {
		endpointURL = "https://" + endpointURL
	}
	endpointURL = strings.TrimSuffix(endpointURL, "/")

	return &CaptchaSolver{
		APIKey:          apiKey,
		EndpointURL:     endpointURL,
		HTTPClient:      &http.Client{Timeout: 15 * time.Second},
		PollingInterval: 5 * time.Second,
		Timeout:         120 * time.Second,
	}
}

// SolveCaptcha submits a CAPTCHA challenge and polls for the solution token.
func (cs *CaptchaSolver) SolveCaptcha(ctx context.Context, method string, siteURL string, siteKey string, extraParams map[string]string) (string, error) {
	if cs.APIKey == "" {
		return "", errors.New("API key cannot be empty")
	}

	// 1. Submit captcha task via in.php
	formData := url.Values{}
	formData.Set("key", cs.APIKey)
	formData.Set("method", method)
	formData.Set("pageurl", siteURL)
	formData.Set("json", "1")

	if method == "userrecaptcha" {
		formData.Set("googlekey", siteKey)
	} else {
		formData.Set("sitekey", siteKey)
	}

	for k, v := range extraParams {
		formData.Set(k, v)
	}

	inURL := fmt.Sprintf("%s/in.php", cs.EndpointURL)
	req, err := http.NewRequestWithContext(ctx, "POST", inURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return "", fmt.Errorf("create request failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := cs.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed submitting captcha: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var inResp struct {
		Status  int    `json:"status"`
		Request string `json:"request"`
	}

	if err := json.Unmarshal(bodyBytes, &inResp); err != nil {
		bodyStr := string(bodyBytes)
		if strings.HasPrefix(bodyStr, "OK|") {
			inResp.Status = 1
			inResp.Request = strings.TrimPrefix(bodyStr, "OK|")
		} else {
			return "", fmt.Errorf("invalid submit response: %s", bodyStr)
		}
	}

	if inResp.Status != 1 {
		return "", fmt.Errorf("submit captcha error: %s", inResp.Request)
	}

	taskID := inResp.Request

	// 2. Poll res.php for solution
	timeout := cs.Timeout
	if deadline, ok := ctx.Deadline(); ok {
		if d := time.Until(deadline); d < timeout {
			timeout = d
		}
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	ticker := time.NewTicker(cs.PollingInterval)
	defer ticker.Stop()

	resURL := fmt.Sprintf("%s/res.php?key=%s&action=get&id=%s&json=1", cs.EndpointURL, url.QueryEscape(cs.APIKey), url.QueryEscape(taskID))

	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-timer.C:
			return "", fmt.Errorf("timeout waiting for captcha solution")
		case <-ticker.C:
			reqPoll, err := http.NewRequestWithContext(ctx, "GET", resURL, nil)
			if err != nil {
				continue
			}

			respPoll, err := cs.HTTPClient.Do(reqPoll)
			if err != nil {
				continue
			}

			pollBytes, err := io.ReadAll(respPoll.Body)
			respPoll.Body.Close()
			if err != nil {
				continue
			}

			var resResp struct {
				Status  int    `json:"status"`
				Request string `json:"request"`
			}

			if err := json.Unmarshal(pollBytes, &resResp); err != nil {
				bodyStr := string(pollBytes)
				if strings.HasPrefix(bodyStr, "OK|") {
					resResp.Status = 1
					resResp.Request = strings.TrimPrefix(bodyStr, "OK|")
				} else if bodyStr == "CAPCHA_NOT_READY" {
					resResp.Status = 0
					resResp.Request = "CAPCHA_NOT_READY"
				} else {
					continue
				}
			}

			if resResp.Status == 1 {
				return resResp.Request, nil
			}

			if resResp.Request != "CAPCHA_NOT_READY" {
				return "", fmt.Errorf("solver error: %s", resResp.Request)
			}
		}
	}
}

// SolveReCAPTCHA solves standard Google reCAPTCHA challenges.
func (cs *CaptchaSolver) SolveReCAPTCHA(ctx context.Context, siteURL, siteKey string) (string, error) {
	return cs.SolveCaptcha(ctx, "userrecaptcha", siteURL, siteKey, nil)
}

// SolveTurnstile solves Cloudflare Turnstile challenges.
func (cs *CaptchaSolver) SolveTurnstile(ctx context.Context, siteURL, siteKey, userAgent string) (string, error) {
	params := map[string]string{}
	if userAgent != "" {
		params["userAgent"] = userAgent
	}
	return cs.SolveCaptcha(ctx, "turnstile", siteURL, siteKey, params)
}

// SolveHCaptcha solves hCaptcha challenges.
func (cs *CaptchaSolver) SolveHCaptcha(ctx context.Context, siteURL, siteKey string) (string, error) {
	return cs.SolveCaptcha(ctx, "hcaptcha", siteURL, siteKey, nil)
}

// ExtractSiteKey attempts to extract a CAPTCHA sitekey and type from HTML content.
func ExtractSiteKey(html string) (sitekey string, captchaType string) {
	// 1. Try Turnstile
	turnstileRe := regexp.MustCompile(`(?:class="cf-turnstile"|id="[^"]+").*?data-sitekey="([0-9a-zA-Z_-]{10,64})"`)
	if matches := turnstileRe.FindStringSubmatch(html); len(matches) > 1 {
		return matches[1], "turnstile"
	}
	// Fallback Turnstile js render
	turnstileJsRe := regexp.MustCompile(`sitekey\s*:\s*['"](0x4[a-zA-Z0-9_-]{10,50})['"]`)
	if matches := turnstileJsRe.FindStringSubmatch(html); len(matches) > 1 {
		return matches[1], "turnstile"
	}

	// 2. Try reCAPTCHA
	recaptchaRe := regexp.MustCompile(`(?:class="g-recaptcha"|id="[^"]+").*?data-sitekey="([0-9a-zA-Z_-]{40})"`)
	if matches := recaptchaRe.FindStringSubmatch(html); len(matches) > 1 {
		return matches[1], "userrecaptcha"
	}
	// Fallback reCAPTCHA js render
	recaptchaJsRe := regexp.MustCompile(`sitekey\s*:\s*['"]([0-9a-zA-Z_-]{40})['"]`)
	if matches := recaptchaJsRe.FindStringSubmatch(html); len(matches) > 1 {
		return matches[1], "userrecaptcha"
	}

	// 3. Try hCaptcha
	hcaptchaRe := regexp.MustCompile(`(?:class="h-captcha"|id="[^"]+").*?data-sitekey="([0-9a-fA-F-]{36})"`)
	if matches := hcaptchaRe.FindStringSubmatch(html); len(matches) > 1 {
		return matches[1], "hcaptcha"
	}

	return "", ""
}
