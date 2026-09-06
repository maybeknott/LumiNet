// Package fronting implements Google Apps Script domain-fronting relay
// transport , masterking32).
//
// The relay contract: POST a JSON payload to
// https://script.google.com/macros/s/<script-id>/exec carrying
//
//	{"k": authKey, "m": "GET", "u": "https://target/", "h": {...}, "b": "<base64 body>"}
//
// Batch mode wraps multiple request objects as {"k": authKey, "q": [...]}.
// The script answers with an envelope {"s": status, "h": headers, "b": base64,
// "gz": 1} or {"e": "error text"}. See envelope.go for decoding.
package fronting

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Error categories produced by ClassifyRelayError. They drive SID blacklisting
// decisions: quota/deploy errors blacklist hard, transient errors blacklist
// briefly, exit-node errors are the target's fault and never blame the SID.
const (
	ErrCategoryGeneric   = "generic"
	ErrCategoryQuota     = "quota"
	ErrCategoryAuth      = "auth"
	ErrCategoryDeploy    = "deploy"
	ErrCategoryTransient = "transient"
	ErrCategoryAdmin     = "admin"
	ErrCategoryExitNode  = "exit-node"
)

type categoryPatterns struct {
	category string
	needles  []string
}

// Ordered classifier mirroring relay_response.py: first matching family wins.
var categoryOrder = []categoryPatterns{
	{ErrCategoryQuota, []string{
		"service invoked too many times", "invoked too many times",
		"bandwidth quota exceeded", "too much upload bandwidth", "too much traffic",
		"urlfetch", "quota", "exceeded", "daily", "rate limit",
	}},
	{ErrCategoryAuth, []string{
		"authorization is required", "unauthorized", "not authorized",
		"permission denied", "access denied",
	}},
	{ErrCategoryDeploy, []string{
		"error code not_found", "not_found", "deployment", "script id", "scriptid", "no script",
	}},
	{ErrCategoryTransient, []string{
		"server not available", "server error occurred", "please try again", "temporarily unavailable",
	}},
	{ErrCategoryAdmin, []string{
		"not permitted by your admin", "contact your administrator",
		"disabled. please contact", "domain policy has disabled", "administrator to enable",
	}},
	{ErrCategoryExitNode, []string{
		"dns", "connection refused", "connection reset", "unable to connect",
		"timeout", "exit node", "invalid url", "url not valid",
	}},
}

// ClassifyRelayError maps a raw Apps Script error string to a category.
func ClassifyRelayError(raw string) string {
	haystack := strings.ToLower(raw)
	for _, family := range categoryOrder {
		for _, needle := range family.needles {
			if strings.Contains(haystack, needle) {
				return family.category
			}
		}
	}
	return ErrCategoryGeneric
}

// RelayEnvelope is the decoded form of the Apps Script JSON answer.
type RelayEnvelope struct {
	Status  int               `json:"s"`
	Headers map[string]any    `json:"h"`
	BodyB64 string            `json:"b"`
	Gzipped bool              `json:"gz,omitempty"`
	Error   string            `json:"e,omitempty"`
	Raw     map[string]any    `json:"-"`
}

// IsError reports whether the envelope carries a script-level failure.
func (e *RelayEnvelope) IsError() bool { return e.Error != "" }

// DecodeBody returns the raw target response bytes after base64 and optional
// relay-level gzip decoding.
func (e *RelayEnvelope) DecodeBody() ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(e.BodyB64)
	if err != nil {
		return nil, fmt.Errorf("relay body base64: %w", err)
	}
	if !e.Gzipped {
		return raw, nil
	}
	reader, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("relay body gunzip: %w", err)
	}
	return io.ReadAll(reader)
}

// RequestPayload is the JSON body POSTed to the Apps Script endpoint.
type RequestPayload struct {
	Key     string            `json:"k"`
	Method  string            `json:"m"`
	URL     string            `json:"u"`
	Headers map[string]string `json:"h,omitempty"`
	BodyB64 string            `json:"b,omitempty"`
	Batch   []RequestPayload  `json:"q,omitempty"`
}

// BuildRequestPayload marshals a single relay request. Method defaults to GET
// and loop-guarded URLs (Apps Script endpoints) are rejected exactly like the
// server side does, so clients fail fast instead of burning UrlFetch quota.
func BuildRequestPayload(key, method, targetURL string, headers map[string]string, body []byte) ([]byte, error) {
	if targetURL == "" {
		return nil, fmt.Errorf("fronting: empty target url")
	}
	lower := strings.ToLower(targetURL)
	if strings.HasPrefix(lower, "http://script.google.com/macros/") ||
		strings.HasPrefix(lower, "https://script.google.com/macros/") {
		return nil, fmt.Errorf("fronting: relay loop detected: target cannot be an Apps Script URL")
	}
	if method == "" {
		method = "GET"
	}
	payload := RequestPayload{Key: key, Method: strings.ToUpper(method), URL: targetURL, Headers: headers}
	if len(body) > 0 {
		payload.BodyB64 = base64.StdEncoding.EncodeToString(body)
	}
	return json.Marshal(payload)
}

// BuildBatchPayload wraps individual payloads into one batch request; items
// must already be valid single-request JSON objects without their own batch key.
func BuildBatchPayload(key string, items []RequestPayload) ([]byte, error) {
	if len(items) == 0 {
		return nil, fmt.Errorf("fronting: empty batch")
	}
	batch := RequestPayload{Key: key, Batch: items}
	return json.Marshal(batch)
}

// ParseEnvelope decodes the raw JSON answer into a RelayEnvelope.
func ParseEnvelope(body []byte) (*RelayEnvelope, error) {
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("fronting: envelope is not JSON: %w", err)
	}
	env := &RelayEnvelope{Raw: raw, Status: 200}
	if msg, ok := raw["e"].(string); ok && msg != "" {
		env.Error = msg
		return env, nil
	}
	if v, ok := raw["s"].(float64); ok {
		env.Status = int(v)
	}
	if h, ok := raw["h"].(map[string]any); ok {
		env.Headers = h
	}
	if b, ok := raw["b"].(string); ok {
		env.BodyB64 = b
	}
	switch raw["gz"].(type) {
	case float64:
		env.Gzipped = raw["gz"].(float64) != 0
	case bool:
		env.Gzipped = raw["gz"].(bool)
	}
	return env, nil
}
