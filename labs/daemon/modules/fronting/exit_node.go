package fronting

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ExitNodeRequest represents the JSON relay envelope sent to an exit node endpoint.
type ExitNodeRequest struct {
	K string            `json:"k"`           // Pre-shared key
	U string            `json:"u"`           // Target URL
	M string            `json:"m"`           // HTTP method (GET, POST, etc.)
	H map[string]string `json:"h"`           // Sanitized headers
	B string            `json:"b,omitempty"` // Base64 payload
}

// ExitNodeResponse represents the JSON relay envelope received from an exit node.
type ExitNodeResponse struct {
	S  int            `json:"s"`            // HTTP status code
	H  map[string]any `json:"h"`            // Response headers (string or []string)
	B  string         `json:"b,omitempty"`  // Base64 response body
	E  string         `json:"e,omitempty"`  // Error message
	Gz bool           `json:"gz,omitempty"` // Gzip compressed flag
}

// StripHeaders lists hop-by-hop headers that must never cross relay hops.
var StripHeaders = map[string]struct{}{
	"host":                 {},
	"connection":           {},
	"content-length":       {},
	"transfer-encoding":    {},
	"keep-alive":           {},
	"te":                   {},
	"trailer":              {},
	"upgrade":              {},
	"proxy-connection":     {},
	"proxy-authorization":  {},
	"proxy-authenticate":   {},
	"x-forwarded-for":      {},
	"x-forwarded-host":     {},
	"x-forwarded-proto":    {},
	"x-forwarded-port":     {},
	"x-real-ip":            {},
	"forwarded":            {},
	"via":                  {},
	"x-mhr-hop":            {},
	"accept-encoding":      {},
}

// SanitizeOutboundHeaders filters out hop-by-hop and proxy headers.
func SanitizeOutboundHeaders(headers map[string]string) map[string]string {
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		lower := strings.ToLower(strings.TrimSpace(k))
		if lower == "" {
			continue
		}
		if _, ok := StripHeaders[lower]; ok {
			continue
		}
		out[k] = v
	}
	return out
}

// IsSafeTargetURL validates that a URL is safe against SSRF attacks.
func IsSafeTargetURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return false
	}

	host := strings.ToLower(u.Hostname())
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return false
	}

	if host == "localhost" || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".lan") || strings.HasSuffix(host, ".home.arpa") {
		return false
	}

	ip := net.ParseIP(host)
	if ip != nil {
		if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return false
		}
		if ip4 := ip.To4(); ip4 != nil {
			// 10.0.0.0/8
			if ip4[0] == 10 {
				return false
			}
			// 172.16.0.0/12
			if ip4[0] == 172 && (ip4[1] >= 16 && ip4[1] <= 31) {
				return false
			}
			// 192.168.0.0/16
			if ip4[0] == 192 && ip4[1] == 168 {
				return false
			}
			// 169.254.0.0/16 (link local)
			if ip4[0] == 169 && ip4[1] == 254 {
				return false
			}
		} else {
			// IPv6 Unique Local Address (fc00::/7)
			if len(ip) >= 1 && (ip[0]&0xfe) == 0xfc {
				return false
			}
		}
	}

	return true
}

// CheckRelayLoop detects self-referencing loops and GAS-to-exit-to-GAS bounces.
func CheckRelayLoop(targetURL, exitHost string, hopHeaderPresent bool) error {
	u, err := url.Parse(targetURL)
	if err != nil {
		return errors.New("malformed target URL")
	}

	targetHostname := strings.ToLower(u.Hostname())
	targetPort := u.Port()
	if targetPort == "" {
		if strings.ToLower(u.Scheme) == "https" {
			targetPort = "443"
		} else {
			targetPort = "80"
		}
	}

	exitHostname := strings.ToLower(exitHost)
	exitPort := ""
	if host, port, err := net.SplitHostPort(exitHost); err == nil {
		exitHostname = strings.ToLower(host)
		exitPort = port
	}

	if targetHostname != "" && exitHostname != "" && targetHostname == exitHostname {
		if exitPort == "" || exitPort == targetPort {
			return fmt.Errorf("loop_detected: self loop to %s:%s", targetHostname, targetPort)
		}
	}

	if hopHeaderPresent && strings.Contains(strings.ToLower(u.Path), "/macros/s/") {
		return fmt.Errorf("loop_detected: GAS hop loop to %s", targetURL)
	}

	return nil
}

// ExitNodeServer handles relay requests as an exit node (Cloudflare/VPS/Deno compatible).
type ExitNodeServer struct {
	psk            string
	maxReqBody     int64
	maxRespBody    int64
	allowPrivate   bool
	outboundClient *http.Client
}

// ExitNodeServerOption mutates ExitNodeServer configuration.
type ExitNodeServerOption func(*ExitNodeServer)

// WithAllowPrivateTargets configures whether private/loopback IP addresses are permitted (useful for local mock tests).
func WithAllowPrivateTargets(allow bool) ExitNodeServerOption {
	return func(s *ExitNodeServer) {
		s.allowPrivate = allow
	}
}

// WithExitNodeLimits sets custom request and response body caps.
func WithExitNodeLimits(maxReq, maxResp int64) ExitNodeServerOption {
	return func(s *ExitNodeServer) {
		if maxReq > 0 {
			s.maxReqBody = maxReq
		}
		if maxResp > 0 {
			s.maxRespBody = maxResp
		}
	}
}

// NewExitNodeServer creates a new ExitNodeServer instance.
func NewExitNodeServer(psk string, opts ...ExitNodeServerOption) *ExitNodeServer {
	s := &ExitNodeServer{
		psk:         psk,
		maxReqBody:  32 * 1024 * 1024,
		maxRespBody: 64 * 1024 * 1024,
		outboundClient: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // preserve 3xx redirects without following
			},
		},
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// ServeHTTP implements http.Handler for the exit node endpoint.
func (s *ExitNodeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":      true,
			"status":  "healthy",
			"message": "LumiNet exit node is running.",
			"usage":   "Send POST with relay payload for actual proxy requests.",
		})
		return
	}

	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"e":       "method_not_allowed",
			"message": "Use POST for relay requests. GET is only a health check.",
		})
		return
	}

	if r.ContentLength > s.maxReqBody {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		_ = json.NewEncoder(w).Encode(map[string]any{"e": "request_too_large"})
		return
	}

	var req ExitNodeRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, s.maxReqBody)).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"e": "bad_json"})
		return
	}

	if s.psk != "" && req.K != s.psk {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{"e": "unauthorized"})
		return
	}

	if !s.allowPrivate && !IsSafeTargetURL(req.U) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"e": "bad_url"})
		return
	}

	hasHopHeader := r.Header.Get("x-mhr-hop") != ""
	if err := CheckRelayLoop(req.U, r.Host, hasHopHeader); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusLoopDetected)
		_ = json.NewEncoder(w).Encode(map[string]any{"e": "loop_detected", "detail": err.Error()})
		return
	}

	method := strings.ToUpper(strings.TrimSpace(req.M))
	if method == "" {
		method = http.MethodGet
	}

	var reqBody io.Reader
	if req.B != "" {
		decoded, err := base64.StdEncoding.DecodeString(req.B)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"e": "bad_base64"})
			return
		}
		reqBody = bytes.NewReader(decoded)
	}

	outReq, err := http.NewRequestWithContext(r.Context(), method, req.U, reqBody)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"e": err.Error()})
		return
	}

	sanitized := SanitizeOutboundHeaders(req.H)
	for k, v := range sanitized {
		outReq.Header.Set(k, v)
	}

	resp, err := s.outboundClient.Do(outReq)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"e": err.Error()})
		return
	}
	defer resp.Body.Close()

	respData, err := io.ReadAll(io.LimitReader(resp.Body, s.maxRespBody))
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"e": "read_response_failed"})
		return
	}

	// Collect headers preserving multi-values (Set-Cookie)
	respHeaders := make(map[string]any, len(resp.Header))
	for k, vals := range resp.Header {
		if len(vals) == 1 {
			respHeaders[k] = vals[0]
		} else if len(vals) > 1 {
			respHeaders[k] = vals
		}
	}

	exitResp := ExitNodeResponse{
		S: resp.StatusCode,
		H: respHeaders,
		B: base64.StdEncoding.EncodeToString(respData),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(exitResp)
}

// ExitNodeClient forwards requests to a remote exit node endpoint.
type ExitNodeClient struct {
	endpoint string
	psk      string
	client   *http.Client
}

// NewExitNodeClient creates an ExitNodeClient connected to a remote exit node.
func NewExitNodeClient(endpoint, psk string, timeout time.Duration) *ExitNodeClient {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &ExitNodeClient{
		endpoint: strings.TrimRight(endpoint, "/"),
		psk:      psk,
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

// Forward transmits an HTTP request payload through the exit node.
func (c *ExitNodeClient) Forward(
	ctx context.Context,
	targetURL string,
	method string,
	headers map[string]string,
	body []byte,
) (*ExitNodeResponse, error) {
	reqPayload := ExitNodeRequest{
		K: c.psk,
		U: targetURL,
		M: method,
		H: SanitizeOutboundHeaders(headers),
	}
	if len(body) > 0 {
		reqPayload.B = base64.StdEncoding.EncodeToString(body)
	}

	encoded, err := json.Marshal(reqPayload)
	if err != nil {
		return nil, fmt.Errorf("marshal exit node request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(encoded))
	if err != nil {
		return nil, fmt.Errorf("create exit node http request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("execute exit node request: %w", err)
	}
	defer resp.Body.Close()

	var exitResp ExitNodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&exitResp); err != nil {
		return nil, fmt.Errorf("decode exit node response: %w", err)
	}

	if exitResp.E != "" {
		return nil, fmt.Errorf("exit node returned error (%d): %s", exitResp.S, exitResp.E)
	}

	return &exitResp, nil
}
