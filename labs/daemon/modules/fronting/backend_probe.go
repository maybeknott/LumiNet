package fronting

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// BackendProbeConfig specifies the target node and probing options.
type BackendProbeConfig struct {
	TargetURL string        `json:"target_url"`
	Path      string        `json:"path,omitempty"`
	Timeout   time.Duration `json:"timeout,omitempty"`
}

// BackendProbeResult contains structured diagnostics for the backend node.
type BackendProbeResult struct {
	OK             bool     `json:"ok"`
	BackendMode    bool     `json:"backend_mode"`
	BackendURL     string   `json:"backend_url"`
	TargetTried    string   `json:"target_tried"`
	UpstreamStatus int      `json:"upstream_status,omitempty"`
	GotWebSocket   bool     `json:"got_websocket"`
	ElapsedMs      int64    `json:"elapsed_ms"`
	ServerHeader   string   `json:"server_header,omitempty"`
	Steps          []string `json:"steps"`
	FixHint        string   `json:"fix_hint,omitempty"`
}

// BackendProber executes reachability and WebSocket upgrade diagnostics against upstream nodes.
type BackendProber struct {
	client *http.Client
}

// NewBackendProber creates a new prober with custom timeouts.
func NewBackendProber() *BackendProber {
	return &BackendProber{
		client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Probe executes WebSocket handshake probing against targetURL.
func (p *BackendProber) Probe(ctx context.Context, cfg BackendProbeConfig) (*BackendProbeResult, error) {
	rawURL := strings.TrimSpace(cfg.TargetURL)
	if rawURL == "" {
		return nil, fmt.Errorf("backend URL is empty")
	}

	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, fmt.Errorf("invalid backend URL scheme (must be http or https): %w", err)
	}

	targetPath := cfg.Path
	if targetPath == "" {
		if parsed.Path != "" && parsed.Path != "/" {
			targetPath = parsed.Path
		} else {
			targetPath = "/novavpn"
		}
	}
	if !strings.HasPrefix(targetPath, "/") {
		targetPath = "/" + targetPath
	}

	targetTried := fmt.Sprintf("%s://%s%s", parsed.Scheme, parsed.Host, targetPath)
	res := &BackendProbeResult{
		OK:          false,
		BackendMode: true,
		BackendURL:  rawURL,
		TargetTried: targetTried,
		Steps:       make([]string, 0, 4),
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetTried, nil)
	if err != nil {
		res.Steps = append(res.Steps, fmt.Sprintf("Failed to construct probe request: %v", err))
		return res, nil
	}

	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("User-Agent", "LumiNet-BackendProber/1.0")

	start := time.Now()
	resp, err := p.client.Do(req)
	elapsed := time.Since(start)
	res.ElapsedMs = elapsed.Milliseconds()

	if err != nil {
		res.Steps = append(res.Steps, fmt.Sprintf("Network dial failed after %dms: %v", res.ElapsedMs, err))
		return res, nil
	}
	defer resp.Body.Close()

	res.UpstreamStatus = resp.StatusCode
	res.ServerHeader = resp.Header.Get("Server")
	isUpgrade := strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") || resp.StatusCode == http.StatusSwitchingProtocols
	res.GotWebSocket = isUpgrade

	hostOnly := parsed.Hostname()
	isRawIP := net.ParseIP(hostOnly) != nil

	if resp.StatusCode == http.StatusSwitchingProtocols {
		res.OK = true
		res.Steps = append(res.Steps, "SUCCESS: Backend reached and upgraded to WebSocket (101). Relay path works.")
		return res, nil
	}

	if resp.StatusCode == http.StatusForbidden {
		if isRawIP && res.ElapsedMs < 100 {
			res.Steps = append(res.Steps, fmt.Sprintf("403 in %dms to RAW IP — Edge SSRF sandbox blocks bare IP.", res.ElapsedMs))
			res.FixHint = "Use a gray-cloud (DNS-only) A record in Backend URL instead of raw IP."
		} else {
			res.Steps = append(res.Steps, "Backend returned 403. Check that path matches Xray wsSettings.path and Host header is accepted.")
			res.FixHint = "Verify wsSettings.path and inbound Host whitelist."
		}
	} else {
		res.Steps = append(res.Steps, fmt.Sprintf("Backend did NOT upgrade. Status %d. Server header: '%s'. Check that port is open and path is configured.", resp.StatusCode, res.ServerHeader))
	}

	return res, nil
}

// BackendProbeHandler returns an http.HandlerFunc handling probe diagnostic requests.
func BackendProbeHandler(prober *BackendProber) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var cfg BackendProbeConfig

		if r.Method == http.MethodGet {
			cfg.TargetURL = r.URL.Query().Get("target")
			cfg.Path = r.URL.Query().Get("path")
		} else if r.Method == http.MethodPost {
			if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
				http.Error(w, fmt.Sprintf("invalid JSON payload: %v", err), http.StatusBadRequest)
				return
			}
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if cfg.TargetURL == "" {
			http.Error(w, "missing 'target' parameter or target_url field", http.StatusBadRequest)
			return
		}

		result, err := prober.Probe(r.Context(), cfg)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

// SessionTrafficMeter tracks duplex throughput for a user session.
type SessionTrafficMeter struct {
	UserID    string `json:"user_id"`
	UpBytes   uint64 `json:"up_bytes"`
	DownBytes uint64 `json:"down_bytes"`
}

// MeterRegistry manages active session traffic meters in a thread-safe manner.
type MeterRegistry struct {
	mu     sync.RWMutex
	meters map[string]*SessionTrafficMeter
}

// NewMeterRegistry initializes a new traffic meter registry.
func NewMeterRegistry() *MeterRegistry {
	return &MeterRegistry{
		meters: make(map[string]*SessionTrafficMeter),
	}
}

// GetOrCreate returns the existing meter or creates a new one for userID.
func (r *MeterRegistry) GetOrCreate(userID string) *SessionTrafficMeter {
	r.mu.Lock()
	defer r.mu.Unlock()
	if m, exists := r.meters[userID]; exists {
		return m
	}
	m := &SessionTrafficMeter{UserID: userID}
	r.meters[userID] = m
	return m
}

// RecordUp atomically increments upload bytes.
func (m *SessionTrafficMeter) RecordUp(n int) {
	if n > 0 {
		atomic.AddUint64(&m.UpBytes, uint64(n))
	}
}

// RecordDown atomically increments download bytes.
func (m *SessionTrafficMeter) RecordDown(n int) {
	if n > 0 {
		atomic.AddUint64(&m.DownBytes, uint64(n))
	}
}

// TotalBytes returns sum of up and down bytes.
func (m *SessionTrafficMeter) TotalBytes() uint64 {
	return atomic.LoadUint64(&m.UpBytes) + atomic.LoadUint64(&m.DownBytes)
}
