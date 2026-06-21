package api

import (
	"net/http"
	"runtime"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/bridge"
)

type capabilityItem struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Domain            string   `json:"domain"`
	Priority          string   `json:"priority"`
	Maturity          string   `json:"maturity"`
	NativeRuntime     string   `json:"native_runtime"`
	SafeState         string   `json:"safe_state"`
	AllowedOperations []string `json:"allowed_operations"`
	ReviewRequired    []string `json:"review_required,omitempty"`
	Warning           string   `json:"warning,omitempty"`
}

type toolTemplate struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Source         string   `json:"source"`
	Status         string   `json:"status"`
	NativeTarget   string   `json:"native_target"`
	UsefulFor      []string `json:"useful_for"`
	SafetyBoundary string   `json:"safety_boundary"`
}

// GetCapabilities handles GET /api/capabilities.
func (s *Server) GetCapabilities(c *gin.Context) {
	base := gin.H{
		"icmp_scan":           true,
		"tcp_scan":            true,
		"dns_scan":            true,
		"tls_scan":            true,
		"sni_scan":            !bridge.MockMode,
		"wg_scan":             !bridge.MockMode,
		"proxy_test":          true,
		"speed_test":          !bridge.MockMode,
		"diagnostics":         true,
		"system_dns":          supportsSystemNetworking(),
		"system_proxy":        supportsSystemNetworking(),
		"ddns":                true,
		"profiles":            true,
		"subnet_scan":         true,
		"wg_audit":            !bridge.MockMode,
		"censorship_audit":    true,
		"captive_portal_scan": true,
	}

	base["schema_version"] = 2
	base["runtime"] = gin.H{
		"os":        runtime.GOOS,
		"arch":      runtime.GOARCH,
		"mock_core": bridge.MockMode,
		"ports": gin.H{
			"rust_core":  "probe primitives, scanners, protocol parsers",
			"go_daemon":  "local API, jobs, OS integration, policy gates",
			"typescript": "operator UI, workflows, visual analytics",
		},
	}
	base["safety_boundary"] = gin.H{
		"mode": "diagnostic_and_operator_control",
		"blocked_operations": []string{
			"hidden traffic interception",
			"automatic policy bypass",
			"unapproved packet capture",
			"untrusted plugin auto-install",
			"irreversible network mutation",
		},
	}
	base["catalog"] = []capabilityItem{
		{
			ID:                "deep_diagnostics",
			Name:              "Deep Path Diagnostics",
			Domain:            "LumiDiag",
			Priority:          "P1",
			Maturity:          "implementation",
			NativeRuntime:     "go+rust",
			SafeState:         "Run cancellable DNS, TLS, HTTP, SNI, and route evidence checks.",
			AllowedOperations: []string{"inspect", "diagnose", "export"},
			ReviewRequired:    []string{"privacy", "traffic_volume"},
		},
		{
			ID:                "plugin_sandboxing",
			Name:              "Capability-Gated Plugins",
			Domain:            "ForgeHub",
			Priority:          "P3",
			Maturity:          "implementation",
			NativeRuntime:     "go",
			SafeState:         "Load plugins only through explicit capability declarations and audit logs.",
			AllowedOperations: []string{"inspect", "plan", "prototype", "implement"},
			ReviewRequired:    []string{"security", "signing"},
			Warning:           "Plugin execution must remain permission-gated and auditable.",
		},
		{
			ID:                "traffic_anomaly_detection",
			Name:              "Explainable Traffic Anomaly Detection",
			Domain:            "Synapse",
			Priority:          "P4",
			Maturity:          "prototype",
			NativeRuntime:     "go+typescript",
			SafeState:         "Show statistical findings from aggregate metrics before any corrective action.",
			AllowedOperations: []string{"inspect", "diagnose", "export"},
			ReviewRequired:    []string{"privacy", "explainability"},
			Warning:           "Self-healing must be opt-in, evidence-based, and reversible.",
		},
		{
			ID:                "proxy_test_matrix",
			Name:              "Proxy Test Matrix",
			Domain:            "LumiProxy",
			Priority:          "P1",
			Maturity:          "implementation",
			NativeRuntime:     "go+typescript",
			SafeState:         "Parse, deduplicate, benchmark, score, and export user-provided proxy configurations.",
			AllowedOperations: []string{"inspect", "test", "export"},
			ReviewRequired:    []string{"credential_redaction"},
			Warning:           "Proxy credentials must be redacted in logs, history, and UI previews.",
		},
		{
			ID:                "clean_ip_calibration",
			Name:              "Clean IP Calibration",
			Domain:            "LumiScan",
			Priority:          "P3",
			Maturity:          "prototype",
			NativeRuntime:     "rust+go",
			SafeState:         "Run bounded user-approved reachability tests and rank latency without automatic rerouting.",
			AllowedOperations: []string{"inspect", "test", "export"},
			ReviewRequired:    []string{"traffic_volume", "rate_limits"},
			Warning:           "Calibration must stay rate-limited and must not mutate routes or system proxy automatically.",
		},
		{
			ID:                "encrypted_dns_controls",
			Name:              "DoH and DoT Posture Controls",
			Domain:            "OmniRoute",
			Priority:          "P4",
			Maturity:          "research",
			NativeRuntime:     "rust+go",
			SafeState:         "Detect and explain encrypted DNS posture before attempting OS-level changes.",
			AllowedOperations: []string{"inspect", "plan", "diagnose"},
			ReviewRequired:    []string{"os_support", "privacy"},
		},
		{
			ID:                "forensics_sidecar",
			Name:              "Forensics Sidecar",
			Domain:            "PhantomCore",
			Priority:          "P5",
			Maturity:          "research",
			NativeRuntime:     "rust",
			SafeState:         "Signed JSON stdin/stdout sidecar status checks only.",
			AllowedOperations: []string{"inspect", "plan", "prototype"},
			ReviewRequired:    []string{"signing", "privacy"},
			Warning:           "Raw packet capture remains disabled until explicit privacy and signing review.",
		},
		{
			ID:                "overlay_status",
			Name:              "Overlay Network Status",
			Domain:            "OmniRoute",
			Priority:          "P5",
			Maturity:          "research",
			NativeRuntime:     "go",
			SafeState:         "Read-only status checks for user-owned overlay tools.",
			AllowedOperations: []string{"inspect", "diagnose"},
			ReviewRequired:    []string{"vendor_policy", "consent"},
			Warning:           "Exit-node, route, and peer mutations require explicit user approval.",
		},
	}
	base["network_tool_templates"] = []toolTemplate{
		{
			ID:             "configstream_worker_audit",
			Name:           "ConfigStream Worker Audit",
			Source:         "internal/workers/cloudflare-bridge",
			Status:         "metadata_only",
			NativeTarget:   "typescript UI + go policy validation",
			UsefulFor:      []string{"Cloudflare deployment checklist", "kill-switch posture", "D1 usage counters", "safe config inventory"},
			SafetyBoundary: "No tunnel relay or masquerade worker code is emitted by the native app.",
		},
		{
			ID:             "masscan_concepts",
			Name:           "Masscan Concept Import",
			Source:         "internal/scanners/feistel-shuffler",
			Status:         "concepts_only",
			NativeTarget:   "rust scan scheduler",
			UsefulFor:      []string{"rate limiting", "exclusion lists", "output formats", "banner parsing backlog"},
			SafetyBoundary: "Do not vendor or invoke raw packet scanner code without a separate review.",
		},
		{
			ID:             "network_lab_diagnostics",
			Name:           "Network Lab Diagnostics",
			Source:         "internal/diagnostics/lab-suite",
			Status:         "ported_as_backlog_and_ui_workflow",
			NativeTarget:   "rust DNS probes + go job orchestration",
			UsefulFor:      []string{"DNS resolver scan", "DoH/DoT posture checks", "local proxy discovery", "port reachability matrix"},
			SafetyBoundary: "Only bounded diagnostics are exposed; automatic chain building remains disabled.",
		},
		{
			ID:             "ping_web_workflows",
			Name:           "PING Web Workflows",
			Source:         "internal/scanners/ping-obfs",
			Status:         "partially_native",
			NativeTarget:   "existing LumiScan/LumiProxy pages",
			UsefulFor:      []string{"calibration page concept", "CSV-to-SOCKS import", "NDJSON progress", "curated target presets"},
			SafetyBoundary: "Packaged executables and duplicate Python backend were not vendored.",
		},
		{
			ID:             "proxy_tester_suite",
			Name:           "Proxy Tester Suite",
			Source:         "internal/proxy/tester-suite",
			Status:         "partially_native",
			NativeTarget:   "go proxy parser/tester + React proxy pages",
			UsefulFor:      []string{"protocol import formats", "storage pagination", "WebSocket progress contract", "log sanitization tests"},
			SafetyBoundary: "Third-party proxy binaries and cache/vendor folders were not copied into the app.",
		},
		{
			ID:             "reviver_sni",
			Name:           "Reviver SNI",
			Source:         "internal/scanners/reviver-sni",
			Status:         "no_runnable_port",
			NativeTarget:   "diagnostic-only SNI scanner",
			UsefulFor:      []string{"SNI candidate note", "SNI scanning and validation telemetry"},
			SafetyBoundary: "Fake TCP/injection concepts are not ported as executable functionality.",
		},
		{
			ID:             "vendor_cache",
			Name:           "Vendor Cache",
			Source:         "internal/vendor-provenance",
			Status:         "ignored",
			NativeTarget:   "none",
			UsefulFor:      []string{"dependency provenance review only"},
			SafetyBoundary: "Cached third-party dependencies are not source features and were not vendored.",
		},
	}

	c.JSON(http.StatusOK, base)
}

func supportsSystemNetworking() bool {
	return runtime.GOOS == "windows" || runtime.GOOS == "darwin" || runtime.GOOS == "linux"
}
