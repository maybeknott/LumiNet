// Package api — public tools gate, startup guard, and API config validation.
//
// Addresses:
//   S-04: Public tracking routes disabled by default
//   S-05: Startup guard — non-empty API key required outside tests

package api

import (
	"fmt"
	"net"
	"strings"
)

// ValidateAPIConfig validates the ServerConfig before daemon startup.
// Returns an error that will prevent startup if security invariants are violated.
//
// Addresses S-05: Local API Risk — require non-empty API key, forbid wildcard CORS.
func ValidateAPIConfig(cfg *ServerConfig) error {
	var errs []string

	if cfg.APIKey == "" {
		errs = append(errs, "api_key must be non-empty (generate with: luminet keygen)")
	}
	for _, origin := range cfg.AllowedOrigins {
		if origin == "*" {
			errs = append(errs, "wildcard CORS origin \"*\" is not allowed for the privileged API")
			break
		}
	}
	// The bind host must actually resolve to a loopback address. Parsing the
	// address (rather than string-prefix matching) rejects hostnames that
	// merely start with "127." while still accepting "localhost" and the
	// bracketed IPv6 loopback spelling.
	host := strings.TrimSpace(cfg.Host)
	host = strings.Trim(host, "[]")
	if host != "" && host != "localhost" {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			errs = append(errs, fmt.Sprintf("host %q must be a loopback address (127.x.x.x or ::1) for privileged API", cfg.Host))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("API config validation failed:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

// HostsOverrideConfig controls DNS host override behaviour.
// Addresses S-08: Default Host Override Changes DNS Truth.
type HostsOverrideConfig struct {
	// Enabled must be explicitly set — default is FALSE.
	Enabled bool `json:"enabled"`
	// BundlePath is the path to a signed JSON override rule bundle.
	BundlePath string `json:"bundle_path,omitempty"`
	// AllowUnsigned allows loading unsigned bundles (development only).
	AllowUnsigned bool `json:"allow_unsigned"`
}

// DefaultHostsOverrideConfig returns a safe default (disabled).
func DefaultHostsOverrideConfig() HostsOverrideConfig {
	return HostsOverrideConfig{
		Enabled:       false, // MUST be explicit opt-in
		AllowUnsigned: false,
	}
}

// OverrideRuleBundle represents a signed DNS override rule bundle.
// Addresses S-08: signed bundles with expiry.
type OverrideRuleBundle struct {
	Schema    int            `json:"schema"`
	BundleID  string         `json:"bundle_id"`
	CreatedAt string         `json:"created_at"`
	ExpiresAt string         `json:"expires_at"`
	Owner     string         `json:"owner"`
	Rules     []OverrideRule `json:"rules"`
	Signature string         `json:"signature"` // base64 HMAC-SHA256
}

// OverrideRule maps a domain to a hardcoded IP.
type OverrideRule struct {
	Domain string `json:"domain"`
	IP     string `json:"ip"`
	Reason string `json:"reason"`
	Source string `json:"source"` // "manual" | "bundle"
}

// BackgroundEgressConfig controls the network health audit scheduler.
// Addresses R-05: Background Network Health Audit Causes Default Egress.
type BackgroundEgressConfig struct {
	// Enabled must be explicitly set — default is FALSE.
	// When false, the network_health_audit job never registers.
	Enabled bool `json:"enabled"`
	// Targets are the external hosts to probe (e.g., "1.1.1.1", "google.com").
	// Empty means no external probing even if Enabled is true.
	Targets []string `json:"targets,omitempty"`
	// IntervalMinutes is the probe interval. Default: 5.
	IntervalMinutes int `json:"interval_minutes"`
}

// DefaultBackgroundEgressConfig returns a safe default (disabled, no targets).
func DefaultBackgroundEgressConfig() BackgroundEgressConfig {
	return BackgroundEgressConfig{
		Enabled:         false, // MUST be explicit opt-in
		IntervalMinutes: 5,
	}
}
