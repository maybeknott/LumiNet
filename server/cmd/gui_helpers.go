//go:build windows && cgo

package cmd

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/maybeknott/luminet/internal/proxy"
)

func formatCapabilities(caps nativeCapabilityResponse) string {
	var b strings.Builder
	for _, item := range caps.Catalog {
		fmt.Fprintf(&b, "%s  [%s / %s]\r\n", item.Name, item.Maturity, item.NativeRuntime)
		fmt.Fprintf(&b, "  Domain: %s    Priority: %s\r\n", item.Domain, item.Priority)
		fmt.Fprintf(&b, "  Safe state: %s\r\n", item.SafeState)
		if len(item.AllowedOperations) > 0 {
			fmt.Fprintf(&b, "  Operations: %s\r\n", strings.Join(item.AllowedOperations, ", "))
		}
		if item.Warning != "" {
			fmt.Fprintf(&b, "  Warning: %s\r\n", item.Warning)
		}
		b.WriteString("\r\n")
	}
	return b.String()
}

func formatToolLedger(caps nativeCapabilityResponse) string {
	var b strings.Builder
	for _, item := range caps.NetworkToolTemplates {
		fmt.Fprintf(&b, "%s  [%s]\r\n", item.Name, item.Status)
		fmt.Fprintf(&b, "  Source: %s\r\n", item.Source)
		fmt.Fprintf(&b, "  Native target: %s\r\n", item.NativeTarget)
		if len(item.UsefulFor) > 0 {
			fmt.Fprintf(&b, "  Useful for: %s\r\n", strings.Join(item.UsefulFor, ", "))
		}
		fmt.Fprintf(&b, "  Boundary: %s\r\n\r\n", item.SafetyBoundary)
	}
	return b.String()
}

func formatBoundary(caps nativeCapabilityResponse) string {
	return fmt.Sprintf("Mode: %s\r\n\r\nBlocked operations:\r\n- %s",
		caps.SafetyBoundary.Mode,
		strings.Join(caps.SafetyBoundary.BlockedOperations, "\r\n- "),
	)
}

func formatRunbookSnapshot(
	health map[string]interface{},
	status nativeSystemStatus,
	caps nativeCapabilityResponse,
	dns nativeDNSStatus,
	systemProxy nativeProxyStatus,
	startup nativeStartupStatus,
	ddns nativeDDNSStatus,
	profiles nativeProfilesStatus,
	history nativeHistoryResponse,
	errs []string,
) string {
	var b strings.Builder
	fmt.Fprintf(&b, "LumiNet native runbook snapshot\r\nGenerated: %s\r\n\r\n", time.Now().Format("2006-01-02 15:04:05"))

	b.WriteString("Readiness\r\n")
	fmt.Fprintf(&b, "- API health: %s\r\n", formatHealth(health))
	fmt.Fprintf(&b, "- Active jobs: %d\r\n", status.ActiveJobs)
	fmt.Fprintf(&b, "- Recorded jobs: %d\r\n", history.Total)
	fmt.Fprintf(&b, "- Core: %s/%s", caps.Runtime.OS, caps.Runtime.Arch)
	if caps.Runtime.MockCore {
		b.WriteString(" with mock core")
	} else if caps.Runtime.OS != "" {
		b.WriteString(" with Rust core")
	}
	b.WriteString("\r\n\r\n")

	b.WriteString("System\r\n")
	fmt.Fprintf(&b, "- Public IPv4: %s\r\n", emptyDash(status.PublicIPv4))
	fmt.Fprintf(&b, "- Public IPv6: %s\r\n", emptyDash(status.PublicIPv6))
	fmt.Fprintf(&b, "- Interfaces: %d active\r\n", len(status.Interfaces))
	fmt.Fprintf(&b, "- DNS: %s on %s (%s)\r\n", emptyDash(strings.Join(dns.Servers, ", ")), emptyDash(dns.Interface), emptyDash(dns.Source))
	fmt.Fprintf(&b, "- System proxy: %s", enabledText(systemProxy.Enabled))
	if systemProxy.Server != "" {
		fmt.Fprintf(&b, "  %s", proxy.URITransportPreview(systemProxy.Server, 96))
	}
	b.WriteString("\r\n")
	fmt.Fprintf(&b, "- Startup: %s\r\n", enabledText(startup.Enabled))
	fmt.Fprintf(&b, "- DDNS: %s", enabledText(ddns.Enabled))
	if ddns.Provider != "" || ddns.Domain != "" {
		fmt.Fprintf(&b, "  provider=%s domain=%s interval=%dmin", emptyDash(ddns.Provider), emptyDash(ddns.Domain), ddns.Interval)
	}
	b.WriteString("\r\n")
	fmt.Fprintf(&b, "- Active SSID: %s\r\n\r\n", emptyDash(profiles.ActiveSSID))

	b.WriteString("Resources\r\n")
	fmt.Fprintf(&b, "- CPU: %d%%\r\n", status.CPUUsage)
	fmt.Fprintf(&b, "- Memory: %d%%  %.1f / %.1f GiB\r\n", status.RAMUsage, status.UsedRAMGb, status.TotalRAMGb)
	fmt.Fprintf(&b, "- Disk: %d%%  %d GiB free\r\n\r\n", status.DiskUsage, status.DiskFreeGb)

	b.WriteString("Ported capability lanes\r\n")
	for _, item := range caps.Catalog {
		fmt.Fprintf(&b, "- %s [%s, %s] %s\r\n", item.Name, item.NativeRuntime, item.Maturity, item.SafeState)
	}
	if len(caps.NetworkToolTemplates) > 0 {
		b.WriteString("\r\nNetwork tool ledger\r\n")
		for _, item := range caps.NetworkToolTemplates {
			fmt.Fprintf(&b, "- %s: %s -> %s\r\n", item.Name, item.Status, item.NativeTarget)
		}
	}
	if len(caps.SafetyBoundary.BlockedOperations) > 0 {
		fmt.Fprintf(&b, "\r\nSafety boundary: %s\r\n", caps.SafetyBoundary.Mode)
		for _, blocked := range caps.SafetyBoundary.BlockedOperations {
			fmt.Fprintf(&b, "- blocked: %s\r\n", blocked)
		}
	}
	if len(errs) > 0 {
		b.WriteString("\r\nSnapshot warnings\r\n")
		for _, err := range errs {
			fmt.Fprintf(&b, "- %s\r\n", err)
		}
	}
	return b.String()
}

func formatHealth(health map[string]interface{}) string {
	if len(health) == 0 {
		return "unknown"
	}
	if status, ok := health["status"]; ok {
		return fmt.Sprint(status)
	}
	return fmt.Sprint(health)
}

func formatStatusOverview(status nativeSystemStatus) string {
	var b strings.Builder
	fmt.Fprintf(&b, "API connected: %v\r\n", status.APIConnected)
	fmt.Fprintf(&b, "Active jobs: %d\r\n", status.ActiveJobs)
	fmt.Fprintf(&b, "CPU: %d%%\r\n", status.CPUUsage)
	fmt.Fprintf(&b, "Memory: %d%%  %.1f / %.1f GiB\r\n", status.RAMUsage, status.UsedRAMGb, status.TotalRAMGb)
	fmt.Fprintf(&b, "Disk: %d%%  %d GiB free\r\n", status.DiskUsage, status.DiskFreeGb)
	fmt.Fprintf(&b, "Public IPv4: %s\r\n", emptyDash(status.PublicIPv4))
	fmt.Fprintf(&b, "Public IPv6: %s\r\n", emptyDash(status.PublicIPv6))
	fmt.Fprintf(&b, "DNS servers: %s\r\n", emptyDash(strings.Join(status.DNSServers, ", ")))
	fmt.Fprintf(&b, "System proxy: %s\r\n", enabledText(status.ProxyActive))
	fmt.Fprintf(&b, "Interfaces: %d active\r\n", len(status.Interfaces))
	if len(status.Interfaces) > 0 {
		b.WriteString("\r\nPrimary interfaces\r\n")
		for i, iface := range status.Interfaces {
			if i >= 4 {
				fmt.Fprintf(&b, "- +%d more\r\n", len(status.Interfaces)-i)
				break
			}
			name := iface.Name
			if iface.SSID != "" {
				name += " / " + iface.SSID
			}
			fmt.Fprintf(&b, "- %s  %s\r\n", emptyDash(name), emptyDash(strings.Join(iface.IPs, ", ")))
		}
	}
	return b.String()
}

func enabledText(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "disabled"
}

func formatHistory(history nativeHistoryResponse) string {
	if len(history.Jobs) == 0 {
		return "No jobs recorded yet.\r\nRun a scan, diagnostic, or proxy test to populate the local job ledger."
	}

	var b strings.Builder
	for i, job := range history.Jobs {
		fmt.Fprintf(&b, "%03d  %s  [%s]  %d%%\r\n", i+1, job.Type, job.Status, job.Progress)
		fmt.Fprintf(&b, "     id: %s\r\n", job.ID)
		fmt.Fprintf(&b, "     created: %s", formatNativeTime(&job.CreatedAt))
		if job.StartedAt != nil {
			fmt.Fprintf(&b, "    started: %s", formatNativeTime(job.StartedAt))
		}
		if job.CompletedAt != nil {
			fmt.Fprintf(&b, "    completed: %s", formatNativeTime(job.CompletedAt))
		}
		b.WriteString("\r\n")
		if summary := summarizeJobConfig(job.Config); summary != "" {
			fmt.Fprintf(&b, "     config: %s\r\n", summary)
		}
		if strings.TrimSpace(job.Error) != "" {
			fmt.Fprintf(&b, "     error: %s\r\n", job.Error)
		}
		b.WriteString("\r\n")
	}
	return b.String()
}

func formatInterfaces(interfaces []nativeNetworkInterface) string {
	if len(interfaces) == 0 {
		return "No active interfaces reported."
	}
	var b strings.Builder
	for i, iface := range interfaces {
		kind := "wired"
		if iface.IsWireless {
			kind = "wireless"
		}
		fmt.Fprintf(&b, "%03d  %s  [%s]\r\n", i+1, emptyDash(iface.Name), kind)
		fmt.Fprintf(&b, "     mac: %s\r\n", emptyDash(iface.MAC))
		fmt.Fprintf(&b, "     ips: %s\r\n", emptyDash(strings.Join(iface.IPs, ", ")))
		fmt.Fprintf(&b, "     gateway: %s\r\n", emptyDash(iface.Gateway))
		if iface.SSID != "" {
			fmt.Fprintf(&b, "     ssid: %s\r\n", iface.SSID)
		}
		b.WriteString("\r\n")
	}
	return b.String()
}

func formatProfiles(status nativeProfilesStatus) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Active SSID: %s\r\n", emptyDash(status.ActiveSSID))
	if status.Message != "" {
		fmt.Fprintf(&b, "%s\r\n", status.Message)
	}
	if len(status.Profiles) == 0 {
		return b.String()
	}
	b.WriteString("\r\nConfigured profiles:\r\n")
	for _, profile := range status.Profiles {
		active := ""
		if profile.Active {
			active = " active"
		}
		fmt.Fprintf(&b, "- %s%s", profile.Name, active)
		if profile.SSID != "" {
			fmt.Fprintf(&b, "  ssid=%s", profile.SSID)
		}
		if profile.BSSID != "" {
			fmt.Fprintf(&b, "  bssid=%s", profile.BSSID)
		}
		b.WriteString("\r\n")
	}
	return b.String()
}

func formatJobDetail(job nativeHistoryJob) string {
	var b strings.Builder
	fmt.Fprintf(&b, "ID: %s\r\n", job.ID)
	fmt.Fprintf(&b, "Type: %s\r\n", job.Type)
	fmt.Fprintf(&b, "Status: %s\r\n", job.Status)
	fmt.Fprintf(&b, "Progress: %d%%\r\n", job.Progress)
	fmt.Fprintf(&b, "Created: %s\r\n", formatNativeTime(&job.CreatedAt))
	if job.StartedAt != nil {
		fmt.Fprintf(&b, "Started: %s\r\n", formatNativeTime(job.StartedAt))
	}
	if job.CompletedAt != nil {
		fmt.Fprintf(&b, "Completed: %s\r\n", formatNativeTime(job.CompletedAt))
	}
	if strings.TrimSpace(job.Error) != "" {
		fmt.Fprintf(&b, "\r\nError:\r\n%s\r\n", job.Error)
	}
	if strings.TrimSpace(job.Config) != "" {
		fmt.Fprintf(&b, "\r\nConfig:\r\n%s\r\n", prettyJobJSON(job.Config, 3000))
	}
	if strings.TrimSpace(job.Results) != "" {
		fmt.Fprintf(&b, "\r\nResults:\r\n%s\r\n", prettyJobJSON(job.Results, 5000))
	}
	return b.String()
}

func prettyJobJSON(raw string, maxLen int) string {
	raw = redactHistoryString(raw)
	var parsed interface{}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return compactText(raw, maxLen)
	}
	formatted, err := json.MarshalIndent(parsed, "", "  ")
	if err != nil {
		return compactText(raw, maxLen)
	}
	return compactText(string(formatted), maxLen)
}

func formatNativeTime(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "-"
	}
	return t.Local().Format("2006-01-02 15:04:05")
}

func summarizeJobConfig(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		return compactText(redactHistoryString(raw), 140)
	}

	keys := []string{
		"target", "type", "host", "hosts", "domain", "domains", "port", "ports",
		"timeout_ms", "concurrency", "test_url", "proxy_preview", "proxy_addr",
	}
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		value, ok := data[key]
		if !ok {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%s", key, compactText(formatHistoryValue(value), 80)))
	}
	if len(parts) == 0 {
		return fmt.Sprintf("%d config field(s)", len(data))
	}
	return strings.Join(parts, "  ")
}

func formatHistoryValue(value interface{}) string {
	switch typed := value.(type) {
	case string:
		return redactHistoryString(typed)
	case []interface{}:
		if len(typed) == 0 {
			return "[]"
		}
		values := make([]string, 0, minInt(len(typed), 4))
		for i, item := range typed {
			if i >= 4 {
				values = append(values, fmt.Sprintf("+%d more", len(typed)-i))
				break
			}
			values = append(values, formatHistoryValue(item))
		}
		return "[" + strings.Join(values, ", ") + "]"
	default:
		return fmt.Sprint(value)
	}
}

func redactHistoryString(value string) string {
	if strings.Contains(value, "://") {
		return proxy.URITransportPreview(value, 120)
	}
	return value
}

func compactText(value string, maxLen int) string {
	value = strings.Join(strings.Fields(value), " ")
	if maxLen <= 0 || len(value) <= maxLen {
		return value
	}
	if maxLen <= 1 {
		return value[:maxLen]
	}
	return value[:maxLen-1] + "..."
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func splitTargets(input string) []string {
	parts := strings.FieldsFunc(input, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t'
	})
	targets := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			targets = append(targets, part)
		}
	}
	if len(targets) == 0 {
		return []string{strings.TrimSpace(input)}
	}
	return targets
}

func firstTarget(input string) string {
	targets := splitTargets(input)
	if len(targets) == 0 {
		return strings.TrimSpace(input)
	}
	return targets[0]
}

func parsePositiveInt(input string, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(input))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func parsePortList(input string) ([]uint16, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, fmt.Errorf("enter one or more ports")
	}

	var ports []uint16
	seen := make(map[uint16]struct{})
	for _, token := range strings.FieldsFunc(input, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' }) {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if strings.Contains(token, "-") {
			bounds := strings.SplitN(token, "-", 2)
			start, err := strconv.Atoi(strings.TrimSpace(bounds[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid port range %q", token)
			}
			end, err := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid port range %q", token)
			}
			if start <= 0 || end <= 0 || start > 65535 || end > 65535 || start > end {
				return nil, fmt.Errorf("port range %q is outside 1-65535", token)
			}
			for port := start; port <= end; port++ {
				p := uint16(port)
				if _, ok := seen[p]; !ok {
					seen[p] = struct{}{}
					ports = append(ports, p)
				}
			}
			continue
		}
		port, err := strconv.Atoi(token)
		if err != nil || port <= 0 || port > 65535 {
			return nil, fmt.Errorf("invalid port %q", token)
		}
		p := uint16(port)
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			ports = append(ports, p)
		}
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("enter one or more ports")
	}
	return ports, nil
}

func firstPortOrDefault(input string, fallback uint16) uint16 {
	ports, err := parsePortList(input)
	if err != nil || len(ports) == 0 {
		return fallback
	}
	return ports[0]
}

func splitCSV(input string) []string {
	parts := strings.FieldsFunc(input, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			values = append(values, part)
		}
	}
	return values
}

func splitProxyLines(input string) []string {
	parts := strings.FieldsFunc(input, func(r rune) bool {
		return r == '\n' || r == '\r'
	})
	values := make([]string, 0, len(parts))
	seen := make(map[string]struct{})
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, ok := seen[part]; ok {
			continue
		}
		seen[part] = struct{}{}
		values = append(values, part)
	}
	return values
}

func emptyDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

func parseProxyText(input string) ([]*proxy.ProxyConfig, error) {
	return proxy.ParseSubscriptionContent(input)
}
