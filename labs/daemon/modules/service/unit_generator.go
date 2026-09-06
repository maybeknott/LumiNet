package service

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var namePattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// ValidateProfileName ensures that profile names contain only alphanumeric characters, hyphens, and underscores.
func ValidateProfileName(name string) (string, error) {
	cleaned := strings.TrimSpace(name)
	if cleaned == "" {
		return "", errors.New("profile name cannot be empty")
	}
	if !namePattern.MatchString(cleaned) {
		return "", fmt.Errorf("invalid profile name %q: must match ^[A-Za-z0-9_-]+$", cleaned)
	}
	return cleaned, nil
}

// UnitConfig holds the metadata and runtime parameters required to generate a systemd service unit.
type UnitConfig struct {
	ProfileName      string
	Description      string
	WorkingDirectory string
	ExecStart        string
	User             string
	RestartPolicy    string
	RestartSec       int
	EnvironmentVars  map[string]string
}

// BuildSystemdUnit compiles a valid systemd unit configuration string.
func BuildSystemdUnit(cfg UnitConfig) (string, error) {
	validName, err := ValidateProfileName(cfg.ProfileName)
	if err != nil {
		return "", err
	}

	desc := cfg.Description
	if desc == "" {
		desc = fmt.Sprintf("LumiNet Tunnel Instance (%s)", validName)
	}

	user := cfg.User
	if user == "" {
		user = "root"
	}

	restart := cfg.RestartPolicy
	if restart == "" {
		restart = "always"
	}

	restartSec := cfg.RestartSec
	if restartSec <= 0 {
		restartSec = 5
	}

	execStart := cfg.ExecStart
	if execStart == "" {
		return "", errors.New("execStart path cannot be empty")
	}

	var sb strings.Builder
	sb.WriteString("[Unit]\n")
	sb.WriteString(fmt.Sprintf("Description=%s\n", desc))
	sb.WriteString("After=network.target\n\n")

	sb.WriteString("[Service]\n")
	sb.WriteString("Type=simple\n")
	if cfg.WorkingDirectory != "" {
		sb.WriteString(fmt.Sprintf("WorkingDirectory=%s\n", cfg.WorkingDirectory))
	}

	// Deterministic ordering of environment variables
	if len(cfg.EnvironmentVars) > 0 {
		keys := make([]string, 0, len(cfg.EnvironmentVars))
		for k := range cfg.EnvironmentVars {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := cfg.EnvironmentVars[k]
			escaped := strings.ReplaceAll(v, "\"", "\\\"")
			sb.WriteString(fmt.Sprintf("Environment=\"%s=%s\"\n", k, escaped))
		}
	}

	sb.WriteString(fmt.Sprintf("ExecStart=%s\n", execStart))
	sb.WriteString(fmt.Sprintf("Restart=%s\n", restart))
	sb.WriteString(fmt.Sprintf("RestartSec=%d\n", restartSec))
	sb.WriteString(fmt.Sprintf("User=%s\n\n", user))

	sb.WriteString("[Install]\n")
	sb.WriteString("WantedBy=multi-user.target\n")

	return sb.String(), nil
}

// GenerateTomlConfig generates formatted TOML configuration lines from key-value pairs.
func GenerateTomlConfig(config map[string]interface{}) string {
	keys := make([]string, 0, len(config))
	for k := range config {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var lines []string
	for _, k := range keys {
		val := config[k]
		switch v := val.(type) {
		case []string:
			quoted := make([]string, len(v))
			for i, item := range v {
				quoted[i] = fmt.Sprintf("%q", item)
			}
			lines = append(lines, fmt.Sprintf("%s = [%s]", k, strings.Join(quoted, ", ")))
		case bool:
			lines = append(lines, fmt.Sprintf("%s = %t", k, v))
		case int:
			lines = append(lines, fmt.Sprintf("%s = %d", k, v))
		case float64:
			lines = append(lines, fmt.Sprintf("%s = %g", k, v))
		default:
			lines = append(lines, fmt.Sprintf("%s = %q", k, fmt.Sprintf("%v", v)))
		}
	}
	return strings.Join(lines, "\n") + "\n"
}

// ParseProcNetDev parses /proc/net/dev content and aggregates total rx and tx bytes across physical interfaces.
func ParseProcNetDev(content string) (uint64, uint64, error) {
	var totalRx, totalTx uint64

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		iface := strings.TrimSpace(parts[0])
		if iface == "lo" {
			continue // ignore loopback
		}

		fields := strings.Fields(parts[1])
		if len(fields) < 9 {
			continue
		}

		rx, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		tx, err := strconv.ParseUint(fields[8], 10, 64)
		if err != nil {
			continue
		}

		totalRx += rx
		totalTx += tx
	}

	return totalRx, totalTx, nil
}

// CalculateNetworkRates derives transfer speeds (in Bytes/sec) from consecutive counter samples.
func CalculateNetworkRates(prevRx, prevTx, currRx, currTx uint64, durationSec float64) (float64, float64) {
	if durationSec <= 0 {
		return 0, 0
	}
	var rxRate, txRate float64
	if currRx >= prevRx {
		rxRate = float64(currRx-prevRx) / durationSec
	}
	if currTx >= prevTx {
		txRate = float64(currTx-prevTx) / durationSec
	}
	return rxRate, txRate
}
