//go:build !windows

package system

import "context"

// NCSIConfig represents Windows NCSI parameters (stub).
type NCSIConfig struct {
	ActiveWebProbeHost     string `json:"active_web_probe_host"`
	ActiveWebProbePath     string `json:"active_web_probe_path"`
	ActiveWebProbeContents string `json:"active_web_probe_contents"`
	ActiveDnsProbeHost     string `json:"active_dns_probe_host"`
	ActiveDnsProbeContent  string `json:"active_dns_probe_content"`
	EnableActiveProbing    uint32 `json:"enable_active_probing"`
}

// GetNCSIConfig reads NCSI registry parameters (stub).
func GetNCSIConfig() (*NCSIConfig, error) {
	return &NCSIConfig{
		EnableActiveProbing: 1,
	}, nil
}

// SetNCSIConfig writes NCSI parameters and restarts NlaSvc (stub).
func SetNCSIConfig(ctx context.Context, config *NCSIConfig) error {
	return nil
}

// ResetNCSIConfig resets the NCSI configuration back to standard Microsoft defaults (stub).
func ResetNCSIConfig(ctx context.Context) error {
	return nil
}

// OverrideNcsiSettings is an alias function mapping to SetNCSIConfig (stub).
func OverrideNcsiSettings(activeHost, activePath, activeContent string) error {
	return nil
}

