//go:build windows

package system

import (
	"context"
	"os/exec"

	"github.com/maybeknott/luminet/internal/utils"
	"golang.org/x/sys/windows/registry"
)

const ncsiRegPath = `SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet`

// NCSIConfig represents Windows NCSI parameters.
type NCSIConfig struct {
	ActiveWebProbeHost     string `json:"active_web_probe_host"`
	ActiveWebProbePath     string `json:"active_web_probe_path"`
	ActiveWebProbeContents string `json:"active_web_probe_contents"`
	ActiveDnsProbeHost     string `json:"active_dns_probe_host"`
	ActiveDnsProbeContent  string `json:"active_dns_probe_content"`
	EnableActiveProbing    uint32 `json:"enable_active_probing"`
}

// GetNCSIConfig reads NCSI registry parameters.
func GetNCSIConfig() (*NCSIConfig, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, ncsiRegPath, registry.READ)
	if err != nil {
		return nil, err
	}
	defer k.Close()

	host, _, _ := k.GetStringValue("ActiveWebProbeHost")
	path, _, _ := k.GetStringValue("ActiveWebProbePath")
	contents, _, _ := k.GetStringValue("ActiveWebProbeContents")
	dnsHost, _, _ := k.GetStringValue("ActiveDnsProbeHost")
	dnsContent, _, _ := k.GetStringValue("ActiveDnsProbeContent")
	probing, _, _ := k.GetIntegerValue("EnableActiveProbing")

	return &NCSIConfig{
		ActiveWebProbeHost:     host,
		ActiveWebProbePath:     path,
		ActiveWebProbeContents: contents,
		ActiveDnsProbeHost:     dnsHost,
		ActiveDnsProbeContent:  dnsContent,
		EnableActiveProbing:    uint32(probing),
	}, nil
}

// SetNCSIConfig writes NCSI parameters and restarts NlaSvc.
func SetNCSIConfig(ctx context.Context, config *NCSIConfig) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, ncsiRegPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	_ = k.SetStringValue("ActiveWebProbeHost", config.ActiveWebProbeHost)
	_ = k.SetStringValue("ActiveWebProbePath", config.ActiveWebProbePath)
	_ = k.SetStringValue("ActiveWebProbeContents", config.ActiveWebProbeContents)
	_ = k.SetStringValue("ActiveDnsProbeHost", config.ActiveDnsProbeHost)
	_ = k.SetStringValue("ActiveDnsProbeContent", config.ActiveDnsProbeContent)
	_ = k.SetDWordValue("EnableActiveProbing", config.EnableActiveProbing)

	// Restart NlaSvc to apply changes
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", "Restart-Service NlaSvc -Force")
	cmd.SysProcAttr = utils.GetHideWindowSysProcAttr()
	_ = cmd.Run() // Restart-Service might take a moment, ignore return errors since NlaSvc dependencies are restarted automatically

	return nil
}

// ResetNCSIConfig resets the NCSI configuration back to standard Microsoft defaults.
func ResetNCSIConfig(ctx context.Context) error {
	return SetNCSIConfig(ctx, &NCSIConfig{
		ActiveWebProbeHost:     "www.msftconnecttest.com",
		ActiveWebProbePath:     "connecttest.txt",
		ActiveWebProbeContents: "Microsoft Connect Test",
		ActiveDnsProbeHost:     "dns.msftncsi.com",
		ActiveDnsProbeContent:  "131.107.255.255",
		EnableActiveProbing:    1,
	})
}

// OverrideNcsiSettings is an alias function mapping to SetNCSIConfig.
func OverrideNcsiSettings(activeHost, activePath, activeContent string) error {
	return SetNCSIConfig(context.Background(), &NCSIConfig{
		ActiveWebProbeHost:     activeHost,
		ActiveWebProbePath:     activePath,
		ActiveWebProbeContents: activeContent,
		ActiveDnsProbeHost:     "dns.msftncsi.com",
		ActiveDnsProbeContent:  "131.107.255.255",
		EnableActiveProbing:    1,
	})
}

