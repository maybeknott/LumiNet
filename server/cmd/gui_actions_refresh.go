//go:build windows && cgo

package cmd

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

func (s *nativeShell) refreshLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if s.mw == nil || s.mw.Handle() == 0 {
			return
		}
		if s.autoRefresh != nil && s.autoRefresh.Checked() {
			s.refreshStatus()
		}
	}
}

func (s *nativeShell) refreshAll() {
	s.refreshStatus()
	s.refreshCapabilities()
	s.refreshHistory()
	s.refreshSystemSettings()
	s.refreshMaintenance()
	s.refreshProxyDirectory()
}

func (s *nativeShell) refreshStatus() {
	go func() {
		var status nativeSystemStatus
		err := s.getJSON("/api/system/status", &status)
		s.sync(func() {
			if err != nil {
				s.setStatus("Status refresh failed: " + err.Error())
				return
			}
			s.lastStatus = status
			s.lastRefresh = time.Now()

			s.cpuHistory = append(s.cpuHistory, status.CPUUsage)
			if len(s.cpuHistory) > 30 {
				s.cpuHistory = s.cpuHistory[1:]
			}
			s.ramHistory = append(s.ramHistory, status.RAMUsage)
			if len(s.ramHistory) > 30 {
				s.ramHistory = s.ramHistory[1:]
			}
			if s.cpuLabel != nil {
				s.cpuLabel.SetText(fmt.Sprintf("%d%%", status.CPUUsage))
			}
			if s.ramLabel != nil {
				s.ramLabel.SetText(fmt.Sprintf("%d%%  %.1f / %.1f GiB", status.RAMUsage, status.UsedRAMGb, status.TotalRAMGb))
			}
			if s.diskLabel != nil {
				s.diskLabel.SetText(fmt.Sprintf("%d%%  %d GiB free", status.DiskUsage, status.DiskFreeGb))
			}
			if s.jobsLabel != nil {
				s.jobsLabel.SetText(fmt.Sprintf("%d active", status.ActiveJobs))
			}
			if s.publicIPLabel != nil {
				s.publicIPLabel.SetText(emptyDash(status.PublicIPv4))
			}
			if s.publicIPv6Label != nil {
				s.publicIPv6Label.SetText(emptyDash(status.PublicIPv6))
			}
			if s.dnsLabel != nil {
				s.dnsLabel.SetText(emptyDash(strings.Join(status.DNSServers, ", ")))
			}
			if s.proxyLabel != nil {
				s.proxyLabel.SetText(map[bool]string{true: "enabled", false: "disabled"}[status.ProxyActive])
			}
			if s.overviewEdit != nil {
				s.overviewEdit.SetText(formatStatusOverview(status))
			}
			if s.interfacesEdit != nil {
				s.interfacesEdit.SetText(formatInterfaces(status.Interfaces))
			}
			s.invalidateCockpit()
			s.refreshEvasionStatus()
			s.setStatus("Status refreshed.")
		})
	}()
}

func (s *nativeShell) refreshInterfaces() {
	go func() {
		var status nativeSystemStatus
		err := s.getJSON("/api/system/status", &status)
		s.sync(func() {
			if err != nil {
				s.setStatus("Interface refresh failed: " + err.Error())
				return
			}
			s.lastStatus = status
			s.lastRefresh = time.Now()
			if s.interfacesEdit != nil {
				s.interfacesEdit.SetText(formatInterfaces(status.Interfaces))
			}
			if s.publicIPLabel != nil {
				s.publicIPLabel.SetText(emptyDash(status.PublicIPv4))
			}
			if s.publicIPv6Label != nil {
				s.publicIPv6Label.SetText(emptyDash(status.PublicIPv6))
			}
			s.invalidateCockpit()
			s.setStatus("Interfaces refreshed.")
		})
	}()
}

func (s *nativeShell) refreshCapabilities() {
	go func() {
		var caps nativeCapabilityResponse
		err := s.getJSON("/api/capabilities", &caps)
		s.sync(func() {
			if err != nil {
				s.setStatus("Capability refresh failed: " + err.Error())
				return
			}
			s.lastCaps = caps
			s.lastRefresh = time.Now()
			coreState := "Rust core active"
			if caps.Runtime.MockCore {
				coreState = "Mock core active"
			}
			if s.runtimeLabel != nil {
				s.runtimeLabel.SetText(fmt.Sprintf("%s/%s - %s", caps.Runtime.OS, caps.Runtime.Arch, coreState))
			}
			if s.capabilityEdit != nil {
				s.capabilityEdit.SetText(formatCapabilities(caps))
			}
			if s.toolLedgerEdit != nil {
				s.toolLedgerEdit.SetText(formatToolLedger(caps))
			}
			if s.boundaryEdit != nil {
				s.boundaryEdit.SetText(formatBoundary(caps))
			}
			s.invalidateCockpit()
			s.setStatus("Capabilities refreshed.")
		})
	}()
}

func (s *nativeShell) refreshSystemSettings() {
	s.refreshDNS()
	s.refreshSystemProxy()
	s.refreshNCSI()
	s.refreshScannerSettings()
}

func (s *nativeShell) refreshDNS() {
	go func() {
		var status nativeDNSStatus
		err := s.getJSON("/api/system/dns", &status)
		s.sync(func() {
			if err != nil {
				s.setStatus("DNS refresh failed: " + err.Error())
				return
			}
			if s.dnsInterface != nil {
				s.dnsInterface.SetText(emptyDash(status.Interface))
			}
			if s.dnsSourceLabel != nil {
				s.dnsSourceLabel.SetText(emptyDash(status.Source))
			}
			if s.dnsServersEdit != nil {
				s.dnsServersEdit.SetText(strings.Join(status.Servers, ", "))
			}
			s.setStatus("DNS settings refreshed.")
		})
	}()
}

func (s *nativeShell) refreshSystemProxy() {
	go func() {
		var status nativeProxyStatus
		err := s.getJSON("/api/system/proxy", &status)
		s.sync(func() {
			if err != nil {
				s.setStatus("Proxy refresh failed: " + err.Error())
				return
			}
			if s.sysProxyEnabled != nil {
				s.sysProxyEnabled.SetChecked(status.Enabled && status.Server != "")
			}
			if s.sysProxyServer != nil {
				s.sysProxyServer.SetText(status.Server)
			}
			if s.sysProxyBypass != nil {
				s.sysProxyBypass.SetText(status.Bypass)
			}
			if s.sysProxyPACEnabled != nil {
				s.sysProxyPACEnabled.SetChecked(status.PacURL != "")
			}
			if s.sysProxyPACURL != nil {
				s.sysProxyPACURL.SetText(status.PacURL)
			}
			s.setStatus("System proxy refreshed.")
		})
	}()
}

func (s *nativeShell) refreshMaintenance() {
	s.refreshStartup()
	s.refreshDDNS()
	s.refreshProfiles()
}

func (s *nativeShell) refreshStartup() {
	go func() {
		var status nativeStartupStatus
		err := s.getJSON("/api/system/startup", &status)
		s.sync(func() {
			if err != nil {
				s.setStatus("Startup refresh failed: " + err.Error())
				return
			}
			if s.startupEnabled != nil {
				s.startupEnabled.SetChecked(status.Enabled)
			}
			s.setStatus("Startup setting refreshed.")
		})
	}()
}

func (s *nativeShell) refreshDDNS() {
	go func() {
		var status nativeDDNSStatus
		err := s.getJSON("/api/system/ddns", &status)
		s.sync(func() {
			if err != nil {
				s.setStatus("DDNS refresh failed: " + err.Error())
				return
			}
			if s.ddnsEnabled != nil {
				s.ddnsEnabled.SetChecked(status.Enabled)
			}
			if s.ddnsProvider != nil {
				s.ddnsProvider.SetText(status.Provider)
			}
			if s.ddnsDomain != nil {
				s.ddnsDomain.SetText(status.Domain)
			}
			if s.ddnsInterval != nil && status.Interval > 0 {
				s.ddnsInterval.SetText(strconv.Itoa(status.Interval))
			}
			s.setStatus("DDNS settings refreshed.")
		})
	}()
}

func (s *nativeShell) refreshProfiles() {
	go func() {
		var status nativeProfilesStatus
		err := s.getJSON("/api/system/profiles", &status)
		s.sync(func() {
			if err != nil {
				s.setStatus("Profiles refresh failed: " + err.Error())
				return
			}
			if s.profilesEdit != nil {
				s.profilesEdit.SetText(formatProfiles(status))
			}
			s.setStatus("Network profiles refreshed.")
		})
	}()
}

func (s *nativeShell) refreshHistory() {
	go func() {
		var history nativeHistoryResponse
		err := s.getJSON("/api/history", &history)
		s.sync(func() {
			if err != nil {
				s.setStatus("History refresh failed: " + err.Error())
				return
			}
			s.lastHistory = history
			s.lastRefresh = time.Now()
			if s.historyTotal != nil {
				s.historyTotal.SetText(fmt.Sprintf("%d recorded job(s)", history.Total))
			}
			if s.historyEdit != nil {
				s.historyEdit.SetText(formatHistory(history))
			}
			s.invalidateCockpit()
			s.setStatus("History refreshed.")
		})
	}()
}

func (s *nativeShell) refreshNCSI() {
	go func() {
		var status nativeNCSIStatus
		err := s.getJSON("/api/system/ncsi", &status)
		s.sync(func() {
			if err != nil {
				s.setStatus("NCSI refresh failed: " + err.Error())
				return
			}
			if s.ncsiWebHost != nil {
				s.ncsiWebHost.SetText(status.ActiveWebProbeHost)
			}
			if s.ncsiWebPath != nil {
				s.ncsiWebPath.SetText(status.ActiveWebProbePath)
			}
			if s.ncsiWebContent != nil {
				s.ncsiWebContent.SetText(status.ActiveWebProbeContents)
			}
			if s.ncsiDnsHost != nil {
				s.ncsiDnsHost.SetText(status.ActiveDnsProbeHost)
			}
			if s.ncsiDnsContent != nil {
				s.ncsiDnsContent.SetText(status.ActiveDnsProbeContent)
			}
			if s.ncsiActiveProbe != nil {
				s.ncsiActiveProbe.SetChecked(status.EnableActiveProbing != 0)
			}
			s.setStatus("NCSI settings refreshed.")
		})
	}()
}

func (s *nativeShell) refreshScannerSettings() {
	go func() {
		var settings nativeScannerSettings
		err := s.getJSON("/api/system/settings", &settings)
		s.sync(func() {
			if err != nil {
				s.setStatus("Scanner settings refresh failed: " + err.Error())
				return
			}
			if s.defaultTimeoutEdit != nil {
				s.defaultTimeoutEdit.SetText(strconv.Itoa(settings.DefaultTimeoutMs))
			}
			if s.maxConcurrencyEdit != nil {
				s.maxConcurrencyEdit.SetText(strconv.Itoa(settings.MaxConcurrency))
			}
			if s.debugLogsCheck != nil {
				s.debugLogsCheck.SetChecked(settings.DebugLogs)
			}
			if s.dnsResolutionCheck != nil {
				s.dnsResolutionCheck.SetChecked(settings.DnsResolution)
			}
			if s.hostsOverrideCheck != nil {
				s.hostsOverrideCheck.SetChecked(settings.HostsOverride)
			}

			if s.bypassChinaCheck != nil {
				s.bypassChinaCheck.SetChecked(settings.MihomoRules.BypassChina)
			}
			if s.bypassIranCheck != nil {
				s.bypassIranCheck.SetChecked(settings.MihomoRules.BypassIran)
			}
			if s.bypassRussiaCheck != nil {
				s.bypassRussiaCheck.SetChecked(settings.MihomoRules.BypassRussia)
			}
			if s.bypassOpenAICheck != nil {
				s.bypassOpenAICheck.SetChecked(settings.MihomoRules.BypassOpenAI)
			}
			if s.bypassGoogleAICheck != nil {
				s.bypassGoogleAICheck.SetChecked(settings.MihomoRules.BypassGoogleAI)
			}
			if s.bypassMicrosoftCheck != nil {
				s.bypassMicrosoftCheck.SetChecked(settings.MihomoRules.BypassMicrosoft)
			}
			if s.bypassOracleCheck != nil {
				s.bypassOracleCheck.SetChecked(settings.MihomoRules.BypassOracle)
			}
			if s.bypassDockerCheck != nil {
				s.bypassDockerCheck.SetChecked(settings.MihomoRules.BypassDocker)
			}
			if s.bypassAdobeCheck != nil {
				s.bypassAdobeCheck.SetChecked(settings.MihomoRules.BypassAdobe)
			}
			if s.bypassEpicGamesCheck != nil {
				s.bypassEpicGamesCheck.SetChecked(settings.MihomoRules.BypassEpicGames)
			}
			if s.bypassIntelCheck != nil {
				s.bypassIntelCheck.SetChecked(settings.MihomoRules.BypassIntel)
			}
			if s.bypassAMDCheck != nil {
				s.bypassAMDCheck.SetChecked(settings.MihomoRules.BypassAMD)
			}
			if s.bypassNvidiaCheck != nil {
				s.bypassNvidiaCheck.SetChecked(settings.MihomoRules.BypassNvidia)
			}
			if s.bypassAsusCheck != nil {
				s.bypassAsusCheck.SetChecked(settings.MihomoRules.BypassAsus)
			}
			if s.bypassHPCheck != nil {
				s.bypassHPCheck.SetChecked(settings.MihomoRules.BypassHP)
			}
			if s.bypassLenovoCheck != nil {
				s.bypassLenovoCheck.SetChecked(settings.MihomoRules.BypassLenovo)
			}
			if s.blockMalwareCheck != nil {
				s.blockMalwareCheck.SetChecked(settings.MihomoRules.BlockMalware)
			}
			if s.blockPhishingCheck != nil {
				s.blockPhishingCheck.SetChecked(settings.MihomoRules.BlockPhishing)
			}
			if s.blockCryptominersCheck != nil {
				s.blockCryptominersCheck.SetChecked(settings.MihomoRules.BlockCryptominers)
			}
			if s.blockAdsCheck != nil {
				s.blockAdsCheck.SetChecked(settings.MihomoRules.BlockAds)
			}
			if s.blockPornCheck != nil {
				s.blockPornCheck.SetChecked(settings.MihomoRules.BlockPorn)
			}

			s.setStatus("Scanner settings refreshed.")
		})
	}()
}
