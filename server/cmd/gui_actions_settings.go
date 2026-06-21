//go:build windows && cgo

package cmd

import (
	"encoding/json"
	"fmt"
	"strings"
)

func (s *nativeShell) applyDNS() {
	servers := splitCSV(s.dnsServersEdit.Text())
	if len(servers) == 0 {
		s.setStatus("Enter at least one DNS server.")
		return
	}
	payload := map[string]interface{}{"servers": servers}
	if s.dnsInterface != nil && strings.TrimSpace(s.dnsInterface.Text()) != "" && s.dnsInterface.Text() != "-" {
		payload["interface"] = strings.TrimSpace(s.dnsInterface.Text())
	}
	go func() {
		body, _ := json.Marshal(payload)
		var result map[string]interface{}
		err := s.postJSON("/api/system/dns", body, &result)
		s.sync(func() {
			if err != nil {
				s.setStatus("Apply DNS failed: " + err.Error())
				return
			}
			s.appendLog(fmt.Sprintf("Applied DNS servers: %s", strings.Join(servers, ", ")))
			s.refreshDNS()
			s.refreshStatus()
		})
	}()
}

func (s *nativeShell) clearDNS() {
	go func() {
		err := s.deleteJSON("/api/system/dns")
		s.sync(func() {
			if err != nil {
				s.setStatus("Clear DNS failed: " + err.Error())
				return
			}
			s.appendLog("Cleared manual DNS settings.")
			s.refreshDNS()
			s.refreshStatus()
		})
	}()
}

func (s *nativeShell) applyQuad9DNS() {
	if s.dnsServersEdit != nil {
		s.dnsServersEdit.SetText("9.9.9.9, 149.112.112.112")
		s.applyDNS()
	}
}

func (s *nativeShell) applySystemProxy() {
	enabled := s.sysProxyEnabled.Checked()
	pacURL := ""
	if s.sysProxyPACEnabled != nil && s.sysProxyPACEnabled.Checked() {
		pacURL = strings.TrimSpace(s.sysProxyPACURL.Text())
		enabled = true
	}

	payload := map[string]interface{}{
		"enabled": enabled,
		"server":  strings.TrimSpace(s.sysProxyServer.Text()),
		"bypass":  strings.TrimSpace(s.sysProxyBypass.Text()),
		"pac_url": pacURL,
	}
	go func() {
		body, _ := json.Marshal(payload)
		var result map[string]interface{}
		err := s.postJSON("/api/system/proxy", body, &result)
		s.sync(func() {
			if err != nil {
				s.setStatus("Apply proxy failed: " + err.Error())
				return
			}
			s.appendLog("Applied system proxy settings.")
			s.refreshSystemProxy()
			s.refreshStatus()
		})
	}()
}

func (s *nativeShell) clearSystemProxy() {
	go func() {
		err := s.deleteJSON("/api/system/proxy")
		s.sync(func() {
			if err != nil {
				s.setStatus("Clear proxy failed: " + err.Error())
				return
			}
			s.appendLog("Cleared system proxy settings.")
			s.refreshSystemProxy()
			s.refreshStatus()
		})
	}()
}

func (s *nativeShell) applyStartup() {
	payload := map[string]interface{}{"enabled": s.startupEnabled.Checked()}
	go func() {
		body, _ := json.Marshal(payload)
		var result map[string]interface{}
		err := s.postJSON("/api/system/startup", body, &result)
		s.sync(func() {
			if err != nil {
				s.setStatus("Apply startup failed: " + err.Error())
				return
			}
			s.appendLog(fmt.Sprintf("Startup setting applied: %v", s.startupEnabled.Checked()))
			s.refreshStartup()
		})
	}()
}

func (s *nativeShell) saveDDNS() {
	payload := map[string]interface{}{
		"enabled":  s.ddnsEnabled.Checked(),
		"provider": strings.TrimSpace(s.ddnsProvider.Text()),
		"domain":   strings.TrimSpace(s.ddnsDomain.Text()),
		"interval": parsePositiveInt(s.ddnsInterval.Text(), 30),
	}
	if token := strings.TrimSpace(s.ddnsToken.Text()); token != "" {
		payload["token"] = token
	}
	go func() {
		body, _ := json.Marshal(payload)
		var result map[string]interface{}
		err := s.postJSON("/api/system/ddns", body, &result)
		s.sync(func() {
			if err != nil {
				s.setStatus("Save DDNS failed: " + err.Error())
				return
			}
			s.ddnsToken.SetText("")
			s.appendLog("Saved DDNS settings.")
			s.refreshDDNS()
		})
	}()
}

func (s *nativeShell) forceDDNS() {
	go func() {
		var result map[string]interface{}
		err := s.postJSON("/api/system/ddns/force", []byte("{}"), &result)
		s.sync(func() {
			if err != nil {
				s.setStatus("Force DDNS failed: " + err.Error())
				return
			}
			s.appendLog(fmt.Sprintf("DDNS force update result: %v", result))
			s.setStatus("DDNS update completed.")
		})
	}()
}

func (s *nativeShell) applyNCSI() {
	var probing uint32
	if s.ncsiActiveProbe != nil && s.ncsiActiveProbe.Checked() {
		probing = 1
	}
	payload := map[string]interface{}{
		"active_web_probe_host":     strings.TrimSpace(s.ncsiWebHost.Text()),
		"active_web_probe_path":     strings.TrimSpace(s.ncsiWebPath.Text()),
		"active_web_probe_contents": strings.TrimSpace(s.ncsiWebContent.Text()),
		"active_dns_probe_host":     strings.TrimSpace(s.ncsiDnsHost.Text()),
		"active_dns_probe_content":  strings.TrimSpace(s.ncsiDnsContent.Text()),
		"enable_active_probing":     probing,
	}
	go func() {
		body, _ := json.Marshal(payload)
		var result map[string]interface{}
		err := s.postJSON("/api/system/ncsi", body, &result)
		s.sync(func() {
			if err != nil {
				s.setStatus("Apply NCSI failed: " + err.Error())
				return
			}
			s.appendLog("Applied system NCSI settings and restarted NlaSvc.")
			s.refreshNCSI()
			s.refreshStatus()
		})
	}()
}

func (s *nativeShell) resetNCSI() {
	go func() {
		var result map[string]interface{}
		err := s.postJSON("/api/system/ncsi/reset", nil, &result)
		s.sync(func() {
			if err != nil {
				s.setStatus("Reset NCSI failed: " + err.Error())
				return
			}
			s.appendLog("Reset NCSI configuration to Microsoft defaults.")
			s.refreshNCSI()
			s.refreshStatus()
		})
	}()
}

func (s *nativeShell) applyScannerSettings() {
	timeout := 4000
	if s.defaultTimeoutEdit != nil {
		timeout = parsePositiveInt(s.defaultTimeoutEdit.Text(), 4000)
	}
	concurrency := 50
	if s.maxConcurrencyEdit != nil {
		concurrency = parsePositiveInt(s.maxConcurrencyEdit.Text(), 50)
	}
	debugLogs := true
	if s.debugLogsCheck != nil {
		debugLogs = s.debugLogsCheck.Checked()
	}
	dnsRes := true
	if s.dnsResolutionCheck != nil {
		dnsRes = s.dnsResolutionCheck.Checked()
	}
	hostsOver := true
	if s.hostsOverrideCheck != nil {
		hostsOver = s.hostsOverrideCheck.Checked()
	}

	mihomoOpts := nativeMihomoRulesOptions{}
	if s.bypassChinaCheck != nil {
		mihomoOpts.BypassChina = s.bypassChinaCheck.Checked()
	}
	if s.bypassIranCheck != nil {
		mihomoOpts.BypassIran = s.bypassIranCheck.Checked()
	}
	if s.bypassRussiaCheck != nil {
		mihomoOpts.BypassRussia = s.bypassRussiaCheck.Checked()
	}
	if s.bypassOpenAICheck != nil {
		mihomoOpts.BypassOpenAI = s.bypassOpenAICheck.Checked()
	}
	if s.bypassGoogleAICheck != nil {
		mihomoOpts.BypassGoogleAI = s.bypassGoogleAICheck.Checked()
	}
	if s.bypassMicrosoftCheck != nil {
		mihomoOpts.BypassMicrosoft = s.bypassMicrosoftCheck.Checked()
	}
	if s.bypassOracleCheck != nil {
		mihomoOpts.BypassOracle = s.bypassOracleCheck.Checked()
	}
	if s.bypassDockerCheck != nil {
		mihomoOpts.BypassDocker = s.bypassDockerCheck.Checked()
	}
	if s.bypassAdobeCheck != nil {
		mihomoOpts.BypassAdobe = s.bypassAdobeCheck.Checked()
	}
	if s.bypassEpicGamesCheck != nil {
		mihomoOpts.BypassEpicGames = s.bypassEpicGamesCheck.Checked()
	}
	if s.bypassIntelCheck != nil {
		mihomoOpts.BypassIntel = s.bypassIntelCheck.Checked()
	}
	if s.bypassAMDCheck != nil {
		mihomoOpts.BypassAMD = s.bypassAMDCheck.Checked()
	}
	if s.bypassNvidiaCheck != nil {
		mihomoOpts.BypassNvidia = s.bypassNvidiaCheck.Checked()
	}
	if s.bypassAsusCheck != nil {
		mihomoOpts.BypassAsus = s.bypassAsusCheck.Checked()
	}
	if s.bypassHPCheck != nil {
		mihomoOpts.BypassHP = s.bypassHPCheck.Checked()
	}
	if s.bypassLenovoCheck != nil {
		mihomoOpts.BypassLenovo = s.bypassLenovoCheck.Checked()
	}
	if s.blockMalwareCheck != nil {
		mihomoOpts.BlockMalware = s.blockMalwareCheck.Checked()
	}
	if s.blockPhishingCheck != nil {
		mihomoOpts.BlockPhishing = s.blockPhishingCheck.Checked()
	}
	if s.blockCryptominersCheck != nil {
		mihomoOpts.BlockCryptominers = s.blockCryptominersCheck.Checked()
	}
	if s.blockAdsCheck != nil {
		mihomoOpts.BlockAds = s.blockAdsCheck.Checked()
	}
	if s.blockPornCheck != nil {
		mihomoOpts.BlockPorn = s.blockPornCheck.Checked()
	}

	payload, err := json.Marshal(nativeScannerSettings{
		DefaultTimeoutMs: timeout,
		MaxConcurrency:   concurrency,
		DebugLogs:        debugLogs,
		DnsResolution:    dnsRes,
		MihomoRules:      mihomoOpts,
		HostsOverride:    hostsOver,
	})
	if err != nil {
		s.setStatus("Apply scanner settings failed: " + err.Error())
		return
	}

	go func() {
		var result map[string]interface{}
		err := s.postJSON("/api/system/settings", payload, &result)
		s.sync(func() {
			if err != nil {
				s.setStatus("Apply scanner settings failed: " + err.Error())
				return
			}
			s.appendLog("Applied general scanner settings.")
			s.refreshScannerSettings()
		})
	}()
}
