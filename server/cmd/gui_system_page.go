//go:build windows && cgo

package cmd

import (
	. "github.com/lxn/walk/declarative"
)

func (s *nativeShell) systemPage() TabPage {
	return TabPage{
		Title:  "System",
		Layout: VBox{Margins: Margins{Left: 14, Top: 14, Right: 14, Bottom: 14}},
		Children: []Widget{
			GroupBox{
				Title:  "DNS",
				Layout: Grid{Columns: 4, Spacing: 10},
				Children: []Widget{
					Label{Text: "Interface"},
					Label{AssignTo: &s.dnsInterface, Text: "-"},
					Label{Text: "Source"},
					Label{AssignTo: &s.dnsSourceLabel, Text: "-"},
					Label{Text: "Servers"},
					LineEdit{AssignTo: &s.dnsServersEdit},
					PushButton{Text: "Apply DNS", OnClicked: s.applyDNS},
					PushButton{Text: "Clear DNS", OnClicked: s.clearDNS},
					Label{Text: "Secure Presets"},
					PushButton{Text: "Apply Quad9 DNS", OnClicked: s.applyQuad9DNS},
					Label{Text: ""},
					Label{Text: ""},
				},
			},
			GroupBox{
				Title:  "System proxy",
				Layout: Grid{Columns: 4, Spacing: 10},
				Children: []Widget{
					Label{Text: "Enabled"},
					CheckBox{AssignTo: &s.sysProxyEnabled, Text: "Use system proxy"},
					Label{Text: "Server"},
					LineEdit{AssignTo: &s.sysProxyServer},
					Label{Text: "Bypass"},
					LineEdit{AssignTo: &s.sysProxyBypass},
					Label{Text: "Use PAC Script"},
					CheckBox{AssignTo: &s.sysProxyPACEnabled, Text: "Enable PAC URL"},
					Label{Text: "PAC URL"},
					LineEdit{AssignTo: &s.sysProxyPACURL},
					PushButton{Text: "Apply proxy", OnClicked: s.applySystemProxy},
					PushButton{Text: "Clear proxy", OnClicked: s.clearSystemProxy},
				},
			},
			GroupBox{
				Title:  "Windows NCSI Fix (Network Connectivity Status Indicator)",
				Layout: Grid{Columns: 4, Spacing: 10},
				Children: []Widget{
					Label{Text: "Web Probe Host"},
					LineEdit{AssignTo: &s.ncsiWebHost},
					Label{Text: "Web Probe Path"},
					LineEdit{AssignTo: &s.ncsiWebPath},
					Label{Text: "Web Probe Content"},
					LineEdit{AssignTo: &s.ncsiWebContent},
					Label{Text: "DNS Probe Host"},
					LineEdit{AssignTo: &s.ncsiDnsHost},
					Label{Text: "DNS Probe Content"},
					LineEdit{AssignTo: &s.ncsiDnsContent},
					Label{Text: "Active Probing"},
					CheckBox{AssignTo: &s.ncsiActiveProbe, Text: "Enable Probing"},
					PushButton{Text: "Apply NCSI Fix", OnClicked: s.applyNCSI},
					PushButton{Text: "Reset to Defaults", OnClicked: s.resetNCSI},
				},
			},
			GroupBox{
				Title:  "General Scanner Configuration",
				Layout: Grid{Columns: 4, Spacing: 10},
				Children: []Widget{
					Label{Text: "Default Timeout (ms):"},
					LineEdit{AssignTo: &s.defaultTimeoutEdit},
					Label{Text: "Max Concurrency:"},
					LineEdit{AssignTo: &s.maxConcurrencyEdit},
					Label{Text: "System Logging:"},
					CheckBox{AssignTo: &s.debugLogsCheck, Text: "Enable Debug Logs"},
					Label{Text: "DNS Scan Options:"},
					CheckBox{AssignTo: &s.dnsResolutionCheck, Text: "Enable DNS Resolution"},
					Label{Text: "Hosts Bypass Override:"},
					CheckBox{AssignTo: &s.hostsOverrideCheck, Text: "Enable Hosts Overrides (X.com, YouTube)"},
					Label{Text: ""},
					Label{Text: ""},
				},
			},
			GroupBox{
				Title:  "Clash/Mihomo Bypass & Blocking Rules",
				Layout: Grid{Columns: 4, Spacing: 10},
				Children: []Widget{
					CheckBox{AssignTo: &s.bypassChinaCheck, Text: "Bypass China"},
					CheckBox{AssignTo: &s.bypassIranCheck, Text: "Bypass Iran"},
					CheckBox{AssignTo: &s.bypassRussiaCheck, Text: "Bypass Russia"},
					CheckBox{AssignTo: &s.bypassOpenAICheck, Text: "Bypass OpenAI"},

					CheckBox{AssignTo: &s.bypassGoogleAICheck, Text: "Bypass Google AI"},
					CheckBox{AssignTo: &s.bypassMicrosoftCheck, Text: "Bypass Microsoft"},
					CheckBox{AssignTo: &s.bypassOracleCheck, Text: "Bypass Oracle"},
					CheckBox{AssignTo: &s.bypassDockerCheck, Text: "Bypass Docker"},

					CheckBox{AssignTo: &s.bypassAdobeCheck, Text: "Bypass Adobe"},
					CheckBox{AssignTo: &s.bypassEpicGamesCheck, Text: "Bypass Epic Games"},
					CheckBox{AssignTo: &s.bypassIntelCheck, Text: "Bypass Intel"},
					CheckBox{AssignTo: &s.bypassAMDCheck, Text: "Bypass AMD"},

					CheckBox{AssignTo: &s.bypassNvidiaCheck, Text: "Bypass Nvidia"},
					CheckBox{AssignTo: &s.bypassAsusCheck, Text: "Bypass Asus"},
					CheckBox{AssignTo: &s.bypassHPCheck, Text: "Bypass HP"},
					CheckBox{AssignTo: &s.bypassLenovoCheck, Text: "Bypass Lenovo"},

					CheckBox{AssignTo: &s.blockMalwareCheck, Text: "Block Malware"},
					CheckBox{AssignTo: &s.blockPhishingCheck, Text: "Block Phishing"},
					CheckBox{AssignTo: &s.blockCryptominersCheck, Text: "Block Cryptominers"},
					CheckBox{AssignTo: &s.blockAdsCheck, Text: "Block Ads"},

					CheckBox{AssignTo: &s.blockPornCheck, Text: "Block Porn"},
				},
			},
			Composite{
				Layout: HBox{MarginsZero: true, Spacing: 10},
				Children: []Widget{
					PushButton{Text: "Apply Scanner Config", OnClicked: s.applyScannerSettings},
					PushButton{Text: "Refresh system settings", OnClicked: s.refreshSystemSettings},
					HSpacer{},
				},
			},
			VSpacer{},
		},
	}
}
