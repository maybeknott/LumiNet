//go:build windows && cgo

package cmd

import (
	. "github.com/lxn/walk/declarative"
)

func (s *nativeShell) scansPage() TabPage {
	return TabPage{
		Title:  "Scans",
		Layout: VBox{Margins: Margins{Left: 14, Top: 14, Right: 14, Bottom: 14}},
		Children: []Widget{
			GroupBox{
				Title:  "Native scan launcher",
				Layout: Grid{Columns: 4, Spacing: 10},
				Children: []Widget{
					Label{Text: "Mode"},
					ComboBox{
						AssignTo: &s.scanMode,
						Model:    []string{"ICMP sweep", "TCP ports", "DNS records", "TLS handshake", "SNI check", "CDN IP sweep", "ASN Spoof check"},
					},
					Label{Text: "Timeout ms"},
					LineEdit{AssignTo: &s.scanTimeout},

					Label{Text: "Target"},
					TextEdit{AssignTo: &s.scanTarget, MinSize: Size{Height: 70}, VScroll: true},
					Label{Text: "Concurrency"},
					LineEdit{AssignTo: &s.scanConcurrency},

					Label{Text: "Ports"},
					LineEdit{AssignTo: &s.scanPorts},
					Label{Text: "IPv6"},
					CheckBox{AssignTo: &s.scanIPv6, Text: "Enable for ICMP"},

					Label{Text: "DNS server"},
					LineEdit{AssignTo: &s.scanDNSServer},
					Label{Text: "Record"},
					ComboBox{
						AssignTo: &s.scanRecordType,
						Model:    []string{"A", "AAAA", "CNAME", "MX", "TXT", "NS"},
					},

					Label{Text: "SNI (Optional):"},
					LineEdit{AssignTo: &s.scanSni},
					Label{Text: ""},
					Label{Text: ""},
				},
			},
			GroupBox{
				Title:  "Clean IP target presets",
				Layout: HBox{Spacing: 10},
				Children: []Widget{
					PushButton{Text: "Cloudflare Presets", OnClicked: s.loadCloudflareIPs},
					PushButton{Text: "Akamai Presets", OnClicked: s.loadAkamaiIPs},
					PushButton{Text: "Fastly Presets", OnClicked: s.loadFastlyIPs},
					PushButton{Text: "GCore Presets", OnClicked: s.loadGCoreIPs},
					PushButton{Text: "WARP Presets", OnClicked: s.loadWarpIPs},
				},
			},
			Composite{
				Layout: HBox{MarginsZero: true},
				Children: []Widget{
					PushButton{Text: "Start native scan", OnClicked: s.startNativeScan},
					PushButton{Text: "Refresh history", OnClicked: s.refreshHistory},
					HSpacer{},
					PushButton{Text: "Export history JSON", OnClicked: func() { s.openPath("/api/export") }},
				},
			},
			GroupBox{
				Title:  "Job feedback",
				Layout: VBox{},
				Children: []Widget{
					Label{Text: "Started jobs appear in Dashboard activity and History. Use Export history JSON for archival review."},
				},
			},
			VSpacer{},
		},
	}
}
