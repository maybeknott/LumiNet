//go:build windows && cgo

package cmd

import (
	"fmt"
	"strconv"
	"strings"

	. "github.com/lxn/walk/declarative"
	"github.com/maybeknott/luminet/internal/bridge"
)

func (s *nativeShell) dnsSecurityPage() TabPage {
	return TabPage{
		Title:  "DNS Security",
		Layout: VBox{Margins: Margins{Left: 14, Top: 14, Right: 14, Bottom: 14}},
		Children: []Widget{
			GroupBox{
				Title:  "DNS Censorship & Poisoning Diagnostic",
				Layout: Grid{Columns: 4, Spacing: 10},
				Children: []Widget{
					Label{Text: "Target Domain:"},
					LineEdit{AssignTo: &s.dnsSecDomain},
					Label{Text: "Plain UDP DNS:"},
					LineEdit{AssignTo: &s.dnsSecUdpServer},

					Label{Text: "DoH Resolver:"},
					LineEdit{AssignTo: &s.dnsSecDohServer},
					Label{Text: "DoT Resolver:"},
					LineEdit{AssignTo: &s.dnsSecDotServer},

					Label{Text: "DoH Preset:"},
					ComboBox{
						AssignTo: &s.dnsSecDohPresetCombo,
						Model: []string{
							"Cloudflare Standard",
							"NordVPN DNS",
							"Cloudflare Family",
							"CleanBrowsing Family",
							"Avast DNS",
							"Comodo DNS",
							"OpenDNS",
							"AdGuard Unfiltered",
							"Yandex Family",
							"Google DNS",
							"Quad9 Secure",
						},
						OnCurrentIndexChanged: s.onDnsSecDohPresetChanged,
					},
				},
			},
			Composite{
				Layout: HBox{MarginsZero: true},
				Children: []Widget{
					PushButton{Text: "Analyze DNS Security", OnClicked: s.runDnsSecurityAnalysis},
					HSpacer{},
				},
			},
			GroupBox{
				Title:  "Analysis Findings",
				Layout: VBox{},
				Children: []Widget{
					TextEdit{AssignTo: &s.dnsSecOutput, ReadOnly: true, VScroll: true, MinSize: Size{Height: 250}},
				},
			},
			VSpacer{},
		},
	}
}

func (s *nativeShell) runDnsSecurityAnalysis() {
	domain := "google.com"
	if s.dnsSecDomain != nil {
		domain = strings.TrimSpace(s.dnsSecDomain.Text())
	}
	if domain == "" {
		s.setStatus("Enter target domain for analysis.")
		return
	}

	udpServer := "8.8.8.8"
	if s.dnsSecUdpServer != nil && s.dnsSecUdpServer.Text() != "" {
		udpServer = strings.TrimSpace(s.dnsSecUdpServer.Text())
	}

	dohServer := "https://cloudflare-dns.com/dns-query"
	if s.dnsSecDohServer != nil && s.dnsSecDohServer.Text() != "" {
		dohServer = strings.TrimSpace(s.dnsSecDohServer.Text())
	}

	dotServer := "one.one.one.one:853"
	if s.dnsSecDotServer != nil && s.dnsSecDotServer.Text() != "" {
		dotServer = strings.TrimSpace(s.dnsSecDotServer.Text())
	}

	s.setStatus("Running DNS security analysis...")
	if s.dnsSecOutput != nil {
		s.dnsSecOutput.SetText(fmt.Sprintf("DNS Security & Censorship Analysis for: %s\r\n--------------------------------------------------\r\nProbing Resolvers...\r\n\r\n", domain))
	}

	go func() {
		// 1. Resolve plain UDP
		udpRes, udpErr := bridge.DnsResolve(udpServer, domain, "A")

		// 2. Resolve DoH
		dohRes, dohErr := bridge.DnsResolve(dohServer, domain, "A")

		// 3. Resolve DoT
		dotRes, dotErr := bridge.DnsResolve(dotServer, domain, "A")

		s.sync(func() {
			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("DNS Security & Censorship Analysis for: %s\r\n", domain))
			sb.WriteString("==================================================\r\n\r\n")

			// UDP Result
			sb.WriteString(fmt.Sprintf("[1] PLAIN UDP RESOLVER (%s):\r\n", udpServer))
			if udpErr != nil {
				sb.WriteString(fmt.Sprintf("  Status:  FAILED (%v)\r\n\r\n", udpErr))
			} else if !udpRes.Success {
				sb.WriteString(fmt.Sprintf("  Status:  ERROR (%s)\r\n\r\n", udpRes.Error))
			} else {
				sb.WriteString(fmt.Sprintf("  Latency: %.1f ms\r\n", udpRes.LatencyMs))
				sb.WriteString("  Records:\r\n")
				for _, r := range udpRes.Records {
					sb.WriteString(fmt.Sprintf("    - %s (%s, TTL=%d) -> %s\r\n", r.Name, r.Type, r.TTL, r.Value))
				}
				sb.WriteString("\r\n")
			}

			// DoH Result
			sb.WriteString(fmt.Sprintf("[2] DNS-over-HTTPS (DoH) RESOLVER (%s):\r\n", dohServer))
			if dohErr != nil {
				sb.WriteString(fmt.Sprintf("  Status:  FAILED (%v)\r\n\r\n", dohErr))
			} else if !dohRes.Success {
				sb.WriteString(fmt.Sprintf("  Status:  ERROR (%s)\r\n\r\n", dohRes.Error))
			} else {
				sb.WriteString(fmt.Sprintf("  Latency: %.1f ms\r\n", dohRes.LatencyMs))
				sb.WriteString("  Records:\r\n")
				for _, r := range dohRes.Records {
					sb.WriteString(fmt.Sprintf("    - %s (%s, TTL=%d) -> %s\r\n", r.Name, r.Type, r.TTL, r.Value))
				}
				sb.WriteString("\r\n")
			}

			// DoT Result
			sb.WriteString(fmt.Sprintf("[3] DNS-over-TLS (DoT) RESOLVER (%s):\r\n", dotServer))
			if dotErr != nil {
				sb.WriteString(fmt.Sprintf("  Status:  FAILED (%v)\r\n\r\n", dotErr))
			} else if !dotRes.Success {
				sb.WriteString(fmt.Sprintf("  Status:  ERROR (%s)\r\n\r\n", dotRes.Error))
			} else {
				sb.WriteString(fmt.Sprintf("  Latency: %.1f ms\r\n", dotRes.LatencyMs))
				sb.WriteString("  Records:\r\n")
				for _, r := range dotRes.Records {
					sb.WriteString(fmt.Sprintf("    - %s (%s, TTL=%d) -> %s\r\n", r.Name, r.Type, r.TTL, r.Value))
				}
				sb.WriteString("\r\n")
			}

			// Censorship Evaluation
			sb.WriteString("==================================================\r\n")
			sb.WriteString("CENSORSHIP & INTEGRITY EVALUATION:\r\n")
			sb.WriteString("--------------------------------------------------\r\n")

			if udpErr != nil && (dohErr == nil && dohRes != nil && dohRes.Success) {
				sb.WriteString("⚠️  UDP DNS Poisoning/Interference Detected:\r\n")
				sb.WriteString("   Plain UDP DNS queries are blocked/intercepted on your network, but DoH resolved successfully.\r\n")
				sb.WriteString("   Recommendation: Enable system-wide DoH/DoT to secure your DNS queries.\r\n")
			} else if udpRes != nil && udpRes.Success && dohRes != nil && dohRes.Success {
				// Compare resolved IPs
				udpIPs := getRecordIPs(udpRes.Records)
				dohIPs := getRecordIPs(dohRes.Records)

				match := ipSetsIntersect(udpIPs, dohIPs)
				if !match && len(udpIPs) > 0 && len(dohIPs) > 0 {
					sb.WriteString("🚨 CRITICAL: DNS Answer Poisoning Detected!\r\n")
					sb.WriteString(fmt.Sprintf("   UDP resolver returned different IPs than secure DoH:\r\n"))
					sb.WriteString(fmt.Sprintf("   - UDP: %v\r\n", udpIPs))
					sb.WriteString(fmt.Sprintf("   - DoH: %v\r\n", dohIPs))
					sb.WriteString("   Poisoning or censorship redirection is active on UDP port 53.\r\n")
				} else {
					sb.WriteString("🟢 DNS Integrity Intact:\r\n")
					sb.WriteString("   Encrypted and plaintext answers resolved to overlapping IP records.\r\n")
				}
			} else if udpErr == nil && dohErr != nil {
				sb.WriteString("ℹ️  Encrypted DNS Blocked:\r\n")
				sb.WriteString("   DoH/DoT endpoints appear blocked or unreachable, while plaintext UDP is working.\r\n")
			} else {
				sb.WriteString("ℹ️  Scan complete. Answers could not be compared due to failed queries.\r\n")
			}

			// SafeSearch / Restricted Mode Redirect Detection
			restrictedDetected := false
			var restrictedDetails []string

			checkRestricted := func(records []bridge.DnsRecord) {
				for _, r := range records {
					val := strings.ToLower(r.Value)
					name := strings.ToLower(r.Name)
					if strings.Contains(val, "restrict.youtube.com") ||
						strings.Contains(val, "restrictmoderate.youtube.com") ||
						strings.Contains(val, "forcesafesearch.google.com") {
						restrictedDetected = true
						restrictedDetails = append(restrictedDetails, fmt.Sprintf("%s -> %s", r.Name, r.Value))
					}
					if strings.Contains(name, "restrict.youtube.com") ||
						strings.Contains(name, "forcesafesearch.google.com") {
						restrictedDetected = true
						restrictedDetails = append(restrictedDetails, fmt.Sprintf("%s -> %s", r.Name, r.Value))
					}
				}
			}

			if udpRes != nil && udpRes.Success {
				checkRestricted(udpRes.Records)
			}
			if dohRes != nil && dohRes.Success {
				checkRestricted(dohRes.Records)
			}
			if dotRes != nil && dotRes.Success {
				checkRestricted(dotRes.Records)
			}

			if restrictedDetected {
				sb.WriteString("\r\n⚠️  FORCED SAFE SEARCH / RESTRICTED MODE DETECTED:\r\n")
				sb.WriteString("   Your provider enforces SafeSearch or YouTube Restricted Mode by redirecting records:\r\n")
				for _, detail := range restrictedDetails {
					sb.WriteString(fmt.Sprintf("     - %s\r\n", detail))
				}
				sb.WriteString("   Recommendation: Use Secure Tunnels or Tor/Proxy Routing to bypass CNAME hijacking.\r\n")
			}

			if s.dnsSecOutput != nil {
				s.dnsSecOutput.SetText(sb.String())
			}
			s.setStatus("DNS Security analysis completed.")
		})
	}()
}

func getRecordIPs(records []bridge.DnsRecord) []string {
	var ips []string
	for _, r := range records {
		if r.Type == "A" || r.Type == "AAAA" {
			ips = append(ips, r.Value)
		}
	}
	return ips
}

func ipSetsIntersect(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	m := make(map[string]bool)
	for _, x := range a {
		m[x] = true
	}
	for _, y := range b {
		if m[y] {
			return true
		}
	}
	return false
}

func (s *nativeShell) dnsBenchmarkPage() TabPage {
	return TabPage{
		Title:  "DNS Benchmark",
		Layout: VBox{Margins: Margins{Left: 14, Top: 14, Right: 14, Bottom: 14}},
		Children: []Widget{
			GroupBox{
				Title:  "Multi-Resolver Performance & Integrity Config",
				Layout: Grid{Columns: 2, Spacing: 10},
				Children: []Widget{
					Label{Text: "Target Benchmark Domain:"},
					LineEdit{AssignTo: &s.dnsBenchDomain},
				},
			},
			Composite{
				Layout: HBox{MarginsZero: true},
				Children: []Widget{
					PushButton{Text: "Run DNS Benchmark", OnClicked: s.runDnsBenchmark},
					HSpacer{},
				},
			},
			GroupBox{
				Title:  "Resolver Latency Benchmark",
				Layout: Grid{Columns: 4, Spacing: 10},
				Children: []Widget{
					Label{Text: "Google DNS (8.8.8.8):"},
					Label{AssignTo: &s.dnsBenchGoogle, Text: "- ms"},
					Label{Text: "Cloudflare DNS (1.1.1.1):"},
					Label{AssignTo: &s.dnsBenchCloudflare, Text: "- ms"},

					Label{Text: "Quad9 DNS (9.9.9.9):"},
					Label{AssignTo: &s.dnsBenchQuad9, Text: "- ms"},
					Label{Text: "OpenDNS (208.67.222.222):"},
					Label{AssignTo: &s.dnsBenchOpenDns, Text: "- ms"},

					Label{Text: "AdGuard DNS (94.140.14.14):"},
					Label{AssignTo: &s.dnsBenchAdGuard, Text: "- ms"},
					Label{Text: "Local ISP DNS:"},
					Label{AssignTo: &s.dnsBenchLocal, Text: "- ms"},

					Label{Text: "Shecan DNS (178.22.122.100):"},
					Label{AssignTo: &s.dnsBenchShecan, Text: "- ms"},
					Label{Text: "403 DNS (10.202.10.202):"},
					Label{AssignTo: &s.dnsBench403, Text: "- ms"},

					Label{Text: "Mullvad DNS (194.242.2.2):"},
					Label{AssignTo: &s.dnsBenchMullvad, Text: "- ms"},
					Label{Text: "Electro DNS (78.157.42.100):"},
					Label{AssignTo: &s.dnsBenchElectro, Text: "- ms"},

					Label{Text: "Radar Game (10.201.10.201):"},
					Label{AssignTo: &s.dnsBenchRadar, Text: "- ms"},
					Label{Text: "Level3 DNS (4.2.2.2):"},
					Label{AssignTo: &s.dnsBenchLevel3, Text: "- ms"},
				},
			},
			GroupBox{
				Title:  "Benchmark Summary & Security Audit",
				Layout: VBox{},
				Children: []Widget{
					TextEdit{AssignTo: &s.dnsBenchOutput, ReadOnly: true, VScroll: true, MinSize: Size{Height: 250}},
				},
			},
			VSpacer{},
		},
	}
}

func (s *nativeShell) runDnsBenchmark() {
	domain := "google.com"
	if s.dnsBenchDomain != nil && s.dnsBenchDomain.Text() != "" {
		domain = strings.TrimSpace(s.dnsBenchDomain.Text())
	}

	s.setStatus("Running multi-resolver DNS benchmark...")
	if s.dnsBenchOutput != nil {
		s.dnsBenchOutput.SetText(fmt.Sprintf("DNS Resolver Performance & Integrity Benchmark for: %s\r\n------------------------------------------------------------\r\nQuerying public name servers...\r\n\r\n", domain))
	}

	if s.dnsBenchGoogle != nil {
		s.dnsBenchGoogle.SetText("Testing...")
	}
	if s.dnsBenchCloudflare != nil {
		s.dnsBenchCloudflare.SetText("Testing...")
	}
	if s.dnsBenchQuad9 != nil {
		s.dnsBenchQuad9.SetText("Testing...")
	}
	if s.dnsBenchOpenDns != nil {
		s.dnsBenchOpenDns.SetText("Testing...")
	}
	if s.dnsBenchAdGuard != nil {
		s.dnsBenchAdGuard.SetText("Testing...")
	}
	if s.dnsBenchLocal != nil {
		s.dnsBenchLocal.SetText("Testing...")
	}
	if s.dnsBenchShecan != nil {
		s.dnsBenchShecan.SetText("Testing...")
	}
	if s.dnsBench403 != nil {
		s.dnsBench403.SetText("Testing...")
	}
	if s.dnsBenchMullvad != nil {
		s.dnsBenchMullvad.SetText("Testing...")
	}
	if s.dnsBenchElectro != nil {
		s.dnsBenchElectro.SetText("Testing...")
	}
	if s.dnsBenchRadar != nil {
		s.dnsBenchRadar.SetText("Testing...")
	}
	if s.dnsBenchLevel3 != nil {
		s.dnsBenchLevel3.SetText("Testing...")
	}

	go func() {
		// Define targets
		servers := map[string]string{
			"Google":     "8.8.8.8",
			"Cloudflare": "1.1.1.1",
			"Quad9":      "9.9.9.9",
			"OpenDNS":    "208.67.222.222",
			"AdGuard":    "94.140.14.14",
			"Shecan":     "178.22.122.100",
			"403":        "10.202.10.202",
			"Mullvad":    "194.242.2.2",
			"Electro":    "78.157.42.100",
			"Radar":      "10.201.10.201",
			"Level3":     "4.2.2.2",
		}

		// Detect active local DNS servers
		localDNSs := []string{"8.8.4.4"}
		if len(s.lastStatus.DNSServers) > 0 {
			localDNSs = s.lastStatus.DNSServers
		}
		for idx, ip := range localDNSs {
			servers[fmt.Sprintf("Local-%d", idx+1)] = ip
		}

		type benchResult struct {
			name     string
			ip       string
			latency  float64
			resolved []string
			err      error
		}

		var results []benchResult

		for name, ip := range servers {
			res, err := bridge.DnsResolve(ip, domain, "A")
			bRes := benchResult{name: name, ip: ip}
			if err != nil {
				bRes.err = err
			} else if !res.Success {
				bRes.err = fmt.Errorf("%s", res.Error)
			} else {
				bRes.latency = res.LatencyMs
				var ips []string
				for _, r := range res.Records {
					if r.Type == "A" {
						ips = append(ips, r.Value)
					}
				}
				bRes.resolved = ips
			}
			results = append(results, bRes)
		}

		s.sync(func() {
			s.setStatus("DNS benchmark completed.")

			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("DNS Resolver Benchmark Results for: %s\r\n", domain))
			sb.WriteString("============================================================\r\n\r\n")

			var fastestName string
			fastestLat := 99999.0
			hasPoisoning := false

			// Helper to look up a result by name
			findRes := func(name string) *benchResult {
				for i := range results {
					if results[i].name == name {
						return &results[i]
					}
				}
				return nil
			}

			// Render individual resolver results in log and update labels
			for _, name := range []string{"Google", "Cloudflare", "Quad9", "OpenDNS", "AdGuard", "Local", "Shecan", "403", "Mullvad", "Electro", "Radar", "Level3"} {
				var res *benchResult
				if name == "Local" {
					// We find the fastest local result to show on s.dnsBenchLocal widget
					var fastestLocalLat float64 = 99999.0
					var fastestLocalIP string
					var fastestLocalErr error
					var fastestLocalName string
					hasAnyLocal := false

					for i := range results {
						r := &results[i]
						if strings.HasPrefix(r.name, "Local-") {
							hasAnyLocal = true
							
							// Write details of this local resolver to sb
							if r.err != nil {
								sb.WriteString(fmt.Sprintf("[%s] %s:\r\n  Status:  FAILED (%v)\r\n\r\n", r.name, r.ip, r.err))
							} else {
								sb.WriteString(fmt.Sprintf("[%s] %s:\r\n  Latency:  %.1f ms\r\n  Resolved: %s\r\n\r\n", r.name, r.ip, r.latency, strings.Join(r.resolved, ", ")))
							}

							if r.err == nil {
								if r.latency < fastestLocalLat {
									fastestLocalLat = r.latency
									fastestLocalIP = r.ip
									fastestLocalName = r.name
								}
							} else if fastestLocalIP == "" {
								fastestLocalErr = r.err
								fastestLocalName = r.name
							}
						}
					}

					if hasAnyLocal {
						labelStr := "- ms"
						if fastestLocalIP != "" {
							labelStr = fmt.Sprintf("%s: %.1f ms", fastestLocalIP, fastestLocalLat)
							if fastestLocalLat < fastestLat {
								fastestLat = fastestLocalLat
								fastestName = fastestLocalName
							}
						} else if fastestLocalErr != nil {
							labelStr = "Failed"
						}
						if s.dnsBenchLocal != nil {
							s.dnsBenchLocal.SetText(labelStr)
						}
					}
					continue
				}

				res = findRes(name)
				if res == nil {
					continue
				}

				labelStr := "- ms"
				if res.err != nil {
					labelStr = "Failed"
					sb.WriteString(fmt.Sprintf("[%s] %s:\r\n  Status:  FAILED (%v)\r\n\r\n", res.name, res.ip, res.err))
				} else {
					labelStr = fmt.Sprintf("%.1f ms", res.latency)
					if res.latency < fastestLat {
						fastestLat = res.latency
						fastestName = res.name
					}
					sb.WriteString(fmt.Sprintf("[%s] %s:\r\n  Latency:  %.1f ms\r\n  Resolved: %s\r\n\r\n", res.name, res.ip, res.latency, strings.Join(res.resolved, ", ")))
				}

				switch name {
				case "Google":
					if s.dnsBenchGoogle != nil {
						s.dnsBenchGoogle.SetText(labelStr)
					}
				case "Cloudflare":
					if s.dnsBenchCloudflare != nil {
						s.dnsBenchCloudflare.SetText(labelStr)
					}
				case "Quad9":
					if s.dnsBenchQuad9 != nil {
						s.dnsBenchQuad9.SetText(labelStr)
					}
				case "OpenDNS":
					if s.dnsBenchOpenDns != nil {
						s.dnsBenchOpenDns.SetText(labelStr)
					}
				case "AdGuard":
					if s.dnsBenchAdGuard != nil {
						s.dnsBenchAdGuard.SetText(labelStr)
					}
				case "Local":
					if s.dnsBenchLocal != nil {
						s.dnsBenchLocal.SetText(labelStr)
					}
				case "Shecan":
					if s.dnsBenchShecan != nil {
						s.dnsBenchShecan.SetText(labelStr)
					}
				case "403":
					if s.dnsBench403 != nil {
						s.dnsBench403.SetText(labelStr)
					}
				case "Mullvad":
					if s.dnsBenchMullvad != nil {
						s.dnsBenchMullvad.SetText(labelStr)
					}
				case "Electro":
					if s.dnsBenchElectro != nil {
						s.dnsBenchElectro.SetText(labelStr)
					}
				case "Radar":
					if s.dnsBenchRadar != nil {
						s.dnsBenchRadar.SetText(labelStr)
					}
				case "Level3":
					if s.dnsBenchLevel3 != nil {
						s.dnsBenchLevel3.SetText(labelStr)
					}
				}
			}

			// Compare resolved IP sets to check for poisoning / hijacking
			cf := findRes("Cloudflare")
			gg := findRes("Google")
			var referenceIPs []string
			if cf != nil && cf.err == nil && len(cf.resolved) > 0 {
				referenceIPs = cf.resolved
			} else if gg != nil && gg.err == nil && len(gg.resolved) > 0 {
				referenceIPs = gg.resolved
			}

			sb.WriteString("Censorship & Hijacking Audit:\r\n")
			sb.WriteString("------------------------------------------------------------\r\n")

			if len(referenceIPs) > 0 {
				for _, res := range results {
					if res.err == nil && len(res.resolved) > 0 {
						if !ipSetsIntersect(referenceIPs, res.resolved) {
							hasPoisoning = true
							sb.WriteString(fmt.Sprintf("  [!] WARNING: Resolver %s (%s) returned completely different IP addresses!\r\n", res.name, res.ip))
							sb.WriteString(fmt.Sprintf("      Expected: %v, Received: %v\r\n", referenceIPs, res.resolved))
							sb.WriteString("      Possible DNS Hijacking or poisoning detected on this network node.\r\n\r\n")
						}
					}
				}
			}

			if !hasPoisoning {
				sb.WriteString("  [+] No DNS hijacking or query poisoning detected across tested resolvers.\r\n\r\n")
			}

			sb.WriteString("Optimization Recommendation:\r\n")
			sb.WriteString("------------------------------------------------------------\r\n")
			if fastestName != "" {
				sb.WriteString(fmt.Sprintf("  -> The fastest resolver is: %s (%.1f ms)\r\n", fastestName, fastestLat))
				if fastestName == "Local" {
					sb.WriteString("  -> Your ISP's default resolver is performing optimally. No manual adjustment is needed for speed.\r\n")
				} else {
					sb.WriteString(fmt.Sprintf("  -> To minimize lookup latency, configure your operating system DNS to use %s (%s).\r\n", fastestName, servers[fastestName]))
				}
			} else {
				sb.WriteString("  -> All queries failed. Please check your network connection.\r\n")
			}

			if s.dnsBenchOutput != nil {
				s.dnsBenchOutput.SetText(sb.String())
			}
		})
	}()
}

func (s *nativeShell) echAuditorPage() TabPage {
	return TabPage{
		Title:  "ECH & SNI Evasion",
		Layout: VBox{Margins: Margins{Left: 14, Top: 14, Right: 14, Bottom: 14}},
		Children: []Widget{
			GroupBox{
				Title:  "ECH & Secure SNI Auditor Configuration",
				Layout: Grid{Columns: 4, Spacing: 10},
				Children: []Widget{
					Label{Text: "Target Hostname:"},
					LineEdit{AssignTo: &s.echTargetEdit},

					Label{Text: "Port:"},
					LineEdit{AssignTo: &s.echPortEdit},

					Label{Text: "DNS Server:"},
					LineEdit{AssignTo: &s.echDnsEdit},

					Label{Text: "DoH Resolver:"},
					LineEdit{AssignTo: &s.echDohEdit},

					Label{Text: "SNI Hostname:"},
					LineEdit{AssignTo: &s.echSniEdit},

					Label{Text: "ECH Config (Hex):"},
					LineEdit{AssignTo: &s.echConfigEdit},

					Label{Text: "ECH Status:"},
					Label{AssignTo: &s.echStatusLabel, Text: "-"},
				},
			},
			Composite{
				Layout: HBox{MarginsZero: true},
				Children: []Widget{
					PushButton{Text: "Run ECH & SNI Audit", OnClicked: s.runEchAudit},
					HSpacer{},
				},
			},
			GroupBox{
				Title:  "Audit logs and Bypassing Analysis",
				Layout: VBox{},
				Children: []Widget{
					TextEdit{AssignTo: &s.echResultEdit, ReadOnly: true, VScroll: true, MinSize: Size{Height: 280}},
				},
			},
			VSpacer{},
		},
	}
}

func (s *nativeShell) runEchAudit() {
	target := "cloudflare.com"
	if s.echTargetEdit != nil && s.echTargetEdit.Text() != "" {
		target = strings.TrimSpace(s.echTargetEdit.Text())
	}

	portVal := uint16(443)
	if s.echPortEdit != nil && s.echPortEdit.Text() != "" {
		pVal, err := strconv.ParseUint(strings.TrimSpace(s.echPortEdit.Text()), 10, 16)
		if err == nil {
			portVal = uint16(pVal)
		}
	}

	dnsServer := "1.1.1.1"
	if s.echDnsEdit != nil && s.echDnsEdit.Text() != "" {
		dnsServer = strings.TrimSpace(s.echDnsEdit.Text())
	}

	dohServer := "https://cloudflare-dns.com/dns-query"
	if s.echDohEdit != nil && s.echDohEdit.Text() != "" {
		dohServer = strings.TrimSpace(s.echDohEdit.Text())
	}

	sni := target
	if s.echSniEdit != nil && s.echSniEdit.Text() != "" {
		sni = strings.TrimSpace(s.echSniEdit.Text())
	}

	s.setStatus("Running ECH & Secure SNI audit...")
	if s.echResultEdit != nil {
		s.echResultEdit.SetText(fmt.Sprintf("ECH & Secure SNI Censorship Audit for: %s\r\n============================================================\r\n", target))
	}
	if s.echStatusLabel != nil {
		s.echStatusLabel.SetText("Auditing...")
	}

	go func() {
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("Target Endpoint: %s:%d\r\n", target, portVal))
		sb.WriteString(fmt.Sprintf("DNS Resolver:    %s\r\n", dnsServer))
		sb.WriteString(fmt.Sprintf("DoH Resolver:    %s\r\n", dohServer))
		sb.WriteString(fmt.Sprintf("SNI Header:      %s\r\n\r\n", sni))

		// Step 1: DNS HTTPS (Type 65) Record Query
		sb.WriteString("Step 1: DNS HTTPS (Type 65) Record Diagnostics\r\n")
		sb.WriteString("------------------------------------------------------------\r\n")
		sb.WriteString(fmt.Sprintf("  [*] Querying HTTPS SVCB record for %s via UDP...\r\n", target))

		dnsResultUdp, errUdp := bridge.DnsResolve(dnsServer, target, "HTTPS")
		hasUdpRecord := false
		if errUdp != nil {
			sb.WriteString(fmt.Sprintf("  [-] UDP Query Failed: %v\r\n", errUdp))
		} else if !dnsResultUdp.Success {
			sb.WriteString(fmt.Sprintf("  [-] UDP Resolver error: %s\r\n", dnsResultUdp.Error))
		} else {
			sb.WriteString(fmt.Sprintf("  [+] UDP Query successful. Latency: %.1f ms\r\n", dnsResultUdp.LatencyMs))
			if len(dnsResultUdp.Records) > 0 {
				hasUdpRecord = true
				sb.WriteString(fmt.Sprintf("  [+] Found %d HTTPS records via UDP:\r\n", len(dnsResultUdp.Records)))
				for _, r := range dnsResultUdp.Records {
					sb.WriteString(fmt.Sprintf("      - Record: %s -> %s\r\n", r.Type, compactText(r.Value, 64)))
				}
			} else {
				sb.WriteString("  [-] No HTTPS records returned via UDP.\r\n")
			}
		}
		sb.WriteString("\r\n")

		sb.WriteString(fmt.Sprintf("  [*] Querying HTTPS SVCB record via secure DoH (%s)...\r\n", dohServer))
		dnsResultDoh, errDoh := bridge.DnsResolve(dohServer, target, "HTTPS")
		hasDohRecord := false
		if errDoh != nil {
			sb.WriteString(fmt.Sprintf("  [-] DoH Query Failed: %v\r\n", errDoh))
		} else if !dnsResultDoh.Success {
			sb.WriteString(fmt.Sprintf("  [-] DoH error: %s\r\n", dnsResultDoh.Error))
		} else {
			sb.WriteString(fmt.Sprintf("  [+] DoH Query successful. Latency: %.1f ms\r\n", dnsResultDoh.LatencyMs))
			if len(dnsResultDoh.Records) > 0 {
				hasDohRecord = true
				sb.WriteString(fmt.Sprintf("  [+] Found %d HTTPS records via DoH:\r\n", len(dnsResultDoh.Records)))
				for _, r := range dnsResultDoh.Records {
					sb.WriteString(fmt.Sprintf("      - Record: %s -> %s\r\n", r.Type, compactText(r.Value, 64)))
				}
			} else {
				sb.WriteString("  [-] No HTTPS records returned via DoH.\r\n")
			}
		}
		sb.WriteString("\r\n")

		// DNS Analysis
		dnsTampering := false
		if !hasUdpRecord && hasDohRecord {
			dnsTampering = true
			sb.WriteString("  [!] DNS INTERFERENCE DETECTED!\r\n")
			sb.WriteString("      Plain UDP DNS queries for HTTPS (Type 65) records are dropped/blocked,\r\n")
			sb.WriteString("      but secure DoH succeeded. This prevents browsers from auto-activating ECH.\r\n\r\n")
		} else if hasUdpRecord {
			sb.WriteString("  [+] DNS HTTPS records are accessible on this network.\r\n\r\n")
		}

		// Step 2: TLS Handshake SNI Posture
		sb.WriteString("Step 2: TLS SNI Handshake Audit\r\n")
		sb.WriteString("------------------------------------------------------------\r\n")
		sb.WriteString(fmt.Sprintf("  [*] Establishing TLS handshake to %s (SNI: %s)...\r\n", target, sni))

		tlsInfoDirect, errDirect := bridge.TlsHandshakeWithSni(target, portVal, sni, 3000)
		directSuccess := false
		if errDirect != nil {
			sb.WriteString(fmt.Sprintf("  [-] Handshake Failed: %v\r\n", errDirect))
		} else {
			directSuccess = true
			sb.WriteString(fmt.Sprintf("  [+] TLS Handshake Successful!\r\n"))
			sb.WriteString(fmt.Sprintf("      - Version:      %s\r\n", tlsInfoDirect.Version))
			sb.WriteString(fmt.Sprintf("      - Cipher Suite: %s\r\n", tlsInfoDirect.CipherSuite))
			sb.WriteString(fmt.Sprintf("      - Cert Issuer:  %s\r\n", tlsInfoDirect.CertIssuer))
			sb.WriteString(fmt.Sprintf("      - Negotiated ALPN: %s\r\n", strings.Join(tlsInfoDirect.ALPN, ", ")))
		}
		sb.WriteString("\r\n")

		// Step 3: Spoofed SNI TLS Audit
		sb.WriteString("Step 3: Spoofed/Mismatched SNI Audit\r\n")
		sb.WriteString("------------------------------------------------------------\r\n")
		spoofSni := "mismatched.net"
		sb.WriteString(fmt.Sprintf("  [*] Establishing TLS handshake to %s (Spoofed SNI: %s)...\r\n", target, spoofSni))

		tlsInfoSpoof, errSpoof := bridge.TlsHandshakeWithSni(target, portVal, spoofSni, 3000)
		spoofSuccess := false
		if errSpoof != nil {
			sb.WriteString(fmt.Sprintf("  [-] Handshake Failed: %v\r\n", errSpoof))
		} else {
			spoofSuccess = true
			sb.WriteString(fmt.Sprintf("  [+] TLS Handshake Successful!\r\n"))
			sb.WriteString(fmt.Sprintf("      - Version:      %s\r\n", tlsInfoSpoof.Version))
			sb.WriteString(fmt.Sprintf("      - Cert Issuer:  %s\r\n", tlsInfoSpoof.CertIssuer))
		}
		sb.WriteString("\r\n")

		// Step 4: ECH Evasion Efficacy & Assessment
		sb.WriteString("Step 4: ECH & SNI Censorship Efficacy Synthesis\r\n")
		sb.WriteString("------------------------------------------------------------\r\n")

		statusText := "Audited"
		if dnsTampering {
			statusText = "DNS Blocked"
			sb.WriteString("  [!] ECH Block Type: DNS Bootstrapping Blocked\r\n")
			sb.WriteString("      The local firewall prevents retrieval of ECH config keys over UDP port 53.\r\n")
			sb.WriteString("      Recommendation: Force DNS-over-HTTPS (DoH) in your browser/agent to bypass this.\r\n")
		} else if !directSuccess {
			statusText = "Blocked"
			sb.WriteString("  [!] Pathway status: Connection Blocked\r\n")
			sb.WriteString("      Direct connection failed. The target host or SNI is actively blocked.\r\n")
			if spoofSuccess {
				sb.WriteString("      [+] Note: Mismatched SNI connection succeeded! SNI-based filtering is in place.\r\n")
				sb.WriteString("          You can bypass this by using Domain Fronting or ECH.\r\n")
			}
		} else {
			statusText = "Safe"
			sb.WriteString("  [+] Pathway status: Safe / Unrestricted\r\n")
			sb.WriteString("      No active DNS tampering or SNI-based blocking detected for this target.\r\n")
			if hasUdpRecord {
				sb.WriteString("      ECH can be fully negotiated securely.\r\n")
			}
		}

		s.sync(func() {
			s.setStatus("ECH & Secure SNI audit completed.")
			if s.echStatusLabel != nil {
				s.echStatusLabel.SetText(statusText)
			}
			if s.echResultEdit != nil {
				s.echResultEdit.AppendText(sb.String())
			}
		})
	}()
}

func (s *nativeShell) onDnsSecDohPresetChanged() {
	if s.dnsSecDohPresetCombo == nil || s.dnsSecDohServer == nil {
		return
	}
	idx := s.dnsSecDohPresetCombo.CurrentIndex()
	if idx < 0 {
		return
	}
	urls := []string{
		"https://cloudflare-dns.com/dns-query",
		"https://dns1.nordvpn.com/dns-query",
		"https://family.cloudflare-dns.com/dns-query",
		"https://doh.cleanbrowsing.org/doh/family-filter/",
		"https://secure.avastdns.com/dns-query",
		"https://dns.comodo.com/dns-query",
		"https://doh.opendns.com/dns-query",
		"https://unfiltered.adguard-dns.com/dns-query",
		"https://family.dot.dns.yandex.net",
		"https://dns.google/dns-query",
		"https://dns.quad9.net/dns-query",
	}
	if idx < len(urls) {
		s.dnsSecDohServer.SetText(urls[idx])
	}
}
