//go:build windows && cgo

package cmd

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	. "github.com/lxn/walk/declarative"
	"github.com/maybeknott/luminet/internal/bridge"
)

func (s *nativeShell) speedBenchmarkPage() TabPage {
	return TabPage{
		Title:  "Speed Test",
		Layout: VBox{Margins: Margins{Left: 14, Top: 14, Right: 14, Bottom: 14}},
		Children: []Widget{
			GroupBox{
				Title:  "Speed Test Config",
				Layout: Grid{Columns: 4, Spacing: 10},
				Children: []Widget{
					Label{Text: "Speed Test Target Preset:"},
					ComboBox{
						AssignTo: &s.speedPresetCombo,
						Model: []string{
							"Tele2 Sweden (speedtest.tele2.net:80)",
							"Tele2 Singapore (speedtest.singapore.tele2.net:80)",
							"Orange France (speedtest.fr.oleane.net:80)",
							"CacheFly CDN (cachefly.cachefly.net:80)",
							"Google DL (dl.google.com:80)",
							"Custom (Type below)",
						},
						OnCurrentIndexChanged: s.onSpeedPresetChanged,
					},
					Label{Text: "Active Target URL/IP:port:"},
					LineEdit{AssignTo: &s.speedServerEdit},

					Label{Text: "Probe Timeout (seconds):"},
					LineEdit{AssignTo: &s.speedTimeoutEdit},
					Label{Text: ""},
					Label{Text: ""},
				},
			},
			Composite{
				Layout: HBox{MarginsZero: true},
				Children: []Widget{
					PushButton{Text: "Start Speed Test", OnClicked: s.runSpeedBenchmark},
					HSpacer{},
				},
			},
			GroupBox{
				Title:  "Real-Time Speed Metrics",
				Layout: Grid{Columns: 4, Spacing: 10},
				Children: []Widget{
					Label{Text: "Download Speed:"},
					Label{AssignTo: &s.speedDownloadLabel, Text: "- Mbps"},
					Label{Text: "Upload Speed:"},
					Label{AssignTo: &s.speedUploadLabel, Text: "- Mbps"},

					Label{Text: "RTT Latency:"},
					Label{AssignTo: &s.speedLatencyLabel, Text: "- ms"},
					Label{Text: "Jitter:"},
					Label{AssignTo: &s.speedJitterLabel, Text: "- ms"},

					Label{Text: "Connection Quality Grade:"},
					Label{AssignTo: &s.speedGradeLabel, Text: "-"},
					Label{Text: ""},
					Label{Text: ""},
				},
			},
			GroupBox{
				Title:  "Detailed Performance Log",
				Layout: VBox{},
				Children: []Widget{
					TextEdit{AssignTo: &s.speedResultEdit, ReadOnly: true, VScroll: true, MinSize: Size{Height: 250}},
				},
			},
			VSpacer{},
		},
	}
}

func (s *nativeShell) runSpeedBenchmark() {
	server := "speedtest.tele2.net:80"
	if s.speedServerEdit != nil && s.speedServerEdit.Text() != "" {
		server = strings.TrimSpace(s.speedServerEdit.Text())
	}

	timeoutMs := uint32(5000)
	if s.speedTimeoutEdit != nil && s.speedTimeoutEdit.Text() != "" {
		if val, err := strconv.ParseUint(strings.TrimSpace(s.speedTimeoutEdit.Text()), 10, 32); err == nil {
			timeoutMs = uint32(val * 1000)
		}
	}

	s.setStatus("Running speed test benchmark...")
	if s.speedResultEdit != nil {
		s.speedResultEdit.SetText(fmt.Sprintf("Speed test benchmark starting against: %s\r\nTimeout: %d ms\r\nRunning tests, please wait...\r\n", server, timeoutMs))
	}
	if s.speedDownloadLabel != nil {
		s.speedDownloadLabel.SetText("- Mbps")
	}
	if s.speedUploadLabel != nil {
		s.speedUploadLabel.SetText("- Mbps")
	}
	if s.speedLatencyLabel != nil {
		s.speedLatencyLabel.SetText("- ms")
	}
	if s.speedJitterLabel != nil {
		s.speedJitterLabel.SetText("- ms")
	}
	if s.speedGradeLabel != nil {
		s.speedGradeLabel.SetText("Testing...")
	}

	go func() {
		res, err := bridge.SpeedTest(server, timeoutMs)

		s.sync(func() {
			if err != nil {
				s.setStatus("Speed test benchmark failed: " + err.Error())
				if s.speedResultEdit != nil {
					s.speedResultEdit.SetText(fmt.Sprintf("Benchmark Failed: %v\r\n", err))
				}
				if s.speedGradeLabel != nil {
					s.speedGradeLabel.SetText("Failed")
				}
				return
			}

			s.setStatus("Speed test benchmark completed.")

			// Update Labels
			if s.speedDownloadLabel != nil {
				s.speedDownloadLabel.SetText(fmt.Sprintf("%.2f Mbps", res.DownloadMbps))
			}
			if s.speedUploadLabel != nil {
				s.speedUploadLabel.SetText(fmt.Sprintf("%.2f Mbps", res.UploadMbps))
			}
			if s.speedLatencyLabel != nil {
				s.speedLatencyLabel.SetText(fmt.Sprintf("%.2f ms", res.LatencyMs))
			}
			if s.speedJitterLabel != nil {
				s.speedJitterLabel.SetText(fmt.Sprintf("%.2f ms", res.JitterMs))
			}

			// Calculate Grade
			grade := "Excellent (A+)"
			if res.DownloadMbps < 10.0 || res.LatencyMs > 150.0 {
				grade = "Poor (D)"
			} else if res.DownloadMbps < 25.0 || res.LatencyMs > 80.0 {
				grade = "Fair (C)"
			} else if res.DownloadMbps < 50.0 || res.LatencyMs > 40.0 {
				grade = "Good (B)"
			}

			if s.speedGradeLabel != nil {
				s.speedGradeLabel.SetText(grade)
			}

			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("Speed test benchmark results for: %s\r\n", res.Server))
			sb.WriteString("==================================================\r\n\r\n")
			sb.WriteString(fmt.Sprintf("  Download Speed:  %.2f Mbps\r\n", res.DownloadMbps))
			sb.WriteString(fmt.Sprintf("  Upload Speed:    %.2f Mbps\r\n", res.UploadMbps))
			sb.WriteString(fmt.Sprintf("  RTT Latency:     %.2f ms\r\n", res.LatencyMs))
			sb.WriteString(fmt.Sprintf("  Jitter:          %.2f ms\r\n", res.JitterMs))
			sb.WriteString(fmt.Sprintf("  Bytes Transf.:   %d bytes\r\n", res.BytesTransferred))
			sb.WriteString(fmt.Sprintf("  Test Duration:   %d ms\r\n\r\n", res.DurationMs))

			sb.WriteString("Connection Performance Assessment:\r\n")
			sb.WriteString("--------------------------------------------------\r\n")
			sb.WriteString(fmt.Sprintf("  Overall Grade:   %s\r\n", grade))

			switch grade {
			case "Excellent (A+)":
				sb.WriteString("  Recommendation: Suitable for all high-bandwidth activities including 4K video streaming, online gaming, and large downloads.\r\n")
			case "Good (B)":
				sb.WriteString("  Recommendation: Good connection. Suitable for HD video streaming, VoIP/video calls, and general browsing.\r\n")
			case "Fair (C)":
				sb.WriteString("  Recommendation: Fair connection. HD streaming might experience minor buffering; suitable for standard browsing and audio streaming.\r\n")
			case "Poor (D)":
				sb.WriteString("  Recommendation: Poor connection. Expect buffering in video streaming, potential lag in gaming/video calls, and slow downloads.\r\n")
			}

			if s.speedResultEdit != nil {
				s.speedResultEdit.SetText(sb.String())
			}
		})
	}()
}

func (s *nativeShell) subnetScannerPage() TabPage {
	return TabPage{
		Title:  "LAN Subnet Scanner",
		Layout: VBox{Margins: Margins{Left: 14, Top: 14, Right: 14, Bottom: 14}},
		Children: []Widget{
			GroupBox{
				Title:  "Subnet Scan & Audit Parameters",
				Layout: Grid{Columns: 4, Spacing: 10},
				Children: []Widget{
					Label{Text: "Subnet CIDR Range:"},
					Composite{
						Layout: HBox{MarginsZero: true, Spacing: 4},
						Children: []Widget{
							LineEdit{AssignTo: &s.subnetCidrEdit, StretchFactor: 2},
							PushButton{Text: "Auto-Detect", MaxSize: Size{Width: 90}, OnClicked: s.onAutoDetectSubnet},
						},
					},

					Label{Text: "Scan Discovery Mode:"},
					ComboBox{
						AssignTo: &s.subnetScanMode,
						Model: []string{
							"ICMP Ping Sweep (Fast)",
							"TCP Port Sweep (Thorough)",
							"Hybrid Sweep (Ping + Web Ports)",
						},
					},

					Label{Text: "Service Ports (comma separated):"},
					LineEdit{AssignTo: &s.subnetPortsEdit},

					Label{Text: "Max Concurrency:"},
					LineEdit{AssignTo: &s.subnetConcurrency},

					Label{Text: "Timeout (ms):"},
					LineEdit{AssignTo: &s.subnetTimeoutEdit},

					Label{Text: "Active Hosts Found:"},
					Label{AssignTo: &s.subnetHostsLabel, Text: "0 hosts"},
				},
			},
			Composite{
				Layout: HBox{MarginsZero: true},
				Children: []Widget{
					PushButton{Text: "Run LAN Subnet Audit", OnClicked: s.runSubnetScan},
					HSpacer{},
				},
			},
			GroupBox{
				Title:  "LAN Audit & Service Discovery Logs",
				Layout: VBox{},
				Children: []Widget{
					TextEdit{AssignTo: &s.subnetResultEdit, ReadOnly: true, VScroll: true, MinSize: Size{Height: 320}},
				},
			},
			VSpacer{},
		},
	}
}

func (s *nativeShell) runSubnetScan() {
	cidr := "192.168.1.0/24"
	if s.subnetCidrEdit != nil && s.subnetCidrEdit.Text() != "" {
		cidr = strings.TrimSpace(s.subnetCidrEdit.Text())
	}

	portsStr := "21,22,23,53,80,443,445,3389,8080"
	if s.subnetPortsEdit != nil && s.subnetPortsEdit.Text() != "" {
		portsStr = strings.TrimSpace(s.subnetPortsEdit.Text())
	}

	var ports []uint16
	for _, pStr := range strings.Split(portsStr, ",") {
		pStr = strings.TrimSpace(pStr)
		if pStr == "" {
			continue
		}
		pVal, err := strconv.ParseUint(pStr, 10, 16)
		if err == nil {
			ports = append(ports, uint16(pVal))
		}
	}

	concurrency := uint32(100)
	if s.subnetConcurrency != nil && s.subnetConcurrency.Text() != "" {
		cVal, err := strconv.ParseUint(strings.TrimSpace(s.subnetConcurrency.Text()), 10, 32)
		if err == nil {
			concurrency = uint32(cVal)
		}
	}

	timeoutMs := uint32(1000)
	if s.subnetTimeoutEdit != nil && s.subnetTimeoutEdit.Text() != "" {
		tVal, err := strconv.ParseUint(strings.TrimSpace(s.subnetTimeoutEdit.Text()), 10, 32)
		if err == nil {
			timeoutMs = uint32(tVal)
		}
	}

	scanModeIdx := 0
	if s.subnetScanMode != nil {
		scanModeIdx = s.subnetScanMode.CurrentIndex()
	}

	s.setStatus("Running LAN Subnet Scan & Port Audit...")
	if s.subnetResultEdit != nil {
		s.subnetResultEdit.SetText(fmt.Sprintf("LAN Subnet Audit for CIDR: %s\r\n============================================================\r\nExpanding CIDR target range...\r\n", cidr))
	}
	if s.subnetHostsLabel != nil {
		s.subnetHostsLabel.SetText("Scanning...")
	}

	go func() {
		targets, err := bridge.ExpandTargets(cidr)
		if err != nil {
			s.sync(func() {
				s.setStatus("LAN scan failed.")
				if s.subnetResultEdit != nil {
					s.subnetResultEdit.SetText(fmt.Sprintf("Error expanding CIDR: %v\r\n", err))
				}
				if s.subnetHostsLabel != nil {
					s.subnetHostsLabel.SetText("Failed")
				}
			})
			return
		}

		if len(targets) > 512 {
			s.sync(func() {
				s.setStatus("Subnet too large.")
				if s.subnetResultEdit != nil {
					s.subnetResultEdit.AppendText(fmt.Sprintf("Error: Subnet size (%d targets) exceeds the limit of 512 hosts for LAN auditing to avoid network overload.\r\nPlease use a /24 or smaller CIDR subnet (e.g. 192.168.1.0/24).\r\n", len(targets)))
				}
				if s.subnetHostsLabel != nil {
					s.subnetHostsLabel.SetText("Too large")
				}
			})
			return
		}

		s.sync(func() {
			if s.subnetResultEdit != nil {
				s.subnetResultEdit.AppendText(fmt.Sprintf("Generated %d target IP addresses.\r\nStarting node discovery sweep...\r\n\r\n", len(targets)))
			}
		})

		cfg := bridge.ScanConfig{
			Timeout:      timeoutMs,
			Concurrency:  concurrency,
			RateLimitPPS: 1000,
			RetryCount:   1,
			AdaptiveRate: true,
		}

		var activeHosts []string
		var hostPings = make(map[string]float64)

		switch scanModeIdx {
		case 0: // ICMP Ping Sweep (Fast)
			results, err := bridge.IcmpScan(targets, cfg)
			if err != nil {
				s.sync(func() {
					s.setStatus("ICMP Scan failed.")
					if s.subnetResultEdit != nil {
						s.subnetResultEdit.AppendText(fmt.Sprintf("ICMP Ping Sweep Error: %v\r\n", err))
					}
				})
			} else {
				for _, res := range results {
					if res.Alive {
						ip := res.IP
						if ip == "" {
							ip = res.Target
						}
						activeHosts = append(activeHosts, ip)
						hostPings[ip] = res.LatencyMs
					}
				}
			}

		case 1: // TCP Port Sweep (Thorough)
			type tcpProbe struct {
				ip    string
				alive bool
			}
			semChan := make(chan struct{}, concurrency)
			probeResults := make(chan tcpProbe, len(targets))

			for _, ip := range targets {
				go func(targetIP string) {
					semChan <- struct{}{}
					defer func() { <-semChan }()

					alive := false
					for _, port := range []uint16{80, 443, 22, 445, 3389} {
						res, err := bridge.TcpConnect(targetIP, port, timeoutMs)
						if err == nil && res.Alive {
							alive = true
							break
						}
					}
					probeResults <- tcpProbe{ip: targetIP, alive: alive}
				}(ip)
			}

			for i := 0; i < len(targets); i++ {
				res := <-probeResults
				if res.alive {
					activeHosts = append(activeHosts, res.ip)
				}
			}

		case 2: // Hybrid (Ping + Web Ports)
			results, err := bridge.IcmpScan(targets, cfg)
			var pingAlive = make(map[string]bool)
			if err == nil {
				for _, res := range results {
					if res.Alive {
						ip := res.IP
						if ip == "" {
							ip = res.Target
						}
						activeHosts = append(activeHosts, ip)
						hostPings[ip] = res.LatencyMs
						pingAlive[ip] = true
					}
				}
			}

			var uncheckedHosts []string
			for _, ip := range targets {
				if !pingAlive[ip] {
					uncheckedHosts = append(uncheckedHosts, ip)
				}
			}

			s.sync(func() {
				if s.subnetResultEdit != nil {
					s.subnetResultEdit.AppendText(fmt.Sprintf("Found %d hosts via ICMP. Probing remaining %d hosts via TCP...\r\n", len(activeHosts), len(uncheckedHosts)))
				}
			})

			type tcpProbe struct {
				ip    string
				alive bool
			}
			semChan := make(chan struct{}, concurrency)
			probeResults := make(chan tcpProbe, len(uncheckedHosts))

			for _, ip := range uncheckedHosts {
				go func(targetIP string) {
					semChan <- struct{}{}
					defer func() { <-semChan }()

					alive := false
					for _, port := range []uint16{80, 443, 22, 445, 3389} {
						res, err := bridge.TcpConnect(targetIP, port, timeoutMs)
						if err == nil && res.Alive {
							alive = true
							break
						}
					}
					probeResults <- tcpProbe{ip: targetIP, alive: alive}
				}(ip)
			}

			for i := 0; i < len(uncheckedHosts); i++ {
				res := <-probeResults
				if res.alive {
					activeHosts = append(activeHosts, res.ip)
				}
			}
		}

		sort.Strings(activeHosts)

		s.sync(func() {
			s.setStatus(fmt.Sprintf("Scan found %d active hosts. Starting service port audit...", len(activeHosts)))
			if s.subnetHostsLabel != nil {
				s.subnetHostsLabel.SetText(fmt.Sprintf("%d hosts active", len(activeHosts)))
			}
			if s.subnetResultEdit != nil {
				s.subnetResultEdit.AppendText(fmt.Sprintf("\r\nDiscovered %d active hosts.\r\nAuditing open service ports: %v\r\n------------------------------------------------------------\r\n", len(activeHosts), ports))
			}
		})

		for _, host := range activeHosts {
			var open []bridge.PortResult
			portResults, err := bridge.PortScan(host, ports, cfg)
			if err == nil {
				for _, pr := range portResults {
					if pr.Open {
						open = append(open, pr)
					}
				}
			}
			lat, ok := hostPings[host]

			s.sync(func() {
				if s.subnetResultEdit != nil {
					var pb strings.Builder
					pb.WriteString(fmt.Sprintf("Host: %s", host))
					if ok {
						pb.WriteString(fmt.Sprintf(" (Ping: %.1f ms)", lat))
					} else {
						pb.WriteString(" (Ping: Failed/Blocked)")
					}
					pb.WriteString("\r\n")

					if len(open) == 0 {
						pb.WriteString("  [+] No open service ports found in the specified range.\r\n")
					} else {
						for _, p := range open {
							pb.WriteString(fmt.Sprintf("  -> Port %d/TCP is OPEN (Latency: %.1f ms)", p.Port, p.LatencyMs))
							if p.Service != "" {
								pb.WriteString(fmt.Sprintf(" [Service: %s]", p.Service))
							}
							if p.Banner != "" {
								pb.WriteString(fmt.Sprintf(" - Banner: %s", strings.TrimSpace(p.Banner)))
							}
							pb.WriteString("\r\n")
						}
					}
					pb.WriteString("\r\n")
					s.subnetResultEdit.AppendText(pb.String())
				}
			})
		}

		s.sync(func() {
			s.setStatus("LAN Subnet scan completed.")
			if s.subnetResultEdit != nil {
				s.subnetResultEdit.AppendText("============================================================\r\nScan Complete.\r\n")
			}
		})
	}()
}

func (s *nativeShell) wgAuditorPage() TabPage {
	return TabPage{
		Title:  "WireGuard Auditor",
		Layout: VBox{Margins: Margins{Left: 14, Top: 14, Right: 14, Bottom: 14}},
		Children: []Widget{
			GroupBox{
				Title:  "WireGuard Endpoint Configuration",
				Layout: Grid{Columns: 4, Spacing: 10},
				Children: []Widget{
					Label{Text: "Endpoint Preset:"},
					ComboBox{
						AssignTo: &s.wgPresetCombo,
						Model: []string{
							"Cloudflare WARP (162.159.192.1:2408)",
							"Cloudflare WARP Alt (188.114.97.1:2408)",
							"ProtonVPN Free (185.159.157.4:51820)",
							"Mullvad Switzerland (193.138.218.223:51820)",
							"Custom (Type below)",
						},
						OnCurrentIndexChanged: s.onWgPresetChanged,
					},
					Label{Text: "Endpoint IP / Host:"},
					LineEdit{AssignTo: &s.wgTargetEdit},

					Label{Text: "UDP Port:"},
					LineEdit{AssignTo: &s.wgPortEdit},

					Label{Text: "Timeout (ms):"},
					LineEdit{AssignTo: &s.wgTimeoutEdit},

					Label{Text: "Padding Bytes:"},
					LineEdit{AssignTo: &s.wgPaddingEdit},

					Label{Text: "Last Probe Status:"},
					Label{AssignTo: &s.wgStatusLabel, Text: "-"},

					Label{Text: "Measured Latency:"},
					Label{AssignTo: &s.wgLatencyLabel, Text: "- ms"},
					Label{Text: ""},
					Label{Text: ""},
				},
			},
			Composite{
				Layout: HBox{MarginsZero: true},
				Children: []Widget{
					PushButton{Text: "Probe Handshake", OnClicked: s.runWgProbe},
					PushButton{Text: "Benchmark Public Endpoints", OnClicked: s.runWgBenchmark},
					HSpacer{},
				},
			},
			GroupBox{
				Title:  "WireGuard Connectivity & DPI Logs",
				Layout: VBox{},
				Children: []Widget{
					TextEdit{AssignTo: &s.wgResultEdit, ReadOnly: true, VScroll: true, MinSize: Size{Height: 320}},
				},
			},
			VSpacer{},
		},
	}
}

func (s *nativeShell) runWgProbe() {
	target := "162.159.192.1"
	if s.wgTargetEdit != nil && s.wgTargetEdit.Text() != "" {
		target = strings.TrimSpace(s.wgTargetEdit.Text())
	}

	portVal := uint16(2408)
	if s.wgPortEdit != nil && s.wgPortEdit.Text() != "" {
		pVal, err := strconv.ParseUint(strings.TrimSpace(s.wgPortEdit.Text()), 10, 16)
		if err == nil {
			portVal = uint16(pVal)
		}
	}

	timeoutMs := uint32(2000)
	if s.wgTimeoutEdit != nil && s.wgTimeoutEdit.Text() != "" {
		tVal, err := strconv.ParseUint(strings.TrimSpace(s.wgTimeoutEdit.Text()), 10, 32)
		if err == nil {
			timeoutMs = uint32(tVal)
		}
	}

	paddingLen := uint32(0)
	if s.wgPaddingEdit != nil && s.wgPaddingEdit.Text() != "" {
		padVal, err := strconv.ParseUint(strings.TrimSpace(s.wgPaddingEdit.Text()), 10, 32)
		if err == nil {
			paddingLen = uint32(padVal)
		}
	}

	s.setStatus(fmt.Sprintf("Probing WireGuard endpoint: %s:%d...", target, portVal))
	if s.wgResultEdit != nil {
		s.wgResultEdit.SetText(fmt.Sprintf("WireGuard Handshake Initiation Audit for: %s:%d (Padding: %d bytes)\r\n============================================================\r\nSending %d-byte UDP Handshake Initiation packet (148 base + %d padding)...\r\n", target, portVal, paddingLen, 148+paddingLen, paddingLen))
	}
	if s.wgStatusLabel != nil {
		s.wgStatusLabel.SetText("Probing...")
	}
	if s.wgLatencyLabel != nil {
		s.wgLatencyLabel.SetText("- ms")
	}

	go func() {
		res, err := bridge.WgProbe(target, portVal, timeoutMs, paddingLen)
		s.sync(func() {
			if err != nil {
				s.setStatus("WireGuard probe failed.")
				if s.wgStatusLabel != nil {
					s.wgStatusLabel.SetText("Failed")
				}
				if s.wgResultEdit != nil {
					s.wgResultEdit.AppendText(fmt.Sprintf("\r\n[!] Error executing probe: %v\r\n", err))
				}
				return
			}

			latencyStr := fmt.Sprintf("%.1f ms", res.LatencyMs)
			if s.wgLatencyLabel != nil {
				s.wgLatencyLabel.SetText(latencyStr)
			}

			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("Probe Completed in %s.\r\n", latencyStr))
			sb.WriteString("------------------------------------------------------------\r\n")

			if res.Alive {
				s.setStatus("WireGuard endpoint active!")
				if s.wgStatusLabel != nil {
					s.wgStatusLabel.SetText("Active/Responsive")
				}
				sb.WriteString(fmt.Sprintf("  [+] RESPONSE DETECTED: %s\r\n", res.Error))
				sb.WriteString("  [+] The endpoint returned a valid UDP packet, confirming network reachability.\r\n")
				sb.WriteString("  [+] This node is highly likely open and suitable for tunneling.\r\n")
			} else {
				s.setStatus("WireGuard probe timeout.")
				if s.wgStatusLabel != nil {
					s.wgStatusLabel.SetText("No Response (Normal / Blocked)")
				}
				sb.WriteString("  [-] TIMEOUT: No UDP response was received from the server.\r\n")
				sb.WriteString("  [!] NOTE: WireGuard protocol design silently drops unauthorized handshakes.\r\n")
				sb.WriteString("      A timeout is normal if the server does not recognize the randomized ephemeral key,\r\n")
				sb.WriteString("      but it can also indicate DPI filtering or that the endpoint is offline.\r\n")
				sb.WriteString("      Check the latency benchmark against public nodes to differentiate blocks from packet drops.\r\n")
			}

			if s.wgResultEdit != nil {
				s.wgResultEdit.AppendText(sb.String())
			}
		})
	}()
}

func (s *nativeShell) runWgBenchmark() {
	s.setStatus("Benchmarking public WireGuard endpoints...")
	if s.wgResultEdit != nil {
		s.wgResultEdit.SetText("WireGuard Public Resolver Benchmarking\r\n============================================================\r\nTesting common endpoints concurrently...\r\n\r\n")
	}

	go func() {
		endpoints := []struct {
			name string
			ip   string
			port uint16
		}{
			{"Cloudflare WARP (IPv4 - Main)", "162.159.192.1", 2408},
			{"Cloudflare WARP (IPv4 - Alt 1)", "162.159.193.1", 2408},
			{"Cloudflare WARP (IPv4 - Alt 2)", "162.159.194.1", 2408},
			{"Cloudflare WARP (IPv4 - Alt 3)", "188.114.97.1", 2408},
			{"ProtonVPN Free IP 1", "185.159.157.4", 51820},
			{"ProtonVPN Free IP 2", "185.159.157.8", 51820},
		}

		type benchResult struct {
			name      string
			ip        string
			port      uint16
			latencyMs float64
			alive     bool
			respType  string
		}

		var results []benchResult
		concurrencyLimit := make(chan struct{}, 4)
		resultChan := make(chan benchResult, len(endpoints))

		for _, ep := range endpoints {
			go func(name, ip string, port uint16) {
				concurrencyLimit <- struct{}{}
				defer func() { <-concurrencyLimit }()

				res, err := bridge.WgProbe(ip, port, 1500, 0)
				if err == nil {
					resultChan <- benchResult{
						name:      name,
						ip:        ip,
						port:      port,
						latencyMs: res.LatencyMs,
						alive:     res.Alive,
						respType:  res.Error,
					}
				} else {
					resultChan <- benchResult{
						name:      name,
						ip:        ip,
						port:      port,
						latencyMs: 9999,
						alive:     false,
						respType:  "Failed",
					}
				}
			}(ep.name, ep.ip, ep.port)
		}

		for i := 0; i < len(endpoints); i++ {
			results = append(results, <-resultChan)
		}

		s.sync(func() {
			s.setStatus("WireGuard benchmark completed.")
			var sb strings.Builder
			sb.WriteString("WireGuard Public Resolver Benchmarking Results:\r\n")
			sb.WriteString("============================================================\r\n\r\n")

			for _, r := range results {
				sb.WriteString(fmt.Sprintf("[%s] %s:%d\r\n", r.name, r.ip, r.port))
				if r.alive {
					sb.WriteString(fmt.Sprintf("  Status:  ACTIVE (Latency: %.1f ms)\r\n", r.latencyMs))
				} else {
					sb.WriteString("  Status:  NO RESPONSE / BLOCKED (Timeout after 1.5s)\r\n")
				}
				sb.WriteString("\r\n")
			}

			if s.wgResultEdit != nil {
				s.wgResultEdit.AppendText(sb.String())
			}
		})
	}()
}

func (s *nativeShell) onSpeedPresetChanged() {
	if s.speedPresetCombo == nil || s.speedServerEdit == nil {
		return
	}
	idx := s.speedPresetCombo.CurrentIndex()
	if idx < 0 {
		return
	}
	targets := []string{
		"speedtest.tele2.net:80",
		"speedtest.singapore.tele2.net:80",
		"speedtest.fr.oleane.net:80",
		"cachefly.cachefly.net:80",
		"dl.google.com:80",
	}
	if idx < len(targets) {
		s.speedServerEdit.SetText(targets[idx])
	}
}

func (s *nativeShell) onAutoDetectSubnet() {
	if s.subnetCidrEdit == nil {
		return
	}
	cidr := "192.168.1.0/24"
	if len(s.lastStatus.Interfaces) > 0 {
		for _, iface := range s.lastStatus.Interfaces {
			for _, ip := range iface.IPs {
				if strings.Contains(ip, ".") && !strings.HasPrefix(ip, "127.") {
					parts := strings.Split(ip, ".")
					if len(parts) == 4 {
						cidr = fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
						break
					}
				}
			}
		}
	}
	s.subnetCidrEdit.SetText(cidr)
	s.setStatus("Auto-detected local subnet: " + cidr)
}

func (s *nativeShell) onWgPresetChanged() {
	if s.wgPresetCombo == nil || s.wgTargetEdit == nil || s.wgPortEdit == nil {
		return
	}
	idx := s.wgPresetCombo.CurrentIndex()
	if idx < 0 {
		return
	}
	type endpoint struct {
		ip   string
		port string
	}
	eps := []endpoint{
		{"162.159.192.1", "2408"},
		{"188.114.97.1", "2408"},
		{"185.159.157.4", "51820"},
		{"193.138.218.223", "51820"},
	}
	if idx < len(eps) {
		s.wgTargetEdit.SetText(eps[idx].ip)
		s.wgPortEdit.SetText(eps[idx].port)
	}
}
