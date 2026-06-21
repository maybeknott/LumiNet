//go:build windows && cgo

package cmd

import (
	"fmt"
	"strings"
	"time"

	. "github.com/lxn/walk/declarative"
	"github.com/maybeknott/luminet/internal/bridge"
)

func (s *nativeShell) bypassWizardPage() TabPage {
	return TabPage{
		Title:  "Evasion Wizard",
		Layout: VBox{Margins: Margins{Left: 14, Top: 14, Right: 14, Bottom: 14}},
		Children: []Widget{
			GroupBox{
				Title:  "DPI Bypass Evasion Wizard",
				Layout: Grid{Columns: 3, Spacing: 10},
				Children: []Widget{
					Label{Text: "Target Domain / Hostname:"},
					LineEdit{AssignTo: &s.wizardTargetEdit},
					PushButton{Text: "Run Evasion Synthesis", OnClicked: s.runEvasionWizard},
				},
			},
			GroupBox{
				Title:  "Optimal Bypass Strategy & Auto-Generated Configs",
				Layout: VBox{},
				Children: []Widget{
					TextEdit{AssignTo: &s.wizardOutput, ReadOnly: true, VScroll: true, MinSize: Size{Height: 420}},
				},
			},
			VSpacer{},
		},
	}
}

func (s *nativeShell) runEvasionWizard() {
	target := "google.com"
	if s.wizardTargetEdit != nil {
		target = strings.TrimSpace(s.wizardTargetEdit.Text())
	}
	if target == "" {
		s.setStatus("Enter target domain for analysis.")
		return
	}

	s.setStatus("Running Evasion Synthesis Wizard...")
	if s.wizardOutput != nil {
		s.wizardOutput.SetText(fmt.Sprintf("============================================================\r\n"+
			"              LUMINET DPI BYPASS & EVASION WIZARD\r\n"+
			"============================================================\r\n"+
			"Target Host: %s\r\n"+
			"Starting diagnostic probes, please wait...\r\n\r\n", target))
	}

	go func() {
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("============================================================\r\n"+
			"              LUMINET DPI BYPASS & EVASION WIZARD\r\n"+
			"============================================================\r\n"+
			"Target Host: %s\r\n"+
			"Probes completed at: %s\r\n\r\n", target, time.Now().Format("15:04:05")))

		// 1. DNS Censorship probe
		sb.WriteString("DIAGNOSTIC PIPELINE SYNTHESIS:\r\n")
		sb.WriteString("------------------------------------------------------------\r\n")
		sb.WriteString("[1] DNS Censorship & Poisoning Audit:\r\n")

		dnsServer := "1.1.1.1"
		dohServer := "https://cloudflare-dns.com/dns-query"

		udpRes, udpErr := bridge.DnsResolve(dnsServer, target, "A")
		dohRes, dohErr := bridge.DnsResolve(dohServer, target, "A")

		dnsCensored := false
		var udpIPs, dohIPs []string
		if udpErr == nil && udpRes.Success {
			for _, r := range udpRes.Records {
				udpIPs = append(udpIPs, r.Value)
			}
		}
		if dohErr == nil && dohRes.Success {
			for _, r := range dohRes.Records {
				dohIPs = append(dohIPs, r.Value)
			}
		}

		if len(udpIPs) > 0 && len(dohIPs) > 0 {
			// Check intersection
			intersect := false
			for _, u := range udpIPs {
				for _, d := range dohIPs {
					if u == d {
						intersect = true
						break
					}
				}
			}
			if !intersect {
				dnsCensored = true
				sb.WriteString(fmt.Sprintf("  [!] UDP DNS POISONING DETECTED! UDP returned: %v, DoH returned: %v\r\n", udpIPs, dohIPs))
				sb.WriteString("      The local resolver is hijacking plaintext DNS answers.\r\n")
			} else {
				sb.WriteString(fmt.Sprintf("  [+] DNS is clean. Consistently returned %v\r\n", udpIPs))
			}
		} else if len(dohIPs) > 0 {
			dnsCensored = true
			sb.WriteString("  [!] UDP DNS queries dropped or failed, but secure DoH succeeded.\r\n")
		} else {
			sb.WriteString("  [-] Unable to resolve target via UDP or DoH. Connection offline?\r\n")
		}

		// 2. TCP Segment Splitting probe
		sb.WriteString("\r\n[2] TCP Evasion & Segment Splitting Audit:\r\n")
		headers := map[string]string{"Host": target, "User-Agent": "LumiNet/1.0"}

		// Run direct
		_, errDirect := s.probeRawHTTP(target, 80, headers, 1500)
		directOk := errDirect == nil

		// Run split
		_, errSplit := s.probeRawHTTPSplit(target, 80, headers, 1500, 2, 20)
		splitOk := errSplit == nil

		splitHelps := false
		if !directOk && splitOk {
			splitHelps = true
			sb.WriteString("  [!] DIRECT CONNECTION BLOCKED but TCP Segment Splitting (2-byte split) SUCCEEDED!\r\n")
			sb.WriteString("      DPI gateway successfully bypassed via stream segmentation.\r\n")
		} else if !directOk && !splitOk {
			sb.WriteString("  [-] Direct and split connections failed. Host offline or strict blocking in place.\r\n")
		} else {
			sb.WriteString("  [+] Direct connection succeeded. No active port-80 HTTP filtering detected.\r\n")
		}

		// 3. TLS SNI Interception probe
		sb.WriteString("\r\n[3] TLS SNI Interception Audit:\r\n")
		tlsDirect, errTlsDirect := bridge.TlsHandshakeWithSni(target, 443, target, 2000)
		_, errTlsSpoof := bridge.TlsHandshakeWithSni(target, 443, "microsoft.com", 2000)

		sniBlocked := false
		mitmDetected := false

		if errTlsDirect != nil {
			if errTlsSpoof == nil {
				sniBlocked = true
				sb.WriteString("  [!] STANDARD SNI HANDSHAKE BLOCKED but Spoofed SNI (microsoft.com) SUCCEEDED!\r\n")
				sb.WriteString("      The local firewall relies on SNI analysis to drop connections.\r\n")
			} else {
				sb.WriteString(fmt.Sprintf("  [-] Direct TLS failed: %v\r\n", errTlsDirect))
			}
		} else {
			sb.WriteString(fmt.Sprintf("  [+] TLS standard handshake succeeded. Negotiated: %s / %s\r\n", tlsDirect.Version, tlsDirect.CipherSuite))
			if strings.Contains(strings.ToLower(tlsDirect.CertIssuer), "fortinet") ||
				strings.Contains(strings.ToLower(tlsDirect.CertIssuer), "zscaler") ||
				strings.Contains(strings.ToLower(tlsDirect.CertIssuer), "sophos") {
				mitmDetected = true
				sb.WriteString(fmt.Sprintf("  [!] WARNING: Active SSL Decryption/MITM Interception detected! Issuer: %s\r\n", tlsDirect.CertIssuer))
			}
		}

		// 4. Evasion Strategy Grade & Recommendation
		sb.WriteString("\r\n============================================================\r\n")
		sb.WriteString("             OPTIMIZED BYPASS STRATEGY REPORT\r\n")
		sb.WriteString("============================================================\r\n")

		grade := "Grade A (Clean Pathway)"
		if dnsCensored || splitHelps || sniBlocked || mitmDetected {
			if sniBlocked || mitmDetected {
				grade = "Grade D (Strict DPI & SNI Blocking)"
			} else if splitHelps {
				grade = "Grade C (DPI Inspection Filter)"
			} else {
				grade = "Grade B (DNS-Only Hijacking)"
			}
		}

		sb.WriteString(fmt.Sprintf("Calculated Network Access Grade: %s\r\n\r\n", grade))

		if grade == "Grade D (Strict DPI & SNI Blocking)" {
			sb.WriteString("Bypass Strategy: SNI Spoofing, Domain Fronting, or Encrypted Client Hello (ECH) required.\r\n" +
				"Go/Rust standard ClientHellos will be fingerprinted. Spoof browser TLS profiles.\r\n\r\n")
		} else if grade == "Grade C (DPI Inspection Filter)" {
			sb.WriteString("Bypass Strategy: Standard TCP segment splitting or header mutation will bypass filters.\r\n" +
				"Route all HTTP/TLS traffic through a local fragmented dialer.\r\n\r\n")
		} else if grade == "Grade B (DNS-Only Hijacking)" {
			sb.WriteString("Bypass Strategy: Simply configure encrypted DNS (DoH/DoT) in your system settings.\r\n" +
				"Plain TCP/UDP pathways are unrestricted.\r\n\r\n")
		} else {
			sb.WriteString("Bypass Strategy: Direct connection path is healthy. No evasion wraps required.\r\n\r\n")
		}

		// Generate configuration snippets
		sb.WriteString("------------------------------------------------------------\r\n")
		sb.WriteString("Option A: sing-box Client Outbound JSON Configuration\r\n")
		sb.WriteString("------------------------------------------------------------\r\n")
		sb.WriteString("{\r\n" +
			"  \"type\": \"selector\",\r\n" +
			"  \"tag\": \"proxy\",\r\n" +
			"  \"outbounds\": [\r\n" +
			"    {\r\n" +
			"      \"type\": \"shadowsocks\",\r\n" +
			"      \"tag\": \"ss-out\",\r\n" +
			"      \"server\": \"127.0.0.1\",\r\n" +
			"      \"server_port\": 1080,\r\n" +
			"      \"method\": \"2022-blake3-aes-128-gcm\",\r\n" +
			"      \"password\": \"dGhpcy1pcy1hLXNlY3JldC1wYXNzd29yZA==\",\r\n" +
			"      \"tcp_fast_open\": true,\r\n" +
			"      \"multiplex\": {\r\n" +
			"        \"enabled\": true,\r\n" +
			"        \"protocol\": \"smux\"\r\n" +
			"      }\r\n" +
			"    }\r\n" +
			"  ],\r\n")

		if dnsCensored {
			sb.WriteString("  \"dns\": {\r\n" +
				"    \"servers\": [\r\n" +
				"      {\r\n" +
				"        \"tag\": \"cloudflare-doh\",\r\n" +
				"        \"address\": \"https://1.1.1.1/dns-query\",\r\n" +
				"        \"detour\": \"ss-out\"\r\n" +
				"      }\r\n" +
				"    ]\r\n" +
				"  }\r\n")
		} else {
			sb.WriteString("  \"dns\": {\r\n" +
				"    \"servers\": [\r\n" +
				"      {\r\n" +
				"        \"tag\": \"local-dns\",\r\n" +
				"        \"address\": \"local\"\r\n" +
				"      }\r\n" +
				"    ]\r\n" +
				"  }\r\n")
		}
		sb.WriteString("}\r\n\r\n")

		sb.WriteString("------------------------------------------------------------\r\n")
		sb.WriteString("Option B: Clash Meta / Mihomo Evasion Config Snippet\r\n")
		sb.WriteString("------------------------------------------------------------\r\n")
		if splitHelps {
			sb.WriteString("dns:\r\n" +
				"  enable: true\r\n" +
				"  enhanced-mode: fake-ip\r\n" +
				"  nameserver:\r\n" +
				"    - https://doh.pub/dns-query\r\n" +
				"\r\n" +
				"proxies:\r\n" +
				"  - name: \"DPI-Bypass-Split\"\r\n" +
				"    type: trojan\r\n" +
				"    server: " + target + "\r\n" +
				"    port: 443\r\n" +
				"    password: password\r\n" +
				"    udp: true\r\n" +
				"    sni: " + target + "\r\n" +
				"    client-fingerprint: chrome\r\n" +
				"    # TCP segment desynchronization parameters\r\n" +
				"    dialer-proxy: direct\r\n" +
				"    smux:\r\n" +
				"      enabled: true\r\n")
		} else {
			sb.WriteString("dns:\r\n" +
				"  enable: true\r\n" +
				"  enhanced-mode: fake-ip\r\n" +
				"  nameserver:\r\n" +
				"    - 1.1.1.1\r\n" +
				"\r\n" +
				"proxies:\r\n" +
				"  - name: \"Direct-TLS\"\r\n" +
				"    type: trojan\r\n" +
				"    server: " + target + "\r\n" +
				"    port: 443\r\n" +
				"    password: password\r\n" +
				"    sni: " + target + "\r\n")
		}
		sb.WriteString("\r\n")

		sb.WriteString("------------------------------------------------------------\r\n")
		sb.WriteString("Option C: AmneziaWG / vwarp (WireGuard UDP Padding)\r\n")
		sb.WriteString("------------------------------------------------------------\r\n")
		sb.WriteString("[Interface]\r\n" +
			"PrivateKey = [YourPrivateKey]\r\n" +
			"Address = 172.16.0.2/32\r\n" +
			"DNS = 1.1.1.1\r\n" +
			"MTU = 1280\r\n" +
			"\r\n" +
			"[Peer]\r\n" +
			"PublicKey = [ServerPublicKey]\r\n" +
			"Endpoint = 162.159.192.1:2408\r\n" +
			"AllowedIPs = 0.0.0.0/0\r\n" +
			"# Evasion Padding Parameters (vwarp Preset Moderate)\r\n" +
			"Jc = 4\r\n" +
			"Jmin = 40\r\n" +
			"Jmax = 80\r\n" +
			"H1 = 1\r\n" +
			"H2 = 2\r\n" +
			"H3 = 3\r\n" +
			"H4 = 4\r\n")

		sb.WriteString("\r\n")
		sb.WriteString("------------------------------------------------------------\r\n")
		sb.WriteString("Option D: Xray Cooperative Overlay (MITM Domain Fronting)\r\n")
		sb.WriteString("------------------------------------------------------------\r\n")
		sb.WriteString("This option uses a local self-signed Root CA (mycert.crt/mycert.key) to decrypt and repack TLS connections to target domains (e.g. Google, Meta, Fastly) using unblocked fronting Server Names (e.g. www.microsoft.com).\r\n\r\n" +
			"Xray Inbound (Mixed SOCKS5/HTTP on 10808):\r\n" +
			"{\r\n" +
			"  \"port\": 10808,\r\n" +
			"  \"protocol\": \"mixed\",\r\n" +
			"  \"sniffing\": { \"enabled\": true, \"destOverride\": [\"fakedns\", \"tls\"] }\r\n" +
			"}\r\n\r\n" +
			"Xray Decrypt Inbound (port 11888):\r\n" +
			"{\r\n" +
			"  \"port\": 11888,\r\n" +
			"  \"protocol\": \"tunnel\",\r\n" +
			"  \"settings\": { \"network\": \"tcp\", \"port\": 443, \"followRedirect\": true },\r\n" +
			"  \"streamSettings\": {\r\n" +
			"    \"security\": \"tls\",\r\n" +
			"    \"tlsSettings\": {\r\n" +
			"      \"certificates\": [ { \"usage\": \"issue\", \"certificateFile\": \"mycert.crt\", \"keyFile\": \"mycert.key\" } ]\r\n" +
			"    }\r\n" +
			"  }\r\n" +
			"}\r\n\r\n" +
			"Xray Repack Outbound (Domain Fronting):\r\n" +
			"{\r\n" +
			"  \"tag\": \"tls-repack-front\",\r\n" +
			"  \"protocol\": \"direct\",\r\n" +
			"  \"streamSettings\": {\r\n" +
			"    \"security\": \"tls\",\r\n" +
			"    \"tlsSettings\": {\r\n" +
			"      \"serverName\": \"www.microsoft.com\",\r\n" +
			"      \"fingerprint\": \"chrome\"\r\n" +
			"    }\r\n" +
			"  }\r\n" +
			"}\r\n")

		s.sync(func() {
			s.setStatus("Evasion Synthesis completed.")
			if s.wizardOutput != nil {
				s.wizardOutput.SetText(sb.String())
			}
		})
	}()
}
