//go:build windows && cgo

package cmd

import (
	"fmt"
	"strconv"
	"strings"

	. "github.com/lxn/walk/declarative"
	"github.com/maybeknott/luminet/internal/bridge"
)

func (s *nativeShell) censorshipAuditorPage() TabPage {
	return TabPage{
		Title:  "Censorship & DPI Auditor",
		Layout: VBox{Margins: Margins{Left: 14, Top: 14, Right: 14, Bottom: 14}},
		Children: []Widget{
			GroupBox{
				Title:  "Censorship Audit Parameters",
				Layout: Grid{Columns: 4, Spacing: 10},
				Children: []Widget{
					Label{Text: "Target Domain:"},
					LineEdit{AssignTo: &s.censorshipTargetEdit},

					Label{Text: "Port:"},
					LineEdit{AssignTo: &s.censorshipPortEdit},

					Label{Text: "SOCKS5 Proxy (for bypass comparison):"},
					LineEdit{AssignTo: &s.censorshipProxyEdit},

					Label{Text: "Direct Connection Status:"},
					Label{AssignTo: &s.censorshipDirectLabel, Text: "-"},

					Label{Text: "Proxy Bypass Status:"},
					Label{AssignTo: &s.censorshipProxyLabel, Text: "-"},

					Label{Text: "MITM Interception Risk:"},
					Label{AssignTo: &s.censorshipRiskLabel, Text: "-"},
				},
			},
			Composite{
				Layout: HBox{MarginsZero: true},
				Children: []Widget{
					PushButton{Text: "Run DPI & Censorship Audit", OnClicked: s.runCensorshipAudit},
					HSpacer{},
				},
			},
			GroupBox{
				Title:  "DPI Inspection & Certificate Interception Logs",
				Layout: VBox{},
				Children: []Widget{
					TextEdit{AssignTo: &s.censorshipResultEdit, ReadOnly: true, VScroll: true, MinSize: Size{Height: 320}},
				},
			},
			VSpacer{},
		},
	}
}

func (s *nativeShell) runCensorshipAudit() {
	target := "google.com"
	if s.censorshipTargetEdit != nil && s.censorshipTargetEdit.Text() != "" {
		target = strings.TrimSpace(s.censorshipTargetEdit.Text())
	}

	portVal := uint16(443)
	if s.censorshipPortEdit != nil && s.censorshipPortEdit.Text() != "" {
		pVal, err := strconv.ParseUint(strings.TrimSpace(s.censorshipPortEdit.Text()), 10, 16)
		if err == nil {
			portVal = uint16(pVal)
		}
	}

	proxyAddr := ""
	if s.censorshipProxyEdit != nil {
		proxyAddr = strings.TrimSpace(s.censorshipProxyEdit.Text())
	}

	s.setStatus("Running DPI & Censorship Audit...")
	if s.censorshipResultEdit != nil {
		s.censorshipResultEdit.SetText(fmt.Sprintf("DPI & Censorship Interception Audit for: %s:%d\r\n============================================================\r\n", target, portVal))
	}
	if s.censorshipDirectLabel != nil {
		s.censorshipDirectLabel.SetText("Testing...")
	}
	if s.censorshipProxyLabel != nil {
		s.censorshipProxyLabel.SetText("Testing...")
	}
	if s.censorshipRiskLabel != nil {
		s.censorshipRiskLabel.SetText("Analyzing...")
	}

	go func() {
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("Target Domain: %s\r\nTarget Port:   %d\r\n\r\n", target, portVal))

		// 1. Direct TCP Probe to check port reachability
		sb.WriteString("Step 1: Direct TCP Reachability Audit\r\n")
		sb.WriteString("------------------------------------------------------------\r\n")
		tcpRes, tcpErr := bridge.TcpConnect(target, portVal, 2000)
		directTCPAlive := false
		if tcpErr == nil && tcpRes.Alive {
			directTCPAlive = true
			sb.WriteString(fmt.Sprintf("  [+] Direct TCP port connection SUCCESSFUL (Latency: %.1f ms)\r\n", tcpRes.LatencyMs))
		} else {
			reason := "Timeout / Connection Refused"
			if tcpErr != nil {
				reason = tcpErr.Error()
			} else if tcpRes.Error != "" {
				reason = tcpRes.Error
			}
			sb.WriteString(fmt.Sprintf("  [-] Direct TCP port connection FAILED: %s\r\n", reason))
		}
		sb.WriteString("\r\n")

		// 2. Direct TLS Handshake and Interception Check
		sb.WriteString("Step 2: Direct TLS Handshake & Certificate Inspection\r\n")
		sb.WriteString("------------------------------------------------------------\r\n")
		var directTlsInfo *bridge.TlsInfo
		var tlsErr error
		if directTCPAlive {
			directTlsInfo, tlsErr = bridge.TlsHandshake(target, portVal, 3000)
			if tlsErr == nil && directTlsInfo != nil {
				sb.WriteString(fmt.Sprintf("  [+] TLS Handshake:       SUCCESSFUL\r\n"))
				sb.WriteString(fmt.Sprintf("  [+] TLS Version:         %s\r\n", directTlsInfo.Version))
				sb.WriteString(fmt.Sprintf("  [+] Cipher Suite:        %s\r\n", directTlsInfo.CipherSuite))
				sb.WriteString(fmt.Sprintf("  [+] Certificate Subject: %s\r\n", directTlsInfo.CertSubject))
				sb.WriteString(fmt.Sprintf("  [+] Certificate Issuer:  %s\r\n", directTlsInfo.CertIssuer))
				sb.WriteString(fmt.Sprintf("  [+] Certificate SHA-256: %s\r\n", directTlsInfo.FingerprintSha256))
			} else {
				sb.WriteString(fmt.Sprintf("  [-] TLS Handshake FAILED: %v\r\n", tlsErr))
				sb.WriteString("  [!] Possible active DPI tampering, SNI blocking, or handshake reset detected.\r\n")
			}
		} else {
			sb.WriteString("  [!] Skipped: TCP Port is unreachable.\r\n")
		}
		sb.WriteString("\r\n")

		// 3. Proxy Bypass Comparison
		sb.WriteString("Step 3: Proxy Bypass Comparison\r\n")
		sb.WriteString("------------------------------------------------------------\r\n")
		proxyBypassSuccess := false
		proxyBypassTested := false
		if proxyAddr != "" {
			proxyBypassTested = true
			pRes, pErr := bridge.Socks5Probe(proxyAddr, fmt.Sprintf("%s:%d", target, portVal), 3000)
			if pErr == nil && pRes.Alive {
				proxyBypassSuccess = true
				sb.WriteString(fmt.Sprintf("  [+] Proxy connection to %s SUCCESSFUL (Latency: %.1f ms)\r\n", proxyAddr, pRes.LatencyMs))
			} else {
				reason := "Connection failed"
				if pErr != nil {
					reason = pErr.Error()
				} else if pRes.Error != "" {
					reason = pRes.Error
				}
				sb.WriteString(fmt.Sprintf("  [-] Proxy connection to %s FAILED: %s\r\n", proxyAddr, reason))
			}
		} else {
			sb.WriteString("  [i] Skipped: No SOCKS5 Proxy configured for comparison.\r\n")
		}
		sb.WriteString("\r\n")

		// 4. Synthesis & Censorship Assessment
		sb.WriteString("Step 4: Synthesis & Censorship Assessment\r\n")
		sb.WriteString("------------------------------------------------------------\r\n")

		directStatusText := "Unreachable"
		proxyStatusText := "Not Tested"
		riskText := "Low"

		if directTCPAlive {
			if directTlsInfo != nil {
				directStatusText = "Secure/TLS Ok"
			} else {
				directStatusText = "TCP Ok / TLS Blocked"
			}
		}

		if proxyBypassTested {
			if proxyBypassSuccess {
				proxyStatusText = "Bypass Ok"
			} else {
				proxyStatusText = "Proxy Fail"
			}
		}

		censorshipSuspected := false
		mitmDetected := false

		if !directTCPAlive && proxyBypassSuccess {
			censorshipSuspected = true
			riskText = "HIGH (Blocked)"
			sb.WriteString("  [!] CENSORSHIP ALERT: Target port is completely blocked directly, but accessible via SOCKS5.\r\n")
			sb.WriteString("      Local gateway or national firewall is dropping or resetting direct connections to this destination.\r\n")
		} else if directTCPAlive && directTlsInfo == nil && proxyBypassSuccess {
			censorshipSuspected = true
			riskText = "HIGH (SNI Blocked)"
			sb.WriteString("  [!] DPI ALERT: TCP connection is open, but TLS handshake fails. SOCKS5 bypass is successful.\r\n")
			sb.WriteString("      This is a signature pattern of SNI-based DPI blocking or TCP Reset injection.\r\n")
		} else if directTlsInfo != nil {
			issuerLower := strings.ToLower(directTlsInfo.CertIssuer)

			if strings.Contains(issuerLower, "localhost") || strings.Contains(issuerLower, "self-signed") ||
				(directTlsInfo.CertIssuer != "" && directTlsInfo.CertIssuer == directTlsInfo.CertSubject) {
				mitmDetected = true
				riskText = "CRITICAL (Self-Signed MITM)"
			} else if strings.Contains(issuerLower, "untangle") || strings.Contains(issuerLower, "fortinet") ||
				strings.Contains(issuerLower, "sophos") || strings.Contains(issuerLower, "bluecoat") ||
				strings.Contains(issuerLower, "zscaler") || strings.Contains(issuerLower, "kaspersky") {
				mitmDetected = true
				riskText = "CRITICAL (Enterprise MITM Intercept)"
			}

			if mitmDetected {
				sb.WriteString("  [!] MITM SECURITY ALERT: Man-in-the-Middle SSL Interception detected!\r\n")
				sb.WriteString(fmt.Sprintf("      The returned certificate was signed by a local gateway/interception CA: '%s'\r\n", directTlsInfo.CertIssuer))
				sb.WriteString("      Your connection is being decrypted and inspected by local network administrators.\r\n")
			} else {
				sb.WriteString("  [+] Clean connection. No MITM certificate interception detected.\r\n")
			}
		} else if !directTCPAlive && !proxyBypassSuccess && proxyBypassTested {
			sb.WriteString("  [-] Offline or Remote Outage: Target is unreachable both directly and through SOCKS5 proxy.\r\n")
			sb.WriteString("      This indicates the target server is down or the SOCKS5 proxy is offline.\r\n")
		} else {
			sb.WriteString("  [+] Connection appears normal and unrestricted.\r\n")
		}

		if censorshipSuspected {
			sb.WriteString("\r\nAssessment Summary: CENSORSHIP SUSPECTED / CONFIRMED. Direct pathway routes are actively restricted.\r\n")
		} else if mitmDetected {
			sb.WriteString("\r\nAssessment Summary: CRITICAL SECURITY RISK. Your encrypted stream is being decrypted by an intermediate node.\r\n")
		} else {
			sb.WriteString("\r\nAssessment Summary: Normal. Direct connections to target domain are clear.\r\n")
		}

		s.sync(func() {
			s.setStatus("Censorship audit completed.")
			if s.censorshipDirectLabel != nil {
				s.censorshipDirectLabel.SetText(directStatusText)
			}
			if s.censorshipProxyLabel != nil {
				s.censorshipProxyLabel.SetText(proxyStatusText)
			}
			if s.censorshipRiskLabel != nil {
				s.censorshipRiskLabel.SetText(riskText)
			}
			if s.censorshipResultEdit != nil {
				s.censorshipResultEdit.AppendText(sb.String())
			}
		})
	}()
}
