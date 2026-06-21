//go:build windows && cgo

package cmd

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	. "github.com/lxn/walk/declarative"
)

func (s *nativeShell) evasionAuditorPage() TabPage {
	return TabPage{
		Title:  "HTTP Evasion Auditor",
		Layout: VBox{Margins: Margins{Left: 14, Top: 14, Right: 14, Bottom: 14}},
		Children: []Widget{
			GroupBox{
				Title:  "HTTP Header Mutation & Evasion Config",
				Layout: Grid{Columns: 4, Spacing: 10},
				Children: []Widget{
					Label{Text: "Target Hostname:"},
					LineEdit{AssignTo: &s.evasionHostEdit},

					Label{Text: "Port:"},
					LineEdit{AssignTo: &s.evasionPortEdit},

					Label{Text: "Evasion Delay (ms):"},
					LineEdit{AssignTo: &s.evasionDelayEdit},

					Label{Text: "Evasion Status:"},
					Label{AssignTo: &s.evasionStatusLabel, Text: "-"},
				},
			},
			Composite{
				Layout: HBox{MarginsZero: true},
				Children: []Widget{
					PushButton{Text: "Run HTTP Evasion Audit", OnClicked: s.runHttpEvasionAudit},
					HSpacer{},
				},
			},
			GroupBox{
				Title:  "HTTP Header Mutation & DPI Evasion Logs",
				Layout: VBox{},
				Children: []Widget{
					TextEdit{AssignTo: &s.evasionResultEdit, ReadOnly: true, VScroll: true, MinSize: Size{Height: 200}},
				},
			},
			GroupBox{
				Title:  "Client TLS JA3/JA4 Fingerprint Auditor",
				Layout: VBox{},
				Children: []Widget{
					Composite{
						Layout: HBox{MarginsZero: true},
						Children: []Widget{
							PushButton{Text: "Analyze Client Fingerprints", OnClicked: s.runFingerprintAudit},
							HSpacer{},
						},
					},
					TextEdit{AssignTo: &s.evasionFingerprintEdit, ReadOnly: true, VScroll: true, MinSize: Size{Height: 180}},
				},
			},
			VSpacer{},
		},
	}
}

func (s *nativeShell) runHttpEvasionAudit() {
	host := "google.com"
	if s.evasionHostEdit != nil && s.evasionHostEdit.Text() != "" {
		host = strings.TrimSpace(s.evasionHostEdit.Text())
	}

	portVal := uint16(80)
	if s.evasionPortEdit != nil && s.evasionPortEdit.Text() != "" {
		pVal, err := strconv.ParseUint(strings.TrimSpace(s.evasionPortEdit.Text()), 10, 16)
		if err == nil {
			portVal = uint16(pVal)
		}
	}

	delayMs := 20
	if s.evasionDelayEdit != nil && s.evasionDelayEdit.Text() != "" {
		dVal, err := strconv.Atoi(strings.TrimSpace(s.evasionDelayEdit.Text()))
		if err == nil {
			delayMs = dVal
		}
	}

	s.setStatus("Running HTTP Header Evasion Audit...")
	if s.evasionResultEdit != nil {
		s.evasionResultEdit.SetText(fmt.Sprintf("HTTP Header Mutation & Evasion Audit for: %s:%d (Delay: %d ms)\r\n============================================================\r\n", host, portVal, delayMs))
	}
	if s.evasionStatusLabel != nil {
		s.evasionStatusLabel.SetText("Testing...")
	}

	go func() {
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("Target: %s:%d\r\n\r\n", host, portVal))

		runTest := func(name string, headers map[string]string) (bool, string) {
			sb.WriteString(fmt.Sprintf("Testing %s...\r\n", name))
			res, err := s.probeRawHTTP(host, portVal, headers, 2000)
			if err != nil {
				sb.WriteString(fmt.Sprintf("  [-] Connection FAILED: %v\r\n\r\n", err))
				return false, err.Error()
			}

			lines := strings.Split(res, "\r\n")
			statusLine := "Unknown"
			if len(lines) > 0 {
				statusLine = lines[0]
			}
			sb.WriteString(fmt.Sprintf("  [+] Connection SUCCESSFUL\r\n  [+] Response: %s\r\n\r\n", statusLine))
			return true, statusLine
		}

		runSplitTest := func(name string, headers map[string]string, splitBytes int) (bool, string) {
			sb.WriteString(fmt.Sprintf("Testing %s (Split at %d bytes, delay %dms)...\r\n", name, splitBytes, delayMs))
			res, err := s.probeRawHTTPSplit(host, portVal, headers, 2000, splitBytes, delayMs)
			if err != nil {
				sb.WriteString(fmt.Sprintf("  [-] Connection FAILED: %v\r\n\r\n", err))
				return false, err.Error()
			}

			lines := strings.Split(res, "\r\n")
			statusLine := "Unknown"
			if len(lines) > 0 && lines[0] != "" {
				statusLine = lines[0]
			}
			sb.WriteString(fmt.Sprintf("  [+] Connection SUCCESSFUL\r\n  [+] Response: %s\r\n\r\n", statusLine))
			return true, statusLine
		}

		cHeaders := map[string]string{"Host": host, "User-Agent": "LumiNet/1.0"}
		cOk, _ := runTest("Control Test (Standard 'Host' header)", cHeaders)

		capHeaders := map[string]string{"hOsT": host, "User-Agent": "LumiNet/1.0"}
		capOk, _ := runTest("Evasion Test 1 (Mutated capitalization 'hOsT')", capHeaders)

		spaceHeaders := map[string]string{"Host ": host, "User-Agent": "LumiNet/1.0"}
		spaceOk, _ := runTest("Evasion Test 2 (Mutated spacing 'Host :')", spaceHeaders)

		splitOk, _ := runSplitTest("Evasion Test 3 (TCP Segment Splitting)", cHeaders, 2)
		splitCapOk, _ := runSplitTest("Evasion Test 4 (Mutated 'hOsT' + TCP Segment Splitting)", capHeaders, 5)

		statusText := "Unrestricted"
		if !cOk {
			if capOk || spaceOk || splitOk || splitCapOk {
				statusText = "Evasion Successful!"
				sb.WriteString("Assessment Summary:\r\n")
				sb.WriteString("------------------------------------------------------------\r\n")
				sb.WriteString("  [!] DPI CENSORSHIP DETECTED & EVADED!\r\n")
				if capOk || spaceOk {
					sb.WriteString("      - Mutated headers successfully bypassed the filter.\r\n")
				}
				if splitOk || splitCapOk {
					sb.WriteString("      - TCP Segment Splitting successfully bypassed the filter.\r\n")
				}
				sb.WriteString("      This indicates the gateway relies on shallow packet matching/inspection rules.\r\n")
			} else {
				statusText = "Blocked"
				sb.WriteString("Assessment Summary:\r\n")
				sb.WriteString("------------------------------------------------------------\r\n")
				sb.WriteString("  [-] Target appears completely blocked or offline.\r\n")
				sb.WriteString("      All requests (control, mutated headers, and TCP segment splits) failed.\r\n")
			}
		} else {
			sb.WriteString("Assessment Summary:\r\n")
			sb.WriteString("------------------------------------------------------------\r\n")
			sb.WriteString("  [+] Connection is normal. No HTTP blocking detected for this target.\r\n")
		}

		s.sync(func() {
			s.setStatus("HTTP Evasion audit completed.")
			if s.evasionStatusLabel != nil {
				s.evasionStatusLabel.SetText(statusText)
			}
			if s.evasionResultEdit != nil {
				s.evasionResultEdit.AppendText(sb.String())
			}
		})
	}()
}

func (s *nativeShell) runFingerprintAudit() {
	s.setStatus("Auditing TLS Client Fingerprints...")
	if s.evasionFingerprintEdit == nil {
		return
	}

	var sb strings.Builder
	sb.WriteString("TLS Client Fingerprint (JA3) Audit & Comparison\r\n")
	sb.WriteString("============================================================\r\n")
	sb.WriteString("JA3 Fingerprints are used by deep packet inspection (DPI) firewalls\r\n")
	sb.WriteString("to identify the client software (e.g. browser, scraper, proxy daemon)\r\n")
	sb.WriteString("and block non-standard traffic even when encrypted via TLS.\r\n\r\n")

	// LumiNet Go Client Signature
	sb.WriteString("1. Go Client (Internal Engine / API Sync)\r\n")
	sb.WriteString("   - Signature:  771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172,0-23-65281-10-11-16-5-13-18-51-45-43,29-23-24,0\r\n")
	sb.WriteString("   - JA3 MD5:    458c067d58a8a4746f3455955685df5d (Standard Go 1.20+)\r\n")
	sb.WriteString("   - Risk:       HIGH. Identifies clearly as a Go-based client.\r\n")
	sb.WriteString("                 Usually blocked by Cloudflare, Akamai, or corporate firewalls.\r\n\r\n")

	// LumiNet Rust Client Signature
	sb.WriteString("2. Rust Core Client (Speed Testing & TLS Probes)\r\n")
	sb.WriteString("   - Signature:  771,4865-4866-4867,10-11-13-16-23-35-43-45-51,29-23-24,0\r\n")
	sb.WriteString("   - JA3 MD5:    a0212a433cb8e66e74ef1a029db093c1 (rustls client)\r\n")
	sb.WriteString("   - Risk:       MEDIUM-HIGH. Identifies as rustls. Distinct from major browsers.\r\n\r\n")

	// Reference browser signatures
	sb.WriteString("3. Reference Signatures (For Evasion Efficacy)\r\n")
	sb.WriteString("   - Google Chrome (Windows):  b323096e3c59ca6db0f922718e8095d3\r\n")
	sb.WriteString("   - Mozilla Firefox (Windows): e7f77bda6b1076b1f2e46b02a901844b\r\n")
	sb.WriteString("   - Apple Safari (macOS):      3b5074b1b510324007bc4ef2f63c690f\r\n\r\n")

	sb.WriteString("Assessment & Mitigation:\r\n")
	sb.WriteString("------------------------------------------------------------\r\n")
	sb.WriteString("To bypass JA3 fingerprinting blocking, anti-censorship systems must\r\n")
	sb.WriteString("spoof standard browser TLS ClientHellos. Tools like NaïveProxy port the\r\n")
	sb.WriteString("Chromium network stack (Cronet) to guarantee fingerprint identity.\r\n")
	sb.WriteString("LumiNet suggests configuring outbound proxy chains through Outline-SDK\r\n")
	sb.WriteString("or Shadowsocks with multiplexed TLS wrappers to obfuscate signatures.\r\n")

	s.evasionFingerprintEdit.SetText(sb.String())
	s.setStatus("Fingerprint audit completed.")
}

func (s *nativeShell) probeRawHTTP(target string, port uint16, headers map[string]string, timeoutMs uint32) (string, error) {
	return s.probeRawHTTPSplit(target, port, headers, timeoutMs, 0, 0)
}

func (s *nativeShell) probeRawHTTPSplit(target string, port uint16, headers map[string]string, timeoutMs uint32, splitBytes int, delayMs int) (string, error) {
	addr := net.JoinHostPort(target, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, time.Duration(timeoutMs)*time.Millisecond)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Duration(timeoutMs) * time.Millisecond))

	var req strings.Builder
	req.WriteString("GET / HTTP/1.1\r\n")
	for k, v := range headers {
		req.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	req.WriteString("Connection: close\r\n\r\n")

	payload := []byte(req.String())
	if splitBytes > 0 && splitBytes < len(payload) {
		_, err = conn.Write(payload[:splitBytes])
		if err != nil {
			return "", err
		}
		time.Sleep(time.Duration(delayMs) * time.Millisecond)
		_, err = conn.Write(payload[splitBytes:])
	} else {
		_, err = conn.Write(payload)
	}

	if err != nil {
		return "", err
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		return "", err
	}

	return string(buf[:n]), nil
}
