//go:build windows && cgo

package cmd

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	. "github.com/lxn/walk/declarative"
	"github.com/maybeknott/luminet/internal/bridge"
)

func (s *nativeShell) captivePortalPage() TabPage {
	return TabPage{
		Title:  "Captive Portal",
		Layout: VBox{Margins: Margins{Left: 14, Top: 14, Right: 14, Bottom: 14}},
		Children: []Widget{
			GroupBox{
				Title:  "Captive Portal Detection Config",
				Layout: Grid{Columns: 4, Spacing: 10},
				Children: []Widget{
					Label{Text: "Probe Timeout (ms):"},
					LineEdit{AssignTo: &s.captiveTimeoutEdit},

					Label{Text: "Detection Status:"},
					Label{AssignTo: &s.captiveStatusLabel, Text: "-"},

					Label{Text: "Redirect Destination:"},
					Label{AssignTo: &s.captiveRedirectLabel, Text: "-"},
				},
			},
			Composite{
				Layout: HBox{MarginsZero: true},
				Children: []Widget{
					PushButton{Text: "Run Captive Portal Audit", OnClicked: s.runCaptivePortalProbe},
					HSpacer{},
				},
			},
			GroupBox{
				Title:  "HTTP Captive Portal Diagnostics & Integrity Logs",
				Layout: VBox{},
				Children: []Widget{
					TextEdit{AssignTo: &s.captiveResultEdit, ReadOnly: true, VScroll: true, MinSize: Size{Height: 320}},
				},
			},
			VSpacer{},
		},
	}
}

func (s *nativeShell) runCaptivePortalProbe() {
	timeoutMs := uint32(3000)
	if s.captiveTimeoutEdit != nil && s.captiveTimeoutEdit.Text() != "" {
		tVal, err := strconv.ParseUint(strings.TrimSpace(s.captiveTimeoutEdit.Text()), 10, 32)
		if err == nil {
			timeoutMs = uint32(tVal)
		}
	}

	s.setStatus("Running captive portal audit...")
	if s.captiveResultEdit != nil {
		s.captiveResultEdit.SetText("HTTP Captive Portal & Network Intercept Audit\r\n============================================================\r\nProbing connectivity check endpoints...\r\n")
	}
	if s.captiveStatusLabel != nil {
		s.captiveStatusLabel.SetText("Auditing...")
	}
	if s.captiveRedirectLabel != nil {
		s.captiveRedirectLabel.SetText("-")
	}

	go func() {
		resJSON, err := bridge.CaptivePortalProbe(timeoutMs)
		s.sync(func() {
			if err != nil {
				s.setStatus("Captive portal probe failed.")
				if s.captiveStatusLabel != nil {
					s.captiveStatusLabel.SetText("Failed")
				}
				if s.captiveResultEdit != nil {
					s.captiveResultEdit.AppendText(fmt.Sprintf("\r\n[!] Error: %v\r\n", err))
				}
				return
			}

			statusText := "Open (Clear)"
			redirectURL := "-"
			var sb strings.Builder
			sb.WriteString("Probes completed.\r\n------------------------------------------------------------\r\n")

			if resJSON == `"Open"` {
				s.setStatus("Network open.")
				sb.WriteString("  [+] No captive portal detected.\r\n")
				sb.WriteString("  [+] HTTP responses returned the expected content signatures with no modification.\r\n")
				sb.WriteString("  [+] Your internet connection appears open and direct.\r\n")
			} else if resJSON == `"ModifiedContent"` {
				statusText = "Tampered Content"
				s.setStatus("Tampered HTTP Content detected!")
				sb.WriteString("  [!] WARNING: HTTP content was modified in transit!\r\n")
				sb.WriteString("      The body returned from the testing endpoints did not match the expected signatures.\r\n")
				sb.WriteString("      This indicates active content injection, ad insertion, or packet hijacking by your ISP/gateway.\r\n")
			} else if resJSON == `"Inconclusive"` {
				statusText = "Inconclusive"
				s.setStatus("Captive portal audit inconclusive.")
				sb.WriteString("  [-] Inconclusive results. Connection timed out or endpoints returned inconsistent status codes.\r\n")
				sb.WriteString("      Check your DNS configuration or physical network connection.\r\n")
			} else {
				type redirectPayload struct {
					CaptiveRedirect struct {
						URL string `json:"url"`
					} `json:"CaptiveRedirect"`
				}
				var rp redirectPayload
				if err := json.Unmarshal([]byte(resJSON), &rp); err == nil && rp.CaptiveRedirect.URL != "" {
					statusText = "Captive Portal Redirect"
					redirectURL = rp.CaptiveRedirect.URL
					s.setStatus("Captive portal detected.")
					sb.WriteString("  [!] CAPTIVE PORTAL DETECTED: You are trapped behind a gateway login page.\r\n")
					sb.WriteString(fmt.Sprintf("  [!] Redirect URL: %s\r\n", rp.CaptiveRedirect.URL))
					sb.WriteString("  [!] You must authenticate or log in through your browser to gain full internet access.\r\n")
				} else {
					statusText = "Unknown Response"
					sb.WriteString(fmt.Sprintf("  [-] Raw response: %s\r\n", resJSON))
				}
			}

			if s.captiveStatusLabel != nil {
				s.captiveStatusLabel.SetText(statusText)
			}
			if s.captiveRedirectLabel != nil {
				s.captiveRedirectLabel.SetText(redirectURL)
			}
			if s.captiveResultEdit != nil {
				s.captiveResultEdit.AppendText(sb.String())
			}
		})
	}()
}
