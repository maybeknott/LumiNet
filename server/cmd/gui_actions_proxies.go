//go:build windows && cgo

package cmd

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/maybeknott/luminet/internal/proxy"
)

func (s *nativeShell) parseProxyInput() {
	input := strings.TrimSpace(s.parserInput.Text())
	if input == "" {
		s.parserOutput.SetText("Paste proxy content first.")
		return
	}

	configs, err := parseProxyText(input)
	if err != nil {
		s.parserOutput.SetText("Parse failed: " + err.Error())
		s.setStatus("Proxy parse failed.")
		return
	}

	configs = proxy.SanitizeAndDedupe(configs)
	var b strings.Builder
	fmt.Fprintf(&b, "Parsed %d unique proxy node(s).\r\n\r\n", len(configs))
	for i, cfg := range configs {
		fmt.Fprintf(&b, "%03d  %s  %s:%d", i+1, cfg.Protocol, cfg.Address, cfg.Port)
		if cfg.Name != "" {
			fmt.Fprintf(&b, "  #%s", cfg.Name)
		}
		if cfg.TLS {
			b.WriteString("  tls")
		}
		if cfg.SNI != "" {
			fmt.Fprintf(&b, "  sni=%s", cfg.SNI)
		}
		if cfg.Transport != "" {
			fmt.Fprintf(&b, "  transport=%s", cfg.Transport)
		}
		if cfg.RawURI != "" {
			fmt.Fprintf(&b, "\r\n     %s", proxy.URITransportPreview(cfg.RawURI, 110))
		}
		b.WriteString("\r\n")
	}
	s.parserOutput.SetText(b.String())
	s.appendLog(fmt.Sprintf("Parsed %d proxy node(s) natively.", len(configs)))
	s.setStatus("Proxy content parsed.")
}

func (s *nativeShell) parseProxyTesterInput() {
	input := strings.TrimSpace(s.proxyTestInput.Text())
	if input == "" {
		s.proxyTestOutput.SetText("Paste proxy content first.")
		return
	}
	configs, err := parseProxyText(input)
	if err != nil {
		s.proxyTestOutput.SetText("Parse failed: " + err.Error())
		s.setStatus("Proxy parse failed.")
		return
	}
	configs = proxy.SanitizeAndDedupe(configs)
	var rawURIs []string
	var b strings.Builder
	fmt.Fprintf(&b, "Ready to test %d unique proxy node(s).\r\n\r\n", len(configs))
	for i, cfg := range configs {
		raw := strings.TrimSpace(cfg.RawURI)
		if raw == "" {
			continue
		}
		rawURIs = append(rawURIs, raw)
		fmt.Fprintf(&b, "%03d  %s\r\n", i+1, proxy.URITransportPreview(raw, 120))
	}
	s.proxyTestInput.SetText(strings.Join(rawURIs, "\r\n"))
	s.proxyTestOutput.SetText(b.String())
	s.setStatus("Proxy tester queue prepared.")
}

func (s *nativeShell) startProxyTests() {
	proxies := splitProxyLines(s.proxyTestInput.Text())
	if len(proxies) == 0 {
		s.setStatus("Paste at least one proxy URI.")
		return
	}
	testURL := strings.TrimSpace(s.proxyTestURL.Text())
	if testURL == "" {
		testURL = "http://cp.cloudflare.com/"
	}
	timeout := parsePositiveInt(s.proxyTimeout.Text(), 10)
	speedTest := s.proxySpeedTest.Checked()

	go func() {
		var b strings.Builder
		fmt.Fprintf(&b, "Queueing %d proxy test job(s).\r\n\r\n", len(proxies))
		created := 0
		for i, raw := range proxies {
			payload := map[string]interface{}{
				"proxy_uri":  raw,
				"urls":       []string{testURL},
				"timeout":    timeout,
				"speed_test": speedTest,
			}
			body, _ := json.Marshal(payload)
			var result map[string]interface{}
			err := s.postJSON("/api/proxy-tests", body, &result)
			if err != nil {
				fmt.Fprintf(&b, "%03d  failed  %s  %s\r\n", i+1, proxy.URITransportPreview(raw, 96), err)
				continue
			}
			created++
			fmt.Fprintf(&b, "%03d  job=%v  %s\r\n", i+1, result["id"], proxy.URITransportPreview(raw, 96))
		}
		s.sync(func() {
			s.proxyTestOutput.SetText(b.String())
			s.appendLog(fmt.Sprintf("Queued %d/%d proxy test job(s).", created, len(proxies)))
			s.setStatus("Proxy test jobs queued.")
			s.refreshStatus()
			s.refreshHistory()
		})
	}()
}

func (s *nativeShell) rewriteProxySubscription() {
	input := strings.TrimSpace(s.rewriteInput.Text())
	if input == "" {
		s.rewriteOutput.SetText("Paste proxy content / subscription first.")
		return
	}

	cleanIPsText := strings.TrimSpace(s.rewriteCleanIPs.Text())
	if cleanIPsText == "" {
		s.rewriteOutput.SetText("Enter clean IP addresses first.")
		return
	}

	// Split by newline or comma
	var cleanIPs []string
	for _, rawIP := range strings.FieldsFunc(cleanIPsText, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ','
	}) {
		ip := strings.TrimSpace(rawIP)
		if ip != "" {
			cleanIPs = append(cleanIPs, ip)
		}
	}

	if len(cleanIPs) == 0 {
		s.rewriteOutput.SetText("Please enter at least one valid clean IP address.")
		return
	}

	portVal := parsePositiveInt(s.rewritePortOverride.Text(), 0)
	nameTpl := strings.TrimSpace(s.rewriteNameTemplate.Text())

	rewritten, err := proxy.RewriteSubscriptionContent(input, cleanIPs, portVal, nameTpl)
	if err != nil {
		s.rewriteOutput.SetText("Rewrite failed: " + err.Error())
		s.setStatus("Proxy rewrite failed.")
		return
	}

	rawOutput := strings.Join(rewritten, "\r\n")
	s.rewriteOutput.SetText(rawOutput)

	// Now generate a preview of the rewritten nodes (first 100)
	previewLimit := 100
	if len(rewritten) < previewLimit {
		previewLimit = len(rewritten)
	}
	previewText := strings.Join(rewritten[:previewLimit], "\n")
	configs, err := parseProxyText(previewText)
	if err != nil {
		s.rewritePreviewOutput.SetText("Preview generation failed: " + err.Error())
		s.setStatus("Proxy rewrite completed with preview error.")
		return
	}

	configs = proxy.SanitizeAndDedupe(configs)
	var b strings.Builder
	fmt.Fprintf(&b, "Rewrote subscription into %d node(s) (previewing first %d unique nodes):\r\n\r\n", len(rewritten), len(configs))
	for i, cfg := range configs {
		fmt.Fprintf(&b, "%03d  %s  %s:%d", i+1, cfg.Protocol, cfg.Address, cfg.Port)
		if cfg.Name != "" {
			fmt.Fprintf(&b, "  #%s", cfg.Name)
		}
		if cfg.TLS {
			b.WriteString("  tls")
		}
		if cfg.SNI != "" {
			fmt.Fprintf(&b, "  sni=%s", cfg.SNI)
		}
		if cfg.Transport != "" {
			fmt.Fprintf(&b, "  transport=%s", cfg.Transport)
		}
		if cfg.RawURI != "" {
			fmt.Fprintf(&b, "\r\n     %s", proxy.URITransportPreview(cfg.RawURI, 110))
		}
		b.WriteString("\r\n")
	}
	s.rewritePreviewOutput.SetText(b.String())

	s.appendLog(fmt.Sprintf("Mapped/Rewrote proxy subscription: %d clean IPs -> %d nodes.", len(cleanIPs), len(rewritten)))
	s.setStatus("Proxy subscription rewritten successfully.")
}

func (s *nativeShell) onProxyRegAuthChanged() {
	if s.proxyRegAuth == nil || s.proxyRegUser == nil || s.proxyRegPass == nil {
		return
	}
	enabled := s.proxyRegAuth.Checked()
	s.proxyRegUser.SetEnabled(enabled)
	s.proxyRegPass.SetEnabled(enabled)
}

func (s *nativeShell) clearProxyForm() {
	if s.proxyRegHost != nil {
		s.proxyRegHost.SetText("")
	}
	if s.proxyRegPort != nil {
		s.proxyRegPort.SetText("")
	}
	if s.proxyRegType != nil {
		_ = s.proxyRegType.SetCurrentIndex(0)
	}
	if s.proxyRegNotes != nil {
		s.proxyRegNotes.SetText("")
	}
	if s.proxyRegAuth != nil {
		s.proxyRegAuth.SetChecked(false)
	}
	if s.proxyRegUser != nil {
		s.proxyRegUser.SetText("")
		s.proxyRegUser.SetEnabled(false)
	}
	if s.proxyRegPass != nil {
		s.proxyRegPass.SetText("")
		s.proxyRegPass.SetEnabled(false)
	}
}

func (s *nativeShell) saveProxyNode() {
	if s.proxyRegHost == nil || s.proxyRegPort == nil {
		return
	}
	host := strings.TrimSpace(s.proxyRegHost.Text())
	if host == "" {
		s.setStatus("Egress host/IP is required.")
		return
	}
	portVal := parsePositiveInt(s.proxyRegPort.Text(), 0)
	if portVal <= 0 {
		s.setStatus("Valid port is required.")
		return
	}

	proto := "HTTP"
	if s.proxyRegType != nil {
		if idx := s.proxyRegType.CurrentIndex(); idx >= 0 {
			proto = s.proxyRegType.Model().([]string)[idx]
		}
	}

	notes := ""
	if s.proxyRegNotes != nil {
		notes = strings.TrimSpace(s.proxyRegNotes.Text())
	}

	auth := false
	username := ""
	password := ""
	if s.proxyRegAuth != nil {
		auth = s.proxyRegAuth.Checked()
		if auth {
			if s.proxyRegUser != nil {
				username = s.proxyRegUser.Text()
			}
			if s.proxyRegPass != nil {
				password = s.proxyRegPass.Text()
			}
		}
	}

	payload := map[string]interface{}{
		"host":     host,
		"port":     portVal,
		"type":     proto,
		"auth":     auth,
		"username": username,
		"password": password,
		"notes":    notes,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		s.setStatus("Failed to marshal request.")
		return
	}

	go func() {
		var result map[string]interface{}
		err := s.postJSON("/api/proxies", body, &result)
		s.sync(func() {
			if err != nil {
				s.setStatus("Failed to save proxy: " + err.Error())
				return
			}
			s.setStatus("Proxy node saved successfully.")
			s.clearProxyForm()
			s.refreshProxyDirectory()
		})
	}()
}

type proxyNodeConfig struct {
	ID       string `json:"id"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Type     string `json:"type"`
	Auth     bool   `json:"auth"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Notes    string `json:"notes"`
}

func (s *nativeShell) refreshProxyDirectory() {
	if s.proxyDirOutput == nil {
		return
	}

	go func() {
		var list []proxyNodeConfig
		err := s.getJSON("/api/proxies", &list)
		s.sync(func() {
			if err != nil {
				s.proxyDirOutput.SetText("Failed to retrieve directory: " + err.Error())
				return
			}

			if len(list) == 0 {
				s.proxyDirOutput.SetText("No proxy nodes registered in directory.")
				return
			}

			var sb strings.Builder
			sb.WriteString("Egress Servers Matrix:\r\n")
			sb.WriteString("============================================================\r\n\r\n")
			for _, n := range list {
				sb.WriteString(fmt.Sprintf("ID:       %s\r\n", n.ID))
				sb.WriteString(fmt.Sprintf("Type:     %s\r\n", n.Type))
				sb.WriteString(fmt.Sprintf("Endpoint: %s:%d\r\n", n.Host, n.Port))
				if n.Notes != "" {
					sb.WriteString(fmt.Sprintf("Notes:    %s\r\n", n.Notes))
				}
				if n.Auth {
					sb.WriteString(fmt.Sprintf("Auth:     Enabled (User: %s)\r\n", n.Username))
				}
				sb.WriteString("\r\n")
			}
			s.proxyDirOutput.SetText(sb.String())
		})
	}()
}

func (s *nativeShell) deleteSelectedProxyNode() {
	if s.proxySelectedId == nil {
		return
	}
	id := strings.TrimSpace(s.proxySelectedId.Text())
	if id == "" {
		s.setStatus("Enter ID or Host to remove.")
		return
	}

	go func() {
		err := s.deleteJSON("/api/proxies/" + id)
		
		if err != nil {
			var list []proxyNodeConfig
			_ = s.getJSON("/api/proxies", &list)
			for _, n := range list {
				if n.Host == id || fmt.Sprintf("%s:%d", n.Host, n.Port) == id {
					err = s.deleteJSON("/api/proxies/" + n.ID)
					break
				}
			}
		}

		s.sync(func() {
			if err != nil {
				s.setStatus("Remove failed: " + err.Error())
				return
			}
			s.setStatus("Proxy node removed.")
			s.proxySelectedId.SetText("")
			s.refreshProxyDirectory()
		})
	}()
}

func (s *nativeShell) testSelectedProxyNode() {
	if s.proxySelectedId == nil {
		return
	}
	id := strings.TrimSpace(s.proxySelectedId.Text())
	if id == "" {
		s.setStatus("Enter ID or Host to test.")
		return
	}

	s.setStatus("Testing egress node latency...")
	go func() {
		var list []proxyNodeConfig
		_ = s.getJSON("/api/proxies", &list)
		var targetNode *proxyNodeConfig
		for _, n := range list {
			if n.ID == id || n.Host == id || fmt.Sprintf("%s:%d", n.Host, n.Port) == id {
				targetNode = &n
				break
			}
		}

		if targetNode == nil {
			s.sync(func() {
				s.setStatus("Proxy node not found in directory.")
			})
			return
		}

		uri := fmt.Sprintf("%s://%s:%d", strings.ToLower(targetNode.Type), targetNode.Host, targetNode.Port)
		payload := map[string]interface{}{
			"proxies":    []string{uri},
			"test_url":   "http://cp.cloudflare.com/",
			"timeout_ms": 5000,
			"concurrency": 1,
			"speed_test": false,
		}

		body, _ := json.Marshal(payload)
		var testResp struct {
			Success bool   `json:"success"`
			ID      string `json:"id"`
			Data    struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		err := s.postJSON("/api/proxy-tests", body, &testResp)
		if err != nil {
			s.sync(func() {
				s.setStatus("Failed to trigger test: " + err.Error())
			})
			return
		}

		jobId := testResp.ID
		if jobId == "" && testResp.Data.ID != "" {
			jobId = testResp.Data.ID
		}

		if jobId == "" {
			s.sync(func() {
				s.setStatus("Invalid test job returned.")
			})
			return
		}

		var jobResult struct {
			Status  string `json:"status"`
			Results []struct {
				Alive     bool    `json:"alive"`
				LatencyMs float64 `json:"latency_ms"`
				Error     string  `json:"error"`
			} `json:"results"`
		}

		attempts := 0
		for attempts < 15 {
			time.Sleep(1 * time.Second)
			attempts++
			err = s.getJSON("/api/jobs/"+jobId, &jobResult)
			if err == nil && (jobResult.Status == "completed" || jobResult.Status == "failed") {
				break
			}
		}

		s.sync(func() {
			if err != nil || (jobResult.Status != "completed" && jobResult.Status != "failed") {
				s.setStatus("Test job timed out or failed.")
				return
			}

			if len(jobResult.Results) > 0 && jobResult.Results[0].Alive {
				s.setStatus(fmt.Sprintf("Proxy %s is ALIVE. Latency: %.1f ms", targetNode.Host, jobResult.Results[0].LatencyMs))
			} else if len(jobResult.Results) > 0 && jobResult.Results[0].Error != "" {
				s.setStatus(fmt.Sprintf("Proxy %s is DEAD: %s", targetNode.Host, jobResult.Results[0].Error))
			} else {
				s.setStatus(fmt.Sprintf("Proxy %s is DEAD (Connection failure)", targetNode.Host))
			}
		})
	}()
}

