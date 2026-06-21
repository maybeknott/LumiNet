//go:build windows && cgo

package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lxn/walk"
)

func (s *nativeShell) runCockpitWorkflow() {
	target := "cloudflare.com"
	if s.cockpitTarget != nil && strings.TrimSpace(s.cockpitTarget.Text()) != "" {
		target = strings.TrimSpace(s.cockpitTarget.Text())
	}
	ports := "80,443,8443"
	if s.cockpitPorts != nil && strings.TrimSpace(s.cockpitPorts.Text()) != "" {
		ports = strings.TrimSpace(s.cockpitPorts.Text())
	}
	if s.targetEdit != nil {
		s.targetEdit.SetText(target)
	}
	if s.scanTarget != nil {
		s.scanTarget.SetText(target)
	}
	if s.scanPorts != nil {
		s.scanPorts.SetText(ports)
	}

	scenario := 0
	if s.cockpitScenario != nil && s.cockpitScenario.CurrentIndex() >= 0 {
		scenario = s.cockpitScenario.CurrentIndex()
	}
	switch scenario {
	case 0:
		if s.diagnosticsMode != nil {
			s.diagnosticsMode.SetCurrentIndex(3)
		}
		s.appendLog("Cockpit workflow: HTTP/TLS diagnostic for " + target)
		s.runDiagnosticFor(target, "http")
	case 1:
		if s.scanMode != nil {
			s.scanMode.SetCurrentIndex(0)
		}
		s.appendLog("Cockpit workflow: ICMP sweep for " + target)
		s.launchNativeScan(0, target, ports, "1.1.1.1", "A", 3000, 100, false)
	case 2:
		if s.scanMode != nil {
			s.scanMode.SetCurrentIndex(1)
		}
		s.appendLog("Cockpit workflow: TCP port scan for " + target)
		s.launchNativeScan(1, target, ports, "1.1.1.1", "A", 3000, 100, false)
	case 3:
		if s.scanMode != nil {
			s.scanMode.SetCurrentIndex(2)
		}
		s.appendLog("Cockpit workflow: DNS record scan for " + target)
		s.launchNativeScan(2, target, ports, "1.1.1.1", "A", 3000, 100, false)
	case 4:
		if s.scanMode != nil {
			s.scanMode.SetCurrentIndex(4)
		}
		s.appendLog("Cockpit workflow: SNI reachability check for " + target)
		s.launchNativeScan(4, target, ports, "1.1.1.1", "A", 3000, 100, false)
	default:
		s.setStatus("Unknown cockpit workflow.")
	}
}

func (s *nativeShell) runDiagnostic() {
	target := ""
	if s.targetEdit != nil {
		target = strings.TrimSpace(s.targetEdit.Text())
	}
	if target == "" && s.cockpitTarget != nil {
		target = strings.TrimSpace(s.cockpitTarget.Text())
	}
	if target == "" {
		target = "cloudflare.com"
	}
	mode := "ping"
	if idx := s.diagnosticsMode.CurrentIndex(); idx >= 0 {
		mode = []string{"ping", "dns", "tls", "http"}[idx]
	}
	s.runDiagnosticFor(target, mode)
}

func (s *nativeShell) runDiagnosticFor(target, mode string) {
	go func() {
		payload, _ := json.Marshal(map[string]string{"target": target, "type": mode})
		var result map[string]interface{}
		err := s.postJSON("/api/diagnostics", payload, &result)
		s.sync(func() {
			if err != nil {
				s.appendLog("Diagnostic failed: " + err.Error())
				s.setStatus("Diagnostic failed.")
				return
			}
			s.appendLog(fmt.Sprintf("Started %s diagnostic for %s. Job: %v", mode, target, result["id"]))
			s.setStatus("Diagnostic job started.")
		})
	}()
}

func (s *nativeShell) healthCheck() {
	go func() {
		var result map[string]interface{}
		err := s.getJSON("/health", &result)
		s.sync(func() {
			if err != nil {
				s.appendLog("Health check failed: " + err.Error())
				return
			}
			s.appendLog(fmt.Sprintf("Health: %v", result))
		})
	}()
}

func (s *nativeShell) loadLatestJob() {
	go func() {
		var history nativeHistoryResponse
		err := s.getJSON("/api/history", &history)
		s.sync(func() {
			if err != nil {
				s.setStatus("Load latest job failed: " + err.Error())
				return
			}
			if len(history.Jobs) == 0 {
				s.jobInspector.SetText("No jobs recorded yet.")
				return
			}
			s.jobIDEdit.SetText(history.Jobs[0].ID)
			s.jobInspector.SetText(formatJobDetail(history.Jobs[0]))
			s.setStatus("Latest job loaded.")
		})
	}()
}

func (s *nativeShell) loadJob() {
	id := strings.TrimSpace(s.jobIDEdit.Text())
	if id == "" {
		s.setStatus("Enter a job ID.")
		return
	}
	go func() {
		var job nativeHistoryJob
		err := s.getJSON("/api/jobs/"+id, &job)
		s.sync(func() {
			if err != nil {
				s.setStatus("Load job failed: " + err.Error())
				return
			}
			s.jobInspector.SetText(formatJobDetail(job))
			s.setStatus("Job loaded.")
		})
	}()
}

func (s *nativeShell) cancelJob() {
	id := strings.TrimSpace(s.jobIDEdit.Text())
	if id == "" {
		s.setStatus("Enter a job ID.")
		return
	}
	go func() {
		var result map[string]interface{}
		err := s.postJSON("/api/jobs/"+id+"/cancel", []byte("{}"), &result)
		s.sync(func() {
			if err != nil {
				s.setStatus("Cancel job failed: " + err.Error())
				return
			}
			s.appendLog("Cancelled job " + id)
			s.loadJob()
			s.refreshStatus()
			s.refreshHistory()
		})
	}()
}

func (s *nativeShell) clearHistory() {
	if s.mw != nil {
		answer := walk.MsgBox(
			s.mw,
			"Clear terminal jobs",
			"Clear completed, failed, and cancelled jobs from the local history store?",
			walk.MsgBoxYesNo|walk.MsgBoxIconQuestion,
		)
		if answer != walk.DlgCmdYes {
			return
		}
	}

	go func() {
		err := s.deleteJSON("/api/history")
		s.sync(func() {
			if err != nil {
				s.setStatus("Clear history failed: " + err.Error())
				return
			}
			s.appendLog("Cleared terminal job history.")
			s.refreshHistory()
		})
	}()
}

func (s *nativeShell) generateRunbook() {
	go func() {
		var health map[string]interface{}
		var status nativeSystemStatus
		var caps nativeCapabilityResponse
		var dns nativeDNSStatus
		var systemProxy nativeProxyStatus
		var startup nativeStartupStatus
		var ddns nativeDDNSStatus
		var profiles nativeProfilesStatus
		var history nativeHistoryResponse

		errs := make([]string, 0)
		if err := s.getJSON("/health", &health); err != nil {
			errs = append(errs, "health: "+err.Error())
		}
		if err := s.getJSON("/api/system/status", &status); err != nil {
			errs = append(errs, "status: "+err.Error())
		}
		if err := s.getJSON("/api/capabilities", &caps); err != nil {
			errs = append(errs, "capabilities: "+err.Error())
		}
		if err := s.getJSON("/api/system/dns", &dns); err != nil {
			errs = append(errs, "dns: "+err.Error())
		}
		if err := s.getJSON("/api/system/proxy", &systemProxy); err != nil {
			errs = append(errs, "proxy: "+err.Error())
		}
		if err := s.getJSON("/api/system/startup", &startup); err != nil {
			errs = append(errs, "startup: "+err.Error())
		}
		if err := s.getJSON("/api/system/ddns", &ddns); err != nil {
			errs = append(errs, "ddns: "+err.Error())
		}
		if err := s.getJSON("/api/system/profiles", &profiles); err != nil {
			errs = append(errs, "profiles: "+err.Error())
		}
		if err := s.getJSON("/api/history", &history); err != nil {
			errs = append(errs, "history: "+err.Error())
		}

		report := formatRunbookSnapshot(health, status, caps, dns, systemProxy, startup, ddns, profiles, history, errs)
		s.sync(func() {
			if s.runbookEdit != nil {
				s.runbookEdit.SetText(report)
			}
			if len(errs) > 0 {
				s.setStatus("Runbook snapshot generated with warnings.")
				return
			}
			s.setStatus("Runbook snapshot generated.")
		})
	}()
}
