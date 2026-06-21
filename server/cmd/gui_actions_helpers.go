//go:build windows && cgo

package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/lxn/walk"
)

func (s *nativeShell) openPath(path string) {
	url := s.baseURL + path
	_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	s.appendLog("Opened " + url)
}

func (s *nativeShell) applyDensity() {
	fontSize := 9
	if !s.compactMode.Checked() {
		fontSize = 10
	}
	font, err := walk.NewFont("Consolas", fontSize, 0)
	if err != nil {
		s.appendLog("Could not apply density: " + err.Error())
		return
	}
	for _, edit := range []*walk.TextEdit{s.overviewEdit, s.capabilityEdit, s.toolLedgerEdit, s.boundaryEdit, s.activityLog, s.parserOutput, s.proxyTestOutput, s.historyEdit, s.profilesEdit, s.jobInspector, s.runbookEdit, s.geoIPOutput, s.tgResultEdit} {
		if edit != nil {
			edit.SetFont(font)
		}
	}
}

// newRequest builds an authenticated request against the local API, attaching
// the session API key as the X-API-Key header so the native shell satisfies the
// always-on authentication middleware.
func (s *nativeShell) newRequest(method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, s.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	if s.apiKey != "" {
		req.Header.Set("X-API-Key", s.apiKey)
	}
	return req, nil
}

func (s *nativeShell) getJSON(path string, out interface{}) error {
	req, err := s.newRequest(http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (s *nativeShell) postJSON(path string, payload []byte, out interface{}) error {
	req, err := s.newRequest(http.MethodPost, path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (s *nativeShell) deleteJSON(path string) error {
	req, err := s.newRequest(http.MethodDelete, path, nil)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return nil
}

func (s *nativeShell) sync(fn func()) {
	if s.mw != nil && s.mw.Handle() != 0 {
		s.mw.Synchronize(fn)
	}
}

func (s *nativeShell) setStatus(text string) {
	if s.statusLine != nil {
		s.statusLine.SetText(text)
	}
}

func (s *nativeShell) invalidateCockpit() {
	if s.cockpitWidget != nil {
		s.cockpitWidget.Invalidate()
	}
}

func (s *nativeShell) appendLog(text string) {
	if s.activityLog == nil {
		return
	}
	current := s.activityLog.Text()
	stamp := time.Now().Format("15:04:05")
	s.activityLog.SetText(current + stamp + "  " + text + "\r\n")
}
