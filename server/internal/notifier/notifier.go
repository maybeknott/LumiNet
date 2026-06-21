// Package notifier manages routing and delivering desktop alerts, webhook payloads, and push messages.
package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/maybeknott/luminet/internal/utils"
)

// Severity represents how critical an alert notification is.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// Alert outlines a generic payload dispatched to notifications.
type Alert struct {
	Title    string   `json:"title"`
	Message  string   `json:"message"`
	Severity Severity `json:"severity"`
}

// Notifier dispatches alerts to desktop channels and external systems.
type Notifier struct {
	webhookURL string
	httpClient *http.Client
}

// NewNotifier creates an instance of a configured Alert dispatcher.
func NewNotifier(webhookURL string) *Notifier {
	return &Notifier{
		webhookURL: webhookURL,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// SendWebhook broadcasts an alert payload to a configured webhook endpoint.
func (n *Notifier) SendWebhook(ctx context.Context, alert *Alert) error {
	if n.webhookURL == "" {
		return fmt.Errorf("webhook URL not configured")
	}

	payload, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("failed to marshal alert: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", n.webhookURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "LumiNet/1.0")

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("webhook request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned non-2xx status: %d", resp.StatusCode)
	}

	return nil
}

// SendDesktop displays a platform-native desktop notification overlay to the active session.
func (n *Notifier) SendDesktop(ctx context.Context, alert *Alert) error {
	switch runtime.GOOS {
	case "windows":
		return sendDesktopWindows(ctx, alert)
	case "darwin":
		return sendDesktopMacOS(ctx, alert)
	case "linux":
		return sendDesktopLinux(ctx, alert)
	default:
		return fmt.Errorf("desktop notifications not supported on %s", runtime.GOOS)
	}
}

func psEscapeDoubleQuoted(s string) string {
	s = strings.ReplaceAll(s, "`", "``")
	s = strings.ReplaceAll(s, "\"", "`\"")
	return s
}

func asEscapeDoubleQuoted(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return s
}

func sendDesktopWindows(ctx context.Context, alert *Alert) error {
	// Use PowerShell to show a toast notification
	script := fmt.Sprintf(`
		[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
		$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
		$textNodes = $template.GetElementsByTagName("text")
		$textNodes.Item(0).AppendChild($template.CreateTextNode("%s")) | Out-Null
		$textNodes.Item(1).AppendChild($template.CreateTextNode("%s")) | Out-Null
		$toast = [Windows.UI.Notifications.ToastNotification]::new($template)
		[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("LumiNet").Show($toast)
	`, psEscapeDoubleQuoted(alert.Title), psEscapeDoubleQuoted(alert.Message))

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.SysProcAttr = utils.GetHideWindowSysProcAttr()
	return cmd.Run()
}

func sendDesktopMacOS(ctx context.Context, alert *Alert) error {
	script := fmt.Sprintf(`display notification "%s" with title "%s"`, asEscapeDoubleQuoted(alert.Message), asEscapeDoubleQuoted(alert.Title))
	cmd := exec.CommandContext(ctx, "osascript", "-e", script)
	return cmd.Run()
}

func sendDesktopLinux(ctx context.Context, alert *Alert) error {
	cmd := exec.CommandContext(ctx, "notify-send", alert.Title, alert.Message)
	return cmd.Run()
}
