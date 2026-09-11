package provision

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	threeXUIImagePattern  = regexp.MustCompile(`^ghcr\.io/mhsanaei/3x-ui@sha256:[a-fA-F0-9]{64}$`)
	postgresImagePattern = regexp.MustCompile(`^postgres@sha256:[a-fA-F0-9]{64}$`)
	alpineImagePattern   = regexp.MustCompile(`^alpine@sha256:[a-fA-F0-9]{64}$`)
	apkVersionPattern    = regexp.MustCompile(`^[0-9][A-Za-z0-9._+~-]*-r[0-9]+$`)
)

type VpsConfig struct {
	IP               string `json:"ip"`
	SSHUser          string `json:"ssh_user"`
	SSHPassword      string `json:"ssh_password"`
	SSHKey           string `json:"ssh_key"`
	SSHHostKeySHA256 string `json:"ssh_host_key_sha256"`
	Domain           string `json:"domain"`
	CFToken          string `json:"cf_token"`
	CFAccountID      string `json:"cf_account_id"`
	ThreeXUIImage    string `json:"three_xui_image"`
	PostgresImage    string `json:"postgres_image"`
	AlpineImage      string `json:"alpine_image"`
	TorAPKVersion    string `json:"tor_apk_version"`
}

func (c VpsConfig) validateRuntimeSupplyChain() error {
	checks := []struct {
		name  string
		value string
		re    *regexp.Regexp
	}{
		{"three_xui_image", c.ThreeXUIImage, threeXUIImagePattern},
		{"postgres_image", c.PostgresImage, postgresImagePattern},
		{"alpine_image", c.AlpineImage, alpineImagePattern},
	}
	for _, check := range checks {
		if !check.re.MatchString(strings.TrimSpace(check.value)) {
			return fmt.Errorf("%s must be an approved repository pinned by sha256 digest", check.name)
		}
	}
	if !apkVersionPattern.MatchString(strings.TrimSpace(c.TorAPKVersion)) {
		return fmt.Errorf("tor_apk_version must be an explicit Alpine package version such as 0.4.8.14-r0")
	}
	return nil
}

type EdgeConfig struct {
	CFToken           string `json:"cf_token"`
	CFAccountID       string `json:"cf_account_id"`
	ScriptName        string `json:"script_name"`
	TargetHost        string `json:"target_host"`
	TargetPort        int    `json:"target_port"`
	UUID              string `json:"uuid"`
	Type              string `json:"type"` // "relay" (default) or "vless" (serverless proxy)
	D1DatabaseBinding string `json:"d1_database_binding"`
	D1DatabaseID      string `json:"d1_database_id"`
	CamouflageHost    string `json:"camouflage_host"`
}

type ProvisionLogger struct {
	mu   sync.RWMutex
	logs []string
}

func NewProvisionLogger() *ProvisionLogger {
	return &ProvisionLogger{}
}

func (l *ProvisionLogger) Log(msg string) {
	line := fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), msg)
	l.mu.Lock()
	l.logs = append(l.logs, line)
	l.mu.Unlock()
}

func (l *ProvisionLogger) Logf(format string, args ...interface{}) {
	l.Log(fmt.Sprintf(format, args...))
}

func (l *ProvisionLogger) GetLogs() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return strings.Join(l.logs, "\n")
}
