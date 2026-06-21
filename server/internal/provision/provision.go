package provision

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

type VpsConfig struct {
	IP          string `json:"ip"`
	SSHUser     string `json:"ssh_user"`
	SSHPassword string `json:"ssh_password"`
	SSHKey      string `json:"ssh_key"`
	Domain      string `json:"domain"`
	CFToken     string `json:"cf_token"`
	CFAccountID string `json:"cf_account_id"`
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
	mu    sync.RWMutex
	logs  []string
	chans []chan string
}

func NewProvisionLogger() *ProvisionLogger {
	return &ProvisionLogger{}
}

func (l *ProvisionLogger) Log(msg string) {
	line := fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), msg)
	l.mu.Lock()
	l.logs = append(l.logs, line)
	chans := make([]chan string, len(l.chans))
	copy(chans, l.chans)
	l.mu.Unlock()

	for _, ch := range chans {
		select {
		case ch <- line:
		default:
		}
	}
}

func (l *ProvisionLogger) Logf(format string, args ...interface{}) {
	l.Log(fmt.Sprintf(format, args...))
}

func (l *ProvisionLogger) GetLogs() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return strings.Join(l.logs, "\n")
}

func (l *ProvisionLogger) Subscribe() (chan string, func()) {
	ch := make(chan string, 50)
	l.mu.Lock()
	l.chans = append(l.chans, ch)
	l.mu.Unlock()

	unsubscribe := func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		for i, c := range l.chans {
			if c == ch {
				l.chans = append(l.chans[:i], l.chans[i+1:]...)
				close(ch)
				break
			}
		}
	}

	// Replay history
	l.mu.RLock()
	for _, log := range l.logs {
		ch <- log
	}
	l.mu.RUnlock()

	return ch, unsubscribe
}
