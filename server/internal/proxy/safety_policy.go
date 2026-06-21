package proxy

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

type SafetySettings struct {
	RespectSafety          bool `json:"respect_safety"`
	AuthorizationConfirmed bool `json:"authorization_confirmed"`
	RateCeiling            int  `json:"rate_ceiling"`
}

type SafetyGovernor struct {
	mu           sync.Mutex
	AuditLogPath string
	logFile      *os.File
}

func NewSafetyGovernor(auditLogPath string) *SafetyGovernor {
	if auditLogPath == "" {
		auditLogPath = "scan_safety_audit.log"
	}
	return &SafetyGovernor{
		AuditLogPath: auditLogPath,
	}
}

func (sg *SafetyGovernor) ValidateScan(targetIP string, settings SafetySettings) error {
	ip := net.ParseIP(targetIP)
	if ip == nil {
		// Try to resolve target IP if it is a host name
		ips, err := net.LookupIP(targetIP)
		if err != nil || len(ips) == 0 {
			return fmt.Errorf("invalid destination address: %s", targetIP)
		}
		ip = ips[0]
	}

	// Enforce RFC 1918 blocking policy
	if isPrivateOrLoopback(ip) {
		if settings.RespectSafety && !settings.AuthorizationConfirmed {
			err := fmt.Errorf("RFC 1918 target IP %s blocked under default safety policy", ip.String())
			sg.writeAudit(targetIP, settings, false, err.Error())
			return err
		}
	}

	// Enforce Scan Rate Ceiling
	if settings.RateCeiling > 1000 && !settings.AuthorizationConfirmed {
		err := fmt.Errorf("rate ceiling (%d pps) exceeds default 1000 pps threshold without authorization attestation", settings.RateCeiling)
		sg.writeAudit(targetIP, settings, false, err.Error())
		return err
	}

	sg.writeAudit(targetIP, settings, true, "")
	return nil
}

func isPrivateOrLoopback(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsUnspecified() {
		return true
	}
	// Check RFC 1918 private ranges
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
			(ip4[0] == 192 && ip4[1] == 168)
	}
	// IPv6 Link-Local / Unique Local Addresses
	return ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsGlobalUnicast() && (ip[0] == 0xfc || ip[0] == 0xfd)
}

func (sg *SafetyGovernor) writeAudit(target string, settings SafetySettings, passed bool, errMsg string) {
	sg.mu.Lock()
	defer sg.mu.Unlock()

	var err error
	if sg.logFile == nil {
		sg.logFile, err = os.OpenFile(sg.AuditLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
		if err != nil {
			return
		}
	}

	status := "APPROVED"
	if !passed {
		status = "DENIED"
	}

	logLine := fmt.Sprintf("[%s] Status: %s | Target: %s | RespectSafety: %v | AuthConfirmed: %v | Rate: %d pps | Err: %s\n",
		time.Now().Format(time.RFC3339),
		status,
		target,
		settings.RespectSafety,
		settings.AuthorizationConfirmed,
		settings.RateCeiling,
		errMsg,
	)

	_, _ = sg.logFile.WriteString(logLine)
}

func (sg *SafetyGovernor) Close() error {
	sg.mu.Lock()
	defer sg.mu.Unlock()
	if sg.logFile != nil {
		err := sg.logFile.Close()
		sg.logFile = nil
		return err
	}
	return nil
}
