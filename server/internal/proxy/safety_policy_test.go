package proxy

import (
	"os"
	"strings"
	"testing"
)

func TestSafetyGovernor_PrivateIPBlock(t *testing.T) {
	tempLog := "temp_safety_audit.log"
	defer os.Remove(tempLog)

	sg := NewSafetyGovernor(tempLog)
	defer sg.Close()

	settings := SafetySettings{
		RespectSafety:          true,
		AuthorizationConfirmed: false,
		RateCeiling:            500,
	}

	// 10.0.0.1 is RFC 1918 private range
	err := sg.ValidateScan("10.0.0.1", settings)
	if err == nil {
		t.Errorf("expected RFC 1918 scanning request to be rejected")
	}

	// 127.0.0.1 is loopback
	err = sg.ValidateScan("127.0.0.1", settings)
	if err == nil {
		t.Errorf("expected loopback scanning request to be rejected")
	}

	// With authorization confirmed, scan should be approved
	settings.AuthorizationConfirmed = true
	err = sg.ValidateScan("10.0.0.1", settings)
	if err != nil {
		t.Errorf("expected RFC 1918 scanning to pass with confirmation: %v", err)
	}
}

func TestSafetyGovernor_RateCeiling(t *testing.T) {
	tempLog := "temp_safety_audit.log"
	defer os.Remove(tempLog)

	sg := NewSafetyGovernor(tempLog)
	defer sg.Close()

	settings := SafetySettings{
		RespectSafety:          true,
		AuthorizationConfirmed: false,
		RateCeiling:            1200, // exceeds 1000 pps ceiling
	}

	err := sg.ValidateScan("8.8.8.8", settings)
	if err == nil {
		t.Errorf("expected scan rate over 1000 pps without authorization to be rejected")
	}

	settings.AuthorizationConfirmed = true
	err = sg.ValidateScan("8.8.8.8", settings)
	if err != nil {
		t.Errorf("expected scan rate over 1000 pps with authorization to be approved: %v", err)
	}
}

func TestSafetyGovernor_AuditLogging(t *testing.T) {
	tempLog := "temp_safety_audit.log"
	defer os.Remove(tempLog)

	sg := NewSafetyGovernor(tempLog)

	settings := SafetySettings{
		RespectSafety:          true,
		AuthorizationConfirmed: false,
		RateCeiling:            100,
	}

	_ = sg.ValidateScan("192.168.1.100", settings)
	_ = sg.ValidateScan("8.8.4.4", settings)
	_ = sg.Close()

	content, err := os.ReadFile(tempLog)
	if err != nil {
		t.Fatalf("failed to read audit log: %v", err)
	}

	logStr := string(content)
	if !strings.Contains(logStr, "DENIED") || !strings.Contains(logStr, "192.168.1.100") {
		t.Errorf("audit log missing DENIED target entry: %s", logStr)
	}
	if !strings.Contains(logStr, "APPROVED") || !strings.Contains(logStr, "8.8.4.4") {
		t.Errorf("audit log missing APPROVED target entry: %s", logStr)
	}
}
