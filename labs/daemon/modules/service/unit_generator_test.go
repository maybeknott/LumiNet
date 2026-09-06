package service

import (
	"strings"
	"testing"
)

func TestValidateProfileName(t *testing.T) {
	valid := []string{"default", "prod-tunnel", "test_01", "A-1_b"}
	for _, v := range valid {
		if _, err := ValidateProfileName(v); err != nil {
			t.Errorf("expected valid profile name for %q, got error: %v", v, err)
		}
	}

	invalid := []string{"", "has space", "semi;colon", "slash/path", "@invalid!"}
	for _, inv := range invalid {
		if _, err := ValidateProfileName(inv); err == nil {
			t.Errorf("expected error for invalid profile name %q", inv)
		}
	}
}

func TestBuildSystemdUnit(t *testing.T) {
	cfg := UnitConfig{
		ProfileName:      "test-instance",
		Description:      "Custom Description",
		WorkingDirectory: "/opt/luminet/runtime/test-instance",
		ExecStart:        "/opt/luminet/runtime/test-instance/luminet-daemon",
		User:             "luminet",
		RestartPolicy:    "always",
		RestartSec:       3,
		EnvironmentVars: map[string]string{
			"LUMINET_PROFILE": "test-instance",
			"CONFIG_FILE":     "/opt/luminet/runtime/test-instance/config.toml",
		},
	}

	unitStr, err := BuildSystemdUnit(cfg)
	if err != nil {
		t.Fatalf("BuildSystemdUnit failed: %v", err)
	}

	expectedSubstrings := []string{
		"[Unit]",
		"Description=Custom Description",
		"After=network.target",
		"[Service]",
		"Type=simple",
		"WorkingDirectory=/opt/luminet/runtime/test-instance",
		"Environment=\"CONFIG_FILE=/opt/luminet/runtime/test-instance/config.toml\"",
		"Environment=\"LUMINET_PROFILE=test-instance\"",
		"ExecStart=/opt/luminet/runtime/test-instance/luminet-daemon",
		"Restart=always",
		"RestartSec=3",
		"User=luminet",
		"[Install]",
		"WantedBy=multi-user.target",
	}

	for _, sub := range expectedSubstrings {
		if !strings.Contains(unitStr, sub) {
			t.Errorf("unit string missing expected substring %q:\n%s", sub, unitStr)
		}
	}
}

func TestGenerateTomlConfig(t *testing.T) {
	conf := map[string]interface{}{
		"DOMAINS":         []string{"tunnel1.example.com", "tunnel2.example.com"},
		"LISTEN_PORT":     18000,
		"ENCRYPTION_KEY":  "secret-key-123",
		"DATA_ENCRYPTION": 2,
		"SOCKS5_AUTH":     false,
	}

	toml := GenerateTomlConfig(conf)
	expectedLines := []string{
		"DATA_ENCRYPTION = 2",
		"DOMAINS = [\"tunnel1.example.com\", \"tunnel2.example.com\"]",
		"ENCRYPTION_KEY = \"secret-key-123\"",
		"LISTEN_PORT = 18000",
		"SOCKS5_AUTH = false",
	}

	for _, line := range expectedLines {
		if !strings.Contains(toml, line) {
			t.Errorf("toml missing expected line %q:\n%s", line, toml)
		}
	}
}

func TestParseProcNetDevAndRates(t *testing.T) {
	mockDev := "Inter-|   Receive                                                |  Transmit\n" +
		" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n" +
		"    lo: 1000000     100    0    0    0     0          0         0  1000000     100    0    0    0     0       0          0\n" +
		"  eth0: 2000000     200    0    0    0     0          0         0  3000000     300    0    0    0     0       0          0\n" +
		" wlan0:  500000      50    0    0    0     0          0         0   200000      20    0    0    0     0       0          0\n"

	rx, tx, err := ParseProcNetDev(mockDev)
	if err != nil {
		t.Fatalf("ParseProcNetDev failed: %v", err)
	}

	// eth0 rx: 2000000 + wlan0 rx: 500000 = 2500000 (lo is excluded)
	if rx != 2500000 {
		t.Errorf("expected rx 2500000, got %d", rx)
	}
	// eth0 tx: 3000000 + wlan0 tx: 200000 = 3200000
	if tx != 3200000 {
		t.Errorf("expected tx 3200000, got %d", tx)
	}

	// Calculate rates after 2 seconds with additional 100,000 rx and 200,000 tx
	rxRate, txRate := CalculateNetworkRates(rx, tx, rx+100000, tx+200000, 2.0)
	if rxRate != 50000.0 {
		t.Errorf("expected rxRate 50000.0, got %f", rxRate)
	}
	if txRate != 100000.0 {
		t.Errorf("expected txRate 100000.0, got %f", txRate)
	}
}
