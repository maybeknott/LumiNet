package proxy

import (
	"strings"
	"testing"
)

func TestExportToClashYaml(t *testing.T) {
	proxies := []*ProxyConfig{
		{
			Protocol: ProtocolShadowsocks,
			Address:  "127.0.0.1",
			Port:     8388,
			Method:   "aes-256-gcm",
			Password: "password123",
			Name:     "TestSS",
		},
		{
			Protocol: ProtocolVMess,
			Address:  "192.168.1.1",
			Port:     443,
			UUID:     "d86f78df-8c29-4560-a2cc-3a9d9cf9e58e",
			TLS:      true,
			SNI:      "example.com",
			Name:     "TestVMess",
		},
		{
			Protocol:        ProtocolVMess,
			Address:         "1.1.1.1",
			Port:            10443,
			UUID:            "d86f78df-8c29-4560-a2cc-3a9d9cf9e58e",
			Name:            "TestMux",
			SmuxEnabled:     true,
			SmuxConcurrency: 8,
		},
	}

	yamlStr, err := ExportToClashYaml(proxies)
	if err != nil {
		t.Fatalf("failed to export: %v", err)
	}

	if !strings.Contains(yamlStr, "proxies:") {
		t.Errorf("missing proxies section in YAML: %s", yamlStr)
	}
	if !strings.Contains(yamlStr, "type: ss") {
		t.Errorf("missing shadowsocks type in YAML: %s", yamlStr)
	}
	if !strings.Contains(yamlStr, "type: vmess") {
		t.Errorf("missing vmess type in YAML: %s", yamlStr)
	}
	if !strings.Contains(yamlStr, "servername: example.com") {
		t.Errorf("missing servername in YAML: %s", yamlStr)
	}
	if !strings.Contains(yamlStr, "smux:") || !strings.Contains(yamlStr, "concurrency: 8") {
		t.Errorf("missing smux or concurrency in YAML: %s", yamlStr)
	}
}
