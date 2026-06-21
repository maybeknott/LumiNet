package proxy

import (
	"strings"
	"testing"
)

func TestRewriteProxyURI(t *testing.T) {
	tests := []struct {
		name      string
		rawURI    string
		newHost   string
		newPort   int
		newName   string
		expectSub string // expected substring
	}{
		{
			name:      "VLESS Rewrite Host and Port",
			rawURI:    "vless://11111111-2222-3333-4444-555555555555@example.com:443?type=ws&security=tls&path=/ray#original-name",
			newHost:   "104.17.134.117",
			newPort:   2053,
			newName:   "rewritten-name",
			expectSub: "vless://11111111-2222-3333-4444-555555555555@104.17.134.117:2053",
		},
		{
			name:      "Trojan Rewrite Host and preserve SNI",
			rawURI:    "trojan://password123@example.com:443?type=ws",
			newHost:   "1.1.1.1",
			newPort:   0,
			newName:   "",
			expectSub: "sni=example.com",
		},
		{
			name:      "Shadowsocks legacy rewrite",
			rawURI:    "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQxMjM=@example.com:443#old-name",
			newHost:   "8.8.8.8",
			newPort:   8443,
			newName:   "new-ss",
			expectSub: "@8.8.8.8:8443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RewriteProxyURI(tt.rawURI, tt.newHost, tt.newPort, tt.newName)
			if err != nil {
				t.Fatalf("RewriteProxyURI failed: %v", err)
			}
			if !strings.Contains(got, tt.expectSub) {
				t.Errorf("Expected rewritten URI to contain %q, got %q", tt.expectSub, got)
			}
			if tt.newName != "" && !strings.Contains(got, tt.newName) {
				t.Errorf("Expected name to be updated to %q, got %q", tt.newName, got)
			}
		})
	}
}

func TestRewriteSubscriptionContent(t *testing.T) {
	content := "vless://11111111-2222-3333-4444-555555555555@example.com:443?type=ws&security=tls#node1\ntrojan://pass@example2.com:443#node2"
	ips := []string{"104.16.1.1", "104.16.2.2"}

	rewritten, err := RewriteSubscriptionContent(content, ips, 80, "{name} | {ip}")
	if err != nil {
		t.Fatalf("RewriteSubscriptionContent failed: %v", err)
	}

	if len(rewritten) != 4 {
		t.Fatalf("Expected 4 rewritten nodes, got %d", len(rewritten))
	}

	expectedNames := []string{
		"node1 | 104.16.1.1",
		"node1 | 104.16.2.2",
		"node2 | 104.16.1.1",
		"node2 | 104.16.2.2",
	}

	for i, uri := range rewritten {
		cfg, err := ParseProxyURI(uri)
		if err != nil {
			t.Fatalf("Failed to parse rewritten URI %q: %v", uri, err)
		}
		if cfg.Name != expectedNames[i] {
			t.Errorf("Expected name %q, got %q", expectedNames[i], cfg.Name)
		}
		if cfg.Port != 80 {
			t.Errorf("Expected port 80, got %d", cfg.Port)
		}
	}
}
