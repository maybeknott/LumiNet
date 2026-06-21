package proxy

import (
	"net"
	"testing"

	"github.com/maybeknott/luminet/internal/config"
)

func TestRulesRouter(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("192.168.1.0/24")
	router := &RulesRouter{
		Rules: []RoutingRule{
			{
				DomainSuffix: []string{".cn", ".google.cn"},
				OutboundTag:  "direct",
			},
			{
				DomainKeyword: []string{"local", "loopback"},
				OutboundTag:   "direct",
			},
			{
				IPRanges:    []*net.IPNet{ipNet},
				OutboundTag: "direct",
			},
		},
	}

	// Match direct by domain suffix
	if tag := router.MatchOutbound("www.google.cn", nil); tag != "direct" {
		t.Errorf("expected 'direct', got '%s'", tag)
	}

	// Match direct by domain keyword
	if tag := router.MatchOutbound("my-local-server.com", nil); tag != "direct" {
		t.Errorf("expected 'direct', got '%s'", tag)
	}

	// Match direct by IP range
	if tag := router.MatchOutbound("example.com", net.ParseIP("192.168.1.50")); tag != "direct" {
		t.Errorf("expected 'direct', got '%s'", tag)
	}

	// Default fallback to proxy
	if tag := router.MatchOutbound("google.com", net.ParseIP("8.8.8.8")); tag != "proxy" {
		t.Errorf("expected 'proxy', got '%s'", tag)
	}
}

func TestBuildMihomoRules(t *testing.T) {
	opts := config.MihomoRulesOptions{
		BypassChina:     true,
		BypassOpenAI:    true,
		BypassGoogleAI:  true,
		BypassMicrosoft: false,
		BlockAds:        true,
		BlockPorn:       true,
	}

	rules := BuildMihomoRules(opts)
	router := &RulesRouter{Rules: rules}

	// Test China Bypass
	if tag := router.MatchOutbound("baidu.cn", nil); tag != "direct" {
		t.Errorf("expected 'direct' for baidu.cn, got '%s'", tag)
	}

	// Test OpenAI Bypass
	if tag := router.MatchOutbound("chat.openai.com", nil); tag != "direct" {
		t.Errorf("expected 'direct' for chat.openai.com, got '%s'", tag)
	}

	// Test GoogleAI Bypass
	if tag := router.MatchOutbound("gemini.google.com", nil); tag != "direct" {
		t.Errorf("expected 'direct' for gemini.google.com, got '%s'", tag)
	}

	// Test Microsoft (disabled bypass, should fallback to proxy)
	if tag := router.MatchOutbound("microsoft.com", nil); tag != "proxy" {
		t.Errorf("expected 'proxy' for microsoft.com, got '%s'", tag)
	}

	// Test Ads Block
	if tag := router.MatchOutbound("doubleclick.net", nil); tag != "reject" {
		t.Errorf("expected 'reject' for doubleclick.net, got '%s'", tag)
	}

	// Test Porn Block
	if tag := router.MatchOutbound("some-nsfw-site.com", nil); tag != "reject" {
		t.Errorf("expected 'reject' for some-nsfw-site.com, got '%s'", tag)
	}

	// Test fallback
	if tag := router.MatchOutbound("randomsite.org", nil); tag != "proxy" {
		t.Errorf("expected 'proxy' for randomsite.org, got '%s'", tag)
	}
}
