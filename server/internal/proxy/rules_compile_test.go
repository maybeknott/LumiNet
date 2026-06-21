package proxy

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRulesCompilerAndLoader(t *testing.T) {
	// Setup temporary compilation output file
	tmpDir, err := os.MkdirTemp("", "rules-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "rules.db")

	_, range1, _ := net.ParseCIDR("192.168.1.0/24")
	_, range2, _ := net.ParseCIDR("10.0.0.0/8")

	originalRules := []RoutingRule{
		{
			DomainSuffix:  []string{"google.com", "yahoo.com"},
			DomainKeyword: []string{"search", "mail"},
			IPRanges:      []*net.IPNet{range1},
			OutboundTag:   "proxy",
		},
		{
			DomainSuffix: []string{"baidu.com", "qq.com"},
			IPRanges:     []*net.IPNet{range2},
			OutboundTag:  "direct",
		},
	}

	// 1. Assert rules compilation works
	if err := CompileRules(originalRules, dbPath); err != nil {
		t.Fatalf("failed to compile rules: %v", err)
	}

	// Verify file size
	if info, err := os.Stat(dbPath); err != nil || info.Size() == 0 {
		t.Fatalf("expected compiled rules file to exist and be non-empty")
	}

	// 2. Assert loading compiled rules works
	router, err := LoadCompiledRules(dbPath)
	if err != nil {
		t.Fatalf("failed to load compiled rules: %v", err)
	}

	if len(router.Rules) != 2 {
		t.Fatalf("expected 2 rules loaded, got %d", len(router.Rules))
	}

	// Verify rules content
	if router.Rules[0].OutboundTag != "proxy" || len(router.Rules[0].DomainSuffix) != 2 {
		t.Errorf("loaded rule mismatch: %+v", router.Rules[0])
	}
}

func TestRulesRouterTriePerformance(t *testing.T) {
	// Build a large ruleset to test Radix Trie suffix matching performance
	var rules []RoutingRule
	suffixes := []string{"cn", "com.cn", "org.cn", "net.cn"}
	for i := 0; i < 1000; i++ {
		suffixes = append(suffixes, fmt.Sprintf("domain-%d.com", i))
	}

	rules = append(rules, RoutingRule{
		DomainSuffix: suffixes,
		OutboundTag:  "direct",
	})

	router := &RulesRouter{Rules: rules}

	// Prime/build the trie
	router.MatchOutbound("probe.com", nil)

	// Measure matching time (target <50 microseconds per match)
	start := time.Now()
	iterations := 10000

	for i := 0; i < iterations; i++ {
		_ = router.MatchOutbound("test-service.domain-500.com", nil)
	}

	elapsed := time.Since(start)
	avgMs := float64(elapsed.Nanoseconds()) / float64(iterations) / 1000.0

	t.Logf("Trie matching average time: %.4f microseconds per match", avgMs)

	if avgMs > 50.0 {
		t.Errorf("Trie matching performance degraded: %.4f microseconds per match (expected < 50.0)", avgMs)
	}
}

func TestGeoIPReader(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "geoip-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "geoip.csv")
	dbContent := `
# Country, IP/CIDR
US,1.1.1.0/24
CN,1.0.1.0/24
CN,2.0.2.0/24
IR,3.0.3.0/24
`
	if err := os.WriteFile(dbPath, []byte(dbContent), 0644); err != nil {
		t.Fatalf("failed to create test GeoIP file: %v", err)
	}

	// Read CN networks
	networks, err := LoadGeoIPRules(dbPath, "CN")
	if err != nil {
		t.Fatalf("failed to load GeoIP rules: %v", err)
	}

	if len(networks) != 2 {
		t.Errorf("expected 2 networks for CN, got %d", len(networks))
	}

	// Verify networks content
	if networks[0].String() != "1.0.1.0/24" || networks[1].String() != "2.0.2.0/24" {
		t.Errorf("unexpected loaded networks: %+v", networks)
	}
}

func TestWasmRuleRunnerExecutionTimeout(t *testing.T) {
	runner := NewWasmRuleRunner([]byte("mock-wasm-bytecode"))

	// 1. Success matching within timeout bounds
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	tag, err := runner.Match(ctx, "wasm-direct.cn", nil)
	if err != nil {
		t.Fatalf("match failed: %v", err)
	}
	if tag != "direct" {
		t.Errorf("expected direct, got %s", tag)
	}

	// 2. Timeout simulation
	ctxTimeout, cancelTimeout := context.WithTimeout(context.Background(), 1*time.Microsecond)
	defer cancelTimeout()

	// Wait a tiny bit to force context expiration before execution completes
	time.Sleep(2 * time.Millisecond)

	_, err = runner.Match(ctxTimeout, "wasm-direct.cn", nil)
	if err == nil {
		t.Errorf("expected timeout error, got nil")
	}
}
