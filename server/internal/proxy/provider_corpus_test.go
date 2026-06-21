package proxy

import (
	"net/netip"
	"testing"
	"time"
)

func TestProviderCorpusParsing(t *testing.T) {
	jsonData := `{
		"schema_version": 1,
		"corpus_id": "test-corpus-123",
		"generator_version": "v1",
		"generated_at": "2026-05-24T00:00:00Z",
		"fetched_at": "2026-05-24T00:00:00Z",
		"stale_after": "2026-06-23T00:00:00Z",
		"checksum": "sha256-test",
		"providers": [
			{
				"provider_id": "cloudflare",
				"display_name": "Cloudflare",
				"source_url": "test://url",
				"source_license": "test-license",
				"source_kind": "fixture",
				"confidence": "high",
				"priority": 100,
				"ipv4_prefixes": ["104.16.0.0/12"],
				"ipv6_prefixes": []
			}
		]
	}`

	corpus, err := ParseProviderCorpus([]byte(jsonData))
	if err != nil {
		t.Fatalf("Failed to parse provider corpus: %v", err)
	}

	if corpus.CorpusID != "test-corpus-123" {
		t.Errorf("Expected CorpusID 'test-corpus-123', got '%s'", corpus.CorpusID)
	}

	snapshot, err := BuildProviderSnapshot(corpus)
	if err != nil {
		t.Fatalf("Failed to build snapshot: %v", err)
	}

	addr := netip.MustParseAddr("104.16.2.3")
	match, ok := snapshot.Lookup(addr)
	if !ok {
		t.Fatalf("Expected address 104.16.2.3 to match cloudflare prefix")
	}

	if match.ProviderID != "cloudflare" {
		t.Errorf("Expected ProviderID 'cloudflare', got '%s'", match.ProviderID)
	}
}

func TestRadixNetworkClassification(t *testing.T) {
	cni := &CorporateNetworkIndex{}
	cni.Insert(netip.MustParsePrefix("104.16.0.0/12"), "cloudflare")
	cni.Insert(netip.MustParsePrefix("104.16.0.0/16"), "cloudflare-strict")

	p, ok := cni.MatchLongestPrefix(netip.MustParseAddr("104.16.1.1"))
	if !ok || p != "cloudflare-strict" {
		t.Errorf("Expected longest prefix match 'cloudflare-strict', got '%s' (ok=%t)", p, ok)
	}

	p, ok = cni.MatchLongestPrefix(netip.MustParseAddr("104.30.1.1"))
	if !ok || p != "cloudflare" {
		t.Errorf("Expected match 'cloudflare', got '%s' (ok=%t)", p, ok)
	}

	_, ok = cni.MatchLongestPrefix(netip.MustParseAddr("8.8.8.8"))
	if ok {
		t.Errorf("Expected no match for 8.8.8.8, but got match")
	}
}

func TestObserveProviderBuiltin(t *testing.T) {
	err := InitBuiltinProviderCorpus()
	if err != nil {
		t.Fatalf("Failed to initialize builtin provider corpus: %v", err)
	}

	status, ok := GetProviderCorpusStoreStatus()
	if !ok {
		t.Fatalf("Failed to get corpus status")
	}
	if status.CorpusID != "builtin-provider-prefixes-v1" {
		t.Errorf("Unexpected corpus status ID: %s", status.CorpusID)
	}

	obs := ObserveProvider("104.16.2.3")
	if obs.ProviderID != "cloudflare" {
		t.Errorf("Expected observed provider 'cloudflare', got '%s'", obs.ProviderID)
	}

	obsRadix := ObserveProvider("151.101.2.3")
	if obsRadix.ProviderID != "fastly" {
		t.Errorf("Expected observed provider 'fastly', got '%s'", obsRadix.ProviderID)
	}

	obsUnk := ObserveProvider("8.8.8.8")
	if obsUnk.ProviderID != "" {
		t.Errorf("Expected empty provider observation for unknown IP, got '%s'", obsUnk.ProviderID)
	}
}

func TestProviderCorpusStoreAtomicSwap(t *testing.T) {
	var store ProviderCorpusStore

	// Empty status should fail
	_, ok := store.Status(time.Now())
	if ok {
		t.Fatal("Expected Status to return ok=false when empty")
	}

	corpus := BuiltinProviderCorpus()
	snapshot, err := BuildProviderSnapshot(corpus)
	if err != nil {
		t.Fatalf("BuildProviderSnapshot failed: %v", err)
	}

	store.Store(snapshot)

	status, ok := store.Status(time.Now())
	if !ok {
		t.Fatal("Expected Status to return ok=true after store")
	}
	if status.CorpusID != "builtin-provider-prefixes-v1" {
		t.Errorf("Expected CorpusID 'builtin-provider-prefixes-v1', got '%s'", status.CorpusID)
	}
}
