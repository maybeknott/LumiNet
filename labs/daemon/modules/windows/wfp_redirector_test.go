//go:build windows
// +build windows

package windows

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWFPRedirector_AddAndGet(t *testing.T) {
	r, err := NewWFPRedirector()
	if err != nil {
		t.Fatalf("NewWFPRedirector: %v", err)
	}
	defer r.Close()

	rule := WFPRule{
		Name:  "block-tcp-443",
		Layer: WFPLayerConnectV4,
		Match: WFPMatchDesc{
			DestPort: 443,
			Protocol: "tcp",
		},
		Action: WFPActionBlock,
		Weight: 10,
	}
	id, err := r.AddRedirectRule(rule)
	if err != nil {
		t.Fatalf("AddRedirectRule: %v", err)
	}
	if id == 0 {
		t.Fatal("expected non-zero rule ID")
	}
	got := r.GetRule(id)
	if got == nil {
		t.Fatal("GetRule returned nil")
	}
	if got.Name != "block-tcp-443" {
		t.Errorf("name: got %q, want %q", got.Name, "block-tcp-443")
	}
	if got.Weight != 10 {
		t.Errorf("weight: got %d, want 10", got.Weight)
	}
}

func TestWFPRedirector_AddRejectsInvalid(t *testing.T) {
	r, err := NewWFPRedirector()
	if err != nil {
		t.Fatalf("NewWFPRedirector: %v", err)
	}
	defer r.Close()

	tests := []struct {
		name string
		rule WFPRule
	}{
		{"empty layer", WFPRule{Action: WFPActionBlock}},
		{"unknown layer", WFPRule{Layer: "FWPM_LAYER_UNKNOWN", Action: WFPActionBlock}},
		{"unknown action", WFPRule{Layer: WFPLayerConnectV4, Action: 0xDEAD}},
		{"unknown protocol", WFPRule{Layer: WFPLayerConnectV4, Action: WFPActionBlock, Match: WFPMatchDesc{Protocol: "icmp"}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := r.AddRedirectRule(tc.rule)
			if err == nil {
				t.Errorf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

func TestWFPRedirector_Remove(t *testing.T) {
	r, err := NewWFPRedirector()
	if err != nil {
		t.Fatalf("NewWFPRedirector: %v", err)
	}
	defer r.Close()

	id, err := r.AddRedirectRule(WFPRule{
		Name: "perm-all", Layer: WFPLayerConnectV4, Action: WFPActionPermit,
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := r.RemoveRedirectRule(id); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if r.GetRule(id) != nil {
		t.Error("expected rule to be removed")
	}
	if err := r.RemoveRedirectRule(id); err == nil {
		t.Error("expected error removing already-removed rule")
	}
}

func TestWFPRedirector_ListRulesSorted(t *testing.T) {
	r, err := NewWFPRedirector()
	if err != nil {
		t.Fatalf("NewWFPRedirector: %v", err)
	}
	defer r.Close()

	for i := 0; i < 3; i++ {
		if _, err := r.AddRedirectRule(WFPRule{
			Name: "rule", Layer: WFPLayerConnectV4, Action: WFPActionPermit,
		}); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}
	rules := r.ListRules()
	if len(rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(rules))
	}
	for i := 1; i < len(rules); i++ {
		if rules[i].ID < rules[i-1].ID {
			t.Errorf("rules not sorted: %d before %d", rules[i].ID, rules[i-1].ID)
		}
	}
}

func TestWFPRedirector_CloseBlocksOperations(t *testing.T) {
	r, err := NewWFPRedirector()
	if err != nil {
		t.Fatalf("NewWFPRedirector: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Errorf("double close: %v", err)
	}
	_, err = r.AddRedirectRule(WFPRule{Layer: WFPLayerConnectV4, Action: WFPActionBlock})
	if err == nil {
		t.Error("expected error adding to closed redirector")
	}
	if !strings.Contains(err.Error(), "closed") {
		t.Errorf("expected closed error, got %v", err)
	}
}

func TestWFPRedirector_Stats(t *testing.T) {
	r, err := NewWFPRedirector()
	if err != nil {
		t.Fatalf("NewWFPRedirector: %v", err)
	}
	defer r.Close()

	id, err := r.AddRedirectRule(WFPRule{Layer: WFPLayerConnectV4, Action: WFPActionBlock})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	stats := r.Stats()
	if stats.RulesAdded != 1 {
		t.Errorf("RulesAdded: got %d, want 1", stats.RulesAdded)
	}
	if stats.EngineOpens != 1 {
		t.Errorf("EngineOpens: got %d, want 1", stats.EngineOpens)
	}
	if stats.ActiveRules != 1 {
		t.Errorf("ActiveRules: got %d, want 1", stats.ActiveRules)
	}
	if err := r.RemoveRedirectRule(id); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	stats = r.Stats()
	if stats.RulesRemoved != 1 {
		t.Errorf("RulesRemoved: got %d, want 1", stats.RulesRemoved)
	}
	if stats.ActiveRules != 0 {
		t.Errorf("ActiveRules after remove: got %d, want 0", stats.ActiveRules)
	}
}

func TestWFPRedirector_Concurrent(t *testing.T) {
	r, err := NewWFPRedirector()
	if err != nil {
		t.Fatalf("NewWFPRedirector: %v", err)
	}
	defer r.Close()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, err := r.AddRedirectRule(WFPRule{
				Name: "concurrent", Layer: WFPLayerConnectV4, Action: WFPActionPermit,
			})
			if err != nil {
				t.Errorf("Add: %v", err)
				return
			}
			_ = r.GetRule(id)
			_ = r.Stats()
		}()
	}
	wg.Wait()
	if s := r.Stats(); s.ActiveRules != 20 {
		t.Errorf("expected 20 rules, got %d", s.ActiveRules)
	}
}

func TestWFPRedirector_CreatedAtDefault(t *testing.T) {
	r, err := NewWFPRedirector()
	if err != nil {
		t.Fatalf("NewWFPRedirector: %v", err)
	}
	defer r.Close()

	before := time.Now()
	id, err := r.AddRedirectRule(WFPRule{
		Layer: WFPLayerConnectV4, Action: WFPActionBlock,
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	got := r.GetRule(id)
	if got.CreatedAt.Before(before) {
		t.Errorf("CreatedAt %v before test start %v", got.CreatedAt, before)
	}
}
