package firewall

import (
	"net/netip"
	"testing"
	"time"
)

func boolPtr(v bool) *bool { return &v }

func TestEnginePriorityPrecedence(t *testing.T) {
	e := NewEngine(ActionAllow)
	e.Replace([]Rule{
		{ID: "base-block", Priority: 10, Action: ActionBlock, Apps: []string{"com.tracker"}},
		{ID: "user-allow", Priority: 100, Action: ActionAllow, Apps: []string{"com.tracker"}, Reason: "user override"},
	})
	d := e.Decide(Event{AppID: "com.tracker", Protocol: "tcp", Port: 443})
	if d.Action != ActionAllow || d.RuleID != "user-allow" {
		t.Fatalf("higher priority must win: %+v", d)
	}
	if d.Default {
		t.Fatal("matched decision flagged as default")
	}
}

func TestEngineDefaultActionAndMatch(t *testing.T) {
	e := NewEngine(ActionBlock)
	e.Replace([]Rule{
		{ID: "dns-any", Priority: 5, Action: ActionStall, Protocols: []string{"udp"}, Ports: []uint16{53}},
	})
	d := e.Decide(Event{AppID: "any", Protocol: "tcp", Port: 443})
	if !d.Default || d.Action != ActionBlock {
		t.Fatalf("unmatched should fall to default: %+v", d)
	}
	d = e.Decide(Event{AppID: "any", Protocol: "udp", Port: 53})
	if d.RuleID != "dns-any" || d.Action != ActionStall {
		t.Fatalf("dns rule mismatch: %+v", d)
	}
}

func TestEngineConditionedRule(t *testing.T) {
	e := NewEngine(ActionAllow)
	e.Replace([]Rule{
		{ID: "block-metered-bg", Priority: 50, Action: ActionBlock,
			Metered: boolPtr(true), ScreenOn: boolPtr(false)},
	})
	matched := e.Decide(Event{AppID: "app", Protocol: "tcp", Metered: true, ScreenOn: false})
	if matched.RuleID != "block-metered-bg" {
		t.Fatalf("conditioned rule should match: %+v", matched)
	}
	wifi := e.Decide(Event{AppID: "app", Protocol: "tcp", Metered: false})
	if wifi.RuleID == "block-metered-bg" {
		t.Fatal("rule must not match on unmetered")
	}
	screenOn := e.Decide(Event{AppID: "app", Protocol: "tcp", Metered: true, ScreenOn: true})
	if screenOn.RuleID == "block-metered-bg" {
		t.Fatal("rule must not match when screen on")
	}
}

func TestEngineExpiry(t *testing.T) {
	e := NewEngine(ActionAllow)
	expiry := time.Now().Add(-time.Minute)
	e.Replace([]Rule{
		{ID: "expired", Priority: 99, Action: ActionBlock, ExpiresAt: &expiry},
	})
	if d := e.Decide(Event{AppID: "x"}); d.Action != ActionAllow {
		t.Fatalf("expired rule must be skipped: %+v", d)
	}
}

func TestEngineDomainSuffixAndIPPrefix(t *testing.T) {
	e := NewEngine(ActionBlock)
	e.Replace([]Rule{
		{ID: "telemetry", Priority: 10, Action: ActionBlock,
			Domains: []string{".telemetry.example"}},
		{ID: "corp-range", Priority: 8, Action: ActionStall,
			IPPrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}},
	})
	if d := e.Decide(Event{AppID: "a", Protocol: "tcp", Domain: "sdk.telemetry.example", Port: 443}); d.Action != ActionBlock {
		t.Fatalf("domain suffix match failed: %+v", d)
	}
	ipEvent := Event{AppID: "a", Protocol: "tcp", IP: netip.MustParseAddr("10.1.2.3"), Port: 8080}
	if d := e.Decide(ipEvent); d.Action != ActionStall {
		t.Fatalf("prefix match failed: %+v", d)
	}
	outside := Event{AppID: "a", Protocol: "tcp", IP: netip.MustParseAddr("8.8.8.8"), Port: 8080}
	if d := e.Decide(outside); d.Default {
		t.Log("outside prefix falls to default (expected)")
	}
}

func TestSortRulesDeterministic(t *testing.T) {
	rules := []Rule{
		{ID: "b", Priority: 5}, {ID: "a", Priority: 5}, {ID: "z", Priority: 9},
	}
	SortRules(rules)
	if rules[0].ID != "z" || rules[1].ID != "a" || rules[2].ID != "b" {
		t.Fatalf("sort order wrong: %v %v %v", rules[0].ID, rules[1].ID, rules[2].ID)
	}
}
