// Package firewall provides the declarative per-app/per-route policy engine
// with allow/block/stall actions, event-conditioned applicability, IP/domain/
// port scoping, priority precedence, and rule expiry.
package firewall

import (
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// Action is the verdict a matched rule imposes.
type Action string

const (
	ActionAllow Action = "allow"
	ActionBlock Action = "block"
	ActionStall Action = "stall" // hold packets to starve censor-side probing
)

// Event is one network decision request.
type Event struct {
	AppID      string
	Direction  string // "outbound" | "inbound"
	Protocol   string // "tcp" | "udp"
	Domain     string
	IP         netip.Addr
	Port       uint16
	ScreenOn   bool
	Metered    bool
	Foreground bool
}

// Rule is a single policy entry. Empty slices mean "any".
type Rule struct {
	ID         string
	Priority   int // higher wins
	Action     Action
	Apps       []string
	Domains    []string // suffix match, e.g. ".example.com"
	IPPrefixes []netip.Prefix
	Ports      []uint16
	Protocols  []string
	Metered    *bool // nil = any; true/false = must match
	ScreenOn   *bool
	ExpiresAt  *time.Time
	Reason     string
}

// Decision records which rule produced what verdict for an event.
type Decision struct {
	RuleID   string `json:"rule_id,omitempty"`
	Action   Action `json:"action"`
	Reason   string `json:"reason,omitempty"`
	Default  bool   `json:"default,omitempty"`
}

// Engine evaluates events against an immutable snapshot of rules.
type Engine struct {
	mu     sync.RWMutex
	rules  []Rule
	deflt  Action
	nowFn  func() time.Time
}

// NewEngine builds an engine with the default action for unmatched traffic.
func NewEngine(deflt Action) *Engine {
	return &Engine{deflt: deflt, nowFn: time.Now}
}

// SetNow overrides the clock (tests).
func (e *Engine) SetNow(fn func() time.Time) { e.nowFn = fn }

// Replace atomically swaps the rule catalog.
func (e *Engine) Replace(rules []Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = rules
}

// DefaultAction returns the fallback action for unmatched events.
func (e *Engine) DefaultAction() Action {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.deflt
}

// Decide evaluates the event. Highest-priority applicable rule wins; ties are
// broken by catalog order (first declared wins). Expired rules are skipped.
func (e *Engine) Decide(ev Event) Decision {
	e.mu.RLock()
	rules := e.rules
	now := e.nowFn()
	bestIdx := -1
	for i, rule := range rules {
		if !rule.applies(ev, now) {
			continue
		}
		if bestIdx == -1 || rule.Priority > rules[bestIdx].Priority {
			bestIdx = i
		}
	}
	e.mu.RUnlock()
	if bestIdx == -1 {
		return Decision{Action: e.deflt, Default: true}
	}
	return Decision{RuleID: rules[bestIdx].ID, Action: rules[bestIdx].Action, Reason: rules[bestIdx].Reason}
}

func (r Rule) applies(ev Event, now time.Time) bool {
	if r.ExpiresAt != nil && now.After(*r.ExpiresAt) {
		return false
	}
	if len(r.Apps) > 0 && !containsFold(r.Apps, ev.AppID) {
		return false
	}
	if len(r.Protocols) > 0 && !containsFold(r.Protocols, ev.Protocol) {
		return false
	}
	if r.Metered != nil && *r.Metered != ev.Metered {
		return false
	}
	if r.ScreenOn != nil && *r.ScreenOn != ev.ScreenOn {
		return false
	}
	if len(r.Domains) > 0 {
		if ev.Domain == "" {
			return false
		}
		matched := false
		lowerDomain := strings.ToLower(ev.Domain)
		for _, suffix := range r.Domains {
			suffix = strings.ToLower(suffix)
			if strings.HasSuffix(lowerDomain, suffix) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if len(r.IPPrefixes) > 0 && ev.IP.IsValid() {
		matched := false
		for _, prefix := range r.IPPrefixes {
			if prefix.Contains(ev.IP) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	} else if len(r.IPPrefixes) > 0 {
		return false
	}
	if len(r.Ports) > 0 {
		matched := false
		for _, port := range r.Ports {
			if port == ev.Port {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func containsFold(haystack []string, needle string) bool {
	n := strings.ToLower(needle)
	for _, item := range haystack {
		if strings.ToLower(item) == n {
			return true
		}
	}
	return false
}

// SortRules orders a catalog by descending priority then ID for stable output.
func SortRules(rules []Rule) {
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Priority != rules[j].Priority {
			return rules[i].Priority > rules[j].Priority
		}
		return rules[i].ID < rules[j].ID
	})
}
