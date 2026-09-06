// Package windows contains Windows-specific transport utilities. This file
// implements a Windows Filtering Platform (WFP) redirector pattern modeled
// after mitmproxy_rs's redirector architecture.
//
// NOTE: This is a clean-room LumiNet implementation. The real WFP call chain
// requires the golang.org/x/sys/windows package with elevated privileges and
// must run on Windows. The cgo bindings here are STUBS that emulate the rule
// lifecycle in user-space; production deployment should wire them to the
// actual fwpuclnt.dll API via x/sys/windows.
//
//go:build windows
// +build windows

package windows

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// WFP layer constants mirror the FWPM_LAYER_* enumeration from
// fwpsk.h / fwpuclnt.h. They are mapped to user-space identifiers here.
const (
	WFPLayerConnectV4 = "FWPM_LAYER_ALE_CONNECT_V4"
	WFPLayerConnectV6 = "FWPM_LAYER_ALE_CONNECT_V6"
	WFPLayerFlowV4    = "FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4"
	WFPLayerFlowV6    = "FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6"
)

// WFP action codes mirror FWPM_ACTION_* from fwpsk.h.
const (
	WFPActionPermit   uint32 = 0x00010000
	WFPActionBlock    uint32 = 0x00020000
	WFPActionRedirect uint32 = 0x00040000
	WFPActionCallout  uint32 = 0x00080000
)

// WFPFilterFlag mirrors FWPM_FILTER_FLAGS. The relevant values for
// redirector rules are persisted-to-disk (0x00000001) and boot-time (0x00000002).
const (
	WFPFlagPersistent uint32 = 0x00000001
	WFPFlagBootTime  uint32 = 0x00000002
)

// WFPMatchDesc is a 5-tuple match used by ALE connect-layer filters.
type WFPMatchDesc struct {
	// SourceAddr / DestAddr are CIDR-style strings or "*" to match all.
	SourceAddr string
	DestAddr   string
	// SourcePort / DestPort are 0 to match all.
	SourcePort uint16
	DestPort   uint16
	// Protocol is one of "tcp", "udp", "*".
	Protocol string
}

// WFPRule is a single WFP filter rule. It is an in-memory representation
// that maps onto an FWPM_FILTER0 descriptor.
type WFPRule struct {
	// ID is a unique 64-bit filter identifier assigned by the engine.
	ID uint64
	// Name is a human-readable label.
	Name string
	// Layer is one of the WFPLayer* constants.
	Layer string
	// Match is the 5-tuple condition.
	Match WFPMatchDesc
	// Action is one of the WFPAction* constants.
	Action uint32
	// Weight selects among overlapping rules. Higher weight wins.
	Weight uint8
	// Flags combine WFPFlag* values.
	Flags uint32
	// Description documents the rule for operators.
	Description string
	// CreatedAt records when the rule was installed.
	CreatedAt time.Time
}

// WFPStats summarizes the redirector's state for diagnostics.
type WFPStats struct {
	RulesAdded   uint64
	RulesRemoved uint64
	ActiveRules  int
	EngineOpens  uint64
	EngineCloses uint64
	LastError    string
}

// cgoBindings is a stub for the fwpuclnt.dll surface. In production this
// would be implemented via x/sys/windows calls; here it records every
// operation in user-space so tests and dry-runs can exercise the rule
// lifecycle without elevated privileges.
type cgoBindings struct {
	mu          sync.Mutex
	opened      bool
	session     uint64
	filterCount uint64
}

// openEngine is the cgo binding stub. In production this would call
// FwpmEngineOpen0 from fwpuclnt.dll.
func (c *cgoBindings) openEngine() (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.opened {
		return c.session, nil
	}
	c.opened = true
	c.session = 0xC0FFEE01
	c.filterCount = 0
	return c.session, nil
}

// closeEngine mirrors FwpmEngineClose0.
func (c *cgoBindings) closeEngine() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.opened {
		return errors.New("engine not open")
	}
	c.opened = false
	c.session = 0
	return nil
}

// addFilter mirrors FwpmFilterAdd0. It returns the assigned filter ID.
func (c *cgoBindings) addFilter(rule *WFPRule) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.opened {
		return 0, errors.New("engine not open")
	}
	c.filterCount++
	rule.ID = 0xF1<<32 | (c.filterCount & 0xFFFFFFFF)
	return rule.ID, nil
}

// deleteFilter mirrors FwpmFilterDeleteById0.
func (c *cgoBindings) deleteFilter(id uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.opened {
		return errors.New("engine not open")
	}
	if c.filterCount == 0 {
		return errors.New("no filters to delete")
	}
	c.filterCount--
	return nil
}

// WFPRedirector owns the WFP engine handle and the in-memory set of
// installed rules. It is safe for concurrent use.
type WFPRedirector struct {
	mu     sync.RWMutex
	rules  map[uint64]*WFPRule
	binds  *cgoBindings
	stats  WFPStats
	closed atomic.Bool
}

// NewWFPRedirector creates a new redirector. It opens the WFP engine
// session via the cgo bindings (currently a stub).
func NewWFPRedirector() (*WFPRedirector, error) {
	binds := &cgoBindings{}
	session, err := binds.openEngine()
	if err != nil {
		return nil, fmt.Errorf("wfp: open engine: %w", err)
	}
	r := &WFPRedirector{
		rules: make(map[uint64]*WFPRule),
		binds: binds,
	}
	r.stats.EngineOpens = 1
	r.stats.ActiveRules = 0
	_ = session
	return r, nil
}

// AddRedirectRule installs a new WFP redirect rule. The rule's ID is
// assigned by the engine and returned.
func (r *WFPRedirector) AddRedirectRule(rule WFPRule) (uint64, error) {
	if r.closed.Load() {
		return 0, errors.New("wfp: redirector is closed")
	}
	if rule.Layer == "" {
		return 0, errors.New("wfp: rule layer is required")
	}
	if !isKnownLayer(rule.Layer) {
		return 0, fmt.Errorf("wfp: unknown layer %q", rule.Layer)
	}
	if !isKnownAction(rule.Action) {
		return 0, fmt.Errorf("wfp: unknown action 0x%x", rule.Action)
	}
	if rule.Match.Protocol != "" && !isKnownProtocol(rule.Match.Protocol) {
		return 0, fmt.Errorf("wfp: unknown protocol %q", rule.Match.Protocol)
	}
	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = time.Now()
	}

	id, err := r.binds.addFilter(&rule)
	if err != nil {
		r.recordError(err)
		return 0, err
	}

	r.mu.Lock()
	r.rules[id] = &rule
	r.stats.RulesAdded++
	r.stats.ActiveRules = len(r.rules)
	r.mu.Unlock()

	return id, nil
}

// RemoveRedirectRule removes a previously installed rule by ID.
func (r *WFPRedirector) RemoveRedirectRule(id uint64) error {
	if r.closed.Load() {
		return errors.New("wfp: redirector is closed")
	}
	r.mu.Lock()
	_, ok := r.rules[id]
	if !ok {
		r.mu.Unlock()
		return fmt.Errorf("wfp: rule %d not found", id)
	}
	delete(r.rules, id)
	r.stats.RulesRemoved++
	r.stats.ActiveRules = len(r.rules)
	r.mu.Unlock()

	if err := r.binds.deleteFilter(id); err != nil {
		r.recordError(err)
		return err
	}
	return nil
}

// GetRule returns a copy of the rule with the given ID.
func (r *WFPRedirector) GetRule(id uint64) *WFPRule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n, ok := r.rules[id]
	if !ok {
		return nil
	}
	cp := *n
	return &cp
}

// ListRules returns a copy of all installed rules sorted by ID.
func (r *WFPRedirector) ListRules() []*WFPRule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*WFPRule, 0, len(r.rules))
	for _, rule := range r.rules {
		cp := *rule
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ID < out[j].ID
	})
	return out
}

// Stats returns a copy of the current WFP statistics.
func (r *WFPRedirector) Stats() WFPStats {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s := r.stats
	s.ActiveRules = len(r.rules)
	return s
}

// Close closes the WFP engine session.
func (r *WFPRedirector) Close() error {
	if r.closed.Swap(true) {
		return nil
	}
	r.mu.Lock()
	rules := make([]uint64, 0, len(r.rules))
	for id := range r.rules {
		rules = append(rules, id)
	}
	r.rules = nil
	r.mu.Unlock()

	for _, id := range rules {
		_ = r.binds.deleteFilter(id)
	}
	if err := r.binds.closeEngine(); err != nil {
		r.recordError(err)
		return err
	}
	r.mu.Lock()
	r.stats.EngineCloses++
	r.mu.Unlock()
	return nil
}

func (r *WFPRedirector) recordError(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stats.LastError = err.Error()
}

// isKnownLayer checks whether the layer name is one of the supported WFP filter layers.
func isKnownLayer(layer string) bool {
	switch layer {
	case WFPLayerConnectV4, WFPLayerConnectV6, WFPLayerFlowV4, WFPLayerFlowV6:
		return true
	}
	return false
}

func isKnownAction(action uint32) bool {
	switch action {
	case WFPActionPermit, WFPActionBlock, WFPActionRedirect, WFPActionCallout:
		return true
	}
	return false
}

func isKnownProtocol(p string) bool {
	switch p {
	case "tcp", "udp", "*":
		return true
	}
	return false
}
