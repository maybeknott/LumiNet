package fronting

import (
	"sync"
	"time"
)

// ScriptIDRotator provides round-robin selection over Apps Script deployment
// IDs with short-term blacklisting for failing/slow deployments. Mirrors
// domain_fronter.py `_next_script_id` / `_blacklist_sid` / `_prune_blacklist`.
type ScriptIDRotator struct {
	mu        sync.Mutex
	ids       []string
	next      int
	blacklist map[string]time.Time
	ttl       time.Duration
	now       func() time.Time
}

// NewScriptIDRotator builds a rotator; ttl <= 0 defaults to 10 minutes.
func NewScriptIDRotator(ids []string, ttl time.Duration) *ScriptIDRotator {
	if ttl <= 0 {
		ttl = 600 * time.Second
	}
	cp := make([]string, len(ids))
	copy(cp, ids)
	return &ScriptIDRotator{
		ids:       cp,
		blacklist: make(map[string]time.Time),
		ttl:       ttl,
		now:       time.Now,
	}
}

// Next returns the next non-blacklisted deployment ID. When every ID is
// blacklisted it prunes expired entries and falls back to plain round-robin so
// traffic keeps flowing (matching the Python behaviour).
func (r *ScriptIDRotator) Next() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := len(r.ids)
	if n == 0 {
		return ""
	}
	for range n {
		sid := r.ids[r.next%n]
		r.next++
		if !r.blacklistedLocked(sid) {
			return sid
		}
	}
	r.pruneLocked()
	sid := r.ids[r.next%n]
	r.next++
	return sid
}

// Blacklist marks a deployment ID unhealthy for the configured TTL. Blacklisting
// is skipped when it would leave no fallback at all.
func (r *ScriptIDRotator) Blacklist(sid string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.ids) <= 1 {
		return
	}
	r.blacklist[sid] = r.now().Add(r.ttl)
}

// Healthy reports how many IDs are currently usable.
func (r *ScriptIDRotator) Healthy() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	count := 0
	for _, id := range r.ids {
		if !r.blacklistedLocked(id) {
			count++
		}
	}
	return count
}

func (r *ScriptIDRotator) blacklistedLocked(sid string) bool {
	until, ok := r.blacklist[sid]
	if !ok {
		return false
	}
	if r.now().After(until) {
		delete(r.blacklist, sid)
		return false
	}
	return true
}

func (r *ScriptIDRotator) pruneLocked() {
	now := r.now()
	for sid, until := range r.blacklist {
		if now.After(until) {
			delete(r.blacklist, sid)
		}
	}
}
