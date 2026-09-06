package immunization

import (
	"encoding/json"
	"strings"
	"sync"
	"time"
)

// AntibodyStore provides thread-safe persistent memory of active evasion antibodies.
type AntibodyStore struct {
	mu         sync.RWMutex
	antibodies map[string]*EvasionAntibody
}

// NewAntibodyStore creates an empty antibody memory store.
func NewAntibodyStore() *AntibodyStore {
	return &AntibodyStore{
		antibodies: make(map[string]*EvasionAntibody),
	}
}

// Put adds or updates an antibody in the store.
func (s *AntibodyStore) Put(ab *EvasionAntibody) {
	if ab == nil || ab.TargetPattern == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	key := strings.ToLower(strings.TrimSpace(ab.TargetPattern))
	if ab.DiscoveredAt.IsZero() {
		ab.DiscoveredAt = time.Now()
	}
	ab.LastUsedAt = time.Now()
	s.antibodies[key] = ab
}

// Get finds the best-matching antibody for a target host.
// It supports exact match followed by wildcard suffix match (e.g. *.example.com).
func (s *AntibodyStore) Get(host string) (*EvasionAntibody, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := strings.ToLower(strings.TrimSpace(host))
	// 1. Direct exact match
	if ab, exists := s.antibodies[key]; exists {
		return ab, true
	}

	// 2. Wildcard domain match
	for pattern, ab := range s.antibodies {
		if strings.HasPrefix(pattern, "*.") {
			suffix := pattern[1:] // e.g. ".example.com"
			if strings.HasSuffix(key, suffix) {
				return ab, true
			}
		}
	}

	return nil, false
}

// RecordSuccess increments the success count and recalculates the efficacy score.
func (s *AntibodyStore) RecordSuccess(host string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if ab, found := s.getUnsafe(host); found {
		ab.SuccessCount++
		ab.LastUsedAt = time.Now()
		total := float64(ab.SuccessCount + ab.FailureCount)
		if total > 0 {
			ab.EfficacyScore = float64(ab.SuccessCount) / total
		}
	}
}

// RecordFailure increments the failure count and updates the efficacy score.
func (s *AntibodyStore) RecordFailure(host string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if ab, found := s.getUnsafe(host); found {
		ab.FailureCount++
		ab.LastUsedAt = time.Now()
		total := float64(ab.SuccessCount + ab.FailureCount)
		if total > 0 {
			ab.EfficacyScore = float64(ab.SuccessCount) / total
		}
	}
}

// List returns a snapshot of all registered antibodies.
func (s *AntibodyStore) List() []*EvasionAntibody {
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := make([]*EvasionAntibody, 0, len(s.antibodies))
	for _, ab := range s.antibodies {
		res = append(res, ab)
	}
	return res
}

// Len returns the count of active antibodies in memory.
func (s *AntibodyStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.antibodies)
}

// ExportJSON serializes all current antibodies for peer-to-peer gossip broadcast.
func (s *AntibodyStore) ExportJSON() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return json.Marshal(s.antibodies)
}

// ImportJSON ingests antibodies from a JSON payload.
func (s *AntibodyStore) ImportJSON(data []byte) error {
	var incoming map[string]*EvasionAntibody
	if err := json.Unmarshal(data, &incoming); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range incoming {
		if v != nil {
			s.antibodies[strings.ToLower(k)] = v
		}
	}
	return nil
}

func (s *AntibodyStore) getUnsafe(host string) (*EvasionAntibody, bool) {
	key := strings.ToLower(strings.TrimSpace(host))
	if ab, exists := s.antibodies[key]; exists {
		return ab, true
	}
	for pattern, ab := range s.antibodies {
		if strings.HasPrefix(pattern, "*.") {
			suffix := pattern[1:]
			if strings.HasSuffix(key, suffix) {
				return ab, true
			}
		}
	}
	return nil, false
}
