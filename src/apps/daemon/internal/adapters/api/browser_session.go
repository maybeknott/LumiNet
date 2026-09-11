package api

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

const browserSessionTTL = 30 * time.Minute

type browserSessionIssuer struct {
	mu     sync.Mutex
	tokens map[string]time.Time
}

func newBrowserSessionIssuer() *browserSessionIssuer {
	return &browserSessionIssuer{tokens: make(map[string]time.Time)}
}

func (i *browserSessionIssuer) issue(now time.Time) (string, time.Time, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	expiresAt := now.Add(browserSessionTTL)
	i.mu.Lock()
	defer i.mu.Unlock()
	for value, expiry := range i.tokens {
		if !expiry.After(now) {
			delete(i.tokens, value)
		}
	}
	i.tokens[token] = expiresAt
	return token, expiresAt, nil
}

func (i *browserSessionIssuer) valid(token string, now time.Time) bool {
	if token == "" {
		return false
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	expiresAt, ok := i.tokens[token]
	if !ok || !expiresAt.After(now) {
		delete(i.tokens, token)
		return false
	}
	return true
}
