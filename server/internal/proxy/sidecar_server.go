package proxy

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type SidecarServer struct {
	listenAddr string
	tokenHash  string
	startTime  time.Time
	mu         sync.Mutex
	srv        *http.Server
	governor   *SafetyGovernor
}

func NewSidecarServer(addr, token string, governor *SafetyGovernor) *SidecarServer {
	return &SidecarServer{
		listenAddr: addr,
		tokenHash:  token,
		startTime:  time.Now(),
		governor:   governor,
	}
}

func (s *SidecarServer) verifyToken(r *http.Request) bool {
	authHeader := r.Header.Get("Authorization")
	var token string
	if strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimPrefix(authHeader, "Bearer ")
	} else {
		token = r.Header.Get("X-Sidecar-Token")
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(s.tokenHash)) == 1
}

func (s *SidecarServer) Start() error {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		if !s.verifyToken(r) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"state":     "running",
			"version":   1,
			"uptime_ms": time.Since(s.startTime).Milliseconds(),
		})
	})

	mux.HandleFunc("/api/dns", func(w http.ResponseWriter, r *http.Request) {
		if !s.verifyToken(r) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			Domain                 string         `json:"domain"`
			SafetySettings         SafetySettings `json:"safety_settings"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		// Enforce safety governor check on DNS target
		if s.governor != nil {
			if err := s.governor.ValidateScan(req.Domain, req.SafetySettings); err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
				return
			}
		}

		w.Header().Set("Content-Type", "application/x-ndjson")
		flusher, ok := w.(http.Flusher)

		// Resolve domain and stream IP records as NDJSON
		ips, err := net.LookupIP(req.Domain)
		if err != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"domain": req.Domain,
				"error":  err.Error(),
			})
			return
		}

		for _, ip := range ips {
			record := map[string]any{
				"domain":   req.Domain,
				"resolved": ip.String(),
				"latency":  12 * time.Millisecond, // mock resolution speed
			}
			_ = json.NewEncoder(w).Encode(record)
			if ok {
				flusher.Flush()
			}
			time.Sleep(50 * time.Millisecond)
		}
	})

	mux.HandleFunc("/api/shutdown", func(w http.ResponseWriter, r *http.Request) {
		if !s.verifyToken(r) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"shutdown_initiated"}`))
		go func() {
			time.Sleep(200 * time.Millisecond)
			_ = s.Stop()
		}()
	})

	s.mu.Lock()
	s.srv = &http.Server{
		Addr:    s.listenAddr,
		Handler: mux,
	}
	s.mu.Unlock()

	// Run listener
	err := s.srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (s *SidecarServer) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		err := s.srv.Shutdown(ctx)
		s.srv = nil
		return err
	}
	return nil
}
