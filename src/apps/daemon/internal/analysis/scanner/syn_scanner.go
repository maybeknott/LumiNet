package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// PortStatus defines the state of a scanned port.
type PortStatus string

const (
	PortOpen     PortStatus = "open"
	PortClosed   PortStatus = "closed"
	PortFiltered PortStatus = "filtered"
)

// SynScanResult holds port audit results.
type SynScanResult struct {
	Port    int           `json:"port"`
	Status  PortStatus    `json:"status"`
	Latency time.Duration `json:"latency"`
}

// SynScanner audits target port accessibility.
type SynScanner struct {
	Target  string
	Ports   []int
	Timeout time.Duration
	Workers int
}

// NewSynScanner creates an instance of SynScanner.
func NewSynScanner(target string, ports []int) *SynScanner {
	return &SynScanner{
		Target:  target,
		Ports:   append([]int(nil), ports...),
		Timeout: time.Second,
		Workers: 50,
	}
}

func (s *SynScanner) validate() error {
	if s == nil {
		return errors.New("scanner is nil")
	}
	if s.Target == "" {
		return errors.New("scan target is required")
	}
	if s.Workers <= 0 {
		return fmt.Errorf("scanner workers must be positive, got %d", s.Workers)
	}
	if s.Timeout <= 0 {
		return fmt.Errorf("scanner timeout must be positive, got %s", s.Timeout)
	}
	for _, port := range s.Ports {
		if port < 1 || port > 65535 {
			return fmt.Errorf("scan port %d is outside 1..65535", port)
		}
	}
	return nil
}

// Scan sweeps target ports concurrently.
func (s *SynScanner) Scan(ctx context.Context) ([]SynScanResult, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if ctx == nil {
		return nil, errors.New("scan context is required")
	}

	results := make([]SynScanResult, len(s.Ports))
	var wg sync.WaitGroup
	sem := make(chan struct{}, s.Workers)
	dialer := net.Dialer{Timeout: s.Timeout}

	for i, port := range s.Ports {
		wg.Add(1)
		go func(idx int, p int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results[idx] = SynScanResult{Port: p, Status: PortFiltered}
				return
			}
			defer func() { <-sem }()

			start := time.Now()
			addr := net.JoinHostPort(s.Target, fmt.Sprintf("%d", p))
			conn, err := dialer.DialContext(ctx, "tcp", addr)
			elapsed := time.Since(start)

			if err != nil {
				status := PortFiltered
				if ctx.Err() == nil {
					var netErr net.Error
					if errors.As(err, &netErr) && !netErr.Timeout() {
						status = PortClosed
					}
				}
				results[idx] = SynScanResult{Port: p, Status: status, Latency: elapsed}
				return
			}
			_ = conn.Close()
			results[idx] = SynScanResult{Port: p, Status: PortOpen, Latency: elapsed}
		}(i, port)
	}

	wg.Wait()
	return results, nil
}
