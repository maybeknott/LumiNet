package scanner

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

func listenerPort(t *testing.T, listener net.Listener) int {
	t.Helper()
	_, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split listener address: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse listener port: %v", err)
	}
	return port
}

func TestSynScanner_LocalControlledPorts(t *testing.T) {
	openListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen open fixture: %v", err)
	}
	defer openListener.Close()
	openPort := listenerPort(t, openListener)

	closedListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen closed fixture: %v", err)
	}
	closedPort := listenerPort(t, closedListener)
	if err := closedListener.Close(); err != nil {
		t.Fatalf("close closed fixture: %v", err)
	}

	scanner := NewSynScanner("127.0.0.1", []int{openPort, closedPort})
	scanner.Timeout = time.Second
	results, err := scanner.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results[0].Port != openPort || results[0].Status != PortOpen {
		t.Fatalf("open fixture result = %+v, want port %d open", results[0], openPort)
	}
	if results[1].Port != closedPort || (results[1].Status != PortClosed && results[1].Status != PortFiltered) {
		t.Fatalf("closed fixture result = %+v, want port %d closed/filtered", results[1], closedPort)
	}
}

func TestSynScannerRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*SynScanner)
	}{
		{name: "empty target", mutate: func(s *SynScanner) { s.Target = "" }},
		{name: "zero workers", mutate: func(s *SynScanner) { s.Workers = 0 }},
		{name: "zero timeout", mutate: func(s *SynScanner) { s.Timeout = 0 }},
		{name: "low port", mutate: func(s *SynScanner) { s.Ports = []int{0} }},
		{name: "high port", mutate: func(s *SynScanner) { s.Ports = []int{65536} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := NewSynScanner("127.0.0.1", []int{443})
			tt.mutate(scanner)
			if _, err := scanner.Scan(context.Background()); err == nil {
				t.Fatal("invalid scanner configuration unexpectedly succeeded")
			}
		})
	}
}

func TestSynScannerHonorsCanceledContext(t *testing.T) {
	scanner := NewSynScanner("203.0.113.1", []int{443})
	scanner.Timeout = 5 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	results, err := scanner.Scan(ctx)
	if err != nil {
		t.Fatalf("Scan returned configuration error: %v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("canceled scan did not stop promptly")
	}
	if len(results) != 1 || results[0].Status != PortFiltered {
		t.Fatalf("canceled scan result = %+v, want one filtered result", results)
	}
}
