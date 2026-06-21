package diagnostics

import (
	"context"
	"testing"
	"time"
)

func TestDiagnostics_ARQ(t *testing.T) {
	pipeline := NewPipeline()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	job := &DiagnosticJob{
		Type:    MetricARQ,
		Target:  "loopback",
		Timeout: 3 * time.Second,
	}

	result, err := pipeline.Run(ctx, job)
	if err != nil {
		t.Fatalf("Failed to run ARQ diagnostic: %v", err)
	}

	if !result.Success {
		t.Fatalf("ARQ diagnostic run was unsuccessful: %s", result.RawOutput)
	}

	if result.LatencyMs < 0 {
		t.Errorf("Expected non-negative latency, got %f", result.LatencyMs)
	}

	if val, ok := result.Metrics["payload_size"]; !ok || val.(int) <= 0 {
		t.Errorf("Expected payload_size metric to be present and positive, got %v", val)
	}

	t.Logf("ARQ Diagnostic raw output: %s", result.RawOutput)
}

func TestDiagnostics_Stealth(t *testing.T) {
	pipeline := NewPipeline()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	job := &DiagnosticJob{
		Type:    MetricStealth,
		Target:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
		Timeout: 3 * time.Second,
		Options: map[string]string{
			"anti_fingerprint":  "true",
			"canvas_obfuscated": "true",
			"audio_obfuscated":  "true",
		},
	}

	result, err := pipeline.Run(ctx, job)
	if err != nil {
		t.Fatalf("Failed to run Stealth diagnostic: %v", err)
	}

	if !result.Success {
		t.Fatalf("Stealth diagnostic run was unsuccessful: %s", result.RawOutput)
	}

	if score, ok := result.Metrics["score"]; !ok || score.(float64) < 50.0 {
		t.Errorf("Expected high stealth score, got %v", score)
	}

	t.Logf("Stealth Diagnostic raw output:\n%s", result.RawOutput)
}

