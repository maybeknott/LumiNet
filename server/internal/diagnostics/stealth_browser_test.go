package diagnostics

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestStealthBrowserAudit(t *testing.T) {
	scrambler := NewFingerprintScrambler(42)
	canvasScript := scrambler.GenerateCanvasNoiseScript()
	audioScript := scrambler.GenerateAudioNoiseScript()

	if !strings.Contains(canvasScript, "HTMLCanvasElement.prototype.toDataURL") {
		t.Errorf("Expected Canvas script to hook toDataURL")
	}

	if !strings.Contains(audioScript, "AudioBuffer.prototype.getChannelData") {
		t.Errorf("Expected Audio script to hook getChannelData")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	opts := StealthBrowserAudit{
		UserAgent:        "Mozilla/5.0 StealthBrowser/1.0",
		AntiFingerprint:  true,
		CanvasObfuscated: true,
		AudioObfuscated:  true,
	}

	details, score, err := RunStealthAudit(ctx, "https://example.com/audit", opts)
	if err != nil {
		t.Fatalf("Failed to run stealth browser audit: %v", err)
	}

	if score != 100.0 {
		t.Errorf("Expected score 100.0, got %f", score)
	}

	if !strings.Contains(details, "StealthBrowser/1.0") {
		t.Errorf("Audit details missing custom user-agent signature")
	}
}
