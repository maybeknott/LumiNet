package diagnostics

import (
	"context"
	"fmt"
	"math/rand"
	"time"
)

// FingerprintScrambler defines techniques to randomize client browser telemetry.
type FingerprintScrambler struct {
	NoiseSeed int64
}

// NewFingerprintScrambler creates a new instance of FingerprintScrambler.
func NewFingerprintScrambler(seed int64) *FingerprintScrambler {
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	return &FingerprintScrambler{NoiseSeed: seed}
}

// GenerateCanvasNoiseScript returns a JavaScript snippet that scrambles HTML5 Canvas
// data URLs on-the-fly to prevent tracking via hardware graphic device fingerprints.
func (s *FingerprintScrambler) GenerateCanvasNoiseScript() string {
	r := rand.New(rand.NewSource(s.NoiseSeed))
	rFactor := r.Float64() * 0.0001
	return fmt.Sprintf(`
		(function() {
			const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
			HTMLCanvasElement.prototype.toDataURL = function() {
				const ctx = this.getContext('2d');
				if (ctx) {
					// Inject tiny imperceptible color noise to shift canvas hash signature
					const imgData = ctx.getImageData(0, 0, this.width, this.height);
					for (let i = 0; i < imgData.data.length; i += 4) {
						imgData.data[i] = Math.min(255, Math.max(0, imgData.data[i] + Math.round((Math.random() - 0.5) * %f)));
					}
					ctx.putImageData(imgData, 0, 0);
				}
				return originalToDataURL.apply(this, arguments);
			};
		})();
	`, rFactor)
}

// GenerateAudioNoiseScript returns a JavaScript snippet that introduces sub-audible
// noise into the Web Audio API channel buffers to defeat audio-based fingerprinting.
func (s *FingerprintScrambler) GenerateAudioNoiseScript() string {
	return `
		(function() {
			const originalGetChannelData = AudioBuffer.prototype.getChannelData;
			AudioBuffer.prototype.getChannelData = function() {
				const buffer = originalGetChannelData.apply(this, arguments);
				for (let i = 0; i < buffer.length; i += 100) {
					buffer[i] += (Math.random() - 0.5) * 0.0000001; // Add sub-audible jitter noise
				}
				return buffer;
			};
		})();
	`
}

// StealthBrowserAudit simulates a headless browser diagnostic session,
// returning the security/obfuscation grade of the current configuration.
type StealthBrowserAudit struct {
	UserAgent        string
	AntiFingerprint  bool
	CanvasObfuscated bool
	AudioObfuscated  bool
}

// RunStealthAudit evaluates the defensive posture of the current client fingerprint settings.
func RunStealthAudit(ctx context.Context, target string, opts StealthBrowserAudit) (string, float64, error) {
	select {
	case <-ctx.Done():
		return "", 0, ctx.Err()
	default:
	}

	score := 0.0
	details := "Stealth Headless Profile Diagnostics:\n"

	if opts.UserAgent != "" {
		details += fmt.Sprintf("  [+] Configured custom User-Agent: %s\n", opts.UserAgent)
		score += 20.0
	} else {
		details += "  [-] Missing user-agent override (using browser default)\n"
	}

	if opts.AntiFingerprint {
		details += "  [+] Enabled navigator override masks (AutomationControlled = false)\n"
		score += 30.0
	}

	if opts.CanvasObfuscated {
		details += "  [+] Enabled Canvas noise injection helper\n"
		score += 25.0
	}

	if opts.AudioObfuscated {
		details += "  [+] Enabled Web Audio API buffer jitter noise helper\n"
		score += 25.0
	}

	details += fmt.Sprintf("  [=] Client Stealth Integrity Grade Score: %.1f%%\n", score)
	return details, score, nil
}

// StealthBrowserOptions defines settings for LaunchStealthAudit.
type StealthBrowserOptions struct {
	ProxyAddr string
	UserAgent string
}

// LaunchStealthAudit is a blueprint compatibility wrapper for RunStealthAudit.
func LaunchStealthAudit(ctx context.Context, targetURL string, opts StealthBrowserOptions) error {
	auditOpts := StealthBrowserAudit{
		UserAgent:        opts.UserAgent,
		AntiFingerprint:  true,
		CanvasObfuscated: true,
		AudioObfuscated:  true,
	}
	_, _, err := RunStealthAudit(ctx, targetURL, auditOpts)
	return err
}

