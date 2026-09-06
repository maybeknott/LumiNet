package immunization

import (
	"context"
	"errors"
	"syscall"
	"testing"
	"time"
)

func TestDetector_MiddleboxInterference(t *testing.T) {
	d := NewDetector()

	// 1. RST Injection during TLS ClientHello
	rstErr := errors.New("read tcp: connection reset by peer")
	timing := PacketTimingProfile{
		Elapsed:        40 * time.Millisecond,
		BytesSent:      280,
		BytesReceived:  0,
		TLSClientHello: true,
	}
	symptom, reason := d.DetectInterference(rstErr, timing)
	if symptom != InterferenceSNIReset {
		t.Errorf("expected InterferenceSNIReset, got %v (%s)", symptom, reason)
	}

	// 2. Silent Handshake Drop
	timeoutErr := errors.New("dial tcp: i/o timeout")
	timeoutTiming := PacketTimingProfile{
		Elapsed:       3000 * time.Millisecond,
		BytesSent:     300,
		BytesReceived: 0,
	}
	symptom2, reason2 := d.DetectInterference(timeoutErr, timeoutTiming)
	if symptom2 != InterferenceHandshakeDrop {
		t.Errorf("expected InterferenceHandshakeDrop, got %v (%s)", symptom2, reason2)
	}

	// 3. HTTP Blockpage
	blockpageTiming := PacketTimingProfile{
		StatusCode:   403,
		ResponseBody: "<html><body>Access Denied: Content Filtered by Administrator Firewall</body></html>",
	}
	symptom3, _ := d.DetectInterference(nil, blockpageTiming)
	if symptom3 != InterferenceHTTPBlockpage {
		t.Errorf("expected InterferenceHTTPBlockpage, got %v", symptom3)
	}

	// 4. Normal connection
	cleanTiming := PacketTimingProfile{
		StatusCode:   200,
		ResponseBody: "<html><body>Welcome</body></html>",
	}
	symptom4, _ := d.DetectInterference(nil, cleanTiming)
	if symptom4 != InterferenceNone {
		t.Errorf("expected InterferenceNone, got %v", symptom4)
	}
}

func TestSynthesizer_LadderProgression(t *testing.T) {
	synth := NewSynthesizer()

	// Configure mock prober that fails on SNI split, but succeeds on Early-Offset-Split-2
	synth.SetProber(func(ctx context.Context, target string, port int, candidate CandidateProfile) error {
		if candidate.Name == "Early-Offset-Split-2" {
			return nil // success
		}
		return syscall.ECONNRESET
	})

	ctx := context.Background()
	ab, err := synth.Synthesize(ctx, "blocked.target.com", 443, InterferenceRSTInjection)
	if err != nil {
		t.Fatalf("Synthesize failed: %v", err)
	}

	if ab.DesyncOffset != 2 {
		t.Errorf("DesyncOffset = %d, want 2", ab.DesyncOffset)
	}
	if ab.TargetPattern != "blocked.target.com" {
		t.Errorf("TargetPattern = %s, want blocked.target.com", ab.TargetPattern)
	}
	if ab.EfficacyScore != 1.0 {
		t.Errorf("EfficacyScore = %f, want 1.0", ab.EfficacyScore)
	}
}

func TestAntibodyStore_ExactAndWildcardMatching(t *testing.T) {
	store := NewAntibodyStore()

	exactAB := &EvasionAntibody{
		TargetPattern: "restricted.site.org",
		DesyncOffset:  3,
		DesyncDelayMs: 25,
	}
	wildcardAB := &EvasionAntibody{
		TargetPattern: "*.censorgrid.net",
		DesyncOffset:  5,
		DesyncDelayMs: 40,
	}

	store.Put(exactAB)
	store.Put(wildcardAB)

	// Exact lookup
	found1, ok1 := store.Get("restricted.site.org")
	if !ok1 || found1.DesyncOffset != 3 {
		t.Errorf("exact match failed: found=%v, ok=%v", found1, ok1)
	}

	// Wildcard lookup
	found2, ok2 := store.Get("api.sub.censorgrid.net")
	if !ok2 || found2.DesyncOffset != 5 {
		t.Errorf("wildcard match failed: found=%v, ok=%v", found2, ok2)
	}

	// Non-matching
	_, ok3 := store.Get("unrestricted.com")
	if ok3 {
		t.Errorf("expected no match for unrestricted.com")
	}

	// Efficacy score tracking
	store.RecordSuccess("restricted.site.org")
	store.RecordFailure("restricted.site.org")
	updated, _ := store.Get("restricted.site.org")
	if updated.SuccessCount != 1 || updated.FailureCount != 1 || updated.EfficacyScore != 0.5 {
		t.Errorf("unexpected score update: %+v", updated)
	}

	// JSON Export/Import
	data, err := store.ExportJSON()
	if err != nil {
		t.Fatalf("ExportJSON: %v", err)
	}

	store2 := NewAntibodyStore()
	if err := store2.ImportJSON(data); err != nil {
		t.Fatalf("ImportJSON: %v", err)
	}
	if store2.Len() != 2 {
		t.Errorf("store2.Len = %d, want 2", store2.Len())
	}
}
