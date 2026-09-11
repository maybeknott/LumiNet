package immunization

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/maybeknott/luminet/internal/protocols/tlsfragment"
)

// CandidateProfile represents a trial configuration during antibody synthesis.
type CandidateProfile struct {
	Name            string
	DesyncOffset    int
	DesyncDelayMs   int
	SplitAtSNI      bool
	FakePacketFlags uint8
	FakePacketTTL   uint8
	HeaderMutation  bool
}

// ProberFunc abstracts dial testing for flexible mockability and zero network leakage during testing.
type ProberFunc func(ctx context.Context, target string, port int, candidate CandidateProfile) error

// Synthesizer discovers winning evasion recipes through adaptive ladder testing.
type Synthesizer struct {
	customProber ProberFunc
}

// NewSynthesizer creates a new antibody synthesizer.
func NewSynthesizer() *Synthesizer {
	return &Synthesizer{}
}

// SetProber allows injecting a custom prober for tests or custom dial pipelines.
func (s *Synthesizer) SetProber(prober ProberFunc) {
	s.customProber = prober
}

// CandidateLadder defines the graduated succession of evasion techniques evaluated against DPI.
var CandidateLadder = []CandidateProfile{
	{
		Name:          "SNI-Boundary-Desync",
		SplitAtSNI:    true,
		DesyncDelayMs: 25,
	},
	{
		Name:          "Early-Offset-Split-2",
		DesyncOffset:  2,
		DesyncDelayMs: 30,
	},
	{
		Name:          "Early-Offset-Split-3",
		DesyncOffset:  3,
		DesyncDelayMs: 35,
	},
	{
		Name:          "Mid-Header-Split-5",
		DesyncOffset:  5,
		DesyncDelayMs: 40,
	},
	{
		Name:            "Decoy-RST-Injection",
		DesyncOffset:    3,
		DesyncDelayMs:   30,
		FakePacketFlags: 0x04, // RST
		FakePacketTTL:   3,
	},
	{
		Name:           "HTTP-Case-Mutation",
		DesyncOffset:   1,
		DesyncDelayMs:  20,
		HeaderMutation: true,
	},
}

// Synthesize tests candidates against target:port and returns the winning antibody.
func (s *Synthesizer) Synthesize(ctx context.Context, target string, port int, symptom InterferenceType) (*EvasionAntibody, error) {
	if port <= 0 {
		port = 443
	}

	for _, cand := range CandidateLadder {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		err := s.testCandidate(ctx, target, port, cand)
		if err == nil {
			// Found winning evasion recipe!
			antibody := &EvasionAntibody{
				TargetPattern:    target,
				InterferenceType: symptom,
				DesyncOffset:     cand.DesyncOffset,
				DesyncDelayMs:    cand.DesyncDelayMs,
				SplitAtSNI:       cand.SplitAtSNI,
				FakePacketFlags:  cand.FakePacketFlags,
				FakePacketTTL:    cand.FakePacketTTL,
				HeaderMutation:   cand.HeaderMutation,
				EfficacyScore:    1.0,
				SuccessCount:     1,
				FailureCount:     0,
				DiscoveredAt:     time.Now(),
				LastUsedAt:       time.Now(),
			}
			return antibody, nil
		}
	}

	// Fallback antibody if none succeeded cleanly
	return &EvasionAntibody{
		TargetPattern:    target,
		InterferenceType: symptom,
		DesyncOffset:     2,
		DesyncDelayMs:    50,
		SplitAtSNI:       true,
		EfficacyScore:    0.5,
		SuccessCount:     0,
		FailureCount:     0,
		DiscoveredAt:     time.Now(),
		LastUsedAt:       time.Now(),
	}, fmt.Errorf("synthesis ladder exhausted without definitive pass; generated conservative fallback antibody")
}

// CalculateSNISplitOffset determines the exact byte split offset for a TLS ClientHello.
func CalculateSNISplitOffset(clientHello []byte) int {
	start, _ := tlsfragment.SNIHostRange(clientHello)
	if start > 0 {
		return start
	}
	// Default split before SNI extension header
	if len(clientHello) > 5 {
		return 5
	}
	return 2
}

func (s *Synthesizer) testCandidate(ctx context.Context, target string, port int, cand CandidateProfile) error {
	if s.customProber != nil {
		return s.customProber(ctx, target, port, cand)
	}

	// Default TCP dial probe
	addr := net.JoinHostPort(target, fmt.Sprintf("%d", port))
	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	// If successful handshake, verify writing split buffer with delay
	testPayload := []byte("GET / HTTP/1.1\r\nHost: " + target + "\r\n\r\n")
	offset := cand.DesyncOffset
	if offset <= 0 || offset >= len(testPayload) {
		offset = 3
	}

	if _, err := conn.Write(testPayload[:offset]); err != nil {
		return err
	}
	if cand.DesyncDelayMs > 0 {
		time.Sleep(time.Duration(cand.DesyncDelayMs) * time.Millisecond)
	}
	if _, err := conn.Write(testPayload[offset:]); err != nil {
		return err
	}

	return nil
}
