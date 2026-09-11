package serverless

import (
	"bytes"
	"net"
)

// ServerlessProfile determines packet delay characteristics for zero-VPS direct evasion.
type ServerlessProfile string

const (
	ServerlessProfileLowDelay  ServerlessProfile = "LowDelay"
	ServerlessProfileHighDelay ServerlessProfile = "HighDelay"
)

// ShaperFragment describes a segment of shaped payload and its delay hint in milliseconds.
type ShaperFragment struct {
	Payload []byte `json:"payload"`
	DelayMs int    `json:"delay_ms"`
}

// ServerlessShaperConfig configures the direct connection shaper.
type ServerlessShaperConfig struct {
	Profile                ServerlessProfile `json:"profile"`
	TLSRecordSplit         int               `json:"tls_record_split"`
	SNISplitOffset         int               `json:"sni_split_offset"`
	MaxSplitTLS            int               `json:"max_split_tls"`
	MaxSplitTCP            int               `json:"max_split_tcp"`
	HappyEyeballsIPv6First bool              `json:"happy_eyeballs_ipv6_first"`
	UDPNoiseEnabled        bool              `json:"udp_noise_enabled"`
	UDPNoiseMinLen         int               `json:"udp_noise_min_len"`
	UDPNoiseMaxLen         int               `json:"udp_noise_max_len"`
	UDPNoiseResetInterval  int               `json:"udp_noise_reset_interval"`
}

// DefaultServerlessShaperConfig returns tested default parameters.
func DefaultServerlessShaperConfig() ServerlessShaperConfig {
	return ServerlessShaperConfig{
		Profile:                ServerlessProfileLowDelay,
		TLSRecordSplit:         5,
		SNISplitOffset:         43,
		MaxSplitTLS:            522,
		MaxSplitTCP:            419,
		HappyEyeballsIPv6First: true,
		UDPNoiseEnabled:        true,
		UDPNoiseMinLen:         1200,
		UDPNoiseMaxLen:         1230,
		UDPNoiseResetInterval:  28,
	}
}

// ServerlessDirectShaper shapes outbound packets for direct DPI evasion.
type ServerlessDirectShaper struct{}

// NewServerlessDirectShaper creates a new shaper instance.
func NewServerlessDirectShaper() *ServerlessDirectShaper {
	return &ServerlessDirectShaper{}
}

// IsCensorshipSink checks whether an IP matches Iranian national censorship redirection sinks:
// - IPv4: 10.10.34.0/24
// - IPv6: 2001:4188:2:600::/64
func (s *ServerlessDirectShaper) IsCensorshipSink(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		return v4[0] == 10 && v4[1] == 10 && v4[2] == 34
	}
	if len(ip) == net.IPv6len {
		// 2001:4188:0002:0600::/64
		return ip[0] == 0x20 && ip[1] == 0x01 &&
			ip[2] == 0x41 && ip[3] == 0x88 &&
			ip[4] == 0x00 && ip[5] == 0x02 &&
			ip[6] == 0x06 && ip[7] == 0x00
	}
	return false
}

// ShapeClientHello slices a TLS ClientHello packet across record boundaries, SNI offsets,
// and 1-byte micro-fragments with profile-directed pacing.
func (s *ServerlessDirectShaper) ShapeClientHello(payload []byte, cfg ServerlessShaperConfig) []ShaperFragment {
	if len(payload) == 0 {
		return nil
	}

	recordSplit := cfg.TLSRecordSplit
	if recordSplit <= 0 {
		recordSplit = 5
	}

	if len(payload) <= recordSplit {
		return []ShaperFragment{{Payload: payload, DelayMs: 0}}
	}

	fragments := make([]ShaperFragment, 0)

	// 1. Record header (0..recordSplit)
	fragments = append(fragments, ShaperFragment{
		Payload: payload[:recordSplit],
		DelayMs: 0,
	})

	currOffset := recordSplit

	// 2. Prefix up to SNI boundary (recordSplit..sniOffset)
	sniBoundary := cfg.SNISplitOffset
	if sniBoundary > len(payload) {
		sniBoundary = len(payload)
	}
	if sniBoundary > currOffset {
		fragments = append(fragments, ShaperFragment{
			Payload: payload[currOffset:sniBoundary],
			DelayMs: s.CalculateDelay(0, cfg.Profile),
		})
		currOffset = sniBoundary
	}

	// 3. Remainder split into 1-byte micro-chunks up to MaxSplitTLS
	sliceIdx := 1
	maxSplit := cfg.MaxSplitTLS
	if maxSplit <= 0 {
		maxSplit = 522
	}

	for currOffset < len(payload) && currOffset < maxSplit {
		chunkLen := 1
		if currOffset+chunkLen > len(payload) {
			chunkLen = len(payload) - currOffset
		}
		delay := s.CalculateDelay(sliceIdx, cfg.Profile)
		fragments = append(fragments, ShaperFragment{
			Payload: payload[currOffset : currOffset+chunkLen],
			DelayMs: delay,
		})
		currOffset += chunkLen
		sliceIdx++
	}

	// 4. Any leftover beyond MaxSplitTLS as a final contiguous fragment
	if currOffset < len(payload) {
		fragments = append(fragments, ShaperFragment{
			Payload: payload[currOffset:],
			DelayMs: s.CalculateDelay(sliceIdx, cfg.Profile),
		})
	}

	return fragments
}

// ShapeTCPStream fragments generic TCP stream data up to MaxSplitTCP.
func (s *ServerlessDirectShaper) ShapeTCPStream(payload []byte, cfg ServerlessShaperConfig) []ShaperFragment {
	if len(payload) == 0 {
		return nil
	}

	fragments := make([]ShaperFragment, 0)
	currOffset := 0
	sliceIdx := 0
	maxSplit := cfg.MaxSplitTCP
	if maxSplit <= 0 {
		maxSplit = 419
	}

	for currOffset < len(payload) && currOffset < maxSplit {
		chunkLen := 1
		if currOffset+chunkLen > len(payload) {
			chunkLen = len(payload) - currOffset
		}
		delay := 0
		if currOffset > 0 {
			delay = s.CalculateDelay(sliceIdx, cfg.Profile)
		}
		fragments = append(fragments, ShaperFragment{
			Payload: payload[currOffset : currOffset+chunkLen],
			DelayMs: delay,
		})
		currOffset += chunkLen
		sliceIdx++
	}

	if currOffset < len(payload) {
		fragments = append(fragments, ShaperFragment{
			Payload: payload[currOffset:],
			DelayMs: s.CalculateDelay(sliceIdx, cfg.Profile),
		})
	}

	return fragments
}

// CalculateDelay computes delay for a given slice index according to profile.
func (s *ServerlessDirectShaper) CalculateDelay(sliceIdx int, profile ServerlessProfile) int {
	switch profile {
	case ServerlessProfileLowDelay:
		return 1
	case ServerlessProfileHighDelay:
		// Rhythmic 400ms stall every 10 slices, otherwise 1ms
		if sliceIdx > 0 && sliceIdx%10 == 0 {
			return 400
		}
		return 1
	default:
		return 1
	}
}

// GenerateUDPNoise creates a randomized noise packet within configured length range.
func (s *ServerlessDirectShaper) GenerateUDPNoise(counter uint32, cfg ServerlessShaperConfig) []byte {
	if !cfg.UDPNoiseEnabled {
		return nil
	}

	minLen := cfg.UDPNoiseMinLen
	maxLen := cfg.UDPNoiseMaxLen
	if minLen <= 0 {
		minLen = 1200
	}
	if maxLen <= minLen {
		maxLen = minLen + 30
	}

	lenRange := maxLen - minLen
	targetLen := minLen + int((counter*7)%uint32(lenRange))

	noise := make([]byte, targetLen)
	for i := range noise {
		noise[i] = byte((int(counter) + i*31) & 0xFF)
	}
	return noise
}

// ReconstructFragments reconstructs the contiguous byte payload from fragments.
func ReconstructFragments(fragments []ShaperFragment) []byte {
	var buf bytes.Buffer
	for _, f := range fragments {
		buf.Write(f.Payload)
	}
	return buf.Bytes()
}
