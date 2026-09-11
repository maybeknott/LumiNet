package immunization

import (
	"time"
)

// InterferenceType classifies the type of Deep Packet Inspection (DPI)
// middlebox interference detected on a network flow.
type InterferenceType string

const (
	InterferenceNone              InterferenceType = "none"
	InterferenceRSTInjection      InterferenceType = "rst_injection"
	InterferenceSNIReset          InterferenceType = "sni_reset"
	InterferenceHandshakeDrop     InterferenceType = "handshake_drop"
	InterferenceHTTPBlockpage     InterferenceType = "http_blockpage"
	InterferenceConnectionTimeout InterferenceType = "connection_timeout"
)

// EvasionAntibody represents a verified set of evasion parameters synthesized
// to bypass middlebox interference for a specific host, domain, or pattern.
type EvasionAntibody struct {
	// TargetPattern is the domain pattern or CIDR (e.g., "*.example.org", "example.com").
	TargetPattern string `json:"target_pattern"`
	// InterferenceType is the middlebox interference symptom this antibody neutralizes.
	InterferenceType InterferenceType `json:"interference_type"`
	// DesyncOffset is the byte position where the TCP stream is fragmented (e.g., 2, 3, 5).
	DesyncOffset int `json:"desync_offset"`
	// DesyncDelayMs is the sleep duration (in milliseconds) between segments.
	DesyncDelayMs int `json:"desync_delay_ms"`
	// SplitAtSNI indicates whether fragmentation occurs at the TLS SNI extension boundary.
	SplitAtSNI bool `json:"split_at_sni"`
	// FakePacketFlags defines TCP flags (SYN=0x02, RST=0x04, ACK=0x10) for decoy packet injection.
	FakePacketFlags uint8 `json:"fake_packet_flags"`
	// FakePacketTTL defines the low TTL value used to prevent fake packets reaching the destination.
	FakePacketTTL uint8 `json:"fake_packet_ttl"`
	// HeaderMutation specifies whether HTTP Host header casing is randomized (e.g. hOsT).
	HeaderMutation bool `json:"header_mutation"`
	// EfficacyScore is the ratio of successful dials using this antibody (0.0 - 1.0).
	EfficacyScore float64 `json:"efficacy_score"`
	// SuccessCount is the total number of successful connections using this antibody.
	SuccessCount uint64 `json:"success_count"`
	// FailureCount is the total number of failures using this antibody.
	FailureCount uint64 `json:"failure_count"`
	// DiscoveredAt is the timestamp when this antibody was synthesized.
	DiscoveredAt time.Time `json:"discovered_at"`
	// LastUsedAt is the timestamp when this antibody was last applied.
	LastUsedAt time.Time `json:"last_used_at"`
}

// PacketTimingProfile holds metrics from an observed TCP/TLS interaction.
type PacketTimingProfile struct {
	Elapsed        time.Duration
	BytesSent      int
	BytesReceived  int
	TCPHandshakeMs float64
	TLSClientHello bool
	StatusCode     int
	ResponseBody   string
}
