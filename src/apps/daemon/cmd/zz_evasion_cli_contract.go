package cmd

// Keep legacy evasion flags parseable for script compatibility without
// presenting unsupported behavior as a production capability. This file is
// intentionally named after system.go so its init runs after the canonical flag
// declarations in the Go toolchain's lexical file order.
func init() {
	if flag := systemEvasionTunnelStartCmd.Flags().Lookup("stego-webrtc-sdp"); flag != nil {
		flag.Usage = "Legacy unsupported WebRTC SDP spoofing compatibility flag (must remain false)"
		_ = systemEvasionTunnelStartCmd.Flags().MarkHidden("stego-webrtc-sdp")
	}
	if flag := systemEvasionTunnelStartCmd.Flags().Lookup("stego-mode"); flag != nil {
		flag.Usage = "Steganography mode (webrtc_voip or pixel; pixel_stego is accepted only as a legacy alias)"
	}
	if flag := systemEvasionTunnelStartCmd.Flags().Lookup("upgen-quic-rate"); flag != nil {
		flag.Usage = "Legacy unsupported UPGen QUIC exhaustion rate (must remain 0)"
		_ = systemEvasionTunnelStartCmd.Flags().MarkHidden("upgen-quic-rate")
	}
}
