package proxy

import "time"

// ScanProgress represents real-time subnet scanning telemetry metrics.
type ScanProgress struct {
	JobID          string    `json:"job_id"`
	TotalIPs       int       `json:"total_ips"`
	ScannedIPs     int       `json:"scanned_ips"`
	ActiveWorkers  int       `json:"active_workers"`
	AverageRTT     float64   `json:"average_rtt_ms"`
	SuccessCount   int       `json:"success_count"`
	StartTime      time.Time `json:"start_time"`
	CompletedCount int       `json:"completed_count"`
}

// PercentageCalculated returns the percentage of subnet address completion.
func (s *ScanProgress) PercentageCalculated() float64 {
	if s.TotalIPs <= 0 {
		return 0.0
	}
	return (float64(s.ScannedIPs) / float64(s.TotalIPs)) * 100.0
}
