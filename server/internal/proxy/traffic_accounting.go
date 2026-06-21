package proxy

import (
	"sync/atomic"
)

var (
	totalUploadBytes   uint64
	totalDownloadBytes uint64
)

// AddUploadBytes adds to the global upload traffic counter.
func AddUploadBytes(n uint64) {
	atomic.AddUint64(&totalUploadBytes, n)
}

// AddDownloadBytes adds to the global download traffic counter.
func AddDownloadBytes(n uint64) {
	atomic.AddUint64(&totalDownloadBytes, n)
}

// GetEvasionTrafficStats returns the aggregated upload and download bytes.
func GetEvasionTrafficStats() (uint64, uint64) {
	return atomic.LoadUint64(&totalUploadBytes), atomic.LoadUint64(&totalDownloadBytes)
}

// ResetEvasionTrafficStats resets the traffic counters back to zero.
func ResetEvasionTrafficStats() {
	atomic.StoreUint64(&totalUploadBytes, 0)
	atomic.StoreUint64(&totalDownloadBytes, 0)
}
