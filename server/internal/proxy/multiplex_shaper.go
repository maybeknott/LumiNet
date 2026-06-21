package proxy

import (
	"net"
)

// ShapedConn wraps a net.Conn and limits its read and write throughput using TokenBuckets.
type ShapedConn struct {
	net.Conn
	readBucket  *TokenBucket
	writeBucket *TokenBucket
}

// NewShapedConn creates a ShapedConn wrapping an active net.Conn with custom read and write rates (bytes/second).
func NewShapedConn(conn net.Conn, readRate, writeRate int64) *ShapedConn {
	var readBucket, writeBucket *TokenBucket
	if readRate > 0 {
		readBucket = NewTokenBucket(readRate, readRate)
	}
	if writeRate > 0 {
		writeBucket = NewTokenBucket(writeRate, writeRate)
	}

	return &ShapedConn{
		Conn:        conn,
		readBucket:  readBucket,
		writeBucket: writeBucket,
	}
}

// Read rate-limits reading from the stream.
func (s *ShapedConn) Read(b []byte) (int, error) {
	n, err := s.Conn.Read(b)
	if err == nil && n > 0 && s.readBucket != nil {
		s.readBucket.Limit(n)
	}
	return n, err
}

// Write rate-limits writing to the stream.
func (s *ShapedConn) Write(b []byte) (int, error) {
	if s.writeBucket != nil {
		s.writeBucket.Limit(len(b))
	}
	return s.Conn.Write(b)
}
