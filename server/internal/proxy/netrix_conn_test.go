package proxy

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"
)

func TestNetrixConn_RawAndCompression(t *testing.T) {
	tests := []struct {
		name        string
		compression string
		payloadSize int
		expectComp  bool
	}{
		{"Raw Under Limit", "", 100, false},
		{"Raw Over Limit", "", 1500, false},
		{"LZ4 Under Limit", "lz4", 100, false},
		{"LZ4 Over Limit", "lz4", 2048, true},
		{"Zstd Under Limit", "zstd", 100, false},
		{"Zstd Over Limit", "zstd", 2048, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c1, c2 := net.Pipe()
			defer c1.Close()
			defer c2.Close()

			// Generate highly compressible payload if we expect compression
			var payload []byte
			if tt.expectComp {
				payload = bytes.Repeat([]byte("A"), tt.payloadSize)
			} else {
				payload = make([]byte, tt.payloadSize)
				_, _ = rand.Read(payload)
			}

			client := NewNetrixConn(c1, tt.compression, false, 0, 0)
			server := NewNetrixConn(c2, tt.compression, false, 0, 0)

			errChan := make(chan error, 1)
			go func() {
				defer c1.Close()
				_, err := client.Write(payload)
				errChan <- err
			}()

			buf := make([]byte, tt.payloadSize+100)
			n, err := io.ReadFull(server, buf[:tt.payloadSize])
			if err != nil {
				t.Fatalf("Read failed: %v", err)
			}

			writeErr := <-errChan
			if writeErr != nil {
				t.Fatalf("Write failed: %v", writeErr)
			}

			if n != tt.payloadSize {
				t.Errorf("expected read size %d, got %d", tt.payloadSize, n)
			}

			if !bytes.Equal(payload, buf[:n]) {
				t.Error("payload mismatch after transmission")
			}
		})
	}
}

func TestNetrixConn_Jitter(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	client := NewNetrixConn(c1, "", true, 10, 20)
	payload := []byte("hello jitter")

	go func() {
		defer c2.Close()
		_, _ = io.Copy(io.Discard, c2)
	}()

	start := time.Now()
	_, err := client.Write(payload)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	duration := time.Since(start)

	// Since jitter min is 10ms, duration should be at least 10ms (with a minor buffer for execution scheduling)
	if duration < 8*time.Millisecond {
		t.Errorf("expected jitter delay of >= 10ms, got %v", duration)
	}
}
