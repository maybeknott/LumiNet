package proxy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"testing"
	"time"
)

// generateClientHello creates a valid TLS ClientHello payload to trigger the evasion logic.
func generateClientHello() []byte {
	data := make([]byte, 200)
	data[0] = 0x16 // Handshake record
	data[1] = 0x03 // TLS
	data[2] = 0x01
	binary.BigEndian.PutUint16(data[3:5], 195)
	data[5] = 0x01 // Client Hello
	data[6] = 0x00
	data[7] = 0x00
	data[8] = 191
	data[9] = 0x03
	data[10] = 0x03
	data[43] = 0x00 // Session ID length
	binary.BigEndian.PutUint16(data[44:46], 2) // Cipher suites
	data[46] = 0x00
	data[47] = 0x2f
	data[48] = 0x01 // Compression
	data[49] = 0x00
	binary.BigEndian.PutUint16(data[50:52], 141) // Extensions length
	binary.BigEndian.PutUint16(data[52:54], 0)   // SNI extension type
	binary.BigEndian.PutUint16(data[54:56], 20)  // SNI extension length
	binary.BigEndian.PutUint16(data[56:58], 18)
	data[58] = 0x00 // Name type: host_name
	binary.BigEndian.PutUint16(data[59:61], 15)  // Name length: 15
	copy(data[61:76], []byte("example.website"))
	return data
}

type perfResult struct {
	mode          string
	helloLatency  time.Duration
	bulkLatency   time.Duration
	throughputMBs float64
	successRate   float64
}

func runSimulation(oob, oobex bool, iterations int, bulkSize int) (perfResult, error) {
	var totalHelloLatency time.Duration
	var totalBulkLatency time.Duration
	successes := 0

	helloPayload := generateClientHello()
	bulkPayload := make([]byte, bulkSize)
	rand.Read(bulkPayload)

	for i := 0; i < iterations; i++ {
		// 1. Setup Listener
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return perfResult{}, fmt.Errorf("failed to listen: %w", err)
		}

		addr := listener.Addr().String()
		errChan := make(chan error, 2)
		var receivedHello []byte
		var receivedBulk []byte

		// 2. Start Receiver Goroutine
		go func() {
			defer listener.Close()
			conn, err := listener.Accept()
			if err != nil {
				errChan <- err
				return
			}
			defer conn.Close()

			if err := setOOBInline(conn); err != nil {
				errChan <- fmt.Errorf("failed to set OOB inline: %w", err)
				return
			}

			if oob {
				// TCP-OOB: 200 bytes normal, then 1 OOB byte
				buf := make([]byte, len(helloPayload))
				_, err = io.ReadFull(conn, buf)
				if err != nil {
					errChan <- fmt.Errorf("failed to read hello normal: %w", err)
					return
				}
				_, err = readOOB(conn) // consume OOB byte
				if err != nil {
					errChan <- fmt.Errorf("failed to read hello OOB byte: %w", err)
					return
				}
				receivedHello = buf
			} else if oobex {
				// TCP-OOBEx:
				// - 15 bytes normal, 1 byte OOB
				// - 4 bytes normal, 1 byte dummy OOB
				// - 180 bytes normal
				buf := make([]byte, len(helloPayload))
				
				_, err = io.ReadFull(conn, buf[:15])
				if err != nil {
					errChan <- fmt.Errorf("failed to read OOBEx chunk 1: %w", err)
					return
				}
				
				oob1, err := readOOB(conn)
				if err != nil {
					errChan <- fmt.Errorf("failed to read OOBEx OOB 1: %w", err)
					return
				}
				buf[15] = oob1
				
				_, err = io.ReadFull(conn, buf[16:20])
				if err != nil {
					errChan <- fmt.Errorf("failed to read OOBEx chunk 2: %w", err)
					return
				}
				
				_, err = readOOB(conn) // dummy OOB byte
				if err != nil {
					errChan <- fmt.Errorf("failed to read OOBEx OOB 2 (dummy): %w", err)
					return
				}
				
				_, err = io.ReadFull(conn, buf[20:])
				if err != nil {
					errChan <- fmt.Errorf("failed to read OOBEx chunk 3: %w", err)
					return
				}
				
				receivedHello = buf
			} else {
				// Normal: 200 bytes normal
				buf := make([]byte, len(helloPayload))
				_, err = io.ReadFull(conn, buf)
				if err != nil {
					errChan <- fmt.Errorf("failed to read hello normal: %w", err)
					return
				}
				receivedHello = buf
			}

			// Read Bulk Data (normal TCP write follows)
			bufBulk := make([]byte, len(bulkPayload))
			_, err = io.ReadFull(conn, bufBulk)
			if err != nil {
				errChan <- fmt.Errorf("failed to read bulk: %w", err)
				return
			}
			receivedBulk = bufBulk

			errChan <- nil
		}()

		// 3. Dial Client
		clientConn, err := net.Dial("tcp", addr)
		if err != nil {
			listener.Close()
			continue
		}

		var activeConn net.Conn = clientConn
		if oob || oobex {
			activeConn = &evasionTunnelConn{
				Conn:         clientConn,
				firstWrite:   true,
				oobEnabled:   oob,
				oobexEnabled: oobex,
				packets:      "tlshello",
			}
		}

		// 4. Perform TLS ClientHello Write (Evasion Step)
		tHello0 := time.Now()
		_, err = activeConn.Write(helloPayload)
		if err != nil {
			fmt.Printf("mode oob:%v oobex:%v iter %d: write hello failed: %v\n", oob, oobex, i, err)
			activeConn.Close()
			listener.Close()
			continue
		}
		helloDur := time.Since(tHello0)

		// 5. Perform Bulk Write
		tBulk0 := time.Now()
		_, err = activeConn.Write(bulkPayload)
		if err != nil {
			fmt.Printf("mode oob:%v oobex:%v iter %d: write bulk failed: %v\n", oob, oobex, i, err)
			activeConn.Close()
			listener.Close()
			continue
		}
		bulkDur := time.Since(tBulk0)

		// 6. Sync and Verify
		select {
		case err := <-errChan:
			if err != nil {
				fmt.Printf("mode oob:%v oobex:%v iter %d: receiver error: %v\n", oob, oobex, i, err)
				activeConn.Close()
				continue
			}
		case <-time.After(2 * time.Second):
			fmt.Printf("mode oob:%v oobex:%v iter %d: timeout waiting for receiver\n", oob, oobex, i)
			activeConn.Close()
			continue
		}

		activeConn.Close()

		// Verify data integrity
		if !bytes.Equal(receivedHello, helloPayload) {
			continue
		}
		if !bytes.Equal(receivedBulk, bulkPayload) {
			continue
		}

		totalHelloLatency += helloDur
		totalBulkLatency += bulkDur
		successes++
	}

	modeName := "Normal"
	if oob {
		modeName = "TCP-OOB"
	} else if oobex {
		modeName = "TCP-OOBEx"
	}

	if successes == 0 {
		return perfResult{
			mode:        modeName,
			successRate: 0.0,
		}, nil
	}

	avgHello := totalHelloLatency / time.Duration(successes)
	avgBulk := totalBulkLatency / time.Duration(successes)
	throughput := (float64(bulkSize) / (1024 * 1024)) / avgBulk.Seconds()

	return perfResult{
		mode:          modeName,
		helloLatency:  avgHello,
		bulkLatency:   avgBulk,
		throughputMBs: throughput,
		successRate:   float64(successes) / float64(iterations) * 100.0,
	}, nil
}

func TestOobPerformance(t *testing.T) {
	const iterations = 30
	const bulkSize = 128 * 1024 // 128 KB

	t.Logf("Starting TCP OOB Evasion Live Network Simulation Performance Test...")
	t.Logf("Configurations: %d iterations, %d KB bulk payload size.", iterations, bulkSize/1024)

	modes := []struct {
		oob   bool
		oobex bool
	}{
		{false, false}, // Normal
		{true, false},  // OOB
		{false, true},  // OOBEx
	}

	var results []perfResult

	for _, m := range modes {
		res, err := runSimulation(m.oob, m.oobex, iterations, bulkSize)
		if err != nil {
			t.Fatalf("Simulation error in mode (oob:%v, oobex:%v): %v", m.oob, m.oobex, err)
		}
		results = append(results, res)
	}

	// Print Summary Table
	t.Logf("\n%-12s | %-22s | %-22s | %-18s | %-12s", "Evasion Mode", "Hello Write Latency", "Bulk Write Latency", "Throughput (MB/s)", "Success Rate")
	t.Logf("-------------------------------------------------------------------------------------------------------------")
	for _, r := range results {
		if r.successRate == 0 {
			t.Logf("%-12s | %-22s | %-22s | %-18s | %-12s", r.mode, "N/A", "N/A", "N/A", "0.00%")
		} else {
			t.Logf("%-12s | %-10d µs (%-8s) | %-10d µs (%-8s) | %-13.2f MB/s | %-6.2f%%",
				r.mode,
				r.helloLatency.Microseconds(), r.helloLatency.String(),
				r.bulkLatency.Microseconds(), r.bulkLatency.String(),
				r.throughputMBs,
				r.successRate,
			)
		}
	}
}
