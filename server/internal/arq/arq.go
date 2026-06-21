package arq

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Packet types
const (
	PACKET_STREAM_DATA      uint8 = 0x0F
	PACKET_STREAM_DATA_ACK  uint8 = 0x10
	PACKET_STREAM_DATA_NACK uint8 = 0x11
	PACKET_STREAM_SYN       uint8 = 0x01
	PACKET_STREAM_SYN_ACK   uint8 = 0x02
	PACKET_STREAM_CLOSE     uint8 = 0x03
	PACKET_STREAM_CLOSE_ACK uint8 = 0x04
	PACKET_STREAM_RST       uint8 = 0x05
	PACKET_STREAM_RST_ACK   uint8 = 0x06
)

// PacketSender abstracts the raw packet transmission layer
type PacketSender interface {
	SendPacket(packetType uint8, seq uint16, payload []byte) error
}

// Logger abstracts logging for the ARQ module
type Logger interface {
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

// DummyLogger provides a no-op logger implementation
type DummyLogger struct{}

func (d *DummyLogger) Debugf(format string, args ...interface{}) {}
func (d *DummyLogger) Infof(format string, args ...interface{})  {}
func (d *DummyLogger) Errorf(format string, args ...interface{}) {}

// arqDataItem tracks an outbound data frame inside the send sliding window
type arqDataItem struct {
	Data           []byte
	CreatedAt      time.Time
	LastSentAt     time.Time
	Dispatched     bool
	Retries        int
	CurrentRTO     time.Duration
	SampleEligible bool
}

// adaptiveRTOState holds the state for dynamically tracking RTT/RTO (RFC 6298)
type adaptiveRTOState struct {
	srtt        time.Duration
	rttvar      time.Duration
	currentBase time.Duration
	initialized bool
}

// Config specifies the tuning options for the ARQ session
type Config struct {
	WindowSize               int
	DefaultRTO               time.Duration
	MaxRTO                   time.Duration
	MaxRetries               int
	EnableControlReliability bool
}

// ARQ coordinates the userspace sliding window ARQ protocol
type ARQ struct {
	mu sync.RWMutex

	sender   PacketSender
	logger   Logger
	config   Config
	isClosed bool

	// Sequence numbers
	sndUna uint16 // Oldest unacknowledged sequence number
	sndNxt uint16 // Next sequence number to send
	rcvNxt uint16 // Next expected sequence number to receive

	// Buffers
	sndBuf map[uint16]*arqDataItem
	rcvBuf map[uint16][]byte

	// RTO & RTT estimation
	dataAdaptiveRTO adaptiveRTOState

	// Concurrency & Lifecycle
	ctx      context.Context
	cancel   context.CancelFunc
	condRead *sync.Cond
	condSend *sync.Cond
}

// NewARQ creates a new ARQ session instance
func NewARQ(sender PacketSender, logger Logger, cfg Config) *ARQ {
	if logger == nil {
		logger = &DummyLogger{}
	}
	if cfg.WindowSize <= 0 {
		cfg.WindowSize = 128
	}
	if cfg.DefaultRTO <= 0 {
		cfg.DefaultRTO = 300 * time.Millisecond
	}
	if cfg.MaxRTO <= 0 {
		cfg.MaxRTO = 5000 * time.Millisecond
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 30
	}

	ctx, cancel := context.WithCancel(context.Background())

	a := &ARQ{
		sender: sender,
		logger: logger,
		config: cfg,
		sndBuf: make(map[uint16]*arqDataItem),
		rcvBuf: make(map[uint16][]byte),
		ctx:    ctx,
		cancel: cancel,
		sndNxt: 1, // start sequence at 1
		sndUna: 1,
		rcvNxt: 1,
	}

	a.condRead = sync.NewCond(&a.mu)
	a.condSend = sync.NewCond(&a.mu)

	return a
}

// Close terminates the ARQ session
func (a *ARQ) Close() error {
	a.mu.Lock()
	if a.isClosed {
		a.mu.Unlock()
		return nil
	}
	a.isClosed = true
	a.cancel()
	a.condRead.Broadcast()
	a.condSend.Broadcast()
	a.mu.Unlock()

	a.logger.Infof("ARQ session closed gracefully")
	return nil
}

// IsClosed returns the session closure state
func (a *ARQ) IsClosed() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.isClosed
}

// Write queues payload bytes into the send buffer and transmits them
func (a *ARQ) Write(payload []byte) error {
	if len(payload) == 0 {
		return nil
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.isClosed {
		return errors.New("write to closed ARQ session")
	}

	// Flow control: check if send window is full
	for int(a.sndNxt-a.sndUna) >= a.config.WindowSize {
		if a.isClosed {
			return errors.New("ARQ session closed during wait")
		}
		a.logger.Debugf("Send window full (una=%d, nxt=%d, limit=%d). Waiting...", a.sndUna, a.sndNxt, a.config.WindowSize)
		a.condSend.Wait()
	}

	seq := a.sndNxt
	a.sndNxt++

	item := &arqDataItem{
		Data:           append([]byte(nil), payload...),
		CreatedAt:      time.Now(),
		LastSentAt:     time.Now(),
		Dispatched:     true,
		Retries:        0,
		CurrentRTO:     a.config.DefaultRTO,
		SampleEligible: true,
	}
	a.sndBuf[seq] = item

	// Transmit packet via sender
	err := a.sender.SendPacket(PACKET_STREAM_DATA, seq, item.Data)
	if err != nil {
		a.logger.Errorf("Failed to send packet seq=%d: %v", seq, err)
	}

	return nil
}

// Read extracts the next in-order contiguous payloads from the receive buffer
func (a *ARQ) Read(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Wait for data if the next expected sequence is not in the buffer
	for _, exists := a.rcvBuf[a.rcvNxt]; !exists; _, exists = a.rcvBuf[a.rcvNxt] {
		if a.isClosed {
			return 0, ioEOFOrClosedErr(a.isClosed)
		}
		a.condRead.Wait()
	}

	// Read contiguous frames
	n := 0
	for {
		data, exists := a.rcvBuf[a.rcvNxt]
		if !exists {
			break
		}

		if len(data) > len(buf)-n {
			// Copy partial data and update buffer
			copy(buf[n:], data[:len(buf)-n])
			a.rcvBuf[a.rcvNxt] = data[len(buf)-n:]
			n = len(buf)
			break
		}

		// Copy complete frame and advance expected sequence
		copy(buf[n:], data)
		n += len(data)
		delete(a.rcvBuf, a.rcvNxt)
		a.rcvNxt++
	}

	return n, nil
}

// HandleInboundPacket processes packets received from the raw network layer
func (a *ARQ) HandleInboundPacket(packetType uint8, seq uint16, payload []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.isClosed {
		return errors.New("cannot handle packet: ARQ closed")
	}

	switch packetType {
	case PACKET_STREAM_DATA:
		// Check if sequence is duplicate or outside sliding window
		if seqLessThan(seq, a.rcvNxt) {
			a.logger.Debugf("Received duplicate packet seq=%d (expected >= %d)", seq, a.rcvNxt)
			// Re-ACK duplicate packets to trigger peer window updates
			a.sender.SendPacket(PACKET_STREAM_DATA_ACK, seq, nil)
			return nil
		}

		// Save payload if it fits within max buffer size bounds
		if _, exists := a.rcvBuf[seq]; !exists {
			a.rcvBuf[seq] = append([]byte(nil), payload...)
			a.condRead.Broadcast()
		}

		// Send ACK back
		a.sender.SendPacket(PACKET_STREAM_DATA_ACK, seq, nil)

	case PACKET_STREAM_DATA_ACK:
		item, exists := a.sndBuf[seq]
		if !exists {
			return nil
		}

		// Perform adaptive RTO calculation
		if item.SampleEligible {
			rttSample := time.Since(item.CreatedAt)
			a.dataAdaptiveRTO = updateAdaptiveRTO(a.dataAdaptiveRTO, rttSample, a.config.DefaultRTO, a.config.MaxRTO)
		}

		delete(a.sndBuf, seq)

		// Advance sndUna
		if seq == a.sndUna {
			for {
				a.sndUna++
				if _, exists := a.sndBuf[a.sndUna]; !exists {
					break
				}
			}
			a.condSend.Broadcast()
		}

	case PACKET_STREAM_DATA_NACK:
		// Fast retransmit of requested sequence
		if item, exists := a.sndBuf[seq]; exists {
			item.SampleEligible = false
			item.LastSentAt = time.Now()
			a.sender.SendPacket(PACKET_STREAM_DATA, seq, item.Data)
		}
	}

	return nil
}

// CheckRetransmissions scans outstanding packets and triggers retransmission for expired RTOs
func (a *ARQ) CheckRetransmissions() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.isClosed {
		return
	}

	now := time.Now()
	for seq, item := range a.sndBuf {
		currentRTO := a.config.DefaultRTO
		if a.dataAdaptiveRTO.initialized {
			currentRTO = a.dataAdaptiveRTO.currentBase
		}

		if now.Sub(item.LastSentAt) >= currentRTO {
			if item.Retries >= a.config.MaxRetries {
				a.logger.Errorf("Max retries reached for packet seq=%d. Closing session...", seq)
				a.isClosed = true
				a.cancel()
				a.condRead.Broadcast()
				a.condSend.Broadcast()
				return
			}

			item.Retries++
			item.LastSentAt = now
			item.SampleEligible = false // RTT sampling is disqualified for retransmissions (Karn's algorithm)
			a.logger.Debugf("Retransmitting packet seq=%d (retry=%d, rto=%v)", seq, item.Retries, currentRTO)
			a.sender.SendPacket(PACKET_STREAM_DATA, seq, item.Data)
		}
	}
}

// seqLessThan computes if a < b in modulo 2^16 sequence space
func seqLessThan(a, b uint16) bool {
	return a != b && (b-a) < 32768
}

// updateAdaptiveRTO implements Jacobson/Karels algorithm for RTT/RTO tuning
func updateAdaptiveRTO(state adaptiveRTOState, sample, minRTO, maxRTO time.Duration) adaptiveRTOState {
	if sample < minRTO {
		sample = minRTO
	}
	if sample > maxRTO {
		sample = maxRTO
	}

	if !state.initialized {
		state.srtt = sample
		state.rttvar = sample / 2
		state.initialized = true
	} else {
		delta := state.srtt - sample
		if delta < 0 {
			delta = -delta
		}
		state.rttvar = (3*state.rttvar + delta) / 4
		state.srtt = (7*state.srtt + sample) / 8
	}

	state.currentBase = state.srtt + 4*state.rttvar
	if state.currentBase < minRTO {
		state.currentBase = minRTO
	}
	if state.currentBase > maxRTO {
		state.currentBase = maxRTO
	}
	return state
}

func ioEOFOrClosedErr(isClosed bool) error {
	if isClosed {
		return fmt.Errorf("read: connection closed")
	}
	return nil
}
