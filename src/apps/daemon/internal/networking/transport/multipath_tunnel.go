package transport

import (
	"encoding/binary"
	"errors"
	"net"
	"sort"
	"sync"
	"time"
)

type PathState int

const (
	PathStateActive PathState = iota
	PathStateStandby
	PathStateDegraded
	PathStateDown
)

type BondingMode int

const (
	BondingRoundRobin BondingMode = iota
	BondingLowestLatency
	BondingRedundantDuplicate
	BondingWeightedLossRatio
)

type PathMetrics struct {
	PathID         uint32
	LocalAddr      *net.UDPAddr
	RemoteAddr     *net.UDPAddr
	RttMs          float64
	LossPercentage float64
	TxBytes        uint64
	RxBytes        uint64
	State          PathState
	Weight         uint32
	LastHeartbeat  time.Time
}

func NewPathMetrics(id uint32, local, remote *net.UDPAddr, weight uint32) *PathMetrics {
	if weight == 0 {
		weight = 1
	}
	return &PathMetrics{
		PathID:        id,
		LocalAddr:     local,
		RemoteAddr:    remote,
		State:         PathStateActive,
		Weight:        weight,
		LastHeartbeat: time.Now(),
	}
}

func (p *PathMetrics) RecordHeartbeatReply(latencyMs float64, lost bool) {
	if p.RttMs <= 0.0 {
		p.RttMs = latencyMs
	} else {
		p.RttMs = p.RttMs*0.8 + latencyMs*0.2
	}

	lossSample := 0.0
	if lost {
		lossSample = 100.0
	}
	p.LossPercentage = p.LossPercentage*0.9 + lossSample*0.1
	p.LastHeartbeat = time.Now()

	// Test the most severe threshold first; otherwise values above 90% also
	// satisfy the degraded condition and PathStateDown is unreachable.
	if p.LossPercentage > 90.0 {
		p.State = PathStateDown
	} else if p.LossPercentage > 50.0 {
		p.State = PathStateDegraded
	} else {
		p.State = PathStateActive
	}
}

type MultipathTunnelManager struct {
	TunnelID          string
	Mode              BondingMode
	paths             map[uint32]*PathMetrics
	roundRobinCounter uint32
	mu                sync.RWMutex
}

func NewMultipathTunnelManager(id string, mode BondingMode) *MultipathTunnelManager {
	return &MultipathTunnelManager{
		TunnelID: id,
		Mode:     mode,
		paths:    make(map[uint32]*PathMetrics),
	}
}

func (m *MultipathTunnelManager) AddPath(path *PathMetrics) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.paths[path.PathID] = path
}

func (m *MultipathTunnelManager) RemovePath(id uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.paths, id)
}

func (m *MultipathTunnelManager) ActivePaths() []uint32 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var active []uint32
	for id, p := range m.paths {
		if p.State == PathStateActive || p.State == PathStateDegraded {
			active = append(active, id)
		}
	}
	sort.Slice(active, func(i, j int) bool { return active[i] < active[j] })
	return active
}

func (m *MultipathTunnelManager) SelectPathForEgress() (uint32, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var active []uint32
	for id, p := range m.paths {
		if p.State == PathStateActive || p.State == PathStateDegraded {
			active = append(active, id)
		}
	}

	if len(active) == 0 {
		return 0, errors.New("no active paths available")
	}

	// Map iteration order is deliberately randomized in Go. Stable ordering is
	// required for round-robin to advance across paths instead of occasionally
	// selecting the same path twice as the map order changes between calls.
	sort.Slice(active, func(i, j int) bool { return active[i] < active[j] })

	switch m.Mode {
	case BondingRoundRobin:
		idx := int(m.roundRobinCounter) % len(active)
		m.roundRobinCounter++
		return active[idx], nil
	case BondingLowestLatency:
		bestID := active[0]
		lowestRtt := 1e9
		for _, id := range active {
			if p, ok := m.paths[id]; ok {
				if p.RttMs < lowestRtt {
					lowestRtt = p.RttMs
					bestID = id
				}
			}
		}
		return bestID, nil
	default:
		return active[0], nil
	}
}

func (m *MultipathTunnelManager) Encapsulate(pathID uint32, payload []byte) ([]byte, error) {
	m.mu.Lock()
	p, ok := m.paths[pathID]
	if !ok {
		m.mu.Unlock()
		return nil, errors.New("unknown path id")
	}
	p.TxBytes += uint64(len(payload))
	m.mu.Unlock()

	frame := make([]byte, 7+len(payload))
	binary.BigEndian.PutUint32(frame[0:4], pathID)
	binary.BigEndian.PutUint16(frame[4:6], uint16(len(payload)))
	frame[6] = 0x01 // Data flag
	copy(frame[7:], payload)
	return frame, nil
}

func (m *MultipathTunnelManager) Decapsulate(frame []byte) (uint32, []byte, error) {
	if len(frame) < 7 {
		return 0, nil, errors.New("frame too small")
	}
	pathID := binary.BigEndian.Uint32(frame[0:4])
	payloadLen := int(binary.BigEndian.Uint16(frame[4:6]))
	if len(frame) < 7+payloadLen {
		return 0, nil, errors.New("truncated payload")
	}

	m.mu.Lock()
	if p, ok := m.paths[pathID]; ok {
		p.RxBytes += uint64(payloadLen)
	}
	m.mu.Unlock()

	payload := make([]byte, payloadLen)
	copy(payload, frame[7:7+payloadLen])
	return pathID, payload, nil
}
