package relay

import (
	"errors"
	"net"
	"sync"
	"time"
)

type PeerLinkMetric struct {
	DirectRttMs float64   `json:"direct_rtt_ms"`
	PacketLoss  float64   `json:"packet_loss"`
	Hops        uint32    `json:"hops"`
	Cost        float64   `json:"cost"`
	LastSeen    time.Time `json:"last_seen"`
}

func CalculateLinkCost(rtt float64, loss float64, hops uint32) float64 {
	// Cost = RTT * 0.7 + Loss * 350.0 + Hops * 15.0
	return (rtt * 0.7) + (loss * 350.0) + (float64(hops) * 15.0)
}

type MeshPeerTable struct {
	mu    sync.RWMutex
	peers map[string]map[string]*PeerLinkMetric
}

func NewMeshPeerTable() *MeshPeerTable {
	return &MeshPeerTable{
		peers: make(map[string]map[string]*PeerLinkMetric),
	}
}

func (m *MeshPeerTable) RecordLink(source, dest string, rtt float64, loss float64, hops uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.peers[source]; !exists {
		m.peers[source] = make(map[string]*PeerLinkMetric)
	}
	cost := CalculateLinkCost(rtt, loss, hops)
	m.peers[source][dest] = &PeerLinkMetric{
		DirectRttMs: rtt,
		PacketLoss:  loss,
		Hops:        hops,
		Cost:        cost,
		LastSeen:    time.Now(),
	}
}

func (m *MeshPeerTable) FindBestRoute(source, dest string) (string, float64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	adj, exists := m.peers[source]
	if !exists {
		return "", 0, errors.New("source peer unknown in mesh table")
	}

	bestNextHop := ""
	minCost := 1e9

	// Direct link
	if direct, ok := adj[dest]; ok {
		bestNextHop = dest
		minCost = direct.Cost
	}

	// 1-hop relay evaluation
	for intermediate, link1 := range adj {
		if intermediate == dest {
			continue
		}
		if interMap, ok := m.peers[intermediate]; ok {
			if link2, ok2 := interMap[dest]; ok2 {
				totalCost := link1.Cost + link2.Cost
				if totalCost < minCost {
					minCost = totalCost
					bestNextHop = intermediate
				}
			}
		}
	}

	if bestNextHop == "" {
		return "", 0, errors.New("no viable route found in mesh")
	}
	return bestNextHop, minCost, nil
}

type MeshNodeInfo struct {
	NodeID   string
	VirtualIP net.IP
}
