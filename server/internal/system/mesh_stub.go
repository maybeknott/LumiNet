package system

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"
)

// ReticulumNode represents a local or remote node in the Reticulum mesh network.
type ReticulumNode struct {
	Address [32]byte
	Name    string
	Online  bool
}

// MeshManager coordinates Reticulum link establishment and routing.
type MeshManager struct {
	mu     sync.RWMutex
	nodes  map[string]*ReticulumNode
	online bool
}

// NewMeshManager creates a new MeshManager instance.
func NewMeshManager() *MeshManager {
	return &MeshManager{
		nodes: make(map[string]*ReticulumNode),
	}
}

// StartNode initializes the local Reticulum node.
func (m *MeshManager) StartNode(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.online = true
	addr := sha256.Sum256([]byte(name))
	m.nodes[name] = &ReticulumNode{
		Address: addr,
		Name:    name,
		Online:  true,
	}
	return nil
}

// EstablishLink sends a link request to a hex address.
func (m *MeshManager) EstablishLink(destHex string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.online {
		return "", fmt.Errorf("mesh manager is offline")
	}

	// Mock path resolution & link handshake
	time.Sleep(10 * time.Millisecond)
	return fmt.Sprintf("link://%s", destHex), nil
}

// RegisterPeer registers a local network peer.
func (m *MeshManager) RegisterPeer(name string, addr [32]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.nodes[name] = &ReticulumNode{
		Address: addr,
		Name:    name,
		Online:  true,
	}
}
