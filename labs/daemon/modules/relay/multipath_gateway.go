package relay

import (
	"fmt"
	"sync"
	"time"
)

// EgressLink represents a physical or overlay path.
type EgressLink struct {
	ID        string        `json:"id"`
	RTT       time.Duration `json:"rtt"`
	Weight    int           `json:"weight"`
	IsActive  bool          `json:"is_active"`
	SentBytes uint64        `json:"sent_bytes"`
}

// MultipathGatewayCoordinator balances egress packets across active links.
type MultipathGatewayCoordinator struct {
	mu          sync.Mutex
	links       map[string]*EgressLink
	orderedKeys []string
	rrCursor    int
}

// NewMultipathGatewayCoordinator creates an egress gateway coordinator.
func NewMultipathGatewayCoordinator() *MultipathGatewayCoordinator {
	return &MultipathGatewayCoordinator{
		links: make(map[string]*EgressLink),
	}
}

// RegisterLink registers or updates an egress link.
func (c *MultipathGatewayCoordinator) RegisterLink(link EgressLink) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.links[link.ID]; !exists {
		c.orderedKeys = append(c.orderedKeys, link.ID)
	}
	c.links[link.ID] = &link
}

// RoutePacket picks the best active link via weighted round-robin.
func (c *MultipathGatewayCoordinator) RoutePacket(payloadLen int) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var activeKeys []string
	for _, k := range c.orderedKeys {
		if c.links[k].IsActive {
			activeKeys = append(activeKeys, k)
		}
	}

	if len(activeKeys) == 0 {
		return "", fmt.Errorf("no active egress links")
	}

	selected := activeKeys[c.rrCursor%len(activeKeys)]
	c.rrCursor++
	c.links[selected].SentBytes += uint64(payloadLen)

	return selected, nil
}

// SetLinkActive toggles active status of an egress link.
func (c *MultipathGatewayCoordinator) SetLinkActive(id string, active bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	link, exists := c.links[id]
	if !exists {
		return fmt.Errorf("link not found: %s", id)
	}
	link.IsActive = active
	return nil
}
