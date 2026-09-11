package relay

import (
	"errors"
	"net"
	"sync"
)

type ZeroTrustResource struct {
	ID                    string `json:"id"`
	Name                  string `json:"name"`
	NetworkCIDR           string `json:"network_cidr"`
	MappedIP              net.IP `json:"mapped_ip"`
	AllowedPermissionMask uint32 `json:"allowed_permission_mask"`
}

type ZeroTrustRouteTable struct {
	mu           sync.RWMutex
	resources    map[string]*ZeroTrustResource
	ipToResource map[string]string
}

func NewZeroTrustRouteTable() *ZeroTrustRouteTable {
	return &ZeroTrustRouteTable{
		resources:    make(map[string]*ZeroTrustResource),
		ipToResource: make(map[string]string),
	}
}

func (t *ZeroTrustRouteTable) RegisterResource(res *ZeroTrustResource) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if res == nil || res.MappedIP == nil {
		return errors.New("invalid zero trust resource")
	}
	t.resources[res.ID] = res
	t.ipToResource[res.MappedIP.String()] = res.ID
	return nil
}

func (t *ZeroTrustRouteTable) LookupByIP(ip net.IP) (*ZeroTrustResource, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if ip == nil {
		return nil, false
	}
	id, exists := t.ipToResource[ip.String()]
	if !exists {
		return nil, false
	}
	res, ok := t.resources[id]
	return res, ok
}

func (t *ZeroTrustRouteTable) EvaluateAccess(ip net.IP, clientPermissions uint32) bool {
	res, found := t.LookupByIP(ip)
	if !found {
		return false
	}
	return (res.AllowedPermissionMask & clientPermissions) == res.AllowedPermissionMask
}
