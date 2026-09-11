package firewall

import (
	"fmt"
	"strings"
	"sync"
)

type GatewayRoute struct {
	DestinationCidr string
	GatewayIP       string
	InterfaceName   string
	Metric          int
}

type DynamicGatewayUpdater struct {
	mu             sync.RWMutex
	routes         map[string]GatewayRoute
	defaultGateway string
	defaultIface   string
}

func NewDynamicGatewayUpdater() *DynamicGatewayUpdater {
	return &DynamicGatewayUpdater{
		routes: make(map[string]GatewayRoute),
	}
}

func (u *DynamicGatewayUpdater) SetDefaultGateway(gw, iface string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.defaultGateway = gw
	u.defaultIface = iface
}

func (u *DynamicGatewayUpdater) AddRoute(route GatewayRoute) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.routes[route.DestinationCidr] = route
}

func (u *DynamicGatewayUpdater) RemoveRoute(cidr string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	delete(u.routes, cidr)
}

func (u *DynamicGatewayUpdater) CompileCommands(osTarget string) []string {
	u.mu.RLock()
	defer u.mu.RUnlock()

	cmds := make([]string, 0, len(u.routes))
	for _, r := range u.routes {
		switch osTarget {
		case "linux":
			cmds = append(cmds, fmt.Sprintf("ip route add %s via %s dev %s metric %d", r.DestinationCidr, r.GatewayIP, r.InterfaceName, r.Metric))
		case "windows":
			dest := strings.Split(r.DestinationCidr, "/")[0]
			cmds = append(cmds, fmt.Sprintf("route add %s mask 255.255.255.0 %s metric %d", dest, r.GatewayIP, r.Metric))
		case "darwin":
			cmds = append(cmds, fmt.Sprintf("route add -net %s %s -interface %s", r.DestinationCidr, r.GatewayIP, r.InterfaceName))
		default:
			cmds = append(cmds, fmt.Sprintf("route add %s gw %s", r.DestinationCidr, r.GatewayIP))
		}
	}
	return cmds
}
