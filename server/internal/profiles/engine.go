// Package profiles handles loading, matching, and applying system configuration state files according to context parameters.
package profiles

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// Profile details a configured state for proxy, DNS, and DDNS toggled by location criteria.
type Profile struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	TargetSSIDs   []string `json:"target_ssids"`
	TargetSubnets []string `json:"target_subnets"`
	DNSServers    []string `json:"dns_servers"`
	ProxyEnabled  bool     `json:"proxy_enabled"`
	ProxyAddress  string   `json:"proxy_address"`
	DDNSEnabled   bool     `json:"ddns_enabled"`
}

// ApplyFunc is a callback invoked when a profile is applied.
// Callers inject DNS/proxy setters via this interface to avoid circular imports.
type ApplyFunc func(ctx context.Context, p *Profile) error

// Engine matches environment heuristics against loaded profiles to apply them.
type Engine struct {
	profiles  []*Profile
	applyFunc ApplyFunc
}

// NewEngine initializes a profile matching Engine.
func NewEngine() *Engine {
	return &Engine{
		profiles: make([]*Profile, 0),
	}
}

// SetApplyFunc registers the callback used when Apply is called.
func (e *Engine) SetApplyFunc(fn ApplyFunc) {
	e.applyFunc = fn
}

// SetProfiles replaces the engine's internal registry of available profiles.
func (e *Engine) SetProfiles(profiles []*Profile) {
	e.profiles = profiles
}

// GetProfiles returns all registered profiles.
func (e *Engine) GetProfiles() []*Profile {
	return e.profiles
}

// Match evaluates context inputs (like WiFi SSID or IPv4 Subnet) to detect the most relevant Profile.
func (e *Engine) Match(ssid string, subnet string) (*Profile, error) {
	for _, p := range e.profiles {
		// Match by SSID
		for _, targetSSID := range p.TargetSSIDs {
			if strings.EqualFold(targetSSID, ssid) {
				return p, nil
			}
		}

		// Match by subnet
		for _, targetSubnet := range p.TargetSubnets {
			_, ipNet, err := net.ParseCIDR(targetSubnet)
			if err != nil {
				continue
			}
			ip := net.ParseIP(subnet)
			if ip != nil && ipNet.Contains(ip) {
				return p, nil
			}
		}
	}
	return nil, fmt.Errorf("no matching profile found for SSID=%q subnet=%q", ssid, subnet)
}

// Apply sets network adapters, environment variables, or background loops to reflect the chosen Profile.
func (e *Engine) Apply(ctx context.Context, p *Profile) error {
	if p == nil {
		return fmt.Errorf("cannot apply nil profile")
	}
	if e.applyFunc != nil {
		return e.applyFunc(ctx, p)
	}
	// Default no-op: caller must register an ApplyFunc for real system changes
	return nil
}

// AddProfile adds a new profile to the engine's registry.
func (e *Engine) AddProfile(p *Profile) error {
	if p.ID == "" {
		return fmt.Errorf("profile ID cannot be empty")
	}
	for _, existing := range e.profiles {
		if existing.ID == p.ID {
			return fmt.Errorf("profile with ID %s already exists", p.ID)
		}
	}
	e.profiles = append(e.profiles, p)
	return nil
}

// RemoveProfile removes a profile by ID.
func (e *Engine) RemoveProfile(id string) error {
	for i, p := range e.profiles {
		if p.ID == id {
			e.profiles = append(e.profiles[:i], e.profiles[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("profile not found: %s", id)
}
