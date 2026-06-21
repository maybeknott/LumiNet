package proxy

import (
	"net"
	"strings"

	"github.com/maybeknott/luminet/internal/config"
)

// RoutingRule defines a single traffic classification rule.
type RoutingRule struct {
	DomainSuffix  []string
	DomainKeyword []string
	IPRanges      []*net.IPNet
	OutboundTag   string
}

// TrieNode represents a node in the domain suffix matching Radix trie.
type TrieNode struct {
	Children    map[string]*TrieNode
	IsEnd       bool
	OutboundTag string
}

// RulesRouter decides the target outbound tag for a given connection destination.
type RulesRouter struct {
	Rules []RoutingRule
	trie  *TrieNode
}

// MatchOutbound evaluates host and IP targets against configured routing rules using O(L) Radix Trie for domains.
func (r *RulesRouter) MatchOutbound(host string, ip net.IP) string {
	r.buildTrie()
	lowerHost := strings.ToLower(host)

	// Step 1: High-Performance Trie Suffix match - O(L) where L is labels count
	labels := strings.Split(lowerHost, ".")
	curr := r.trie
	for i := len(labels) - 1; i >= 0; i-- {
		label := labels[i]
		if curr.Children == nil {
			break
		}
		next, exists := curr.Children[label]
		if !exists {
			break
		}
		curr = next
		if curr.IsEnd {
			return curr.OutboundTag
		}
	}

	// Step 2: Fallback to Domain Keyword and IP range checks
	for _, rule := range r.Rules {
		// Check Domain Keywords
		for _, kw := range rule.DomainKeyword {
			if strings.Contains(lowerHost, strings.ToLower(kw)) {
				return rule.OutboundTag
			}
		}

		// Check IP Range matches
		if ip != nil {
			for _, ipNet := range rule.IPRanges {
				if ipNet.Contains(ip) {
					return rule.OutboundTag
				}
			}
		}
	}

	return "proxy" // Default outbound tag
}

func (r *RulesRouter) buildTrie() {
	if r.trie != nil {
		return
	}
	r.trie = &TrieNode{Children: make(map[string]*TrieNode)}
	for _, rule := range r.Rules {
		for _, suffix := range rule.DomainSuffix {
			r.insertTrie(suffix, rule.OutboundTag)
		}
	}
}

func (r *RulesRouter) insertTrie(suffix string, tag string) {
	suffix = strings.TrimPrefix(suffix, ".")
	labels := strings.Split(strings.ToLower(suffix), ".")

	curr := r.trie
	for i := len(labels) - 1; i >= 0; i-- {
		label := labels[i]
		if curr.Children == nil {
			curr.Children = make(map[string]*TrieNode)
		}
		if curr.Children[label] == nil {
			curr.Children[label] = &TrieNode{Children: make(map[string]*TrieNode)}
		}
		curr = curr.Children[label]
	}
	curr.IsEnd = true
	curr.OutboundTag = tag
}

// BuildMihomoRules generates Clash-matching rules based on options.
func BuildMihomoRules(opts config.MihomoRulesOptions) []RoutingRule {
	var rules []RoutingRule

	// Always add private networks
	rules = append(rules, RoutingRule{
		DomainSuffix: []string{"private"},
		OutboundTag:  "direct",
	})

	if opts.BypassChina {
		rules = append(rules, RoutingRule{
			DomainSuffix: []string{"cn"},
			OutboundTag:  "direct",
		})
	}
	if opts.BypassIran {
		rules = append(rules, RoutingRule{
			DomainSuffix: []string{"ir"},
			OutboundTag:  "direct",
		})
	}
	if opts.BypassRussia {
		rules = append(rules, RoutingRule{
			DomainSuffix: []string{"ru"},
			OutboundTag:  "direct",
		})
	}
	if opts.BypassOpenAI {
		rules = append(rules, RoutingRule{
			DomainSuffix: []string{"openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com"},
			OutboundTag:  "direct",
		})
	}
	if opts.BypassGoogleAI {
		rules = append(rules, RoutingRule{
			DomainSuffix: []string{"deepmind.com", "gemini.google.com", "generativeai.google"},
			OutboundTag:  "direct",
		})
	}
	if opts.BypassMicrosoft {
		rules = append(rules, RoutingRule{
			DomainSuffix: []string{"microsoft.com", "live.com", "outlook.com", "office.com"},
			OutboundTag:  "direct",
		})
	}
	if opts.BypassOracle {
		rules = append(rules, RoutingRule{
			DomainSuffix: []string{"oracle.com"},
			OutboundTag:  "direct",
		})
	}
	if opts.BypassDocker {
		rules = append(rules, RoutingRule{
			DomainSuffix: []string{"docker.com", "docker.io"},
			OutboundTag:  "direct",
		})
	}
	if opts.BypassAdobe {
		rules = append(rules, RoutingRule{
			DomainSuffix: []string{"adobe.com", "behance.net"},
			OutboundTag:  "direct",
		})
	}
	if opts.BypassEpicGames {
		rules = append(rules, RoutingRule{
			DomainSuffix: []string{"epicgames.com", "unrealengine.com"},
			OutboundTag:  "direct",
		})
	}
	if opts.BypassIntel {
		rules = append(rules, RoutingRule{
			DomainSuffix: []string{"intel.com"},
			OutboundTag:  "direct",
		})
	}
	if opts.BypassAMD {
		rules = append(rules, RoutingRule{
			DomainSuffix: []string{"amd.com"},
			OutboundTag:  "direct",
		})
	}
	if opts.BypassNvidia {
		rules = append(rules, RoutingRule{
			DomainSuffix: []string{"nvidia.com", "geforce.com"},
			OutboundTag:  "direct",
		})
	}
	if opts.BypassAsus {
		rules = append(rules, RoutingRule{
			DomainSuffix: []string{"asus.com"},
			OutboundTag:  "direct",
		})
	}
	if opts.BypassHP {
		rules = append(rules, RoutingRule{
			DomainSuffix: []string{"hp.com"},
			OutboundTag:  "direct",
		})
	}
	if opts.BypassLenovo {
		rules = append(rules, RoutingRule{
			DomainSuffix: []string{"lenovo.com"},
			OutboundTag:  "direct",
		})
	}

	// Blocks
	if opts.BlockMalware {
		rules = append(rules, RoutingRule{
			DomainKeyword: []string{"malware"},
			OutboundTag:   "reject",
		})
	}
	if opts.BlockPhishing {
		rules = append(rules, RoutingRule{
			DomainKeyword: []string{"phishing"},
			OutboundTag:   "reject",
		})
	}
	if opts.BlockCryptominers {
		rules = append(rules, RoutingRule{
			DomainSuffix: []string{"coinhive.com", "crypto-loot.com"},
			OutboundTag:  "reject",
		})
	}
	if opts.BlockAds {
		rules = append(rules, RoutingRule{
			DomainSuffix: []string{"doubleclick.net", "adservice.google.com", "ads.yahoo.com"},
			OutboundTag:  "reject",
		})
	}
	if opts.BlockPorn {
		rules = append(rules, RoutingRule{
			DomainKeyword: []string{"nsfw"},
			DomainSuffix:  []string{"porn"},
			OutboundTag:   "reject",
		})
	}

	return rules
}

