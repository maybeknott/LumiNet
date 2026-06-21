package proxy

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// ProviderCorpus represents a JSON registry of CDN/provider IP prefixes.
type ProviderCorpus struct {
	SchemaVersion    int                `json:"schema_version"`
	CorpusID         string             `json:"corpus_id"`
	GeneratorVersion string             `json:"generator_version"`
	GeneratedAt      string             `json:"generated_at"`
	FetchedAt        string             `json:"fetched_at"`
	StaleAfter       string             `json:"stale_after"`
	Checksum         string             `json:"checksum"`
	Providers        []ProviderManifest `json:"providers"`
}

// ProviderManifest represents a single provider's details and prefixes.
type ProviderManifest struct {
	ProviderID    string   `json:"provider_id"`
	DisplayName   string   `json:"display_name"`
	SourceURL     string   `json:"source_url"`
	SourceLicense string   `json:"source_license"`
	SourceKind    string   `json:"source_kind"`
	Confidence    string   `json:"confidence"`
	Priority      int      `json:"priority"`
	IPv4Prefixes  []string `json:"ipv4_prefixes"`
	IPv6Prefixes  []string `json:"ipv6_prefixes"`
	ASNTags       []string `json:"asn_tags,omitempty"`
	RegionTags    []string `json:"region_tags,omitempty"`
}

// ProviderMatch represents a successful prefix lookup match.
type ProviderMatch struct {
	ProviderID    string
	DisplayName   string
	Prefix        netip.Prefix
	Confidence    string
	Priority      int
	CorpusID      string
	SourceURL     string
	SourceLicense string
}

type providerPrefixRecord struct {
	prefix        netip.Prefix
	providerID    string
	displayName   string
	confidence    string
	priority      int
	sourceURL     string
	sourceLicense string
}

// ProviderSnapshot holds compiled records optimized for lookup.
type ProviderSnapshot struct {
	CorpusID         string
	GeneratorVersion string
	GeneratedAt      string
	FetchedAt        string
	StaleAfter       string
	Checksum         string
	records          []providerPrefixRecord
}

// ProviderCorpusStatus describes current health of the prefix store.
type ProviderCorpusStatus struct {
	SchemaVersion    int    `json:"schema_version"`
	CorpusID         string `json:"corpus_id"`
	GeneratorVersion string `json:"generator_version"`
	GeneratedAt      string `json:"generated_at"`
	FetchedAt        string `json:"fetched_at"`
	StaleAfter       string `json:"stale_after"`
	Checksum         string `json:"checksum"`
	Stale            bool   `json:"stale"`
}

// ProviderCorpusStore is a thread-safe atomic pointer store for snapshots.
type ProviderCorpusStore struct {
	value atomic.Value
}

// RadixNode represents a node in the binary trie for IP lookup.
type RadixNode struct {
	Prefix  *netip.Prefix
	Payload string
	Left    *RadixNode
	Right   *RadixNode
}

// CorporateNetworkIndex handles fast longest-prefix matches using a Radix trie.
type CorporateNetworkIndex struct {
	sync.RWMutex
	RootNode *RadixNode
}

var (
	// Global network classification index
	networkClassificationIndex = &CorporateNetworkIndex{}
	// Global provider corpus store
	providerCorpusStore ProviderCorpusStore
)

// ProviderObservation holds lookup metadata returned to clients.
type ProviderObservation struct {
	ProviderID  string `json:"provider_id,omitempty"`
	DisplayName string `json:"provider_name,omitempty"`
	Prefix      string `json:"provider_prefix,omitempty"`
	Confidence  string `json:"provider_confidence,omitempty"`
	CorpusID    string `json:"provider_corpus_id,omitempty"`
	Source      string `json:"provider_source,omitempty"`
}

// ParseProviderCorpus decodes and validates a JSON provider corpus payload.
func ParseProviderCorpus(data []byte) (ProviderCorpus, error) {
	var corpus ProviderCorpus
	if err := json.Unmarshal(data, &corpus); err != nil {
		return ProviderCorpus{}, err
	}
	if err := validateProviderCorpus(corpus); err != nil {
		return ProviderCorpus{}, err
	}
	return corpus, nil
}

func validateProviderCorpus(corpus ProviderCorpus) error {
	if corpus.SchemaVersion != 1 {
		return fmt.Errorf("unsupported provider corpus schema_version %d", corpus.SchemaVersion)
	}
	if corpus.CorpusID == "" || corpus.Checksum == "" || corpus.GeneratorVersion == "" {
		return fmt.Errorf("provider corpus missing identity fields")
	}
	seen := map[string]bool{}
	for _, provider := range corpus.Providers {
		if provider.ProviderID == "" {
			return fmt.Errorf("provider missing provider_id")
		}
		if seen[provider.ProviderID] {
			return fmt.Errorf("duplicate provider_id %q", provider.ProviderID)
		}
		seen[provider.ProviderID] = true
		if len(provider.IPv4Prefixes)+len(provider.IPv6Prefixes) == 0 {
			return fmt.Errorf("provider %q has no prefixes", provider.ProviderID)
		}
		for _, raw := range append(append([]string{}, provider.IPv4Prefixes...), provider.IPv6Prefixes...) {
			if _, err := netip.ParsePrefix(raw); err != nil {
				return fmt.Errorf("provider %q invalid prefix %q: %w", provider.ProviderID, raw, err)
			}
		}
	}
	return nil
}

// BuildProviderSnapshot converts a corpus into an optimized snapshot.
func BuildProviderSnapshot(corpus ProviderCorpus) (*ProviderSnapshot, error) {
	if err := validateProviderCorpus(corpus); err != nil {
		return nil, err
	}
	snapshot := &ProviderSnapshot{
		CorpusID:         corpus.CorpusID,
		GeneratorVersion: corpus.GeneratorVersion,
		GeneratedAt:      corpus.GeneratedAt,
		FetchedAt:        corpus.FetchedAt,
		StaleAfter:       corpus.StaleAfter,
		Checksum:         corpus.Checksum,
	}
	for _, provider := range corpus.Providers {
		for _, raw := range append(append([]string{}, provider.IPv4Prefixes...), provider.IPv6Prefixes...) {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil {
				return nil, err
			}
			snapshot.records = append(snapshot.records, providerPrefixRecord{
				prefix:        prefix.Masked(),
				providerID:    provider.ProviderID,
				displayName:   provider.DisplayName,
				confidence:    provider.Confidence,
				priority:      provider.Priority,
				sourceURL:     provider.SourceURL,
				sourceLicense: provider.SourceLicense,
			})
		}
	}
	sort.SliceStable(snapshot.records, func(i, j int) bool {
		a := snapshot.records[i]
		b := snapshot.records[j]
		if a.prefix.Bits() != b.prefix.Bits() {
			return a.prefix.Bits() > b.prefix.Bits()
		}
		return a.priority > b.priority
	})
	return snapshot, nil
}

// Lookup finds the best matching provider prefix for a given IP address.
func (snapshot *ProviderSnapshot) Lookup(addr netip.Addr) (ProviderMatch, bool) {
	if snapshot == nil || !addr.IsValid() {
		return ProviderMatch{}, false
	}
	for _, record := range snapshot.records {
		if record.prefix.Contains(addr) {
			return ProviderMatch{
				ProviderID:    record.providerID,
				DisplayName:   record.displayName,
				Prefix:        record.prefix,
				Confidence:    record.confidence,
				Priority:      record.priority,
				CorpusID:      snapshot.CorpusID,
				SourceURL:     record.sourceURL,
				SourceLicense: record.sourceLicense,
			}, true
		}
	}
	return ProviderMatch{}, false
}

// Store atomically replaces the active snapshot in the store.
func (store *ProviderCorpusStore) Store(snapshot *ProviderSnapshot) {
	store.value.Store(snapshot)
}

// Lookup queries the active snapshot in the store.
func (store *ProviderCorpusStore) Lookup(addr netip.Addr) (ProviderMatch, bool) {
	value := store.value.Load()
	if value == nil {
		return ProviderMatch{}, false
	}
	snapshot, ok := value.(*ProviderSnapshot)
	if !ok {
		return ProviderMatch{}, false
	}
	return snapshot.Lookup(addr)
}

// Status returns status details of the active corpus snapshot.
func (store *ProviderCorpusStore) Status(now time.Time) (ProviderCorpusStatus, bool) {
	value := store.value.Load()
	if value == nil {
		return ProviderCorpusStatus{}, false
	}
	snapshot, ok := value.(*ProviderSnapshot)
	if !ok || snapshot == nil {
		return ProviderCorpusStatus{}, false
	}
	status := ProviderCorpusStatus{
		SchemaVersion:    1,
		CorpusID:         snapshot.CorpusID,
		GeneratorVersion: snapshot.GeneratorVersion,
		GeneratedAt:      snapshot.GeneratedAt,
		FetchedAt:        snapshot.FetchedAt,
		StaleAfter:       snapshot.StaleAfter,
		Checksum:         snapshot.Checksum,
	}
	if snapshot.StaleAfter != "" {
		if staleAfterAt, err := time.Parse(time.RFC3339, snapshot.StaleAfter); err == nil && now.After(staleAfterAt) {
			status.Stale = true
		}
	}
	return status, true
}

// Insert adds a CIDR prefix to the radix trie.
func (cni *CorporateNetworkIndex) Insert(prefix netip.Prefix, payload string) {
	cni.Lock()
	defer cni.Unlock()
	cni.RootNode = insertNode(cni.RootNode, prefix, payload, 0)
}

func insertNode(node *RadixNode, prefix netip.Prefix, payload string, bitIndex int) *RadixNode {
	if node == nil {
		node = &RadixNode{}
	}
	if bitIndex == prefix.Bits() {
		p := prefix
		node.Prefix = &p
		node.Payload = payload
		return node
	}
	bit := getBit(prefix.Addr(), bitIndex)
	if bit == 0 {
		node.Left = insertNode(node.Left, prefix, payload, bitIndex+1)
	} else {
		node.Right = insertNode(node.Right, prefix, payload, bitIndex+1)
	}
	return node
}

// MatchLongestPrefix finds the longest matching CIDR prefix for an IP in the radix trie.
func (cni *CorporateNetworkIndex) MatchLongestPrefix(addr netip.Addr) (string, bool) {
	cni.RLock()
	defer cni.RUnlock()
	var bestPayload string
	var found bool
	curr := cni.RootNode
	for bitIndex := 0; curr != nil; bitIndex++ {
		if curr.Prefix != nil && curr.Prefix.Contains(addr) {
			bestPayload = curr.Payload
			found = true
		}
		if bitIndex >= addr.BitLen() {
			break
		}
		bit := getBit(addr, bitIndex)
		if bit == 0 {
			curr = curr.Left
		} else {
			curr = curr.Right
		}
	}
	return bestPayload, found
}

func getBit(addr netip.Addr, bitIndex int) int {
	bytes := addr.AsSlice()
	byteIdx := bitIndex / 8
	bitIdx := 7 - (bitIndex % 8)
	if byteIdx >= len(bytes) {
		return 0
	}
	return int((bytes[byteIdx] >> bitIdx) & 1)
}

// UpdateProviderCorpusRegistry swaps the active provider corpus snapshot and rebuilds the radix classification trie.
func UpdateProviderCorpusRegistry(corpus ProviderCorpus) error {
	snapshot, err := BuildProviderSnapshot(corpus)
	if err != nil {
		return err
	}
	providerCorpusStore.Store(snapshot)

	// Rebuild the radix trie index
	newIndex := &CorporateNetworkIndex{}
	for _, p := range corpus.Providers {
		for _, raw := range append(append([]string{}, p.IPv4Prefixes...), p.IPv6Prefixes...) {
			if prefix, err := netip.ParsePrefix(raw); err == nil {
				newIndex.Insert(prefix, p.ProviderID)
			}
		}
	}

	networkClassificationIndex.Lock()
	networkClassificationIndex.RootNode = newIndex.RootNode
	networkClassificationIndex.Unlock()

	return nil
}

// InitBuiltinProviderCorpus registers default CDN prefixes in both the Radix trie and snapshot store.
func InitBuiltinProviderCorpus() error {
	corpus := BuiltinProviderCorpus()
	snapshot, err := BuildProviderSnapshot(corpus)
	if err != nil {
		return err
	}
	providerCorpusStore.Store(snapshot)

	// Populate radix trie index
	for _, p := range corpus.Providers {
		for _, raw := range append(append([]string{}, p.IPv4Prefixes...), p.IPv6Prefixes...) {
			if prefix, err := netip.ParsePrefix(raw); err == nil {
				networkClassificationIndex.Insert(prefix, p.ProviderID)
			}
		}
	}
	return nil
}

// GetProviderCorpusStoreStatus returns status of the active provider corpus.
func GetProviderCorpusStoreStatus() (ProviderCorpusStatus, bool) {
	return providerCorpusStore.Status(time.Now())
}

// ObserveProvider searches the prefix store for the given IP address and returns its observations.
func ObserveProvider(ip string) ProviderObservation {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ProviderObservation{}
	}
	match, ok := providerCorpusStore.Lookup(addr)
	if !ok {
		// Fallback to trie index lookup
		if classification, ok := networkClassificationIndex.MatchLongestPrefix(addr); ok {
			corpus := BuiltinProviderCorpus()
			for _, p := range corpus.Providers {
				if p.ProviderID == classification {
					return ProviderObservation{
						ProviderID:  p.ProviderID,
						DisplayName: p.DisplayName,
						Source:      "network_classification_radix",
					}
				}
			}
		}
		return ProviderObservation{}
	}
	return ProviderObservation{
		ProviderID:  match.ProviderID,
		DisplayName: match.DisplayName,
		Prefix:      match.Prefix.String(),
		Confidence:  match.Confidence,
		CorpusID:    match.CorpusID,
		Source:      "provider_corpus_store",
	}
}

// MatchRadixClassification returns provider classification name using radix lookup.
func MatchRadixClassification(ip netip.Addr) (string, bool) {
	return networkClassificationIndex.MatchLongestPrefix(ip)
}

// BuiltinProviderCorpus returns the built-in CDN provider prefix registry.
func BuiltinProviderCorpus() ProviderCorpus {
	return ProviderCorpus{
		SchemaVersion:    1,
		CorpusID:         "builtin-provider-prefixes-v1",
		GeneratorVersion: "manual-builtin-provider-prefixes-v1",
		GeneratedAt:      "2026-05-24T00:00:00Z",
		FetchedAt:        "2026-05-24T00:00:00Z",
		StaleAfter:       "2026-06-23T00:00:00Z",
		Checksum:         "manual:builtin-provider-prefixes-v1",
		Providers: []ProviderManifest{
			{
				ProviderID:    "cloudflare",
				DisplayName:   "Cloudflare",
				SourceURL:     "builtin://provider_observer",
				SourceLicense: "manual-builtin",
				SourceKind:    "manual_fixture",
				Confidence:    "medium",
				Priority:      100,
				IPv4Prefixes:  []string{"104.16.0.0/12", "172.64.0.0/13"},
				IPv6Prefixes:  []string{"2606:4700::/32"},
			},
			{
				ProviderID:    "fastly",
				DisplayName:   "Fastly",
				SourceURL:     "builtin://provider_observer",
				SourceLicense: "manual-builtin",
				SourceKind:    "manual_fixture",
				Confidence:    "medium",
				Priority:      90,
				IPv4Prefixes:  []string{"151.101.0.0/16"},
				IPv6Prefixes:  []string{"2a04:4e42::/32"},
			},
			{
				ProviderID:    "cloudfront",
				DisplayName:   "Amazon CloudFront",
				SourceURL:     "builtin://provider_observer",
				SourceLicense: "manual-builtin",
				SourceKind:    "manual_fixture",
				Confidence:    "medium",
				Priority:      80,
				IPv4Prefixes:  []string{"13.32.0.0/15", "13.224.0.0/14", "18.64.0.0/14", "54.230.0.0/16"},
				IPv6Prefixes:  []string{},
			},
			{
				ProviderID:    "akamai",
				DisplayName:   "Akamai",
				SourceURL:     "builtin://provider_observer",
				SourceLicense: "manual-builtin",
				SourceKind:    "manual_fixture",
				Confidence:    "medium",
				Priority:      70,
				IPv4Prefixes:  []string{"23.32.0.0/11", "23.192.0.0/11", "184.24.0.0/13"},
				IPv6Prefixes:  []string{"2a02:26f0::/32"},
			},
		},
	}
}
