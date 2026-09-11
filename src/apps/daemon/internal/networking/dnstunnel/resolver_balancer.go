package dnstunnel

import (
	"fmt"
	"math"
	"math/rand"
	"sort"
	"sync"
	"time"
)

// BalancerMode selects which resolver serves each query at traffic time.
// Taxonomy .go (MIT): eight modes covering
// deterministic rotation, randomness, and quality-first strategies.
type BalancerMode string

const (
	BalanceRoundRobin      BalancerMode = "round-robin"
	BalanceRandom          BalancerMode = "random"
	BalanceLeastLoss       BalancerMode = "least-loss"
	BalanceLowestLatency   BalancerMode = "lowest-latency"
	BalanceHybridScore     BalancerMode = "hybrid-score"
	BalanceLossThenLatency BalancerMode = "loss-then-latency"
	BalanceTopNRandom      BalancerMode = "top-n-random"
	BalanceTopNRoundRobin  BalancerMode = "top-n-round-robin"
)

// ParseBalancerMode validates a mode string.
func ParseBalancerMode(raw string) (BalancerMode, error) {
	mode := BalancerMode(raw)
	switch mode {
	case BalanceRoundRobin, BalanceRandom, BalanceLeastLoss, BalanceLowestLatency,
		BalanceHybridScore, BalanceLossThenLatency, BalanceTopNRandom, BalanceTopNRoundRobin:
		return mode, nil
	default:
		return "", fmt.Errorf("unknown balancer mode %q", raw)
	}
}

// Balancer picks a resolver index per query. Construct with
// NewBalancer(mode, plans); plans must be the tiered output of planResolvers
// (invalid tiers are skipped automatically). Safe for concurrent use.
type Balancer struct {
	mode     BalancerMode
	plans    []ResolverPlan // eligible only (reachable candidates)
	topN     int            // for top-N modes
	mu       sync.Mutex
	rrCursor int
	rng      *rand.Rand
}

// NewBalancer filters to eligible resolvers and returns a ready dispatcher.
// topN defaults to min(3, len(eligible)) for the top-N modes.
func NewBalancer(mode BalancerMode, plans []ResolverPlan, topN int) (*Balancer, error) {
	parsed, err := ParseBalancerMode(string(mode))
	if err != nil {
		return nil, err
	}
	eligible := make([]ResolverPlan, 0, len(plans))
	for _, p := range plans {
		if p.Tier == "active" || p.Tier == "reserve" || p.Tier == "candidate" {
			eligible = append(eligible, p)
		}
	}
	if len(eligible) == 0 {
		return nil, fmt.Errorf("balancer has no eligible resolvers")
	}
	sort.SliceStable(eligible, func(i, j int) bool {
		if eligible[i].LossPct != eligible[j].LossPct {
			return eligible[i].LossPct < eligible[j].LossPct
		}
		if eligible[i].RTTMs != eligible[j].RTTMs {
			return eligible[i].RTTMs < eligible[j].RTTMs
		}
		return eligible[i].Name < eligible[j].Name
	})
	if topN <= 0 || topN > len(eligible) {
		topN = len(eligible)
		if topN > 3 {
			topN = 3
		}
	}
	return &Balancer{mode: parsed, plans: eligible, topN: topN, rng: rand.New(rand.NewSource(time.Now().UnixNano()))}, nil
}

// Pick returns the index (into the eligible slice) of the chosen resolver.
func (b *Balancer) Pick() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(b.plans)
	switch b.mode {
	case BalanceRoundRobin, BalanceTopNRoundRobin:
		limit := n
		if b.mode == BalanceTopNRoundRobin && b.topN < n {
			limit = b.topN
		}
		idx := b.rrCursor % limit
		b.rrCursor++
		return idx
	case BalanceRandom:
		return b.rng.Intn(n)
	case BalanceLeastLoss:
		return b.extremum(func(p ResolverPlan) float64 { return p.LossPct }, true)
	case BalanceLowestLatency:
		return b.extremum(func(p ResolverPlan) float64 { return p.RTTMs }, true)
	case BalanceLossThenLatency:
		best := 0
		for i := 1; i < n; i++ {
			if b.plans[i].LossPct < b.plans[best].LossPct ||
				(b.plans[i].LossPct == b.plans[best].LossPct && b.plans[i].RTTMs < b.plans[best].RTTMs) {
				best = i
			}
		}
		return best
	case BalanceHybridScore:
		best, bestScore := 0, math.Inf(1)
		for i, p := range b.plans {
			rtt := p.RTTMs
			if rtt <= 0 {
				rtt = 1
			}
			score := p.LossPct + rtt/100.0
			if score < bestScore {
				bestScore = score
				best = i
			}
		}
		return best
	case BalanceTopNRandom:
		limit := b.topN
		if limit > n {
			limit = n
		}
		return b.rng.Intn(limit)
	default:
		return b.rrCursor % n
	}
}

func (b *Balancer) extremum(value func(ResolverPlan) float64, minimum bool) int {
	// Reservoir-sample equal extrema so ties are genuinely randomized while
	// every resolver, including index zero, participates in the comparison.
	best := 0
	bestVal := value(b.plans[0])
	ties := 1
	for i := 1; i < len(b.plans); i++ {
		v := value(b.plans[i])
		better := (minimum && v < bestVal) || (!minimum && v > bestVal)
		if better {
			best = i
			bestVal = v
			ties = 1
			continue
		}
		if v == bestVal {
			ties++
			if b.rng.Intn(ties) == 0 {
				best = i
			}
		}
	}
	return best
}

// Plan returns the resolver plan at an eligible index.
func (b *Balancer) Plan(idx int) ResolverPlan {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.plans[idx]
}

// Len reports the number of eligible resolvers.
func (b *Balancer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.plans)
}
