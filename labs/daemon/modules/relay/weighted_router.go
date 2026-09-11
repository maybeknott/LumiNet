package relay

import (
	"math"
	"sync"
)

type EgressRoute struct {
	ID            string
	Endpoint      string
	Weight        int
	CurrentWeight int
	Healthy       bool
}

type WeightedEgressRouter struct {
	mu     sync.Mutex
	routes []*EgressRoute
}

func NewWeightedEgressRouter() *WeightedEgressRouter {
	return &WeightedEgressRouter{
		routes: make([]*EgressRoute, 0),
	}
}

func (r *WeightedEgressRouter) AddRoute(id, endpoint string, weight int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.routes = append(r.routes, &EgressRoute{
		ID:            id,
		Endpoint:      endpoint,
		Weight:        weight,
		CurrentWeight: 0,
		Healthy:       true,
	})
}

func (r *WeightedEgressRouter) SetHealth(id string, healthy bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, rt := range r.routes {
		if rt.ID == id {
			rt.Healthy = healthy
			if !healthy {
				rt.CurrentWeight = 0
			}
			break
		}
	}
}

func (r *WeightedEgressRouter) NextRoute() (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	totalHealthyWeight := 0
	for _, rt := range r.routes {
		if rt.Healthy && rt.Weight > 0 {
			totalHealthyWeight += rt.Weight
		}
	}

	if totalHealthyWeight <= 0 {
		return "", false
	}

	var bestRoute *EgressRoute
	maxWeight := math.MinInt32

	for _, rt := range r.routes {
		if !rt.Healthy || rt.Weight <= 0 {
			continue
		}
		rt.CurrentWeight += rt.Weight
		if rt.CurrentWeight > maxWeight {
			maxWeight = rt.CurrentWeight
			bestRoute = rt
		}
	}

	if bestRoute != nil {
		bestRoute.CurrentWeight -= totalHealthyWeight
		return bestRoute.Endpoint, true
	}

	return "", false
}
