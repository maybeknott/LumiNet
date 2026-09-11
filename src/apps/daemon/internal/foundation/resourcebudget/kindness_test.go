package resourcebudget

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func newTestBudget(t *testing.T, mode KindnessMode) *KindnessBudget {
	t.Helper()
	ranges := []PortRange{
		{Start: 10000, End: 10009, Kind: "kind"},
		{Start: 20000, End: 20009, Kind: "normal"},
	}
	b, err := NewKindnessBudget(ranges, mode)
	if err != nil {
		t.Fatalf("NewKindnessBudget: %v", err)
	}
	return b
}

func TestKindnessBudget_ReserveAndRelease(t *testing.T) {
	b := newTestBudget(t, Balanced)
	ctx := context.Background()
	r1, err := b.Reserve(ctx, "client1", "kind", DefaultBackoffConfig)
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if r1.Port < 10000 || r1.Port > 20009 {
		t.Errorf("port %d outside configured range", r1.Port)
	}
	if err := b.Release("client1"); err != nil {
		t.Fatalf("Release: %v", err)
	}
}

func TestKindnessBudget_ReserveFailsWhenFull(t *testing.T) {
	ranges := []PortRange{{Start: 20000, End: 20001}}
	b, err := NewKindnessBudget(ranges, Balanced)
	if err != nil {
		t.Fatalf("NewKindnessBudget: %v", err)
	}
	ctx := context.Background()
	if _, err := b.Reserve(ctx, "a", "normal", DefaultBackoffConfig); err != nil {
		t.Fatalf("Reserve a: %v", err)
	}
	if _, err := b.Reserve(ctx, "b", "normal", DefaultBackoffConfig); err != nil {
		t.Fatalf("Reserve b: %v", err)
	}
	shortBackoff := BackoffConfig{InitialDelay: time.Millisecond, MaxDelay: time.Millisecond, Multiplier: 1}
	_, err = b.Reserve(ctx, "c", "normal", shortBackoff)
	if !errors.Is(err, ErrNoFreePort) {
		t.Errorf("expected ErrNoFreePort, got %v", err)
	}
}

func TestKindnessBudget_KindnessMode_PrefersLowPorts(t *testing.T) {
	b := newTestBudget(t, KindClient)
	ctx := context.Background()
	r, err := b.Reserve(ctx, "mobile", "kind", DefaultBackoffConfig)
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if r.Port < 10000 || r.Port > 10009 {
		t.Errorf("KindClient should pick from kind range, got %d", r.Port)
	}
}

func TestKindnessBudget_GenerousMode_PrefersHighPorts(t *testing.T) {
	b := newTestBudget(t, Generous)
	ctx := context.Background()
	r, err := b.Reserve(ctx, "server", "normal", DefaultBackoffConfig)
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if r.Port < 20000 || r.Port > 20009 {
		t.Errorf("Generous should pick from normal range, got %d", r.Port)
	}
}

func TestKindnessBudget_RejectsInvalidRange(t *testing.T) {
	_, err := NewKindnessBudget([]PortRange{
		{Start: 5000, End: 4000},
	}, Balanced)
	if err == nil {
		t.Error("expected error for inverted range")
	}
	_, err = NewKindnessBudget([]PortRange{}, Balanced)
	if err == nil {
		t.Error("expected error for empty ranges")
	}
}

func TestKindnessBudget_ReleaseUnknownID(t *testing.T) {
	b := newTestBudget(t, Balanced)
	err := b.Release("nonexistent")
	if !errors.Is(err, ErrNoReservation) {
		t.Errorf("expected ErrNoReservation, got %v", err)
	}
}

func TestKindnessBudget_Stats(t *testing.T) {
	b := newTestBudget(t, Balanced)
	ctx := context.Background()
	if _, err := b.Reserve(ctx, "a", "normal", DefaultBackoffConfig); err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if _, err := b.Reserve(ctx, "b", "normal", DefaultBackoffConfig); err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	stats := b.Stats()
	if stats.Allocations != 2 {
		t.Errorf("Allocations: got %d, want 2", stats.Allocations)
	}
	if stats.Active != 2 {
		t.Errorf("Active: got %d, want 2", stats.Active)
	}
	if err := b.Release("a"); err != nil {
		t.Fatalf("Release: %v", err)
	}
	stats = b.Stats()
	if stats.Releases != 1 {
		t.Errorf("Releases: got %d, want 1", stats.Releases)
	}
	if stats.Active != 1 {
		t.Errorf("Active after release: got %d", stats.Active)
	}
}

func TestKindnessBudget_ConcurrentReserve(t *testing.T) {
	ranges := []PortRange{{Start: 30000, End: 30019}}
	b, err := NewKindnessBudget(ranges, Balanced)
	if err != nil {
		t.Fatalf("NewKindnessBudget: %v", err)
	}
	ctx := context.Background()
	var wg sync.WaitGroup
	gotPorts := make([]uint16, 0, 20)
	var mu sync.Mutex

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r, err := b.Reserve(ctx, "client-"+string(rune('a'+i)), "normal", DefaultBackoffConfig)
			if err != nil {
				t.Errorf("Reserve: %v", err)
				return
			}
			mu.Lock()
			gotPorts = append(gotPorts, r.Port)
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	// All 20 ports should be unique.
	seen := make(map[uint16]bool)
	for _, p := range gotPorts {
		if seen[p] {
			t.Errorf("duplicate port %d", p)
		}
		seen[p] = true
	}
	if len(seen) != 20 {
		t.Errorf("expected 20 unique ports, got %d", len(seen))
	}
}

func TestKindnessBudget_Backoff(t *testing.T) {
	ranges := []PortRange{{Start: 40000, End: 40000}}
	b, err := NewKindnessBudget(ranges, Balanced)
	if err != nil {
		t.Fatalf("NewKindnessBudget: %v", err)
	}
	ctx := context.Background()
	if _, err := b.Reserve(ctx, "holder", "normal", DefaultBackoffConfig); err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	cfg := BackoffConfig{
		InitialDelay:   50 * time.Millisecond,
		MaxDelay:       200 * time.Millisecond,
		Multiplier:     2.0,
		JitterFraction: 0,
	}
	start := time.Now()
	_, err = b.Reserve(ctx, "contender", "normal", cfg)
	if !errors.Is(err, ErrNoFreePort) {
		t.Fatalf("expected ErrNoFreePort, got %v", err)
	}
	if time.Since(start) < 50*time.Millisecond {
		t.Errorf("backoff did not delay (took %v)", time.Since(start))
	}
	// Second attempt should also fail with the exponentially longer penalty.
	start = time.Now()
	_, err = b.Reserve(ctx, "contender", "normal", cfg)
	if !errors.Is(err, ErrNoFreePort) {
		t.Fatalf("expected ErrNoFreePort, got %v", err)
	}
	if time.Since(start) < 100*time.Millisecond {
		t.Errorf("second backoff should be longer, took %v", time.Since(start))
	}
}

func TestKindnessBudget_RejectsDuplicateReservationID(t *testing.T) {
	b := newTestBudget(t, Balanced)
	ctx := context.Background()
	if _, err := b.Reserve(ctx, "same", "normal", DefaultBackoffConfig); err != nil {
		t.Fatalf("first Reserve: %v", err)
	}
	if _, err := b.Reserve(ctx, "same", "normal", DefaultBackoffConfig); !errors.Is(err, ErrAlreadyHeld) {
		t.Fatalf("duplicate reservation id: got %v, want ErrAlreadyHeld", err)
	}
	if got := b.Stats().Active; got != 1 {
		t.Fatalf("duplicate reservation leaked a port: active=%d, want 1", got)
	}
}

func TestKindnessBudget_BalancedDoesNotAllocateRangeGaps(t *testing.T) {
	b, err := NewKindnessBudget([]PortRange{{Start: 10000, End: 10000}, {Start: 20000, End: 20000}}, Balanced)
	if err != nil {
		t.Fatalf("NewKindnessBudget: %v", err)
	}
	ctx := context.Background()
	first, err := b.Reserve(ctx, "first", "normal", DefaultBackoffConfig)
	if err != nil {
		t.Fatalf("first Reserve: %v", err)
	}
	second, err := b.Reserve(ctx, "second", "normal", DefaultBackoffConfig)
	if err != nil {
		t.Fatalf("second Reserve: %v", err)
	}
	if first.Port != 10000 || second.Port != 20000 {
		t.Fatalf("allocated outside configured sparse ranges: got %d and %d", first.Port, second.Port)
	}
}

func TestKindnessBudget_MaxUint16RangeDoesNotWrap(t *testing.T) {
	b, err := NewKindnessBudget([]PortRange{{Start: 65534, End: 65535}}, Balanced)
	if err != nil {
		t.Fatalf("NewKindnessBudget: %v", err)
	}
	ctx := context.Background()
	first, err := b.Reserve(ctx, "first", "normal", DefaultBackoffConfig)
	if err != nil {
		t.Fatalf("first Reserve: %v", err)
	}
	second, err := b.Reserve(ctx, "second", "normal", DefaultBackoffConfig)
	if err != nil {
		t.Fatalf("second Reserve: %v", err)
	}
	if first.Port != 65534 || second.Port != 65535 {
		t.Fatalf("unexpected high-port allocation: got %d and %d", first.Port, second.Port)
	}
}

func TestKindnessBudget_SetMode(t *testing.T) {
	b := newTestBudget(t, Balanced)
	if b.mode != Balanced {
		t.Fatalf("initial mode wrong: %v", b.mode)
	}
	b.SetMode(KindClient)
	if b.mode != KindClient {
		t.Errorf("mode not updated: %v", b.mode)
	}
}
