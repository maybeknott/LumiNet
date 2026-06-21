package proxy

import (
	"testing"
)

func TestCircularCacheEviction(t *testing.T) {
	cache := NewCircularCache(3)

	cache.Set("k1", "v1")
	cache.Set("k2", "v2")
	cache.Set("k3", "v3")

	if cache.Len() != 3 {
		t.Errorf("expected length 3, got %d", cache.Len())
	}

	// Verify all items are present
	if val, ok := cache.Get("k1"); !ok || val != "v1" {
		t.Errorf("expected k1=v1, got %v (ok=%t)", val, ok)
	}

	// Insert 4th item, triggering eviction of oldest ("k1")
	cache.Set("k4", "v4")

	if cache.Len() != 3 {
		t.Errorf("expected length 3 after eviction, got %d", cache.Len())
	}

	// k1 should be evicted (missing)
	if _, ok := cache.Get("k1"); ok {
		t.Error("expected k1 to be evicted, but it was found")
	}

	// k2, k3, k4 should be present
	for _, key := range []string{"k2", "k3", "k4"} {
		if _, ok := cache.Get(key); !ok {
			t.Errorf("expected key %s to be present", key)
		}
	}

	// Delete an item and verify
	cache.Delete("k2")
	if cache.Len() != 2 {
		t.Errorf("expected length 2 after delete, got %d", cache.Len())
	}
	if _, ok := cache.Get("k2"); ok {
		t.Error("expected k2 to be deleted")
	}
}
