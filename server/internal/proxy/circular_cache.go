package proxy

import (
	"container/list"
	"sync"
)

// cacheEntry holds the key-value pair stored in the ordered list.
type cacheEntry struct {
	key   string
	value interface{}
}

// CircularCache is a thread-safe ordered cache with a fixed capacity.
// When the capacity is reached, the oldest inserted items are evicted.
type CircularCache struct {
	capacity  int
	evictList *list.List
	items     map[string]*list.Element
	mu        sync.Mutex
}

// NewCircularCache creates a new CircularCache with the specified capacity.
func NewCircularCache(capacity int) *CircularCache {
	return &CircularCache{
		capacity:  capacity,
		evictList: list.New(),
		items:     make(map[string]*list.Element),
	}
}

// Get retrieves a value from the cache.
func (c *CircularCache) Get(key string) (interface{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		entry := elem.Value.(*cacheEntry)
		return entry.value, true
	}
	return nil, false
}

// Set adds or updates a value in the cache. Evicts the oldest item if capacity is exceeded.
func (c *CircularCache) Set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// If item already exists, update its value and move to back (most recent)
	if elem, ok := c.items[key]; ok {
		entry := elem.Value.(*cacheEntry)
		entry.value = value
		c.evictList.MoveToBack(elem)
		return
	}

	// Add new item
	entry := &cacheEntry{key: key, value: value}
	elem := c.evictList.PushBack(entry)
	c.items[key] = elem

	// Evict the oldest item (front of the list) if capacity is exceeded
	if c.capacity > 0 && c.evictList.Len() > c.capacity {
		c.evictOldest()
	}
}

// Delete removes an item from the cache.
func (c *CircularCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.removeElement(elem)
	}
}

// Len returns the number of items currently in the cache.
func (c *CircularCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.evictList.Len()
}

func (c *CircularCache) evictOldest() {
	elem := c.evictList.Front()
	if elem != nil {
		c.removeElement(elem)
	}
}

func (c *CircularCache) removeElement(elem *list.Element) {
	c.evictList.Remove(elem)
	entry := elem.Value.(*cacheEntry)
	delete(c.items, entry.key)
}
