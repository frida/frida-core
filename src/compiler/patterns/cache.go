package patterns

import (
	"container/list"
	"sync"
)

type cache[K comparable, V any] struct {
	mu       sync.Mutex
	capacity int
	entries  map[K]*list.Element
	recency  list.List
}

type cacheEntry[K comparable, V any] struct {
	key   K
	value V
}

func newCache[K comparable, V any](capacity int) *cache[K, V] {
	return &cache[K, V]{capacity: capacity, entries: map[K]*list.Element{}}
}

func (c *cache[K, V]) obtain(key K, create func() V) V {
	c.mu.Lock()
	defer c.mu.Unlock()

	if element, found := c.entries[key]; found {
		c.recency.MoveToFront(element)
		return element.Value.(*cacheEntry[K, V]).value
	}
	value := create()
	c.insert(key, value)
	return value
}

func (c *cache[K, V]) get(key K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	element, found := c.entries[key]
	if !found {
		var missing V
		return missing, false
	}
	c.recency.MoveToFront(element)
	return element.Value.(*cacheEntry[K, V]).value, true
}

func (c *cache[K, V]) put(key K, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if element, found := c.entries[key]; found {
		c.evict(element)
	}
	c.insert(key, value)
}

func (c *cache[K, V]) insert(key K, value V) {
	c.entries[key] = c.recency.PushFront(&cacheEntry[K, V]{key: key, value: value})
	if c.recency.Len() > c.capacity {
		c.evict(c.recency.Back())
	}
}

func (c *cache[K, V]) evict(element *list.Element) {
	c.recency.Remove(element)
	delete(c.entries, element.Value.(*cacheEntry[K, V]).key)
}
