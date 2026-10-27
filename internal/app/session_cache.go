package app

import (
	"container/list"
	"sync"
	"time"
)

const (
	sessionCacheSize = 4096
	sessionCacheTTL  = 30 * time.Second
)

type cachedSession struct {
	key     string
	value   any
	expires time.Time
}

// Only immutable payloads are cached. Callers must check Redis key liveness
// before using a cached value; the cache is never an authorization authority.
type sessionCache struct {
	mu      sync.Mutex
	entries map[string]*list.Element
	lru     *list.List
}

func newSessionCache() *sessionCache {
	return &sessionCache{entries: make(map[string]*list.Element), lru: list.New()}
}

func (c *sessionCache) get(key string) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[key]; ok {
		v := e.Value.(cachedSession)
		if time.Now().Before(v.expires) {
			c.lru.MoveToFront(e)
			return v.value, true
		}
		c.remove(e)
	}
	return nil, false
}

func (c *sessionCache) put(key string, value any, expires time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[key]; ok {
		c.remove(e)
	}
	c.entries[key] = c.lru.PushFront(cachedSession{key: key, value: value, expires: expires})
	for len(c.entries) > sessionCacheSize {
		c.remove(c.lru.Back())
	}
}

func (c *sessionCache) delete(keys ...string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, key := range keys {
		if e, ok := c.entries[key]; ok {
			c.remove(e)
		}
	}
}

func (c *sessionCache) remove(e *list.Element) {
	delete(c.entries, e.Value.(cachedSession).key)
	c.lru.Remove(e)
}
