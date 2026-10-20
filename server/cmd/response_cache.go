package main

import (
	"sync"
	"time"
)

// sourceCatalogCacheTTL keeps rule-source catalog responses warm without
// hiding configuration changes for long. Source updates clear the relevant
// cache entries immediately.
const sourceCatalogCacheTTL = 30 * time.Second

type ttlResponseCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[string]ttlResponseEntry
}

type ttlResponseEntry struct {
	body      []byte
	expiresAt time.Time
}

func newTTLResponseCache(ttl time.Duration) *ttlResponseCache {
	return &ttlResponseCache{ttl: ttl, entries: map[string]ttlResponseEntry{}}
}

func (c *ttlResponseCache) get(key string) ([]byte, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if time.Now().After(entry.expiresAt) {
		delete(c.entries, key)
		return nil, false
	}
	return entry.body, true
}

func (c *ttlResponseCache) set(key string, body []byte) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = map[string]ttlResponseEntry{}
	}
	c.entries[key] = ttlResponseEntry{body: append([]byte(nil), body...), expiresAt: time.Now().Add(c.ttl)}
}

func (c *ttlResponseCache) clear() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.entries)
}

var (
	ruleSourcesResponseCache         = newTTLResponseCache(sourceCatalogCacheTTL)
	rulePlatformSourcesResponseCache = newTTLResponseCache(sourceCatalogCacheTTL)
)
