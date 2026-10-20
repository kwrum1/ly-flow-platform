package main

import (
	"context"
	"encoding/json"
	"sync"
	"time"
)

// sourceCatalogCacheTTL keeps rule-source catalog responses warm without
// hiding configuration changes for long. Source updates clear the relevant
// cache entries immediately.
const sourceCatalogCacheTTL = 5 * time.Minute

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

// warmRulePlatformSourcesCache removes the first-request penalty for the
// database-backed rule-platform source catalog. It intentionally runs in the
// background and degrades silently: the HTTP handler still loads the catalog
// on demand if warmup fails.
func warmRulePlatformSourcesCache(cfg *Config) {
	if cfg == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	items, err := loadRulePlatformSources(ctx, cfg)
	if err != nil {
		return
	}
	body, err := json.Marshal(map[string]interface{}{"code": 0, "message": "success", "data": map[string]interface{}{"items": items, "total": len(items)}})
	if err != nil {
		return
	}
	rulePlatformSourcesResponseCache.set("rule-platform-sources", body)
}
