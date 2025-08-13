// ABOUTME: In-memory caching system for vulnerability data to reduce ECR API calls.
// ABOUTME: Uses TTL-based expiration to balance data freshness with API rate limits.

package cache

import (
	"sync"
	"time"

	"github.com/jfeddern/VulnRelay/internal/types"

	"github.com/sirupsen/logrus"
)

type CacheEntry struct {
	Data      *types.ImageVulnerability
	ExpiresAt time.Time
}

type VulnerabilityCache struct {
	cache  map[string]*CacheEntry
	mutex  sync.RWMutex
	ttl    time.Duration
	logger *logrus.Logger
}

func NewVulnerabilityCache(logger *logrus.Logger) *VulnerabilityCache {
	cache := &VulnerabilityCache{
		cache:  make(map[string]*CacheEntry),
		ttl:    30 * time.Minute, // Cache for 30 minutes
		logger: logger,
	}

	// Start cleanup goroutine
	go cache.startCleanup()

	return cache
}

func (c *VulnerabilityCache) Get(imageURI string) *types.ImageVulnerability {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	entry, exists := c.cache[imageURI]
	if !exists {
		return nil
	}

	// Check if entry has expired
	if time.Now().After(entry.ExpiresAt) {
		// Don't delete here to avoid write lock in read operation
		// Cleanup will handle expired entries
		return nil
	}

	c.logger.WithField("image", imageURI).Debug("Cache hit")
	return entry.Data
}

func (c *VulnerabilityCache) Set(imageURI string, vulnerability *types.ImageVulnerability) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.cache[imageURI] = &CacheEntry{
		Data:      vulnerability,
		ExpiresAt: time.Now().Add(c.ttl),
	}

	c.logger.WithField("image", imageURI).Debug("Cached vulnerability data")
}

func (c *VulnerabilityCache) startCleanup() {
	ticker := time.NewTicker(10 * time.Minute) // Cleanup every 10 minutes
	defer ticker.Stop()

	for range ticker.C {
		c.cleanup()
	}
}

func (c *VulnerabilityCache) cleanup() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := time.Now()
	expiredCount := 0

	for imageURI, entry := range c.cache {
		if now.After(entry.ExpiresAt) {
			delete(c.cache, imageURI)
			expiredCount++
		}
	}

	if expiredCount > 0 {
		c.logger.WithFields(logrus.Fields{
			"expired_entries":   expiredCount,
			"remaining_entries": len(c.cache),
		}).Debug("Cache cleanup completed")
	}
}

func (c *VulnerabilityCache) Stats() (total int, expired int) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	now := time.Now()
	total = len(c.cache)

	for _, entry := range c.cache {
		if now.After(entry.ExpiresAt) {
			expired++
		}
	}

	return total, expired
}
