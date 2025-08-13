// ABOUTME: Unit tests for vulnerability data caching functionality.
// ABOUTME: Tests TTL-based cache operations and cleanup mechanisms.

package cache

import (
	"testing"
	"time"

	"github.com/jfeddern/VulnRelay/internal/types"

	"github.com/sirupsen/logrus"
)

func TestVulnerabilityCache(t *testing.T) {
	logger := logrus.New()
	cache := NewVulnerabilityCache(logger)

	// Test data
	testImage := "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:v1.0.0"
	testVuln := &types.ImageVulnerability{
		ImageURI:        testImage,
		Vulnerabilities: map[string]int{"HIGH": 5, "MEDIUM": 10},
		TotalCount:      15,
		ScanStatus:      "COMPLETE",
	}

	t.Run("cache miss", func(t *testing.T) {
		result := cache.Get("nonexistent")
		if result != nil {
			t.Error("Expected cache miss, but got result")
		}
	})

	t.Run("cache hit", func(t *testing.T) {
		// Set data
		cache.Set(testImage, testVuln)

		// Get data
		result := cache.Get(testImage)
		if result == nil {
			t.Fatal("Expected cache hit, but got nil")
		}

		if result.ImageURI != testVuln.ImageURI {
			t.Errorf("ImageURI mismatch: got %s, want %s", result.ImageURI, testVuln.ImageURI)
		}

		if result.TotalCount != testVuln.TotalCount {
			t.Errorf("TotalCount mismatch: got %d, want %d", result.TotalCount, testVuln.TotalCount)
		}
	})

	t.Run("cache stats", func(t *testing.T) {
		total, expired := cache.Stats()
		if total < 1 {
			t.Errorf("Expected at least 1 cache entry, got %d", total)
		}

		if expired > total {
			t.Errorf("Expired count (%d) cannot be greater than total (%d)", expired, total)
		}
	})
}

func TestCacheExpiration(t *testing.T) {
	logger := logrus.New()
	cache := &VulnerabilityCache{
		cache:  make(map[string]*CacheEntry),
		ttl:    100 * time.Millisecond, // Very short TTL for testing
		logger: logger,
	}

	testImage := "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:v1.0.0"
	testVuln := &types.ImageVulnerability{
		ImageURI:   testImage,
		TotalCount: 5,
	}

	// Set data
	cache.Set(testImage, testVuln)

	// Should be available immediately
	result := cache.Get(testImage)
	if result == nil {
		t.Error("Expected cache hit immediately after set")
	}

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	// Should be expired now
	result = cache.Get(testImage)
	if result != nil {
		t.Error("Expected cache miss after expiration")
	}
}
