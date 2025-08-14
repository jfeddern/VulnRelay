// ABOUTME: Unit tests for vulnerability data caching functionality.
// ABOUTME: Tests TTL-based cache operations and cleanup mechanisms.

package cache

import (
	"fmt"
	"strings"
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

func TestCacheCleanup(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Minimize test output

	cache := &VulnerabilityCache{
		cache:  make(map[string]*CacheEntry),
		ttl:    50 * time.Millisecond, // Very short TTL for testing
		logger: logger,
	}

	// Add some test data
	testImages := []string{
		"123456789012.dkr.ecr.us-east-1.amazonaws.com/app1:v1.0.0",
		"123456789012.dkr.ecr.us-east-1.amazonaws.com/app2:v2.0.0",
		"123456789012.dkr.ecr.us-east-1.amazonaws.com/app3:v3.0.0",
	}

	for i, image := range testImages {
		cache.Set(image, &types.ImageVulnerability{
			ImageURI:   image,
			TotalCount: i + 1,
		})
	}

	// Verify all entries exist
	total, expired := cache.Stats()
	if total != 3 {
		t.Errorf("Expected 3 total entries, got %d", total)
	}

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Check that entries are marked as expired but still in cache
	total, expired = cache.Stats()
	if total != 3 {
		t.Errorf("Expected 3 total entries before cleanup, got %d", total)
	}
	if expired != 3 {
		t.Errorf("Expected 3 expired entries, got %d", expired)
	}

	// Manually trigger cleanup
	cache.cleanup()

	// Verify entries are removed
	total, expired = cache.Stats()
	if total != 0 {
		t.Errorf("Expected 0 entries after cleanup, got %d", total)
	}
	if expired != 0 {
		t.Errorf("Expected 0 expired entries after cleanup, got %d", expired)
	}
}

func TestCacheCleanupWithMixedExpiry(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	cache := &VulnerabilityCache{
		cache:  make(map[string]*CacheEntry),
		ttl:    200 * time.Millisecond, // Longer TTL
		logger: logger,
	}

	// Add entries at different times
	cache.Set("expired1", &types.ImageVulnerability{ImageURI: "expired1", TotalCount: 1})
	cache.Set("expired2", &types.ImageVulnerability{ImageURI: "expired2", TotalCount: 2})

	// Manually expire these entries
	cache.mutex.Lock()
	for key, entry := range cache.cache {
		if key == "expired1" || key == "expired2" {
			entry.ExpiresAt = time.Now().Add(-1 * time.Minute) // Already expired
		}
	}
	cache.mutex.Unlock()

	// Add fresh entry
	time.Sleep(10 * time.Millisecond)
	cache.Set("fresh", &types.ImageVulnerability{ImageURI: "fresh", TotalCount: 3})

	// Verify mixed state
	total, expired := cache.Stats()
	if total != 3 {
		t.Errorf("Expected 3 total entries, got %d", total)
	}
	if expired != 2 {
		t.Errorf("Expected 2 expired entries, got %d", expired)
	}

	// Cleanup
	cache.cleanup()

	// Verify only fresh entry remains
	total, expired = cache.Stats()
	if total != 1 {
		t.Errorf("Expected 1 entry after cleanup, got %d", total)
	}
	if expired != 0 {
		t.Errorf("Expected 0 expired entries after cleanup, got %d", expired)
	}

	// Verify the fresh entry is still accessible
	result := cache.Get("fresh")
	if result == nil {
		t.Error("Expected fresh entry to still be accessible")
	}
	if result.TotalCount != 3 {
		t.Errorf("Expected TotalCount=3, got %d", result.TotalCount)
	}
}

func TestCacheConcurrency(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	cache := NewVulnerabilityCache(logger)

	// Number of concurrent goroutines
	numGoroutines := 10
	numOperations := 100

	// Test concurrent read/write operations
	done := make(chan bool, numGoroutines*2)

	// Writers
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			for j := 0; j < numOperations; j++ {
				imageURI := fmt.Sprintf("image-%d-%d", id, j)
				vuln := &types.ImageVulnerability{
					ImageURI:   imageURI,
					TotalCount: j,
				}
				cache.Set(imageURI, vuln)
			}
			done <- true
		}(i)
	}

	// Readers
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			for j := 0; j < numOperations; j++ {
				imageURI := fmt.Sprintf("image-%d-%d", id, j)
				cache.Get(imageURI) // May or may not find data, that's ok
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines*2; i++ {
		<-done
	}

	// Verify cache is still functional
	testImage := "test-after-concurrency"
	testVuln := &types.ImageVulnerability{
		ImageURI:   testImage,
		TotalCount: 42,
	}

	cache.Set(testImage, testVuln)
	result := cache.Get(testImage)

	if result == nil {
		t.Error("Cache should still be functional after concurrent access")
	}
	if result.TotalCount != 42 {
		t.Errorf("Expected TotalCount=42, got %d", result.TotalCount)
	}
}

func TestCacheOverwrite(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	cache := NewVulnerabilityCache(logger)

	testImage := "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:v1.0.0"

	// Set initial data
	initialVuln := &types.ImageVulnerability{
		ImageURI:   testImage,
		TotalCount: 5,
		ScanStatus: "COMPLETE",
	}
	cache.Set(testImage, initialVuln)

	// Verify initial data
	result := cache.Get(testImage)
	if result == nil {
		t.Fatal("Expected cache hit for initial data")
	}
	if result.TotalCount != 5 {
		t.Errorf("Expected initial TotalCount=5, got %d", result.TotalCount)
	}

	// Overwrite with new data
	updatedVuln := &types.ImageVulnerability{
		ImageURI:   testImage,
		TotalCount: 10,
		ScanStatus: "UPDATED",
	}
	cache.Set(testImage, updatedVuln)

	// Verify updated data
	result = cache.Get(testImage)
	if result == nil {
		t.Fatal("Expected cache hit for updated data")
	}
	if result.TotalCount != 10 {
		t.Errorf("Expected updated TotalCount=10, got %d", result.TotalCount)
	}
	if result.ScanStatus != "UPDATED" {
		t.Errorf("Expected updated ScanStatus=UPDATED, got %s", result.ScanStatus)
	}
}

func TestCacheStatsAccuracy(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	cache := &VulnerabilityCache{
		cache:  make(map[string]*CacheEntry),
		ttl:    100 * time.Millisecond,
		logger: logger,
	}

	// Start with empty cache
	total, expired := cache.Stats()
	if total != 0 || expired != 0 {
		t.Errorf("Empty cache should have 0 total and 0 expired, got total=%d, expired=%d", total, expired)
	}

	// Add entries
	cache.Set("fresh1", &types.ImageVulnerability{ImageURI: "fresh1", TotalCount: 1})
	cache.Set("fresh2", &types.ImageVulnerability{ImageURI: "fresh2", TotalCount: 2})

	total, expired = cache.Stats()
	if total != 2 || expired != 0 {
		t.Errorf("Expected total=2, expired=0, got total=%d, expired=%d", total, expired)
	}

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	total, expired = cache.Stats()
	if total != 2 || expired != 2 {
		t.Errorf("Expected total=2, expired=2 after expiration, got total=%d, expired=%d", total, expired)
	}

	// Add fresh entry
	cache.Set("fresh3", &types.ImageVulnerability{ImageURI: "fresh3", TotalCount: 3})

	total, expired = cache.Stats()
	if total != 3 || expired != 2 {
		t.Errorf("Expected total=3, expired=2 after adding fresh entry, got total=%d, expired=%d", total, expired)
	}
}

func TestCacheDebugLogging(t *testing.T) {
	// Create logger that captures debug messages
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	// Capture log output
	var logEntries []logrus.Entry
	logger.AddHook(&testLogHook{entries: &logEntries})

	cache := NewVulnerabilityCache(logger)

	testImage := "test-logging"
	testVuln := &types.ImageVulnerability{ImageURI: testImage, TotalCount: 1}

	// This should generate a debug log for caching
	cache.Set(testImage, testVuln)

	// This should generate a debug log for cache hit
	cache.Get(testImage)

	// Check that debug logs were generated
	foundSetLog := false
	foundGetLog := false

	for _, entry := range logEntries {
		if strings.Contains(entry.Message, "Cached vulnerability data") {
			foundSetLog = true
		}
		if strings.Contains(entry.Message, "Cache hit") {
			foundGetLog = true
		}
	}

	if !foundSetLog {
		t.Error("Expected debug log for cache set operation")
	}
	if !foundGetLog {
		t.Error("Expected debug log for cache hit operation")
	}
}

// Test hook to capture log entries
type testLogHook struct {
	entries *[]logrus.Entry
}

func (h *testLogHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (h *testLogHook) Fire(entry *logrus.Entry) error {
	*h.entries = append(*h.entries, *entry)
	return nil
}
