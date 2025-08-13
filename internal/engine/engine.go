// ABOUTME: Main vulnerability collection engine that orchestrates providers.
// ABOUTME: Coordinates cloud providers and vulnerability sources to collect and cache data.

package engine

import (
	"context"
	"sync"
	"time"

	"github.com/jfeddern/VulnRelay/internal/cache"
	"github.com/jfeddern/VulnRelay/internal/types"
	"github.com/sirupsen/logrus"
)

// CloudProvider interface abstracts different cloud providers (AWS EKS, Google GKE, Azure AKS)
type CloudProvider interface {
	Name() string
	DiscoverImages(ctx context.Context) ([]types.ImageInfo, error)
	IsRegistryImage(imageURI string) bool
}

// VulnerabilitySource interface abstracts different vulnerability scanning sources
type VulnerabilitySource interface {
	Name() string
	GetImageVulnerabilities(ctx context.Context, imageURI string) (*types.ImageVulnerability, error)
	ParseImageURI(imageURI string) (repository, tag string, err error)
}

// Config holds configuration for the vulnerability collection engine
type Config struct {
	Mode           string
	Port           int
	ECRAccountID   string
	ECRRegion      string
	ImageListFile  string
	ScrapeInterval time.Duration
	MockMode       bool // Enable mock providers for local testing
}

// Engine orchestrates vulnerability data collection using pluggable providers
type Engine struct {
	cloudProvider       CloudProvider
	vulnerabilitySource VulnerabilitySource
	cache               *cache.VulnerabilityCache
	config              *Config
	logger              *logrus.Logger

	// Current vulnerability data with metadata
	mutex              sync.RWMutex
	vulnerabilityData  map[string]*types.ImageVulnerabilityData
	lastCollectionTime time.Time
}

// NewEngine creates a new vulnerability collection engine
func NewEngine(cloudProvider CloudProvider, vulnerabilitySource VulnerabilitySource, config *Config, logger *logrus.Logger) *Engine {
	return &Engine{
		cloudProvider:       cloudProvider,
		vulnerabilitySource: vulnerabilitySource,
		cache:               cache.NewVulnerabilityCache(logger),
		config:              config,
		logger:              logger,
		vulnerabilityData:   make(map[string]*types.ImageVulnerabilityData),
	}
}

// Start begins the vulnerability collection process
func (e *Engine) Start(ctx context.Context) {
	logger := e.logger.WithField("component", "vulnerability_engine")

	// Perform initial collection
	if err := e.collectVulnerabilities(ctx); err != nil {
		logger.WithError(err).Error("Initial vulnerability collection failed")
	}

	// Start periodic collection
	ticker := time.NewTicker(e.config.ScrapeInterval)
	defer ticker.Stop()

	logger.WithField("interval", e.config.ScrapeInterval).Info("Starting periodic vulnerability collection")

	for {
		select {
		case <-ctx.Done():
			logger.Info("Vulnerability engine stopping")
			return
		case <-ticker.C:
			if err := e.collectVulnerabilities(ctx); err != nil {
				logger.WithError(err).Error("Vulnerability collection failed")
			}
		}
	}
}

func (e *Engine) collectVulnerabilities(ctx context.Context) error {
	logger := e.logger.WithField("operation", "collect_vulnerabilities")
	startTime := time.Now()

	logger.Info("Starting vulnerability data collection")

	// Discover images using cloud provider
	images, err := e.cloudProvider.DiscoverImages(ctx)
	if err != nil {
		return err
	}

	logger.WithField("image_count", len(images)).Info("Discovered images")

	// Collect vulnerabilities for each image
	newVulnerabilityData := make(map[string]*types.ImageVulnerabilityData)

	// Use semaphore to limit concurrent API calls
	semaphore := make(chan struct{}, 10) // Max 10 concurrent calls
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, imageInfo := range images {
		wg.Add(1)
		go func(imgInfo types.ImageInfo) {
			defer wg.Done()

			semaphore <- struct{}{}        // Acquire semaphore
			defer func() { <-semaphore }() // Release semaphore

			vuln, err := e.getImageVulnerability(ctx, imgInfo.URI)
			if err != nil {
				logger.WithError(err).WithField("image", imgInfo.URI).Error("Failed to get vulnerability data")
				return
			}

			mu.Lock()
			newVulnerabilityData[imgInfo.URI] = &types.ImageVulnerabilityData{
				ImageVulnerability: vuln,
				ImageInfo:          imgInfo,
			}
			mu.Unlock()
		}(imageInfo)
	}

	wg.Wait()

	// Update the vulnerability data
	e.mutex.Lock()
	e.vulnerabilityData = newVulnerabilityData
	e.lastCollectionTime = time.Now()
	e.mutex.Unlock()

	duration := time.Since(startTime)
	logger.WithFields(logrus.Fields{
		"duration":                duration,
		"images_processed":        len(newVulnerabilityData),
		"total_images_discovered": len(images),
	}).Info("Vulnerability data collection completed")

	return nil
}

func (e *Engine) getImageVulnerability(ctx context.Context, imageURI string) (*types.ImageVulnerability, error) {
	// Try cache first
	if cachedVuln := e.cache.Get(imageURI); cachedVuln != nil {
		return cachedVuln, nil
	}

	// Fetch from vulnerability source
	vuln, err := e.vulnerabilitySource.GetImageVulnerabilities(ctx, imageURI)
	if err != nil {
		return nil, err
	}

	// Cache the result
	e.cache.Set(imageURI, vuln)

	return vuln, nil
}

// GetVulnerabilityData returns current vulnerability data and collection time
func (e *Engine) GetVulnerabilityData() (map[string]*types.ImageVulnerabilityData, time.Time) {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	// Return a copy to prevent race conditions
	data := make(map[string]*types.ImageVulnerabilityData)
	for k, v := range e.vulnerabilityData {
		data[k] = v
	}

	return data, e.lastCollectionTime
}
