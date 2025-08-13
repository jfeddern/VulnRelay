// ABOUTME: Factory for creating cloud providers and vulnerability sources.
// ABOUTME: Centralizes provider instantiation and configuration logic.

package providers

import (
	"context"
	"fmt"

	"github.com/jfeddern/VulnRelay/internal/engine"
	"github.com/jfeddern/VulnRelay/internal/providers/aws"
	"github.com/jfeddern/VulnRelay/internal/providers/local"
	"github.com/jfeddern/VulnRelay/internal/providers/mock"
	"github.com/sirupsen/logrus"
)

// ProviderConfig holds configuration for creating providers
type ProviderConfig struct {
	Mode          string
	ECRAccountID  string
	ECRRegion     string
	ImageListFile string
	MockMode      bool // Enable mock providers for local testing
}

// CreateCloudProvider creates a cloud provider based on configuration
func CreateCloudProvider(config *ProviderConfig, logger *logrus.Logger) (engine.CloudProvider, error) {
	// Check for mock mode first
	if config.MockMode {
		logger.Info("Using mock cloud provider for testing")
		return mock.NewMockEKSProvider(logger), nil
	}

	switch config.Mode {
	case "cluster":
		// For now, assume EKS for cluster mode
		// TODO: Add provider detection or explicit configuration
		return aws.NewEKSProvider(logger)
	case "local":
		return local.NewLocalProvider(config.ImageListFile, logger), nil
	default:
		return nil, fmt.Errorf("unsupported mode: %s", config.Mode)
	}
}

// CreateVulnerabilitySource creates a vulnerability source based on configuration
func CreateVulnerabilitySource(ctx context.Context, config *ProviderConfig, logger *logrus.Logger) (engine.VulnerabilitySource, error) {
	// Check for mock mode first
	if config.MockMode {
		logger.Info("Using mock vulnerability source for testing")
		return mock.NewMockECRSource(logger), nil
	}

	// For now, only ECR is supported
	// TODO: Add support for other vulnerability sources
	if config.ECRAccountID != "" && config.ECRRegion != "" {
		return aws.NewECRSource(ctx, config.ECRAccountID, config.ECRRegion, logger)
	}

	return nil, fmt.Errorf("no vulnerability source configured")
}
