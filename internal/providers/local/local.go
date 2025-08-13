// ABOUTME: Local file-based provider for development and testing purposes.
// ABOUTME: Reads container image lists from JSON files without cloud API dependencies.

package local

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/jfeddern/VulnRelay/internal/types"
	"github.com/sirupsen/logrus"
)

// LocalProvider implements CloudProvider for local file-based image discovery
type LocalProvider struct {
	imageListFile string
	logger        *logrus.Logger
}

// NewLocalProvider creates a new local file-based provider
func NewLocalProvider(imageListFile string, logger *logrus.Logger) *LocalProvider {
	return &LocalProvider{
		imageListFile: imageListFile,
		logger:        logger,
	}
}

// Name returns the provider name
func (l *LocalProvider) Name() string {
	return "local"
}

// IsRegistryImage checks if the image matches any registry pattern
// For local mode, we accept any image URI format
func (l *LocalProvider) IsRegistryImage(imageURI string) bool {
	return imageURI != ""
}

// DiscoverImages reads container images from a JSON file
func (l *LocalProvider) DiscoverImages(ctx context.Context) ([]types.ImageInfo, error) {
	logger := l.logger.WithField("operation", "discover_images_local")

	// Read the image list file
	data, err := os.ReadFile(l.imageListFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read image list file '%s': %w", l.imageListFile, err)
	}

	var imageURIs []string
	if err := json.Unmarshal(data, &imageURIs); err != nil {
		return nil, fmt.Errorf("failed to parse image list JSON: %w", err)
	}

	logger.WithField("image_count", len(imageURIs)).Info("Read image list from file")

	// Convert to ImageInfo structs
	var images []types.ImageInfo
	for _, uri := range imageURIs {
		if uri != "" {
			images = append(images, types.ImageInfo{
				URI:          uri,
				Namespace:    "local",
				Workload:     "local",
				WorkloadType: "Local",
			})
		}
	}

	logger.WithField("valid_images", len(images)).Info("Local image discovery completed")
	return images, nil
}
