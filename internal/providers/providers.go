// ABOUTME: Provider interfaces for cloud platforms and vulnerability sources.
// ABOUTME: Defines contracts for supporting multiple cloud providers and vulnerability scanners.

package providers

import (
	"context"

	"github.com/jfeddern/VulnRelay/internal/types"
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
