// ABOUTME: AWS EKS cloud provider implementation for image discovery.
// ABOUTME: Discovers container images from EKS Kubernetes workloads using the Kubernetes API.

package aws

import (
	"context"
	"fmt"
	"strings"

	"github.com/jfeddern/VulnRelay/internal/types"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// EKSProvider implements CloudProvider for Amazon EKS
type EKSProvider struct {
	clientset kubernetes.Interface
	logger    *logrus.Logger
}

// NewEKSProvider creates a new EKS cloud provider
func NewEKSProvider(logger *logrus.Logger) (*EKSProvider, error) {
	var config *rest.Config
	var err error

	// Try in-cluster config first (for pod deployment)
	config, err = rest.InClusterConfig()
	if err != nil {
		// Fallback to kubeconfig (for local development)
		logger.Info("In-cluster config not available, trying kubeconfig")
		config, err = clientcmd.BuildConfigFromFlags("", clientcmd.RecommendedHomeFile)
		if err != nil {
			return nil, fmt.Errorf("failed to build kubernetes config: %w", err)
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes clientset: %w", err)
	}

	logger.Info("Successfully connected to EKS cluster")
	return &EKSProvider{
		clientset: clientset,
		logger:    logger,
	}, nil
}

// Name returns the provider name
func (e *EKSProvider) Name() string {
	return "aws-eks"
}

// IsRegistryImage checks if the image is from ECR registry
func (e *EKSProvider) IsRegistryImage(imageURI string) bool {
	return strings.Contains(imageURI, ".dkr.ecr.") && strings.Contains(imageURI, ".amazonaws.com/")
}

// DiscoverImages discovers container images from EKS workloads
func (e *EKSProvider) DiscoverImages(ctx context.Context) ([]types.ImageInfo, error) {
	logger := e.logger.WithField("operation", "discover_images")

	var images []types.ImageInfo

	// Discover images from Deployments
	deploymentImages, err := e.discoverFromDeployments(ctx)
	if err != nil {
		logger.WithError(err).Error("Failed to discover images from deployments")
		return nil, err
	}
	images = append(images, deploymentImages...)

	// Discover images from StatefulSets
	statefulSetImages, err := e.discoverFromStatefulSets(ctx)
	if err != nil {
		logger.WithError(err).Error("Failed to discover images from statefulsets")
		return nil, err
	}
	images = append(images, statefulSetImages...)

	logger.WithField("image_count", len(images)).Info("Image discovery completed")
	return images, nil
}

func (e *EKSProvider) discoverFromDeployments(ctx context.Context) ([]types.ImageInfo, error) {
	logger := e.logger.WithField("resource_type", "deployments")

	deployments, err := e.clientset.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list deployments: %w", err)
	}

	logger.WithField("deployment_count", len(deployments.Items)).Info("Processing deployments")

	var images []types.ImageInfo
	for _, deployment := range deployments.Items {
		deploymentImages := e.extractImagesFromPodSpec(
			deployment.Spec.Template.Spec,
			deployment.Namespace,
			deployment.Name,
			"Deployment",
		)
		images = append(images, deploymentImages...)
	}

	return images, nil
}

func (e *EKSProvider) discoverFromStatefulSets(ctx context.Context) ([]types.ImageInfo, error) {
	logger := e.logger.WithField("resource_type", "statefulsets")

	statefulSets, err := e.clientset.AppsV1().StatefulSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list statefulsets: %w", err)
	}

	logger.WithField("statefulset_count", len(statefulSets.Items)).Info("Processing statefulsets")

	var images []types.ImageInfo
	for _, statefulSet := range statefulSets.Items {
		statefulSetImages := e.extractImagesFromPodSpec(
			statefulSet.Spec.Template.Spec,
			statefulSet.Namespace,
			statefulSet.Name,
			"StatefulSet",
		)
		images = append(images, statefulSetImages...)
	}

	return images, nil
}

func (e *EKSProvider) extractImagesFromPodSpec(podSpec corev1.PodSpec, namespace, workload, workloadType string) []types.ImageInfo {
	var images []types.ImageInfo

	// Extract from main containers
	for _, container := range podSpec.Containers {
		if e.IsRegistryImage(container.Image) {
			images = append(images, types.ImageInfo{
				URI:          container.Image,
				Namespace:    namespace,
				Workload:     workload,
				WorkloadType: workloadType,
			})
		}
	}

	// Extract from init containers
	for _, container := range podSpec.InitContainers {
		if e.IsRegistryImage(container.Image) {
			images = append(images, types.ImageInfo{
				URI:          container.Image,
				Namespace:    namespace,
				Workload:     workload,
				WorkloadType: workloadType,
			})
		}
	}

	// Extract from ephemeral containers (if any)
	for _, container := range podSpec.EphemeralContainers {
		if e.IsRegistryImage(container.Image) {
			images = append(images, types.ImageInfo{
				URI:          container.Image,
				Namespace:    namespace,
				Workload:     workload,
				WorkloadType: workloadType,
			})
		}
	}

	return images
}
