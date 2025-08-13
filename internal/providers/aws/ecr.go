// ABOUTME: AWS ECR vulnerability source implementation for scanning container images.
// ABOUTME: Handles authentication and vulnerability data retrieval from Amazon ECR.

package aws

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/jfeddern/VulnRelay/internal/types"
	"github.com/sirupsen/logrus"
)

// ECRSource implements VulnerabilitySource for Amazon ECR
type ECRSource struct {
	client    *ecr.Client
	accountID string
	region    string
	logger    *logrus.Logger
}

// NewECRSource creates a new ECR vulnerability source
func NewECRSource(ctx context.Context, accountID, region string, logger *logrus.Logger) (*ECRSource, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Handle role assumption for cross-account access
	var ecrClient *ecr.Client

	// Check if we need to assume a role based on AWS_IAM_ASSUME_ROLE_ARN environment variable
	if assumeRoleARN := os.Getenv("AWS_IAM_ASSUME_ROLE_ARN"); assumeRoleARN != "" {
		logger.WithField("role_arn", assumeRoleARN).Info("Assuming role from AWS_IAM_ASSUME_ROLE_ARN environment variable")

		currentCfg := cfg.Copy()
		stsClient := sts.NewFromConfig(currentCfg)

		// Create STS credentials for role assumption
		stsCreds := stscreds.NewAssumeRoleProvider(stsClient, assumeRoleARN)
		cfg.Credentials = stsCreds
	} else {
		// Fallback: Check caller identity and assume role if in different account
		currentCfg := cfg.Copy()
		stsClient := sts.NewFromConfig(currentCfg)

		identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		if err != nil {
			logger.WithError(err).Warn("Could not get caller identity, proceeding with default credentials")
		} else {
			currentAccountID := aws.ToString(identity.Account)
			logger.WithFields(logrus.Fields{
				"current_account": currentAccountID,
				"target_account":  accountID,
			}).Info("AWS identity information")

			// If we're in a different account, assume we need to assume a role
			if currentAccountID != accountID {
				roleARN := fmt.Sprintf("arn:aws:iam::%s:role/ECRVulnerabilityExporterRole", accountID)
				logger.WithField("role_arn", roleARN).Info("Assuming cross-account role")

				// Create STS credentials for role assumption
				stsCreds := stscreds.NewAssumeRoleProvider(stsClient, roleARN)
				cfg.Credentials = stsCreds
			}
		}
	}

	ecrClient = ecr.NewFromConfig(cfg)

	return &ECRSource{
		client:    ecrClient,
		accountID: accountID,
		region:    region,
		logger:    logger,
	}, nil
}

// Name returns the vulnerability source name
func (e *ECRSource) Name() string {
	return "aws-ecr"
}

// ParseImageURI extracts repository name and tag from a full ECR image URI
// Expected format: account.dkr.ecr.region.amazonaws.com/repository:tag
func (e *ECRSource) ParseImageURI(imageURI string) (repository, tag string, err error) {
	// Split by '/' to get the repository part
	parts := strings.Split(imageURI, "/")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid image URI format: %s", imageURI)
	}

	// The repository is everything after the first '/'
	repoWithTag := strings.Join(parts[1:], "/")

	// Split by ':' to separate repository and tag
	repoParts := strings.Split(repoWithTag, ":")
	if len(repoParts) != 2 {
		return "", "", fmt.Errorf("invalid image URI format, missing tag: %s", imageURI)
	}

	return repoParts[0], repoParts[1], nil
}

// GetImageVulnerabilities retrieves vulnerability data for a container image from ECR
func (e *ECRSource) GetImageVulnerabilities(ctx context.Context, imageURI string) (*types.ImageVulnerability, error) {
	logger := e.logger.WithField("image_uri", imageURI)

	// Parse the image URI to extract repository and tag
	repo, tag, err := e.ParseImageURI(imageURI)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image URI: %w", err)
	}

	logger = logger.WithFields(logrus.Fields{
		"repository": repo,
		"tag":        tag,
	})

	// Check scan results
	imageID := &ecrtypes.ImageIdentifier{
		ImageTag: aws.String(tag),
	}

	input := &ecr.DescribeImageScanFindingsInput{
		RepositoryName: aws.String(repo),
		ImageId:        imageID,
	}

	output, err := e.client.DescribeImageScanFindings(ctx, input)
	if err != nil {
		logger.WithError(err).Error("Failed to describe image scan findings")
		return &types.ImageVulnerability{
			ImageURI:        imageURI,
			Vulnerabilities: make(map[string]int),
			TotalCount:      0,
			ScanStatus:      "FAILED",
		}, err
	}

	vulnerabilities := make(map[string]int)
	totalCount := 0

	// Extract detailed findings and count vulnerabilities
	var detailedFindings []types.VulnerabilityFinding
	findingsCounts := make(map[string]int)
	findingsTotalCount := 0

	if output.ImageScanFindings != nil {
		// Process basic scanning findings
		for _, finding := range output.ImageScanFindings.Findings {
			severity := string(finding.Severity)
			findingsCounts[severity]++
			findingsTotalCount++

			// Create detailed finding
			detailedFinding := types.VulnerabilityFinding{
				Severity:         severity,
				ExploitAvailable: "unknown",
				FixAvailable:     "unknown",
			}

			if finding.Name != nil {
				detailedFinding.Name = *finding.Name
			}
			if finding.Description != nil {
				detailedFinding.Description = *finding.Description
			}
			if finding.Uri != nil {
				detailedFinding.URI = *finding.Uri
			}

			detailedFindings = append(detailedFindings, detailedFinding)
		}

		// Process enhanced scanning findings (Amazon Inspector)
		for _, enhancedFinding := range output.ImageScanFindings.EnhancedFindings {
			if enhancedFinding.Severity != nil {
				severity := *enhancedFinding.Severity
				findingsCounts[severity]++
				findingsTotalCount++

				// Create detailed finding with enhanced data
				detailedFinding := types.VulnerabilityFinding{
					Severity:         severity,
					Score:            enhancedFinding.Score,
					ExploitAvailable: "unknown",
					FixAvailable:     "unknown",
				}

				if enhancedFinding.Title != nil {
					detailedFinding.Name = *enhancedFinding.Title
				}
				if enhancedFinding.Description != nil {
					detailedFinding.Description = *enhancedFinding.Description
				}
				if enhancedFinding.Status != nil {
					detailedFinding.Status = *enhancedFinding.Status
				}
				if enhancedFinding.Type != nil {
					detailedFinding.Type = *enhancedFinding.Type
				}
				if enhancedFinding.ExploitAvailable != nil {
					detailedFinding.ExploitAvailable = *enhancedFinding.ExploitAvailable
				}
				if enhancedFinding.FixAvailable != nil {
					detailedFinding.FixAvailable = *enhancedFinding.FixAvailable
				}

				// Extract package information from vulnerability details
				if enhancedFinding.PackageVulnerabilityDetails != nil {
					if enhancedFinding.PackageVulnerabilityDetails.Source != nil {
						detailedFinding.Name = *enhancedFinding.PackageVulnerabilityDetails.Source
					}
					if enhancedFinding.PackageVulnerabilityDetails.VulnerablePackages != nil {
						for _, pkg := range enhancedFinding.PackageVulnerabilityDetails.VulnerablePackages {
							if pkg.Name != nil {
								detailedFinding.PackageName = *pkg.Name
							}
							if pkg.Version != nil {
								detailedFinding.PackageVersion = *pkg.Version
							}
							if pkg.FixedInVersion != nil {
								detailedFinding.FixVersion = *pkg.FixedInVersion
							}
							break // Use first package for simplicity
						}
					}
				}

				detailedFindings = append(detailedFindings, detailedFinding)
			}
		}

		// Use FindingSeverityCounts from API for comparison
		apiCounts := make(map[string]int)
		apiTotalCount := 0
		if output.ImageScanFindings.FindingSeverityCounts != nil {
			for severity, count := range output.ImageScanFindings.FindingSeverityCounts {
				apiCounts[string(severity)] = int(count)
				apiTotalCount += int(count)
			}
		}

		logger.WithFields(logrus.Fields{
			"basic_findings_count":    len(output.ImageScanFindings.Findings),
			"enhanced_findings_count": len(output.ImageScanFindings.EnhancedFindings),
			"findings_direct_counts":  findingsCounts,
			"findings_direct_total":   findingsTotalCount,
			"api_severity_counts":     apiCounts,
			"api_total":               apiTotalCount,
		}).Info("Vulnerability counting comparison")

		// Use direct counting from findings arrays if available, otherwise use API counts
		if findingsTotalCount > 0 {
			vulnerabilities = findingsCounts
			totalCount = findingsTotalCount
			logger.Debug("Using direct findings count")
		} else if apiTotalCount > 0 {
			vulnerabilities = apiCounts
			totalCount = apiTotalCount
			logger.Debug("Using API severity counts")
		}
	}

	var scanStatus string
	var lastScanTime *string

	if output.ImageScanStatus != nil {
		scanStatus = string(output.ImageScanStatus.Status)
	}

	if output.ImageScanFindings != nil && output.ImageScanFindings.ImageScanCompletedAt != nil {
		timeStr := output.ImageScanFindings.ImageScanCompletedAt.Format("2006-01-02T15:04:05Z")
		lastScanTime = &timeStr
	}

	logger.WithFields(logrus.Fields{
		"total_vulnerabilities": totalCount,
		"scan_status":           scanStatus,
		"vulnerabilities":       vulnerabilities,
		"detailed_findings":     len(detailedFindings),
	}).Info("Retrieved vulnerability data")

	return &types.ImageVulnerability{
		ImageURI:        imageURI,
		Repository:      repo,
		Tag:             tag,
		Vulnerabilities: vulnerabilities,
		TotalCount:      totalCount,
		ScanStatus:      scanStatus,
		LastScanTime:    lastScanTime,
		Findings:        detailedFindings,
	}, nil
}
