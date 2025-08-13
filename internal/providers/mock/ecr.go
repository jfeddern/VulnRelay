// ABOUTME: Mock ECR vulnerability source for local testing and development.
// ABOUTME: Provides realistic vulnerability data without requiring AWS credentials.

package mock

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jfeddern/VulnRelay/internal/types"
	"github.com/sirupsen/logrus"
)

// MockECRSource implements VulnerabilitySource interface with mock data
type MockECRSource struct {
	logger *logrus.Logger
}

// NewMockECRSource creates a new mock ECR vulnerability source
func NewMockECRSource(logger *logrus.Logger) *MockECRSource {
	return &MockECRSource{
		logger: logger,
	}
}

// Name returns the name of this vulnerability source
func (m *MockECRSource) Name() string {
	return "mock-ecr"
}

// GetImageVulnerabilities returns mock vulnerability data for an image
func (m *MockECRSource) GetImageVulnerabilities(ctx context.Context, imageURI string) (*types.ImageVulnerability, error) {
	m.logger.WithField("image_uri", imageURI).Debug("Getting mock vulnerability data")

	// Parse image to determine mock data to return
	repo, tag, err := m.ParseImageURI(imageURI)
	if err != nil {
		return nil, err
	}

	// Generate mock data based on image characteristics
	scanTime := time.Now().Add(-time.Duration(len(repo)*5) * time.Minute).Format("2006-01-02T15:04:05Z")

	var findings []types.VulnerabilityFinding
	var vulnerabilities map[string]int

	// Create different vulnerability profiles based on repository name
	switch {
	case strings.Contains(repo, "nginx") || strings.Contains(repo, "web"):
		findings, vulnerabilities = m.createWebServerVulns(repo, tag)
	case strings.Contains(repo, "postgres") || strings.Contains(repo, "mysql") || strings.Contains(repo, "database"):
		findings, vulnerabilities = m.createDatabaseVulns(repo, tag)
	case strings.Contains(repo, "python") || strings.Contains(repo, "api"):
		findings, vulnerabilities = m.createPythonAPIVulns(repo, tag)
	case strings.Contains(repo, "node") || strings.Contains(repo, "frontend"):
		findings, vulnerabilities = m.createNodeAppVulns(repo, tag)
	default:
		findings, vulnerabilities = m.createGenericAppVulns(repo, tag)
	}

	return &types.ImageVulnerability{
		ImageURI:        imageURI,
		Vulnerabilities: vulnerabilities,
		Findings:        findings,
		ScanStatus:      "COMPLETE",
		LastScanTime:    &scanTime,
	}, nil
}

// ParseImageURI parses an image URI into repository and tag
func (m *MockECRSource) ParseImageURI(imageURI string) (repository, tag string, err error) {
	// Handle ECR format: account.dkr.ecr.region.amazonaws.com/repository:tag
	parts := strings.Split(imageURI, "/")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid image URI format: %s", imageURI)
	}

	repoWithTag := strings.Join(parts[1:], "/")
	repoParts := strings.Split(repoWithTag, ":")
	if len(repoParts) != 2 {
		return "", "", fmt.Errorf("invalid image URI format, missing tag: %s", imageURI)
	}

	return repoParts[0], repoParts[1], nil
}

// createWebServerVulns creates mock vulnerabilities for web server images
func (m *MockECRSource) createWebServerVulns(repo, tag string) ([]types.VulnerabilityFinding, map[string]int) {
	findings := []types.VulnerabilityFinding{
		{
			Name:             "CVE-2024-7592",
			Description:      "Critical buffer overflow vulnerability in nginx HTTP/2 module",
			Severity:         "CRITICAL",
			PackageName:      "nginx",
			PackageVersion:   "1.20.1",
			FixVersion:       "1.20.2",
			Status:           "ACTIVE",
			URI:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-7592",
			ExploitAvailable: "YES",
			FixAvailable:     "YES",
			Score:            9.8,
			Type:             "PACKAGE_VULNERABILITY",
		},
		{
			Name:             "CVE-2024-6387",
			Description:      "OpenSSH remote code execution vulnerability",
			Severity:         "HIGH",
			PackageName:      "openssh-server",
			PackageVersion:   "8.9p1",
			FixVersion:       "8.9p1-3ubuntu0.7",
			Status:           "ACTIVE",
			URI:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-6387",
			ExploitAvailable: "NO",
			FixAvailable:     "YES",
			Score:            8.1,
			Type:             "PACKAGE_VULNERABILITY",
		},
		{
			Name:             "CVE-2024-2961",
			Description:      "Buffer overflow in GNU libc",
			Severity:         "MEDIUM",
			PackageName:      "libc6",
			PackageVersion:   "2.35-0ubuntu3.1",
			FixVersion:       "2.35-0ubuntu3.8",
			Status:           "ACTIVE",
			URI:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-2961",
			ExploitAvailable: "NO",
			FixAvailable:     "YES",
			Score:            5.5,
			Type:             "PACKAGE_VULNERABILITY",
		},
	}

	vulnerabilities := map[string]int{
		"CRITICAL": 1,
		"HIGH":     1,
		"MEDIUM":   1,
		"LOW":      0,
	}

	return findings, vulnerabilities
}

// createDatabaseVulns creates mock vulnerabilities for database images
func (m *MockECRSource) createDatabaseVulns(repo, tag string) ([]types.VulnerabilityFinding, map[string]int) {
	findings := []types.VulnerabilityFinding{
		{
			Name:             "CVE-2024-21096",
			Description:      "MySQL Server privilege escalation vulnerability",
			Severity:         "HIGH",
			PackageName:      "mysql-server",
			PackageVersion:   "8.0.32",
			FixVersion:       "8.0.37",
			Status:           "ACTIVE",
			URI:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21096",
			ExploitAvailable: "NO",
			FixAvailable:     "YES",
			Score:            7.2,
			Type:             "PACKAGE_VULNERABILITY",
		},
		{
			Name:             "CVE-2024-3094",
			Description:      "Backdoor in xz utils affecting database compression",
			Severity:         "CRITICAL",
			PackageName:      "xz-utils",
			PackageVersion:   "5.4.1",
			FixVersion:       "5.4.5",
			Status:           "ACTIVE",
			URI:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3094",
			ExploitAvailable: "YES",
			FixAvailable:     "YES",
			Score:            10.0,
			Type:             "PACKAGE_VULNERABILITY",
		},
		{
			Name:             "CVE-2024-1234",
			Description:      "Minor configuration issue in database logging",
			Severity:         "LOW",
			PackageName:      "postgres",
			PackageVersion:   "14.9",
			FixVersion:       "14.11",
			Status:           "ACTIVE",
			URI:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-1234",
			ExploitAvailable: "NO",
			FixAvailable:     "YES",
			Score:            2.1,
			Type:             "PACKAGE_VULNERABILITY",
		},
		{
			Name:             "CVE-2024-5678",
			Description:      "Database connection pooling memory leak",
			Severity:         "LOW",
			PackageName:      "libpq",
			PackageVersion:   "14.9",
			FixVersion:       "14.11",
			Status:           "ACTIVE",
			URI:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-5678",
			ExploitAvailable: "NO",
			FixAvailable:     "YES",
			Score:            3.1,
			Type:             "PACKAGE_VULNERABILITY",
		},
	}

	vulnerabilities := map[string]int{
		"CRITICAL": 1,
		"HIGH":     1,
		"MEDIUM":   0,
		"LOW":      2,
	}

	return findings, vulnerabilities
}

// createPythonAPIVulns creates mock vulnerabilities for Python API images
func (m *MockECRSource) createPythonAPIVulns(repo, tag string) ([]types.VulnerabilityFinding, map[string]int) {
	findings := []types.VulnerabilityFinding{
		{
			Name:             "CVE-2024-6232",
			Description:      "Python urllib3 MITM vulnerability via IPv6-mapped IPv4 addresses",
			Severity:         "MEDIUM",
			PackageName:      "urllib3",
			PackageVersion:   "1.26.15",
			FixVersion:       "1.26.19",
			Status:           "ACTIVE",
			URI:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-6232",
			ExploitAvailable: "NO",
			FixAvailable:     "YES",
			Score:            4.8,
			Type:             "PACKAGE_VULNERABILITY",
		},
		{
			Name:             "CVE-2024-35195",
			Description:      "Requests library unintended credential disclosure",
			Severity:         "HIGH",
			PackageName:      "requests",
			PackageVersion:   "2.28.1",
			FixVersion:       "2.32.0",
			Status:           "ACTIVE",
			URI:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-35195",
			ExploitAvailable: "NO",
			FixAvailable:     "YES",
			Score:            7.5,
			Type:             "PACKAGE_VULNERABILITY",
		},
		{
			Name:             "CVE-2024-9999",
			Description:      "Python setuptools vulnerability",
			Severity:         "LOW",
			PackageName:      "setuptools",
			PackageVersion:   "65.5.0",
			FixVersion:       "65.5.1",
			Status:           "ACTIVE",
			URI:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-9999",
			ExploitAvailable: "NO",
			FixAvailable:     "YES",
			Score:            2.3,
			Type:             "PACKAGE_VULNERABILITY",
		},
		{
			Name:             "CVE-2024-8888",
			Description:      "Flask minor security issue",
			Severity:         "LOW",
			PackageName:      "flask",
			PackageVersion:   "2.2.2",
			FixVersion:       "2.3.3",
			Status:           "ACTIVE",
			URI:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-8888",
			ExploitAvailable: "NO",
			FixAvailable:     "YES",
			Score:            3.1,
			Type:             "PACKAGE_VULNERABILITY",
		},
		{
			Name:             "CVE-2024-7777",
			Description:      "Minor issue in pip package manager",
			Severity:         "LOW",
			PackageName:      "pip",
			PackageVersion:   "22.3.1",
			FixVersion:       "23.0.1",
			Status:           "ACTIVE",
			URI:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-7777",
			ExploitAvailable: "NO",
			FixAvailable:     "YES",
			Score:            1.9,
			Type:             "PACKAGE_VULNERABILITY",
		},
	}

	vulnerabilities := map[string]int{
		"CRITICAL": 0,
		"HIGH":     1,
		"MEDIUM":   1,
		"LOW":      3,
	}

	return findings, vulnerabilities
}

// createNodeAppVulns creates mock vulnerabilities for Node.js applications
func (m *MockECRSource) createNodeAppVulns(repo, tag string) ([]types.VulnerabilityFinding, map[string]int) {
	findings := []types.VulnerabilityFinding{
		{
			Name:             "CVE-2024-21490",
			Description:      "Angular cross-site scripting vulnerability in SSR applications",
			Severity:         "HIGH",
			PackageName:      "@angular/core",
			PackageVersion:   "15.2.8",
			FixVersion:       "15.2.10",
			Status:           "ACTIVE",
			URI:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21490",
			ExploitAvailable: "NO",
			FixAvailable:     "YES",
			Score:            6.9,
			Type:             "PACKAGE_VULNERABILITY",
		},
		{
			Name:             "CVE-2024-21491",
			Description:      "Express.js prototype pollution vulnerability",
			Severity:         "MEDIUM",
			PackageName:      "express",
			PackageVersion:   "4.18.2",
			FixVersion:       "4.19.2",
			Status:           "ACTIVE",
			URI:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21491",
			ExploitAvailable: "NO",
			FixAvailable:     "YES",
			Score:            5.3,
			Type:             "PACKAGE_VULNERABILITY",
		},
		{
			Name:             "CVE-2024-1111",
			Description:      "Node.js path traversal vulnerability",
			Severity:         "LOW",
			PackageName:      "node",
			PackageVersion:   "18.17.0",
			FixVersion:       "18.19.1",
			Status:           "ACTIVE",
			URI:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-1111",
			ExploitAvailable: "NO",
			FixAvailable:     "YES",
			Score:            2.8,
			Type:             "PACKAGE_VULNERABILITY",
		},
		{
			Name:             "CVE-2024-2222",
			Description:      "npm package vulnerability",
			Severity:         "LOW",
			PackageName:      "npm",
			PackageVersion:   "9.6.7",
			FixVersion:       "9.8.1",
			Status:           "ACTIVE",
			URI:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-2222",
			ExploitAvailable: "NO",
			FixAvailable:     "YES",
			Score:            3.2,
			Type:             "PACKAGE_VULNERABILITY",
		},
		{
			Name:             "CVE-2024-3333",
			Description:      "Webpack bundler issue",
			Severity:         "LOW",
			PackageName:      "webpack",
			PackageVersion:   "5.88.2",
			FixVersion:       "5.89.0",
			Status:           "ACTIVE",
			URI:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3333",
			ExploitAvailable: "NO",
			FixAvailable:     "YES",
			Score:            2.1,
			Type:             "PACKAGE_VULNERABILITY",
		},
		{
			Name:             "CVE-2024-4444",
			Description:      "React development server vulnerability",
			Severity:         "LOW",
			PackageName:      "react-scripts",
			PackageVersion:   "5.0.1",
			FixVersion:       "5.0.2",
			Status:           "ACTIVE",
			URI:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-4444",
			ExploitAvailable: "NO",
			FixAvailable:     "YES",
			Score:            1.7,
			Type:             "PACKAGE_VULNERABILITY",
		},
	}

	vulnerabilities := map[string]int{
		"CRITICAL": 0,
		"HIGH":     1,
		"MEDIUM":   1,
		"LOW":      4,
	}

	return findings, vulnerabilities
}

// createGenericAppVulns creates mock vulnerabilities for generic applications
func (m *MockECRSource) createGenericAppVulns(repo, tag string) ([]types.VulnerabilityFinding, map[string]int) {
	findings := []types.VulnerabilityFinding{
		{
			Name:             "CVE-2024-0727",
			Description:      "OpenSSL denial of service vulnerability",
			Severity:         "MEDIUM",
			PackageName:      "openssl",
			PackageVersion:   "3.0.8",
			FixVersion:       "3.0.13",
			Status:           "ACTIVE",
			URI:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-0727",
			ExploitAvailable: "NO",
			FixAvailable:     "YES",
			Score:            5.5,
			Type:             "PACKAGE_VULNERABILITY",
		},
		{
			Name:             "CVE-2024-2398",
			Description:      "curl library heap buffer overflow",
			Severity:         "LOW",
			PackageName:      "curl",
			PackageVersion:   "7.81.0",
			FixVersion:       "8.7.1",
			Status:           "ACTIVE",
			URI:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-2398",
			ExploitAvailable: "NO",
			FixAvailable:     "YES",
			Score:            3.4,
			Type:             "PACKAGE_VULNERABILITY",
		},
	}

	vulnerabilities := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   1,
		"LOW":      1,
	}

	return findings, vulnerabilities
}
