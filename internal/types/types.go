// ABOUTME: Common types shared across the VulnRelay system.
// ABOUTME: Defines data structures for images, vulnerabilities, and findings.

package types

// ImageInfo represents a discovered container image with its Kubernetes context
type ImageInfo struct {
	URI          string
	Namespace    string
	Workload     string
	WorkloadType string // "Deployment", "StatefulSet", etc.
}

// VulnerabilityFinding represents a single vulnerability finding
type VulnerabilityFinding struct {
	Name             string  `json:"name"`              // CVE ID
	Description      string  `json:"description"`       // Vulnerability description
	Severity         string  `json:"severity"`          // CRITICAL, HIGH, MEDIUM, LOW
	PackageName      string  `json:"package_name"`      // Vulnerable package name
	PackageVersion   string  `json:"package_version"`   // Current package version
	FixVersion       string  `json:"fix_version"`       // Version with fix (if available)
	Status           string  `json:"status"`            // Finding status
	URI              string  `json:"uri"`               // Reference URI
	ExploitAvailable string  `json:"exploit_available"` // YES, NO, or unknown
	FixAvailable     string  `json:"fix_available"`     // YES, NO, PARTIAL, or unknown
	Score            float64 `json:"score"`             // CVSS or provider-specific score
	Type             string  `json:"type"`              // Vulnerability type
}

// ImageVulnerability represents vulnerability information for a container image
type ImageVulnerability struct {
	ImageURI        string                 `json:"image_uri"`
	Repository      string                 `json:"repository"`
	Tag             string                 `json:"tag"`
	Vulnerabilities map[string]int         `json:"vulnerability_counts"` // severity -> count
	TotalCount      int                    `json:"total_count"`
	ScanStatus      string                 `json:"scan_status"`
	LastScanTime    *string                `json:"last_scan_time"`
	Findings        []VulnerabilityFinding `json:"findings"` // Detailed findings
}

// ImageVulnerabilityData combines vulnerability data with discovery metadata
type ImageVulnerabilityData struct {
	*ImageVulnerability
	ImageInfo
}
