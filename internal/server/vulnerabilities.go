// ABOUTME: HTTP handler for detailed vulnerability information endpoint.
// ABOUTME: Provides detailed CVE, package, and fix information for all discovered images.

package server

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jfeddern/VulnRelay/internal/types"

	"github.com/sirupsen/logrus"
)

type VulnerabilityDataProvider interface {
	GetVulnerabilityData() (map[string]*types.ImageVulnerabilityData, time.Time)
}

type VulnerabilitiesHandler struct {
	collector VulnerabilityDataProvider
	logger    *logrus.Logger
}

type VulnerabilitiesResponse struct {
	Images      []types.ImageVulnerabilityData `json:"images"`
	Summary     VulnerabilitySummary           `json:"summary"`
	LastUpdated string                         `json:"last_updated"`
}

type VulnerabilitySummary struct {
	TotalImages          int            `json:"total_images"`
	TotalVulnerabilities int            `json:"total_vulnerabilities"`
	SeverityBreakdown    map[string]int `json:"severity_breakdown"`
	TopCVEs              []CVESummary   `json:"top_cves"`
}

type CVESummary struct {
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	ImageCount  int    `json:"image_count"`
	Description string `json:"description"`
}

func NewVulnerabilitiesHandler(collector VulnerabilityDataProvider, logger *logrus.Logger) *VulnerabilitiesHandler {
	return &VulnerabilitiesHandler{
		collector: collector,
		logger:    logger,
	}
}

func (v *VulnerabilitiesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger := v.logger.WithField("endpoint", "/vulnerabilities")

	// Get current vulnerability data
	vulnerabilityData, lastCollectionTime := v.collector.GetVulnerabilityData()

	// Check for query parameters for filtering
	imageFilter := strings.TrimSpace(r.URL.Query().Get("image"))
	severityFilter := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("severity")))
	limitParam := strings.TrimSpace(r.URL.Query().Get("limit"))

	// Validate severity filter
	if severityFilter != "" {
		validSeverities := map[string]bool{
			"CRITICAL": true,
			"HIGH":     true,
			"MEDIUM":   true,
			"LOW":      true,
		}
		if !validSeverities[severityFilter] {
			http.Error(w, "Invalid severity filter. Must be one of: CRITICAL, HIGH, MEDIUM, LOW", http.StatusBadRequest)
			return
		}
	}

	// Validate and parse limit parameter
	var limit int = 0 // No limit by default
	if limitParam != "" {
		parsed, err := strconv.Atoi(limitParam)
		if err != nil || parsed < 0 {
			http.Error(w, "Invalid limit parameter. Must be a positive integer", http.StatusBadRequest)
			return
		}
		if parsed > 10000 {
			http.Error(w, "Limit parameter too large. Maximum allowed is 10000", http.StatusBadRequest)
			return
		}
		limit = parsed
	}

	// Validate image filter length to prevent potential DoS
	if len(imageFilter) > 200 {
		http.Error(w, "Image filter too long. Maximum allowed is 200 characters", http.StatusBadRequest)
		return
	}

	logger.WithFields(logrus.Fields{
		"image_filter":    imageFilter,
		"severity_filter": severityFilter,
		"limit":           limit,
		"total_images":    len(vulnerabilityData),
	}).Debug("Processing vulnerabilities request")

	// Filter and prepare response data
	var filteredImages []types.ImageVulnerabilityData
	severityBreakdown := make(map[string]int)
	totalVulns := 0
	cveMap := make(map[string]*CVESummary)

	for _, vulnData := range vulnerabilityData {
		// Apply image filter if specified
		if imageFilter != "" && !strings.Contains(vulnData.ImageURI, imageFilter) {
			continue
		}

		// Filter findings by severity if specified
		var filteredFindings []types.VulnerabilityFinding
		if severityFilter != "" {
			for _, finding := range vulnData.Findings {
				if finding.Severity == severityFilter {
					filteredFindings = append(filteredFindings, finding)
				}
			}
		} else {
			filteredFindings = vulnData.Findings
		}

		// Apply limit if specified
		if limit > 0 && len(filteredFindings) > limit {
			filteredFindings = filteredFindings[:limit]
		}

		// Create filtered image data
		if len(filteredFindings) > 0 || (imageFilter == "" && severityFilter == "") {
			filteredImage := *vulnData // Copy the struct
			filteredImage.Findings = filteredFindings
			filteredImages = append(filteredImages, filteredImage)
		}

		// Update statistics (use original data for accurate totals)
		for severity, count := range vulnData.Vulnerabilities {
			severityBreakdown[severity] += count
			totalVulns += count
		}

		// Track CVE occurrences
		for _, finding := range vulnData.Findings {
			if finding.Name != "" {
				if cve, exists := cveMap[finding.Name]; exists {
					cve.ImageCount++
				} else {
					cveMap[finding.Name] = &CVESummary{
						Name:        finding.Name,
						Severity:    finding.Severity,
						ImageCount:  1,
						Description: finding.Description,
					}
				}
			}
		}
	}

	// Get top CVEs (sort by frequency)
	var topCVEs []CVESummary
	for _, cve := range cveMap {
		topCVEs = append(topCVEs, *cve)
	}
	sort.Slice(topCVEs, func(i, j int) bool {
		if topCVEs[i].ImageCount != topCVEs[j].ImageCount {
			return topCVEs[i].ImageCount > topCVEs[j].ImageCount
		}
		// Secondary sort by severity priority
		severityPriority := map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
		return severityPriority[topCVEs[i].Severity] > severityPriority[topCVEs[j].Severity]
	})

	// Limit top CVEs to 10
	if len(topCVEs) > 10 {
		topCVEs = topCVEs[:10]
	}

	response := VulnerabilitiesResponse{
		Images: filteredImages,
		Summary: VulnerabilitySummary{
			TotalImages:          len(vulnerabilityData),
			TotalVulnerabilities: totalVulns,
			SeverityBreakdown:    severityBreakdown,
			TopCVEs:              topCVEs,
		},
		LastUpdated: lastCollectionTime.Format("2006-01-02T15:04:05Z"),
	}

	w.Header().Set("Content-Type", "application/json")

	// Pretty print if requested
	if r.URL.Query().Get("pretty") != "" {
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(response); err != nil {
			logger.WithError(err).Error("Failed to encode JSON response")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	} else {
		if err := json.NewEncoder(w).Encode(response); err != nil {
			logger.WithError(err).Error("Failed to encode JSON response")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	}

	logger.WithFields(logrus.Fields{
		"filtered_images": len(filteredImages),
		"total_vulns":     totalVulns,
		"top_cves":        len(topCVEs),
	}).Info("Served vulnerabilities response")
}

// CreateVulnerabilitiesHandler creates a standard HTTP handler
func CreateVulnerabilitiesHandler(dataProvider VulnerabilityDataProvider, logger *logrus.Logger) http.HandlerFunc {
	handler := NewVulnerabilitiesHandler(dataProvider, logger)
	return handler.ServeHTTP
}
