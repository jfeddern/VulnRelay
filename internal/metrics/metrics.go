// ABOUTME: Prometheus metrics exposition for ECR vulnerability data.
// ABOUTME: Defines metrics structure and provides HTTP handler for /metrics endpoint.

package metrics

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jfeddern/VulnRelay/internal/types"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

type VulnerabilityDataProvider interface {
	GetVulnerabilityData() (map[string]*types.ImageVulnerabilityData, time.Time)
}

type MetricsHandler struct {
	collector VulnerabilityDataProvider
	logger    *logrus.Logger

	// Prometheus metrics
	vulnerabilityCount *prometheus.GaugeVec
	lastScanTime       *prometheus.GaugeVec
	scanStatus         *prometheus.GaugeVec
	collectionInfo     *prometheus.GaugeVec

	// Detailed vulnerability metrics
	vulnerabilityInfo    *prometheus.GaugeVec
	packageVulnerability *prometheus.GaugeVec
	fixAvailability      *prometheus.GaugeVec
	exploitAvailability  *prometheus.GaugeVec
}

func NewMetricsHandler(collector VulnerabilityDataProvider, logger *logrus.Logger) *MetricsHandler {
	return &MetricsHandler{
		collector: collector,
		logger:    logger,

		vulnerabilityCount: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "ecr_image_vulnerability_count",
				Help: "Number of vulnerabilities found in ECR images by severity",
			},
			[]string{"image_uri", "repository", "tag", "severity", "namespace", "workload", "workload_type"},
		),

		lastScanTime: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "ecr_image_last_scan_timestamp",
				Help: "Timestamp of the last vulnerability scan for ECR images",
			},
			[]string{"image_uri", "repository", "tag", "namespace", "workload", "workload_type"},
		),

		scanStatus: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "ecr_image_scan_status",
				Help: "Status of vulnerability scan for ECR images (1=COMPLETE, 0=other)",
			},
			[]string{"image_uri", "repository", "tag", "status", "namespace", "workload", "workload_type"},
		),

		collectionInfo: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "ecr_vulnerability_collection_info",
				Help: "Information about vulnerability data collection",
			},
			[]string{"info_type"},
		),

		vulnerabilityInfo: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "ecr_vulnerability_info",
				Help: "Detailed vulnerability information with CVE details",
			},
			[]string{"image_uri", "repository", "tag", "cve_name", "severity", "description", "status", "type", "namespace", "workload", "workload_type"},
		),

		packageVulnerability: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "ecr_package_vulnerability",
				Help: "Package-level vulnerability information with fix details",
			},
			[]string{"image_uri", "repository", "tag", "cve_name", "severity", "package_name", "package_version", "fix_version", "namespace", "workload", "workload_type"},
		),

		fixAvailability: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "ecr_vulnerability_fix_available",
				Help: "Fix availability for vulnerabilities (1=YES, 0.5=PARTIAL, 0=NO)",
			},
			[]string{"image_uri", "repository", "tag", "cve_name", "severity", "fix_status", "namespace", "workload", "workload_type"},
		),

		exploitAvailability: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "ecr_vulnerability_exploit_available",
				Help: "Exploit availability for vulnerabilities (1=YES, 0=NO)",
			},
			[]string{"image_uri", "repository", "tag", "cve_name", "severity", "exploit_status", "namespace", "workload", "workload_type"},
		),
	}
}

func (m *MetricsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Create a new registry for this request to avoid conflicts
	registry := prometheus.NewRegistry()

	// Register our metrics
	registry.MustRegister(m.vulnerabilityCount)
	registry.MustRegister(m.lastScanTime)
	registry.MustRegister(m.scanStatus)
	registry.MustRegister(m.collectionInfo)
	registry.MustRegister(m.vulnerabilityInfo)
	registry.MustRegister(m.packageVulnerability)
	registry.MustRegister(m.fixAvailability)
	registry.MustRegister(m.exploitAvailability)

	// Reset all metrics to avoid stale data
	m.vulnerabilityCount.Reset()
	m.lastScanTime.Reset()
	m.scanStatus.Reset()
	m.collectionInfo.Reset()
	m.vulnerabilityInfo.Reset()
	m.packageVulnerability.Reset()
	m.fixAvailability.Reset()
	m.exploitAvailability.Reset()

	// Get current vulnerability data
	vulnerabilityData, lastCollectionTime := m.collector.GetVulnerabilityData()

	// Populate metrics
	for imageURI, vulnDataWithInfo := range vulnerabilityData {
		vulnData := vulnDataWithInfo.ImageVulnerability
		namespace := vulnDataWithInfo.Namespace
		workload := vulnDataWithInfo.Workload
		workloadType := vulnDataWithInfo.WorkloadType

		repo, tag, err := parseImageURI(imageURI)
		if err != nil {
			m.logger.WithError(err).WithField("image_uri", imageURI).Error("Failed to parse image URI for metrics")
			continue
		}

		// Vulnerability counts by severity
		for severity, count := range vulnData.Vulnerabilities {
			m.vulnerabilityCount.WithLabelValues(imageURI, repo, tag, severity, namespace, workload, workloadType).Set(float64(count))
		}

		// Last scan time
		if vulnData.LastScanTime != nil {
			if scanTime, err := time.Parse("2006-01-02T15:04:05Z", *vulnData.LastScanTime); err == nil {
				m.lastScanTime.WithLabelValues(imageURI, repo, tag, namespace, workload, workloadType).Set(float64(scanTime.Unix()))
			}
		}

		// Scan status (1 for COMPLETE, 0 for others)
		statusValue := float64(0)
		if vulnData.ScanStatus == "COMPLETE" {
			statusValue = 1
		}
		m.scanStatus.WithLabelValues(imageURI, repo, tag, vulnData.ScanStatus, namespace, workload, workloadType).Set(statusValue)

		// Detailed vulnerability information
		for _, finding := range vulnData.Findings {
			// Sanitize strings for Prometheus labels (remove newlines, limit length)
			cve := sanitizeLabelValue(finding.Name)
			description := sanitizeLabelValue(finding.Description)
			status := sanitizeLabelValue(finding.Status)
			vulnType := sanitizeLabelValue(finding.Type)
			packageName := sanitizeLabelValue(finding.PackageName)
			packageVersion := sanitizeLabelValue(finding.PackageVersion)
			fixVersion := sanitizeLabelValue(finding.FixVersion)

			// Vulnerability info metric (always 1 to indicate presence)
			m.vulnerabilityInfo.WithLabelValues(
				imageURI, repo, tag, cve, finding.Severity, description, status, vulnType, namespace, workload, workloadType,
			).Set(1)

			// Package vulnerability metric (Inspector score if available, otherwise 1)
			score := finding.Score
			if score == 0 {
				score = 1 // Default for basic scanning
			}
			m.packageVulnerability.WithLabelValues(
				imageURI, repo, tag, cve, finding.Severity, packageName, packageVersion, fixVersion, namespace, workload, workloadType,
			).Set(score)

			// Fix availability metric
			fixValue := float64(0)
			switch finding.FixAvailable {
			case "YES":
				fixValue = 1
			case "PARTIAL":
				fixValue = 0.5
			case "NO":
				fixValue = 0
			}
			m.fixAvailability.WithLabelValues(
				imageURI, repo, tag, cve, finding.Severity, finding.FixAvailable, namespace, workload, workloadType,
			).Set(fixValue)

			// Exploit availability metric
			exploitValue := float64(0)
			if finding.ExploitAvailable == "YES" {
				exploitValue = 1
			}
			m.exploitAvailability.WithLabelValues(
				imageURI, repo, tag, cve, finding.Severity, finding.ExploitAvailable, namespace, workload, workloadType,
			).Set(exploitValue)
		}
	}

	// Collection info
	m.collectionInfo.WithLabelValues("last_collection_timestamp").Set(float64(lastCollectionTime.Unix()))
	m.collectionInfo.WithLabelValues("images_monitored").Set(float64(len(vulnerabilityData)))

	// Serve metrics
	handler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	handler.ServeHTTP(w, r)
}

// sanitizeLabelValue cleans strings for use as Prometheus labels
func sanitizeLabelValue(value string) string {
	if value == "" {
		return "unknown"
	}

	// Remove newlines and carriage returns
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\t", " ")

	// Limit length to prevent excessive label sizes
	if len(value) > 200 {
		value = value[:200] + "..."
	}

	// Remove any leading/trailing whitespace
	return strings.TrimSpace(value)
}

// parseImageURI extracts repository name and tag from a full image URI
// Expected format: registry.com/repository:tag
func parseImageURI(imageURI string) (repository, tag string, err error) {
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

// CreateMetricsHandler creates a standard HTTP handler that can be used with http.ServeMux
func CreateMetricsHandler(dataProvider VulnerabilityDataProvider, logger *logrus.Logger) http.HandlerFunc {
	metricsHandler := NewMetricsHandler(dataProvider, logger)
	return metricsHandler.ServeHTTP
}
