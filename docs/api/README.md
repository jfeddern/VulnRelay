# API Reference

Complete reference for VulnRelay's HTTP endpoints, Prometheus metrics, and response formats.

## 📡 Endpoints Overview

| Endpoint | Method | Purpose | Format |
|----------|--------|---------|--------|
| `/health` | GET | Health check for readiness/liveness probes | JSON |
| `/metrics` | GET | Prometheus metrics for monitoring | Prometheus |
| `/vulnerabilities` | GET | Detailed vulnerability data with filtering | JSON |

## 🏥 Health Check - `/health`

Simple health endpoint for Kubernetes readiness and liveness probes.

### Request
```http
GET /health HTTP/1.1
Host: localhost:9090
```

### Response
```json
{
  "status": "ok"
}
```

### Usage
```bash
# Basic health check
curl http://localhost:9090/health

# With timeout for scripts
curl --max-time 5 http://localhost:9090/health

# Kubernetes probe format
curl -f http://localhost:9090/health || exit 1
```

## 📊 Prometheus Metrics - `/metrics`

Returns vulnerability data in Prometheus format for metrics collection and alerting.

### Core Metrics

#### Vulnerability Counts
```prometheus
# HELP ecr_image_vulnerability_count Number of vulnerabilities by severity
# TYPE ecr_image_vulnerability_count gauge
ecr_image_vulnerability_count{image_uri="123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:v1.0.0",repository="my-app",tag="v1.0.0",severity="CRITICAL",namespace="production",workload="my-app",workload_type="Deployment"} 2
```

**Labels:**
- `image_uri`: Complete ECR image URI
- `repository`: ECR repository name
- `tag`: Image tag
- `severity`: CRITICAL, HIGH, MEDIUM, LOW
- `namespace`: Kubernetes namespace
- `workload`: Kubernetes workload name
- `workload_type`: Deployment, StatefulSet

#### Scan Status
```prometheus
# HELP ecr_image_scan_status Scan status (1=COMPLETE, 0=other)
# TYPE ecr_image_scan_status gauge
ecr_image_scan_status{image_uri="123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:v1.0.0",repository="my-app",tag="v1.0.0",status="COMPLETE",namespace="production",workload="my-app",workload_type="Deployment"} 1
```

#### Last Scan Timestamp
```prometheus
# HELP ecr_image_last_scan_timestamp Unix timestamp of last vulnerability scan
# TYPE ecr_image_last_scan_timestamp gauge
ecr_image_last_scan_timestamp{image_uri="123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:v1.0.0",repository="my-app",tag="v1.0.0",namespace="production",workload="my-app",workload_type="Deployment"} 1705315800
```

### Detailed Vulnerability Metrics

#### Individual CVE Information
```prometheus
# HELP ecr_vulnerability_info Detailed vulnerability information
# TYPE ecr_vulnerability_info gauge
ecr_vulnerability_info{image_uri="123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:v1.0.0",repository="my-app",tag="v1.0.0",cve_name="CVE-2024-12345",severity="CRITICAL",description="Critical security vulnerability",status="ACTIVE",type="PACKAGE_VULNERABILITY",namespace="production",workload="my-app",workload_type="Deployment"} 1
```

#### Package-Level Details
```prometheus
# HELP ecr_package_vulnerability Package-level vulnerability details (value=CVSS score)
# TYPE ecr_package_vulnerability gauge
ecr_package_vulnerability{image_uri="123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:v1.0.0",repository="my-app",tag="v1.0.0",cve_name="CVE-2024-12345",severity="CRITICAL",package_name="openssl",package_version="1.1.1f",fix_version="1.1.1n",namespace="production",workload="my-app",workload_type="Deployment"} 9.8
```

#### Fix Availability
```prometheus
# HELP ecr_vulnerability_fix_available Fix availability (1=YES, 0.5=PARTIAL, 0=NO)
# TYPE ecr_vulnerability_fix_available gauge
ecr_vulnerability_fix_available{image_uri="123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:v1.0.0",repository="my-app",tag="v1.0.0",cve_name="CVE-2024-12345",severity="CRITICAL",fix_status="YES",namespace="production",workload="my-app",workload_type="Deployment"} 1
```

#### Exploit Availability
```prometheus
# HELP ecr_vulnerability_exploit_available Exploit availability (1=YES, 0=NO)
# TYPE ecr_vulnerability_exploit_available gauge
ecr_vulnerability_exploit_available{image_uri="123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:v1.0.0",repository="my-app",tag="v1.0.0",cve_name="CVE-2024-12345",severity="CRITICAL",exploit_status="NO",namespace="production",workload="my-app",workload_type="Deployment"} 0
```

#### Collection Metadata
```prometheus
# HELP ecr_vulnerability_collection_info Collection metadata
# TYPE ecr_vulnerability_collection_info gauge
ecr_vulnerability_collection_info{info_type="total_images"} 15
```

### Prometheus Queries

#### High-Level Dashboards
```promql
# Total critical vulnerabilities across all images
sum(ecr_image_vulnerability_count{severity="CRITICAL"})

# Images with the most critical vulnerabilities
topk(10, sum by (image_uri, namespace, workload) (ecr_image_vulnerability_count{severity="CRITICAL"}))

# Vulnerability counts by namespace
sum by (namespace) (ecr_image_vulnerability_count)
```

#### Alerting Queries
```promql
# Images with more than 5 critical vulnerabilities
ecr_image_vulnerability_count{severity="CRITICAL"} > 5

# Images that haven't been scanned recently (24 hours)
time() - ecr_image_last_scan_timestamp > 86400

# Failed scans
ecr_image_scan_status{status!="COMPLETE"} == 0
```

## 🔍 Vulnerability Details - `/vulnerabilities`

Returns comprehensive vulnerability information in JSON format with filtering and pagination.

### Query Parameters

| Parameter | Type | Description | Example | Validation |
|-----------|------|-------------|---------|------------|
| `image` | string | Filter by image name (partial match) | `?image=my-app` | Max 200 chars |
| `severity` | string | Filter by severity level | `?severity=CRITICAL` | CRITICAL, HIGH, MEDIUM, LOW |
| `limit` | integer | Limit findings per image | `?limit=100` | 1-10000 |
| `pretty` | any | Pretty-print JSON output | `?pretty=1` | Any value enables |

### Response Format

```json
{
  "images": [
    {
      "image_uri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:v1.0.0",
      "repository": "my-app",
      "tag": "v1.0.0",
      "vulnerability_counts": {
        "CRITICAL": 2,
        "HIGH": 5,
        "MEDIUM": 12,
        "LOW": 3
      },
      "total_count": 22,
      "scan_status": "COMPLETE",
      "last_scan_time": "2025-01-15T10:30:00Z",
      "namespace": "production",
      "workload": "my-app", 
      "workload_type": "Deployment",
      "findings": [
        {
          "name": "CVE-2024-12345",
          "description": "Critical buffer overflow vulnerability in libssl",
          "severity": "CRITICAL",
          "package_name": "openssl",
          "package_version": "1.1.1f",
          "fix_version": "1.1.1n",
          "status": "ACTIVE",
          "uri": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-12345",
          "exploit_available": "YES",
          "fix_available": "YES",
          "score": 9.8,
          "type": "PACKAGE_VULNERABILITY"
        }
      ]
    }
  ],
  "summary": {
    "total_images": 15,
    "total_vulnerabilities": 234,
    "severity_breakdown": {
      "CRITICAL": 12,
      "HIGH": 45,
      "MEDIUM": 123,
      "LOW": 54
    },
    "top_cves": [
      {
        "name": "CVE-2024-12345",
        "severity": "CRITICAL", 
        "image_count": 8,
        "description": "Critical buffer overflow vulnerability"
      }
    ]
  },
  "last_updated": "2025-01-15T10:35:00Z"
}
```

### Field Reference

#### Image Fields
| Field | Type | Description |
|-------|------|-------------|
| `image_uri` | string | Complete ECR image URI |
| `repository` | string | ECR repository name (extracted from URI) |
| `tag` | string | Image tag (extracted from URI) |
| `vulnerability_counts` | object | Count of vulnerabilities by severity |
| `total_count` | integer | Total number of vulnerabilities |
| `scan_status` | string | ECR scan status (COMPLETE, IN_PROGRESS, FAILED) |
| `last_scan_time` | string | ISO 8601 timestamp of last scan |
| `namespace` | string | Kubernetes namespace (cluster mode only) |
| `workload` | string | Kubernetes workload name (cluster mode only) |
| `workload_type` | string | Workload type: Deployment or StatefulSet |
| `findings` | array | Detailed vulnerability findings |

#### Finding Fields
| Field | Type | Description |
|-------|------|-------------|
| `name` | string | CVE identifier |
| `description` | string | Vulnerability description |
| `severity` | string | Severity level (CRITICAL, HIGH, MEDIUM, LOW) |
| `package_name` | string | Vulnerable package name |
| `package_version` | string | Current package version |
| `fix_version` | string | Fixed package version (if available) |
| `status` | string | Vulnerability status (ACTIVE, RESOLVED) |
| `uri` | string | CVE reference URL |
| `exploit_available` | string | Exploit availability (YES, NO, unknown) |
| `fix_available` | string | Fix availability (YES, NO, PARTIAL, unknown) |
| `score` | number | CVSS score (0-10) |
| `type` | string | Vulnerability type |

#### Summary Fields
| Field | Type | Description |
|-------|------|-------------|
| `total_images` | integer | Total number of scanned images |
| `total_vulnerabilities` | integer | Total vulnerabilities across all images |
| `severity_breakdown` | object | Count of vulnerabilities by severity |
| `top_cves` | array | Most common CVEs across images |
| `last_updated` | string | ISO 8601 timestamp of last data collection |

### Usage Examples

#### Basic Queries
```bash
# Get all vulnerabilities
curl "http://localhost:9090/vulnerabilities"

# Pretty-printed output
curl "http://localhost:9090/vulnerabilities?pretty=1"

# Get summary only
curl "http://localhost:9090/vulnerabilities" | jq '.summary'
```

#### Filtering
```bash
# Critical vulnerabilities only
curl "http://localhost:9090/vulnerabilities?severity=CRITICAL&pretty=1"

# Filter by image name
curl "http://localhost:9090/vulnerabilities?image=my-app&pretty=1"

# Limit findings per image
curl "http://localhost:9090/vulnerabilities?limit=5&pretty=1"

# Combined filters
curl "http://localhost:9090/vulnerabilities?image=api&severity=HIGH&limit=10&pretty=1"
```

#### Analysis Queries
```bash
# Top vulnerable images
curl "http://localhost:9090/vulnerabilities" | jq '.summary.top_cves'

# Count by severity
curl "http://localhost:9090/vulnerabilities" | jq '.summary.severity_breakdown'

# Images with exploitable vulnerabilities
curl "http://localhost:9090/vulnerabilities" | jq '.images[] | select(.findings[].exploit_available == "YES") | .image_uri'

# Packages with no fix available
curl "http://localhost:9090/vulnerabilities" | jq '.images[].findings[] | select(.fix_available == "NO") | {name, package_name, severity}'
```

### Error Responses

| Status Code | Response | Description |
|-------------|----------|-------------|
| 400 | `{"error": "Invalid severity filter. Must be one of: CRITICAL, HIGH, MEDIUM, LOW"}` | Invalid severity parameter |
| 400 | `{"error": "Invalid limit parameter. Must be a positive integer"}` | Invalid limit parameter |
| 400 | `{"error": "Limit parameter too large. Maximum allowed is 10000"}` | Limit exceeds maximum |
| 400 | `{"error": "Image filter too long. Maximum allowed is 200 characters"}` | Image filter too long |
| 405 | `{"error": "Method not allowed"}` | Non-GET/HEAD request |
| 500 | `{"error": "Internal server error"}` | Server error |

## 🔒 Security Headers

All endpoints include comprehensive security headers:

```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Content-Security-Policy: default-src 'none'; script-src 'none'; object-src 'none'; frame-ancestors 'none'
```

## 📝 Response Examples

See the [examples](./examples/) directory for complete response examples:

- [`health-response.json`](./examples/health-response.json)
- [`vulnerabilities-response.json`](./examples/vulnerabilities-response.json)
- [`metrics-response.txt`](./examples/metrics-response.txt)
- [`error-responses.json`](./examples/error-responses.json)