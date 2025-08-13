#!/bin/bash
# ABOUTME: Example script to demonstrate VulnRelay mock mode for local testing.
# ABOUTME: Shows how to start the service and query all endpoints without external dependencies.

set -e

echo "🚀 Testing VulnRelay Mock Mode"
echo "==============================="

# Build the application
echo "📦 Building VulnRelay..."
go build -o vulnrelay ./cmd/vulnrelay

# Start VulnRelay in mock mode
echo "▶️  Starting VulnRelay in mock mode..."
export MOCK_MODE=true
export LOG_LEVEL=info
./vulnrelay -port 9090 &
VULNRELAY_PID=$!

# Wait for startup
echo "⏳ Waiting for startup..."
sleep 5

echo ""
echo "🔍 Testing endpoints:"
echo "-------------------"

# Test health endpoint
echo "✅ Health check:"
curl -s http://localhost:9090/health | jq .

echo ""
echo "📊 Sample metrics (first 10 lines):"
curl -s http://localhost:9090/metrics | head -10

echo ""
echo "🛡️  Vulnerability summary:"
curl -s 'http://localhost:9090/vulnerabilities' | jq '.summary'

echo ""
echo "🔴 Critical vulnerabilities:"
curl -s 'http://localhost:9090/vulnerabilities?severity=CRITICAL&pretty=1' | jq '.images[] | {image_uri, critical_count: .vulnerability_counts.CRITICAL, findings: [.findings[] | {name, severity, description}]}'

echo ""
echo "📈 Image with most vulnerabilities:"
curl -s 'http://localhost:9090/vulnerabilities' | jq -r '.images | sort_by(.total_count) | reverse | .[0] | "Image: \(.image_uri) - Total vulnerabilities: \(.total_count)"'

# Cleanup
echo ""
echo "🧹 Cleaning up..."
kill $VULNRELAY_PID
wait $VULNRELAY_PID 2>/dev/null || true

echo "✨ Mock mode test completed successfully!"
echo ""
echo "💡 Tips:"
echo "   - No AWS credentials required in mock mode"
echo "   - Mock data includes 10 diverse container images"
echo "   - Different vulnerability profiles per image type"
echo "   - Perfect for development and CI/CD testing"