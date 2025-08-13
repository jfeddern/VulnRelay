# Multi-stage build for minimal security footprint
FROM golang:1.24.6-alpine3.22 AS builder

# Build arguments for metadata
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

# Install SSL certificates and build tools
RUN apk --no-cache add ca-certificates git

# Set working directory
WORKDIR /app

# Copy Go modules files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application with static linking and build metadata
RUN CGO_ENABLED=0 GOOS=linux go build \
    -a -installsuffix cgo \
    -ldflags "-X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
    -o vulnrelay ./cmd/vulnrelay

# Final stage: minimal runtime image
FROM scratch

# Copy SSL certificates from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the binary
COPY --from=builder /app/vulnrelay /vulnrelay

# Create non-root user (using numeric IDs for scratch compatibility)
USER 65534:65534

# Expose metrics port
EXPOSE 9090

# Run the application
ENTRYPOINT ["/vulnrelay"]