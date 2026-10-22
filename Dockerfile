# Knox Suite Dockerfile
# Multi-stage build for minimal final image

# ========================================
# Stage 1: Builder
# ========================================
FROM golang:1.23-alpine AS builder

# Install build dependencies and security tools
RUN apk add --no-cache \
    git \
    make \
    gcc \
    musl-dev \
    nmap \
    nuclei \
    subfinder \
    httpx \
    dnsx \
    sslscan \
    whatweb \
    nikto \
    dirsearch \
    sqlmap \
    ffuf \
    katana \
    gau \
    waybackurls \
    amass

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build binary with version info
ARG VERSION=dev
ARG BUILD_TIME=unknown
RUN CGO_ENABLED=0 go build \
    -ldflags "-X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME} -s -w" \
    -o knox ./cmd/knox

# ========================================
# Stage 2: Runtime
# ========================================
FROM alpine:3.20

# Install runtime dependencies and security tools
RUN apk add --no-cache \
    ca-certificates \
    nmap \
    nuclei \
    subfinder \
    httpx \
    dnsx \
    sslscan \
    whatweb \
    nikto \
    dirsearch \
    sqlmap \
    ffuf \
    katana \
    gau \
    waybackurls \
    amass \
    curl \
    jq

# Create non-root user
RUN addgroup -g 1000 knox && \
    adduser -D -u 1000 -G knox knox

WORKDIR /home/knox

# Copy binary from builder
COPY --from=builder /app/knox /usr/local/bin/knox

# Create directories
RUN mkdir -p /home/knox/reports /home/knox/.knox && \
    chown -R knox:knox /home/knox

USER knox

# Set environment variables
ENV HOME=/home/knox
ENV KNOX_OUTPUT_DIR=/home/knox/reports

# Update nuclei templates on startup
RUN nuclei -update-templates 2>/dev/null || true

ENTRYPOINT ["knox"]
CMD ["--help"]