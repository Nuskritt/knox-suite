# Knox Suite Makefile

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS := -ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -s -w"

BINARY := knox
BUILD_DIR := build
DIST_DIR := dist

.PHONY: all build clean install test lint fmt vet run help

all: build

build:
	@echo "Building $(BINARY)..."
	@mkdir -p $(BUILD_DIR)
	@go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) ./cmd/knox

build-linux:
	@echo "Building for Linux..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-linux-amd64 ./cmd/knox

build-darwin:
	@echo "Building for macOS..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-darwin-amd64 ./cmd/knox
	@GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-darwin-arm64 ./cmd/knox

build-windows:
	@echo "Building for Windows..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-windows-amd64.exe ./cmd/knox

build-all: build-linux build-darwin build-windows

install: build
	@echo "Installing to $(GOPATH)/bin/$(BINARY)..."
	@cp $(BUILD_DIR)/$(BINARY) $(GOPATH)/bin/

clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR) $(DIST_DIR)

test:
	@echo "Running tests..."
	@go test ./... -v

test-coverage:
	@echo "Running tests with coverage..."
	@go test ./... -coverprofile=coverage.out
	@go tool cover -html=coverage.out -o coverage.html

lint:
	@echo "Running linter..."
	@golangci-lint run

fmt:
	@echo "Formatting code..."
	@go fmt ./...

vet:
	@echo "Vetting code..."
	@go vet ./...

run: build
	@./$(BUILD_DIR)/$(BINARY) $(ARGS)

# Example usage: make scan TARGET=example.com
scan: build
	@./$(BUILD_DIR)/$(BINARY) scan $(TARGET)

recon: build
	@./$(BUILD_DIR)/$(BINARY) recon $(TARGET)

# Create release archives
release: build-all
	@mkdir -p $(DIST_DIR)
	@cd $(BUILD_DIR) && tar -czf ../$(DIST_DIR)/$(BINARY)-$(VERSION)-linux-amd64.tar.gz $(BINARY)-linux-amd64
	@cd $(BUILD_DIR) && tar -czf ../$(DIST_DIR)/$(BINARY)-$(VERSION)-darwin-amd64.tar.gz $(BINARY)-darwin-amd64
	@cd $(BUILD_DIR) && tar -czf ../$(DIST_DIR)/$(BINARY)-$(VERSION)-darwin-arm64.tar.gz $(BINARY)-darwin-arm64
	@cd $(BUILD_DIR) && zip ../$(DIST_DIR)/$(BINARY)-$(VERSION)-windows-amd64.zip $(BINARY)-windows-amd64.exe
	@echo "Release archives created in $(DIST_DIR)/"

# Generate checksums
checksums: release
	@cd $(DIST_DIR) && sha256sum * > checksums.txt
	@cat $(DIST_DIR)/checksums.txt

# Docker build
docker-build:
	@docker build -t knox-suite:$(VERSION) -t knox-suite:latest .

docker-run: docker-build
	@docker run --rm -it -v $(PWD)/.env:/app/.env knox-suite:latest $(ARGS)

help:
	@echo "Knox Suite Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  build         - Build binary for current platform"
	@echo "  build-all     - Build for Linux, macOS, Windows"
	@echo "  install       - Install to GOPATH/bin"
	@echo "  clean         - Clean build artifacts"
	@echo "  test          - Run tests"
	@echo "  lint          - Run linter"
	@echo "  fmt           - Format code"
	@echo "  vet           - Vet code"
	@echo "  run ARGS=...  - Build and run with arguments"
	@echo "  scan TARGET=  - Build and run scan on target"
	@echo "  recon TARGET= - Build and run recon on target"
	@echo "  release       - Create release archives"
	@echo "  docker-build  - Build Docker image"
	@echo "  docker-run    - Run in Docker"