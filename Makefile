.PHONY: help build test clean docker-build docker-build-full docker-push run lint

# Variables
BINARY_NAME=lgtm-lbac-proxy
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_DATE=$(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS=-ldflags "-w -s -X main.Version=$(VERSION) -X main.Commit=$(GIT_COMMIT)"

# Container variables
CONTAINER_RUNTIME?=docker
IMAGE_NAME?=lgtm-lbac-proxy
IMAGE_TAG?=$(VERSION)
REGISTRY?=ghcr.io/at-blacknight-projects

## help: Display this help message
help:
	@echo "LGTM LBAC Proxy - Build Targets"
	@echo ""
	@echo "Usage:"
	@echo "  make <target>"
	@echo ""
	@echo "Targets:"
	@awk 'BEGIN {FS = ":.*##"; printf "\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

## build: Build the binary
build:
	@echo "Building $(BINARY_NAME) $(VERSION)..."
	CGO_ENABLED=0 go build $(LDFLAGS) -trimpath -o $(BINARY_NAME) .
	@echo "Binary built: $(BINARY_NAME)"

## test: Run all tests
test:
	@echo "Running tests..."
	go test -v -race -coverprofile=coverage.out ./...

## test-coverage: Run tests with coverage report
test-coverage: test
	@echo "Generating coverage report..."
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

## lint: Run linters (requires golangci-lint)
lint:
	@echo "Running linters..."
	golangci-lint run ./...

## clean: Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -f $(BINARY_NAME)
	rm -f coverage.out coverage.html
	rm -rf dist/

## run: Run the application locally
run: build
	@echo "Running $(BINARY_NAME)..."
	./$(BINARY_NAME)

##@ Container

## docker-build: Build container with pre-built binary
docker-build: build
	@echo "Building container $(IMAGE_NAME):$(IMAGE_TAG)..."
	$(CONTAINER_RUNTIME) build \
		-f Containerfile \
		-t $(IMAGE_NAME):$(IMAGE_TAG) \
		-t $(IMAGE_NAME):latest \
		.

## docker-build-full: Build container from source (multi-stage)
docker-build-full:
	@echo "Building container from source $(IMAGE_NAME):$(IMAGE_TAG)..."
	$(CONTAINER_RUNTIME) build \
		-f Containerfile.Build \
		-t $(IMAGE_NAME):$(IMAGE_TAG) \
		-t $(IMAGE_NAME):latest \
		.

## docker-build-multiarch: Build multi-architecture images
docker-build-multiarch:
	@echo "Building multi-arch container $(IMAGE_NAME):$(IMAGE_TAG)..."
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		-f Containerfile.Build \
		-t $(IMAGE_NAME):$(IMAGE_TAG) \
		-t $(IMAGE_NAME):latest \
		.

## docker-push: Push container to registry
docker-push:
	@echo "Pushing container to $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)..."
	$(CONTAINER_RUNTIME) tag $(IMAGE_NAME):$(IMAGE_TAG) $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)
	$(CONTAINER_RUNTIME) tag $(IMAGE_NAME):latest $(REGISTRY)/$(IMAGE_NAME):latest
	$(CONTAINER_RUNTIME) push $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)
	$(CONTAINER_RUNTIME) push $(REGISTRY)/$(IMAGE_NAME):latest

## docker-run: Run container locally
docker-run:
	@echo "Running container $(IMAGE_NAME):$(IMAGE_TAG)..."
	$(CONTAINER_RUNTIME) run --rm \
		-p 8080:8080 \
		-p 8081:8081 \
		-v $(PWD)/configs:/etc/config/config:ro \
		$(IMAGE_NAME):$(IMAGE_TAG)

## docker-scan: Scan container for vulnerabilities
docker-scan:
	@echo "Scanning container $(IMAGE_NAME):$(IMAGE_TAG)..."
	@which trivy > /dev/null && trivy image $(IMAGE_NAME):$(IMAGE_TAG) || echo "Install trivy for security scanning"

##@ Dependencies

## deps: Download dependencies
deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod verify

## deps-update: Update dependencies
deps-update:
	@echo "Updating dependencies..."
	go get -u ./...
	go mod tidy

## deps-vendor: Vendor dependencies
deps-vendor:
	@echo "Vendoring dependencies..."
	go mod vendor

##@ Quality

## fmt: Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...

## vet: Run go vet
vet:
	@echo "Running go vet..."
	go vet ./...

## check: Run all quality checks
check: fmt vet lint test

##@ Release

## release-dry-run: Test release build without publishing
release-dry-run:
	@echo "Testing release build..."
	@which goreleaser > /dev/null || (echo "Install goreleaser first" && exit 1)
	goreleaser release --snapshot --clean

## release: Create a new release
release:
	@echo "Creating release..."
	@which goreleaser > /dev/null || (echo "Install goreleaser first" && exit 1)
	goreleaser release --clean

##@ CI/CD

## ci: Run all CI checks
ci: deps check docker-build-full docker-scan
	@echo "CI checks passed!"

## version: Display version information
version:
	@echo "Version:     $(VERSION)"
	@echo "Build Date:  $(BUILD_DATE)"
	@echo "Git Commit:  $(GIT_COMMIT)"
