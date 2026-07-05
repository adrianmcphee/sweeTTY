# SweeTTY build and verification tasks.
# Run `make` or `make help` for the list.

BINARY := sweetty
PKG := ./...
GOFILES := $(shell find . -name '*.go' -not -path './vendor/*')

# Version metadata, injected via -ldflags. VERSION prefers an exact tag and falls
# back to a describe/short-sha so local builds stay traceable; the release
# workflow overrides VERSION with the pushed tag. Keep these flags identical to
# scripts/build-release.sh so `make build` and the release stamp the same way.
VERSION    ?= $(shell git describe --tags --exact-match 2>/dev/null || git describe --tags --always --dirty 2>/dev/null || echo dev)
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS    := -s -w \
	-X main.version=$(VERSION) \
	-X main.gitCommit=$(GIT_COMMIT) \
	-X main.buildDate=$(BUILD_DATE)

.DEFAULT_GOAL := help

.PHONY: help build run version test adversary vet fmt fmt-check check tidy cover clean release-local hooks

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

build: ## Build the version-stamped sweetty binary (PIE for ASLR, as the release does)
	go build -buildmode=pie -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/sweetty

run: build ## Build and run (loads ./config.json)
	./$(BINARY)

version: build ## Print the embedded build metadata
	./$(BINARY) version

test: ## Run all tests
	go test $(PKG)

adversary: ## Run the anti-detection gate
	go test ./internal/adversary/...

vet: ## Run go vet
	go vet $(PKG)

fmt: ## Format all Go files in place
	gofmt -w $(GOFILES)

fmt-check: ## Fail if any Go file is not gofmt-clean
	@out=$$(gofmt -l $(GOFILES)); \
		if [ -n "$$out" ]; then echo "unformatted:"; echo "$$out"; exit 1; fi

check: fmt-check vet build adversary test ## The gate before committing: fmt-check + vet + build + adversary + test

tidy: ## Tidy go.mod / go.sum
	go mod tidy

cover: ## Run tests with a coverage summary
	go test -cover $(PKG)

clean: ## Remove build artifacts
	rm -f $(BINARY) coverage.out
	rm -rf dist

release-local: ## Dry-run the cross-platform release build into ./dist
	bash scripts/build-release.sh

hooks: ## Install the repo git hooks (blocks AI attribution in commit messages)
	git config core.hooksPath .githooks
	@echo "git hooks installed: core.hooksPath -> .githooks"
