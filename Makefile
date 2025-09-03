BINARY_NAME=cloudtrail-log-parser
ROLE_NAME=${BINARY_NAME}-execution-role
REGION=eu-west-1
LAMBDA_HANDLER=bootstrap
RULES_FILE=rules.yaml

BIN_DIR ?= $(shell pwd)/bin
LDFLAGS := -ldflags="-s -w -X"

.DEFAULT_GOAL := help

default: test build archive
.PHONY: default

help: ## Show this help message
	@echo "CloudTrail Log Parser - Makefile Commands"
	@echo "========================================="
	@echo ""
	@echo "Usage: make [command] [ARGS=value]"
	@echo ""
	@echo "Available commands:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Configuration variables:"
	@echo "  RULES_FILE    - Configuration file to use (default: rules.yaml)"
	@echo "  FILE          - File to convert (for yaml-to-json/json-to-yaml)"
	@echo "  REGION        - AWS region (default: eu-west-1)"
	@echo ""
	@echo "Examples:"
	@echo "  make build                          # Build the application"
	@echo "  make test                           # Run all tests"
	@echo "  make validate-config RULES_FILE=rules-example.yaml"
	@echo "  make yaml-to-json FILE=rules.yaml  # Convert YAML to JSON"
	@echo "  make show-config-json | jq '.rules[0]'"
.PHONY: help

build: ## Build the application for all platforms
	@echo "--- build it all"
	@mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags prod $(LDFLAGS) -trimpath -o dist/${BINARY_NAME}-linux-amd64 -tags lambda.norpc,prod ./cmd/...
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -tags prod $(LDFLAGS) -trimpath -o dist/${BINARY_NAME}-linux-arm64 -tags lambda.norpc,prod ./cmd/...
	CGO_ENABLED=0 GOOS=macos GOARCH=arm64 go build -tags prod $(LDFLAGS) -trimpath -o dist/${BINARY_NAME}-macos-arm64 -tags lambda.norpc,prod ./cmd/...
.PHONY: build

test: ## Run all tests
	@echo "--- running tests"
	@go test -v ./...
.PHONY: test

bench: ## Run performance benchmarks
	@echo "--- running benchmarks"
	@go test -bench=. -benchmem ./pkg/cloudtrailprocessor/...
.PHONY: bench

test-coverage: ## Run tests with coverage report
	@echo "--- running tests with coverage"
	@go test -v -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"
.PHONY: test-coverage

test-integration: ## Run integration tests
	@echo "--- running integration tests"
	@go test -v -tags=integration ./...
.PHONY: test-integration

run: ## Run the application in production mode
	@echo "--- running prod mode"
	@go run ./cmd/main.go
.PHONY: run

run-dev: ## Run the application in development mode
	@echo "--- running dev mode"
	@go run ./cmd/dev.go
.PHONY: run-dev

test-local: ## Test CloudTrail parsing locally with example file
	@echo "--- testing CloudTrail parsing locally"
	@go run -tags dev cmd/dev.go -file ./examples/cloudtrail.json -rules ./rules-example.yaml
.PHONY: test-local

clean: ## Clean build artifacts and temporary files
	@echo "--- clean up everything"
	@rm -rf ./dist
	@find . -type f -name '*.out.json' -delete
	@rm -f coverage.out coverage.html
	@go clean
.PHONY: clean

archive: ## Create Lambda deployment archive (handler.zip)
	@echo "--- build an archive"
	@cd dist && zip -X -9 -r ./handler.zip ${BINARY_NAME} && zip -j ./handler.zip ../${RULES_FILE}
.PHONY: archive

# Configuration export/import commands
export-json: ## Export RULES_FILE to JSON format
	@echo "--- exporting configuration to JSON"
	@go run cmd/config-export/main.go -input $(RULES_FILE) -format json -output $(RULES_FILE:.yaml=.json)
	@echo "Exported to $(RULES_FILE:.yaml=.json)"
.PHONY: export-json

export-yaml: ## Export JSON config back to YAML format
	@echo "--- exporting configuration to YAML"
	@go run cmd/config-export/main.go -input $(RULES_FILE:.json=.yaml) -format yaml -output $(RULES_FILE)
	@echo "Exported to $(RULES_FILE)"
.PHONY: export-yaml

# Export example configuration
export-example-json: ## Export rules-example.yaml to JSON
	@echo "--- exporting example configuration to JSON"
	@go run cmd/config-export/main.go -input rules-example.yaml -format json -output rules-example.json
	@echo "Exported to rules-example.json"
.PHONY: export-example-json

# Validate configuration
validate-config: ## Validate RULES_FILE configuration
	@echo "--- validating configuration"
	@go run cmd/config-export/main.go -input $(RULES_FILE) -format yaml > /dev/null && echo "Configuration is valid" || echo "Configuration validation failed"
.PHONY: validate-config

# Show configuration in JSON format
show-config-json: ## Display RULES_FILE as formatted JSON
	@echo "--- showing configuration as JSON"
	@go run cmd/config-export/main.go -input $(RULES_FILE) -format json | jq '.'
.PHONY: show-config-json

# Convert between formats
yaml-to-json: ## Convert YAML file to JSON (requires FILE=)
	@echo "--- converting YAML to JSON"
	@test -f $(FILE) || (echo "Error: FILE parameter required (e.g., make yaml-to-json FILE=rules.yaml)" && exit 1)
	@go run cmd/config-export/main.go -input $(FILE) -format json -output $(FILE:.yaml=.json)
	@echo "Converted $(FILE) to $(FILE:.yaml=.json)"
.PHONY: yaml-to-json

json-to-yaml: ## Convert JSON file to YAML (requires FILE=)
	@echo "--- converting JSON to YAML"
	@test -f $(FILE) || (echo "Error: FILE parameter required (e.g., make json-to-yaml FILE=rules.json)" && exit 1)
	@go run cmd/config-export/main.go -input $(FILE) -format yaml -output $(FILE:.json=.yaml)
	@echo "Converted $(FILE) to $(FILE:.json=.yaml)"
.PHONY: json-to-yaml
