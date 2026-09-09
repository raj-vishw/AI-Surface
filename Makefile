MODULE       := ai-recon-platform
VERSION      := $(shell cat VERSION 2>/dev/null || echo 0.0.0-dev)
COMMIT       := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE   := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -X '$(MODULE)/internal/version.Version=$(VERSION)' \
           -X '$(MODULE)/internal/version.Commit=$(COMMIT)' \
           -X '$(MODULE)/internal/version.BuildDate=$(BUILD_DATE)'

BIN_DIR      := bin
COMPOSE_FILE := deployments/docker/docker-compose/dev.yml
BIN          ?= cli

.PHONY: build build-all test test-unit test-integration test-race vet fmt fmt-check lint \
        vuln-check secret-scan security-check \
        dev-up dev-down dev-logs dev-ps dev-wait docker-up docker-down \
        migrate migrate-up migrate-status migrate-version \
        run-worker run-cli clean

## Build a single executable, default cli: make build [BIN=cli|worker|migrate]
build:
	@mkdir -p $(BIN_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BIN) ./cmd/$(BIN)

## Build every executable
build-all:
	@mkdir -p $(BIN_DIR)
	@for cmd in cli worker migrate; do \
		echo "building $$cmd"; \
		go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$$cmd ./cmd/$$cmd || exit 1; \
	done

## Run unit tests (excludes integration-tagged tests requiring live services)
test:
	go test ./...

## Alias for `test` (master spec's name for the same target)
test-unit: test

## Run integration tests against docker-compose services (run `make dev-up` first)
test-integration:
	go test -tags=integration ./...

## Run the full test suite under the race detector (phase15.md §131/§158)
test-race:
	go test -race ./...

vet:
	go vet ./...

## Rewrite files in place to match gofmt
fmt:
	gofmt -l -w .

## Fail if any file is not gofmt-formatted (used in CI)
fmt-check:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "the following files are not gofmt-formatted:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi

## Run golangci-lint (must be installed: https://golangci-lint.run/welcome/install/)
lint:
	golangci-lint run ./...

## Check Go module dependencies (incl. the standard library) for known
## vulnerabilities (phase15.md §63; must be installed:
## `go install golang.org/x/vuln/cmd/govulncheck@latest`)
vuln-check:
	govulncheck ./...

## Scan the working tree for committed secrets (phase15.md §6; must be
## installed: https://github.com/gitleaks/gitleaks#installing). See
## .gitleaks.toml for the (narrow, test-fixture-only) allowlist.
secret-scan:
	gitleaks detect --source . --no-git --config .gitleaks.toml

## Run every local security check this Makefile knows about (does not
## replace the container-image scan CI runs separately for the Docker
## build — see .github/workflows/ci.yml's security job).
security-check: vuln-check secret-scan

## Start PostgreSQL and Redis for local development
dev-up:
	docker compose -f $(COMPOSE_FILE) --env-file .env up -d --build

## Stop and remove the development environment
dev-down:
	docker compose -f $(COMPOSE_FILE) --env-file .env down

## Aliases for dev-up/dev-down (master spec's names for the same targets)
docker-up: dev-up
docker-down: dev-down

## Tail logs from the development environment
dev-logs:
	docker compose -f $(COMPOSE_FILE) --env-file .env logs -f

## Show status of the development environment's containers
dev-ps:
	docker compose -f $(COMPOSE_FILE) --env-file .env ps

## Block until PostgreSQL and Redis are accepting connections
dev-wait:
	./scripts/dev/wait-for-services.sh

## Apply pending database migrations (master spec's default `make migrate`)
migrate: migrate-up

migrate-up:
	go run ./cmd/migrate up

## Print migration status
migrate-status:
	go run ./cmd/migrate status

## Print the current (highest applied) migration version
migrate-version:
	go run ./cmd/migrate version

run-worker:
	go run ./cmd/worker

run-cli:
	go run ./cmd/cli $(ARGS)

clean:
	rm -rf $(BIN_DIR)
