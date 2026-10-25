APP_NAME := threat-info-service
BIN_DIR := bin

GOOSE := go run github.com/pressly/goose/v3/cmd/goose@v3.29.0

THREAT_INFO_DATABASE_DSN ?= postgres://threats:threats@localhost:5432/threats?sslmode=disable
export THREAT_INFO_DATABASE_DSN

.DEFAULT_GOAL := help

.PHONY: help
help:
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-16s %s\n", $$1, $$2}'

.PHONY: up
up: db migrate-up ## Start everything: database, migrations, service
	docker compose up -d --build
	@echo "Service is ready: http://localhost:8080"

.PHONY: down
down: ## Stop the stack
	docker compose down

.PHONY: db
db: ## Start the database and wait until it is healthy
	docker compose up -d --wait postgres

.PHONY: migrate-up
migrate-up: ## Apply the pending migrations
	$(GOOSE) -dir migrations postgres "$(THREAT_INFO_DATABASE_DSN)" up

.PHONY: migrate-down
migrate-down: ## Revert the last migration
	$(GOOSE) -dir migrations postgres "$(THREAT_INFO_DATABASE_DSN)" down

.PHONY: migrate-status
migrate-status: ## Show the applied migrations
	$(GOOSE) -dir migrations postgres "$(THREAT_INFO_DATABASE_DSN)" status

.PHONY: migrate-create
migrate-create: ## Create a migration: make migrate-create name=add_source
	$(GOOSE) -dir migrations -s create $(name) sql

.PHONY: run
run: db migrate-up ## Run the service from source
	go run ./cmd

.PHONY: build
build: ## Build the binary into bin/
	CGO_ENABLED=0 go build -o $(BIN_DIR)/$(APP_NAME) ./cmd

.PHONY: generate
generate: ## Regenerate the API code from the OpenAPI spec
	go tool oapi-codegen -config api/oapi-codegen.yaml api/openapi.yaml

.PHONY: test
test: ## Run the tests with the race detector
	go test -race ./...

.PHONY: test-integration
test-integration: ## Run the integration tests (needs Docker)
	go test -race -tags integration ./tests/integration/...

.PHONY: test-e2e
test-e2e: ## Run the end-to-end tests against the running stack (make up first)
	go test -count=1 -tags e2e ./tests/e2e/...

.PHONY: lint
lint: ## Run golangci-lint
	golangci-lint run ./...

.PHONY: fmt
fmt: ## Format the sources
	golangci-lint fmt ./...

.PHONY: clean
clean: ## Remove build output
	rm -rf $(BIN_DIR)
