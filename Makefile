APP_NAME := threat-info-service
BIN_DIR := bin

THREAT_INFO_DATABASE_DSN ?= postgres://threats:threats@localhost:5432/threats?sslmode=disable
export THREAT_INFO_DATABASE_DSN

.PHONY: build
build:
	CGO_ENABLED=0 go build -o $(BIN_DIR)/$(APP_NAME) ./cmd

.PHONY: run
run:
	go run ./cmd

.PHONY: test
test:
	go test -race ./...

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: fmt
fmt:
	golangci-lint fmt ./...

.PHONY: up
up:
	docker compose up --build -d

.PHONY: down
down:
	docker compose down

.PHONY: clean
clean:
	rm -rf $(BIN_DIR)
