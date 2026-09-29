.PHONY: run run-upstream run-users run-orders generate-key build test test-integration test-race fmt vet tidy check

run:
	AEGIS_CONFIG_PATH=configs/config.example.yaml go run ./cmd/gateway

run-upstream:
	go run ./cmd/example-upstream

run-users:
	EXAMPLE_SERVICE_NAME=users-upstream EXAMPLE_HTTP_ADDR=:8081 go run ./cmd/example-upstream

run-orders:
	EXAMPLE_SERVICE_NAME=orders-upstream EXAMPLE_HTTP_ADDR=:8082 go run ./cmd/example-upstream

generate-key:
	go run ./cmd/keygen

build:
	go build ./...

test:
	go test ./...

test-integration:
	AEGIS_REDIS_INTEGRATION_ADDR=$${AEGIS_REDIS_INTEGRATION_ADDR:-127.0.0.1:6379} go test -count=1 -v ./internal/ratelimit

test-race:
	go test -race ./...

fmt:
	gofmt -w .

vet:
	go vet ./...

tidy:
	go mod tidy

check:
	test -z "$$(gofmt -l .)"
	go vet ./...
	go test ./...
