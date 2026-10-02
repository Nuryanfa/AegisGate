.PHONY: run run-upstream run-users run-orders generate-key build test test-integration test-race test-fuzz bench-waf bench-security-events fmt vet tidy check

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

test-fuzz:
	go test ./internal/waf -run=^$$ -fuzz=FuzzNormalizeQuery -fuzztime=2s
	go test ./internal/waf -run=^$$ -fuzz=FuzzInspectJSON -fuzztime=2s
	go test ./internal/waf -run=^$$ -fuzz=FuzzRuleEvaluation -fuzztime=2s

bench-waf:
	go test ./internal/waf -run=^$$ -bench=BenchmarkWAF -benchmem -count=1 -benchtime=500ms

bench-security-events:
	go test ./internal/securityevent -run=^$$ -bench='Benchmark(Publish|Detector)' -benchmem -count=1 -benchtime=500ms

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
