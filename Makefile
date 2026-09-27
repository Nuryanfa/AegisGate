.PHONY: run run-upstream build test test-race fmt vet tidy check

run:
	go run ./cmd/gateway

run-upstream:
	go run ./cmd/example-upstream

build:
	go build ./...

test:
	go test ./...

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
