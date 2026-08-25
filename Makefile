BINARY := bin/keg
POC    := poc/keg-poc

.DEFAULT_GOAL := build

.PHONY: build lint test tidy integration clean

build:
	go build -o $(BINARY) ./cmd/keg

lint:
	golangci-lint run

test:
	go test -race ./...

integration:
	go test -race -tags integration ./test/integration/... -v

tidy:
	go mod tidy
	git diff --exit-code go.mod go.sum

clean:
	rm -rf bin $(POC)
