BINARY  := bin/keg
POC     := poc/keg-poc
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -X main.Version=$(VERSION)

.DEFAULT_GOAL := build

.PHONY: build lint test tidy integration clean release release-amd64 release-arm64

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/keg

release: release-amd64 release-arm64

release-amd64:
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS) -s -w" -o bin/keg-$(VERSION)-linux-amd64 ./cmd/keg
	chmod +x bin/keg-$(VERSION)-linux-amd64
	gzip -f bin/keg-$(VERSION)-linux-amd64

release-arm64:
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS) -s -w" -o bin/keg-$(VERSION)-linux-arm64 ./cmd/keg
	chmod +x bin/keg-$(VERSION)-linux-arm64
	gzip -f bin/keg-$(VERSION)-linux-arm64

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

