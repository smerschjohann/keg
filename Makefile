DIST    := dist
BINARY  := bin/keg
POC     := poc/keg-poc
IMAGE  ?= keg:dev
IMAGE_RUNTIME ?= keg:runtime-dev
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -X main.Version=$(VERSION)

.DEFAULT_GOAL := build

.PHONY: build lint test tidy integration clean release release-amd64 release-arm64 checksums dist-binaries image image-runtime

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/keg

# Release artifacts are static, trimpath'd binaries in versioned tarballs plus
# checksums.txt. The GitHub release workflow calls the per-arch targets and
# publishes dist/ for the pushed tag.
release: release-amd64 release-arm64 checksums

release-amd64:
	$(call release_build,amd64)

release-arm64:
	$(call release_build,arm64)

define release_build
	@mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=$(1) go build -trimpath -ldflags "$(LDFLAGS) -s -w" -o $(DIST)/keg ./cmd/keg
	tar -C $(DIST) -czf $(DIST)/keg_$(VERSION)_linux_$(1).tar.gz keg
	rm -f $(DIST)/keg
endef

checksums:
	cd $(DIST) && sha256sum keg_$(VERSION)_linux_*.tar.gz > checksums.txt

# Local convenience for the release images; CI builds both multi-arch
# directly with buildx from the same tarballs.
dist-binaries: release
	@for arch in amd64 arm64; do \
		tar -xzf $(DIST)/keg_$(VERSION)_linux_$$arch.tar.gz -O keg > $(DIST)/keg_linux-$$arch; \
		chmod +x $(DIST)/keg_linux-$$arch; \
	done

image: dist-binaries
	docker build --target binary --build-arg VERSION=$(VERSION) -t $(IMAGE) .

image-runtime: dist-binaries
	docker build --target runtime --build-arg VERSION=$(VERSION) -t $(IMAGE_RUNTIME) .

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
	rm -rf bin dist $(POC)
