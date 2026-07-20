.PHONY: build run test clean install tidy vet fmt

BINARY := keysmith
BUILD_DIR := bin
CMD_DIR := ./cmd/keysmith

.PHONY: default
default: build

## build: Compile + UPX-compress keysmith binary into ./bin
build:
	@mkdir -p $(BUILD_DIR)
	go build -ldflags "-s -w -X main.version=v$$(cat VERSION 2>/dev/null || echo dev)" -o $(BUILD_DIR)/$(BINARY) $(CMD_DIR)
	@if command -v upx >/dev/null 2>&1 && [ "$$(go env GOOS)" != "darwin" ]; then \
		upx -q --best $(BUILD_DIR)/$(BINARY) >/dev/null 2>&1 && echo "UPX compressed: $$(du -h $(BUILD_DIR)/$(BINARY) | cut -f1)" || echo "UPX skipped (unsupported)"; \
	fi

## run: Build and run keysmith with any args via ARGS=...
run: build
	./$(BUILD_DIR)/$(BINARY) $(ARGS)

## test: Run the test suite
test:
	go test ./...

## tidy: Run go mod tidy
tidy:
	go mod tidy

## vet: Run go vet
vet:
	go vet ./...

## fmt: Format all Go sources
fmt:
	go fmt ./...

## clean: Remove build artifacts
clean:
	rm -rf $(BUILD_DIR)

## install: Install keysmith into $$GOBIN (or $$GOPATH/bin)
install:
	go install $(CMD_DIR)
# Local CI targets (gitignored) — billing-free replacement for GitHub Actions
-include Makefile.local
