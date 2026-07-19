.PHONY: build run test clean install tidy vet fmt

BINARY := keysmith
BUILD_DIR := bin
CMD_DIR := ./cmd/keysmith

.PHONY: default
default: build

## build: Compile the keysmith binary into ./bin
build:
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY) $(CMD_DIR)

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