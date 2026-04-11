# roughtime - https://github.com/tannerryan/roughtime

# Binaries
BINARIES     = roughtime roughtime-client roughtime-debug
FUZZ_TARGETS = FuzzDecode FuzzParseRequest FuzzVerifyReply \
               FuzzVerifyReplyAllVersions FuzzCreateReplies \
               FuzzCreateRepliesBatch FuzzDecodeTimestamp FuzzEncode \
               FuzzExtractVersion FuzzSelectVersion FuzzParseMalfeasanceReport \
               FuzzChainNonce FuzzChainVerify FuzzGrease
FUZZ_TIME   ?= 30s

.PHONY: all deps build test test-verbose test-race test-cover test-all \
        fuzz lint vet fmt check clean

# Default: format, vet, build, test with race detector
all: fmt vet build test-race

# Install development tools
deps:
	go install golang.org/x/tools/cmd/goimports@latest
	go install honnef.co/go/tools/cmd/staticcheck@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/gojp/goreportcard/cmd/goreportcard-cli@latest

# Build all binaries
build:
	go build -o roughtime .
	go build -o roughtime-client ./client
	go build -o roughtime-debug ./debug

# Run unit tests
test:
	go test ./...

# Run unit tests with verbose output
test-verbose:
	go test -v ./...

# Run unit tests with race detector
test-race:
	go test -race ./...

# Run unit tests with coverage
test-cover:
	go test -cover ./...

# Run all test variants (verbose + race + cover)
test-all: test-verbose test-race test-cover

# Run all fuzz targets sequentially (FUZZ_TIME=30s by default)
fuzz:
	@for target in $(FUZZ_TARGETS); do \
		echo "=== fuzzing $$target ($(FUZZ_TIME)) ==="; \
		go test -fuzz="^$${target}$$" -fuzztime=$(FUZZ_TIME) ./protocol/ || exit 1; \
	done

# Run gofmt and goimports
fmt:
	gofmt -w .
	goimports -w .

# Run go vet
vet:
	go vet ./...

# Run all linters (staticcheck, golangci-lint, gopls, go vet)
lint: vet
	staticcheck ./...
	golangci-lint run ./...
	gopls check ./protocol/protocol.go ./protocol/chain.go ./main.go ./debug/main.go ./client/main.go

# Run full check suite: format, vet, lint, build, test with race, coverage,
# report card
check: fmt vet lint build test-race test-cover
	goreportcard-cli -v

# Remove built binaries
clean:
	rm -f $(BINARIES)
