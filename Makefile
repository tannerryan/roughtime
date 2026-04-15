# roughtime - https://github.com/tannerryan/roughtime

# Binaries
BINARIES     = roughtime roughtime-client roughtime-debug roughtime-bench
# Fuzz targets, grouped by package. `name:pkg` — the fuzz rule splits on ':'.
FUZZ_TARGETS = \
    FuzzDecode:./protocol/ \
    FuzzParseRequest:./protocol/ \
    FuzzVerifyReply:./protocol/ \
    FuzzVerifyReplyAllVersions:./protocol/ \
    FuzzCreateReplies:./protocol/ \
    FuzzCreateRepliesBatch:./protocol/ \
    FuzzCreateRequestWithNonce:./protocol/ \
    FuzzDecodeTimestamp:./protocol/ \
    FuzzEncode:./protocol/ \
    FuzzExtractVersion:./protocol/ \
    FuzzSelectVersion:./protocol/ \
    FuzzGrease:./protocol/ \
    FuzzParseMalfeasanceReport:./protocol/ \
    FuzzChainNonce:./protocol/ \
    FuzzChainVerify:./protocol/ \
    FuzzValidateRequest:./server/ \
    FuzzServeOnce:./server/
FUZZ_TIME   ?= 30s

.PHONY: all deps build test test-verbose test-race test-cover test-race-cover \
        test-all fuzz lint vet fmt verify coverage-report check clean

# Default: format, vet, build, test with race detector
all: fmt vet build test-race

# Install development tools
deps:
	go install golang.org/x/tools/cmd/goimports@latest
	go install honnef.co/go/tools/cmd/staticcheck@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/gopls@latest
	go install github.com/gojp/goreportcard/cmd/goreportcard-cli@latest

# Build all binaries
build:
	go build -o roughtime ./server
	go build -o roughtime-client ./client
	go build -o roughtime-debug ./debug
	go build -o roughtime-bench ./bench

# Run unit tests
test:
	go test ./...

# Run unit tests with verbose output
test-verbose:
	go test -v ./...

# Run unit tests with race detector
test-race:
	go test -race ./...

# Run unit tests with coverage (protocol + server packages)
test-cover:
	go test -cover ./protocol/ ./server/

# Run unit tests with race detector and coverage profile (used by CI)
test-race-cover:
	go test -race -covermode=atomic -coverprofile=coverage.out ./protocol/ ./server/

# Verify module checksums match go.sum
verify:
	go mod download
	go mod verify

# Generate per-function summary and HTML coverage report from coverage.out
coverage-report: test-race-cover
	go tool cover -func=coverage.out > coverage.txt
	cat coverage.txt
	go tool cover -html=coverage.out -o coverage.html

# Run all test variants (verbose + race + cover)
test-all: test-verbose test-race test-cover

# Run all fuzz targets sequentially (FUZZ_TIME=30s by default). Each entry
# encodes name:pkg so the dispatch covers both ./protocol/ and ./server/.
fuzz:
	@for entry in $(FUZZ_TARGETS); do \
		name=$${entry%%:*}; pkg=$${entry#*:}; \
		echo "=== fuzzing $$name ($$pkg, $(FUZZ_TIME)) ==="; \
		go test -fuzz="^$${name}$$" -fuzztime=$(FUZZ_TIME) $$pkg || exit 1; \
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
	gopls check ./protocol/protocol.go ./protocol/chain.go ./server/main.go ./server/listen_linux.go ./server/listen_other.go ./debug/main.go ./client/main.go ./bench/main.go

# Run full check suite: module verify, format, vet, lint, build, test with race
# + coverage, report card
check: verify fmt vet lint build test-race-cover
	goreportcard-cli -v

# Remove built binaries and coverage artifacts
clean:
	rm -f $(BINARIES) coverage.out coverage.txt coverage.html
