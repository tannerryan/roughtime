# roughtime - https://github.com/tannerryan/roughtime

BINARIES     = roughtime roughtime-client roughtime-debug roughtime-bench roughtime-stamp
# name:pkg — split on ':' by the fuzz rule
FUZZ_TARGETS = \
    FuzzParseEcosystem:./ \
    FuzzDecodePublicKey:./ \
    FuzzVersionsForScheme:./ \
    FuzzParseProof:./ \
    FuzzDecode:./protocol/ \
    FuzzParsePacketHeader:./protocol/ \
    FuzzParseRequest:./protocol/ \
    FuzzParseShortVersion:./protocol/ \
    FuzzVerifyReply:./protocol/ \
    FuzzVerifyReplyAllVersions:./protocol/ \
    FuzzPQVerifyReply:./protocol/ \
    FuzzCreateReplies:./protocol/ \
    FuzzCreateRepliesBatch:./protocol/ \
    FuzzCreateRequestWithNonce:./protocol/ \
    FuzzNonceOffsetInRequest:./protocol/ \
    FuzzDecodeTimestamp:./protocol/ \
    FuzzEncode:./protocol/ \
    FuzzExtractVersion:./protocol/ \
    FuzzSelectVersion:./protocol/ \
    FuzzGrease:./protocol/ \
    FuzzParseMalfeasanceReport:./protocol/ \
    FuzzChainNonce:./protocol/ \
    FuzzChainVerify:./protocol/ \
    FuzzValidateRequest:./server/ \
    FuzzServeOnce:./server/ \
    FuzzReadTCPFrame:./server/
FUZZ_TIME   ?= 30s

.PHONY: all deps build test test-verbose test-race test-cover test-race-cover \
        test-all fuzz lint vet fmt verify coverage-report check clean

# Default: fmt, vet, build, race tests
all: fmt vet build test-race

# Install dev tools
deps:
	go install golang.org/x/tools/cmd/goimports@latest
	go install honnef.co/go/tools/cmd/staticcheck@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/gopls@latest
	go install github.com/gojp/goreportcard/cmd/goreportcard-cli@latest

# Build binaries
build:
	go build -o roughtime ./server
	go build -o roughtime-client ./client
	go build -o roughtime-debug ./debug
	go build -o roughtime-bench ./bench
	go build -o roughtime-stamp ./stamp

# Unit tests
test:
	go test ./...

# Unit tests, verbose
test-verbose:
	go test -v ./...

# Unit tests with race detector
test-race:
	go test -race ./...

# Unit tests with coverage
test-cover:
	go test -cover ./ ./protocol/ ./server/

# Race + coverage profile (CI)
test-race-cover:
	go test -race -covermode=atomic -coverprofile=coverage.out ./ ./protocol/ ./server/

# Verify module checksums
verify:
	go mod download
	go mod verify

# Per-function summary + HTML coverage report
coverage-report: test-race-cover
	go tool cover -func=coverage.out > coverage.txt
	cat coverage.txt
	go tool cover -html=coverage.out -o coverage.html

# All test variants
test-all: test-verbose test-race test-cover

# Run all fuzz targets sequentially. Up to 3 attempts absorb the upstream
# go-fuzz coordinator deadline-race flake; real crashes replay from
# testdata/fuzz.
fuzz:
	@for entry in $(FUZZ_TARGETS); do \
		name=$${entry%%:*}; pkg=$${entry#*:}; \
		echo "=== fuzzing $$name ($$pkg, $(FUZZ_TIME)) ==="; \
		for _ in 1 2 3; do \
			go test -run='^$$' -fuzz="^$${name}$$" -fuzztime=$(FUZZ_TIME) $$pkg && break; \
		done || exit 1; \
	done

# gofmt + goimports
fmt:
	gofmt -w .
	goimports -w .

# go vet
vet:
	go vet ./...

# All linters (staticcheck, golangci-lint, gopls, vet)
lint: vet
	staticcheck ./...
	golangci-lint run ./...
	gopls check ./protocol/protocol.go ./protocol/chain.go ./protocol/sigscheme.go ./protocol/transport.go ./server/main.go ./server/listen_linux.go ./server/listen_other.go ./server/listen_tcp.go ./server/listen_unix.go ./debug/main.go ./client/main.go ./bench/main.go ./stamp/main.go ./roughtime.go

# Full check: verify, fmt, vet, lint, build, race+cover, report card
check: verify fmt vet lint build test-race-cover
	goreportcard-cli -v

# Remove binaries and coverage artifacts
clean:
	rm -f $(BINARIES) coverage.out coverage.txt coverage.html
