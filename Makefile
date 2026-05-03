# roughtime - https://github.com/tannerryan/roughtime

BINARIES     = roughtime roughtime-client roughtime-debug roughtime-bench roughtime-stamp
# name:pkg — split on ':' by the fuzz rule
FUZZ_TARGETS = \
    FuzzConsensus:./ \
    FuzzParseEcosystem:./ \
    FuzzDecodePublicKey:./ \
    FuzzVersionsForScheme:./ \
    FuzzParseProof:./ \
    FuzzVerify:./ \
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
    FuzzFindTagRange:./protocol/ \
    FuzzDecodeTimestamp:./protocol/ \
    FuzzEncode:./protocol/ \
    FuzzExtractVersion:./protocol/ \
    FuzzSelectVersion:./protocol/ \
    FuzzGrease:./protocol/ \
    FuzzParseMalfeasanceReport:./protocol/ \
    FuzzChainNonce:./protocol/ \
    FuzzChainVerify:./protocol/ \
    FuzzValidateRequest:./cmd/roughtime/ \
    FuzzServeOnce:./cmd/roughtime/ \
    FuzzReadTCPFrame:./cmd/roughtime/ \
    FuzzEscapeHelp:./cmd/roughtime/ \
    FuzzEscapeLabel:./cmd/roughtime/ \
    FuzzFormatValue:./cmd/roughtime/
FUZZ_TIME   ?= 30s

.PHONY: all deps build test test-verbose test-race test-cover test-race-cover \
        test-all fuzz lint vet fmt verify verify-tidy coverage-report check clean

# Default: fmt, vet, build, race tests
all: fmt vet build test-race

# Install dev tools
deps:
	go install golang.org/x/tools/cmd/goimports@latest
	go install honnef.co/go/tools/cmd/staticcheck@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/gopls@latest
	go install github.com/gojp/goreportcard/cmd/goreportcard-cli@latest

# Inject commit + build date into binaries via -ldflags. Empty when git is
# absent; the version package falls back to the bare release string.
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null)
BUILD_DATE  ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
VERSION_PKG  = github.com/tannerryan/roughtime/internal/version
LDFLAGS      = -X $(VERSION_PKG).Commit=$(COMMIT) -X $(VERSION_PKG).Date=$(BUILD_DATE)

# Cross-compile knobs. `make build GOOS=linux GOARCH=arm64` produces a Linux
# arm64 binary with the same -ldflags as a host build.
GOOS        ?= $(shell go env GOOS)
GOARCH      ?= $(shell go env GOARCH)
CGO_ENABLED ?= 0
export GOOS GOARCH CGO_ENABLED

# Build binaries
build:
	go build -ldflags "$(LDFLAGS)" -o roughtime ./cmd/roughtime
	go build -ldflags "$(LDFLAGS)" -o roughtime-client ./cmd/roughtime-client
	go build -ldflags "$(LDFLAGS)" -o roughtime-debug ./cmd/roughtime-debug
	go build -ldflags "$(LDFLAGS)" -o roughtime-bench ./cmd/roughtime-bench
	go build -ldflags "$(LDFLAGS)" -o roughtime-stamp ./cmd/roughtime-stamp

# Unit tests
test:
	go test ./...

# Unit tests, verbose
test-verbose:
	go test -v ./...

# Unit tests with race detector (-race requires cgo)
test-race: export CGO_ENABLED = 1
test-race:
	go test -race ./...

# Unit tests with coverage
test-cover:
	go test -cover ./ ./protocol/ ./cmd/roughtime/

# Race + coverage profile (CI)
test-race-cover: export CGO_ENABLED = 1
test-race-cover:
	go test -race -covermode=atomic -coverprofile=coverage.out ./ ./protocol/ ./cmd/roughtime/

# Verify module checksums
verify:
	go mod download
	go mod verify

# Verify go.mod and go.sum are tidy (CI guard)
verify-tidy:
	go mod tidy
	git diff --exit-code go.mod go.sum

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
	@files=$$(find . -maxdepth 4 -name '*.go' ! -name '*_test.go' ! -path './vendor/*'); \
	    test -n "$$files" || { echo "lint: no Go files found for gopls check" >&2; exit 1; }; \
	    gopls check $$files

# Full check: verify, fmt, lint, build, race+cover, report card
check: verify fmt lint build test-race-cover
	goreportcard-cli -v

# Remove binaries and coverage artifacts
clean:
	rm -f $(BINARIES) coverage.out coverage.txt coverage.html
