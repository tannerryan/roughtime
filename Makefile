BINARIES = roughtime roughtime-client roughtime-debug roughtime-bench roughtime-stamp

FUZZ_TARGETS = \
	FuzzParseEcosystem:./ \
	FuzzParseProof:./ \
	FuzzDecode:./protocol/ \
	FuzzParseRequest:./protocol/ \
	FuzzVerifyReply:./protocol/ \
	FuzzParseMalfeasanceReport:./protocol/ \
	FuzzValidateRequest:./cmd/roughtime/
FUZZ_TIME ?= 30s

COMMIT      ?= $(shell \
	commit=$$(git rev-parse --short HEAD 2>/dev/null); \
	if test -n "$$commit"; then \
		test -z "$$(git status --porcelain --untracked-files=normal 2>/dev/null)" || commit="$$commit-dirty"; \
		printf '%s' "$$commit"; \
	fi)
BUILD_DATE  ?= $(shell git show -s --format=%cI HEAD 2>/dev/null)
VERSION_PKG  = github.com/tannerryan/roughtime/internal/version
LDFLAGS      = -X $(VERSION_PKG).Commit=$(COMMIT) -X $(VERSION_PKG).Date=$(BUILD_DATE)

GOOS        ?= $(shell go env GOOS)
GOARCH      ?= $(shell go env GOARCH)
CGO_ENABLED ?= 0
export GOOS GOARCH CGO_ENABLED

.PHONY: all deps deps-ci build test test-race fuzz fmt vet lint vuln verify \
	verify-tidy verify-vendor check clean

all: fmt vet build test

deps: deps-ci

deps-ci:
	go install golang.org/x/tools/cmd/goimports@latest
	go install honnef.co/go/tools/cmd/staticcheck@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o roughtime ./cmd/roughtime
	go build -trimpath -ldflags "$(LDFLAGS)" -o roughtime-client ./cmd/roughtime-client
	go build -trimpath -ldflags "$(LDFLAGS)" -o roughtime-debug ./cmd/roughtime-debug
	go build -trimpath -ldflags "$(LDFLAGS)" -o roughtime-bench ./cmd/roughtime-bench
	go build -trimpath -ldflags "$(LDFLAGS)" -o roughtime-stamp ./cmd/roughtime-stamp

test:
	go test ./...

test-race: export CGO_ENABLED = 1
test-race:
	go test -race ./...

fuzz:
	@for entry in $(FUZZ_TARGETS); do \
		name=$${entry%%:*}; pkg=$${entry#*:}; \
		echo "=== fuzzing $$name ($$pkg, $(FUZZ_TIME)) ==="; \
		go test -run='^$$' -fuzz="^$${name}$$" -fuzztime="$(FUZZ_TIME)" "$$pkg" || exit 1; \
	done

fmt:
	find . -path ./vendor -prune -o -name '*.go' -exec gofmt -w {} +
	find . -path ./vendor -prune -o -name '*.go' -exec goimports -w {} +

vet:
	go vet ./...

lint: vet
	staticcheck ./...

vuln:
	govulncheck ./...

verify:
	go mod download
	go mod verify

verify-tidy:
	go mod tidy -diff

verify-vendor:
	@tmp=$$(mktemp -d); \
	trap 'rm -rf "$$tmp"' EXIT; \
	go mod vendor -o "$$tmp/vendor"; \
	diff -ruN vendor "$$tmp/vendor"

check: verify verify-tidy verify-vendor fmt lint vuln build test-race

clean:
	rm -f $(BINARIES)
