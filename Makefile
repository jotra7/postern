GO ?= go
LDFLAGS := -X github.com/jotra7/postern/internal/version.version=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev) \
           -X github.com/jotra7/postern/internal/version.buildUnix=$(shell date +%s)

export CGO_ENABLED=0

.PHONY: test
test:
	$(GO) test ./...

.PHONY: test-linux
test-linux:
	./scripts/linux-test.sh ./...

.PHONY: test-rules
test-rules:
	# "Health is the join" is computed in PromQL, because no single postern
	# process can hold both halves of it. This is the only thing that evaluates
	# it; `go test` can check that the rules name metrics that exist, not that
	# they mean what they say.
	./scripts/promtool-test.sh

.PHONY: fuzz
fuzz:
	$(GO) test ./internal/spa/ -run=Fuzz -fuzz=FuzzParse -fuzztime=60s

.PHONY: lint
lint:
	# GOOS=linux, mirroring test-linux: spike/nft-interval imports
	# google/nftables, which pulls in golang.org/x/sys/unix constants
	# (unix.NFPROTO_IPV4 and friends) that only exist under the Linux build
	# tags. Linting natively on macOS otherwise fails the whole run with
	# typecheck errors from that one throwaway package before gosec — the
	# only automated security control in this repo — ever gets to run.
	GOOS=linux golangci-lint run

.PHONY: build
build:
	$(GO) build -ldflags "$(LDFLAGS)" -o bin/postern ./cmd/postern
