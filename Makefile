SHELL := /bin/sh

# Runnable examples are checked separately and are intentionally excluded from
# the library coverage profile.
LIB_PACKAGES := . ./internal/... ./jwttest
COVERAGE_FILE := coverage.out

.PHONY: all fmt gofmt-check lint lint-fix test test-race coverage vet check clean

all: check

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './.git/*')
	golangci-lint run --enable-only=wsl_v5 --fix ./...

gofmt-check:
	@test -z "$$(find . -name '*.go' -not -path './.git/*' -print0 | xargs -0 gofmt -l)" || { echo "gofmt required; run 'make fmt'"; exit 1; }

lint:
	golangci-lint run ./...

lint-fix:
	golangci-lint run --fix ./...

test:
	go test ./...

test-race:
	go test -race ./...

coverage:
	go test -race -covermode=atomic -coverprofile=$(COVERAGE_FILE) $(LIB_PACKAGES)
	go tool cover -func=$(COVERAGE_FILE)

vet:
	go vet ./...

check: gofmt-check lint test vet

clean:
	rm -f $(COVERAGE_FILE)
