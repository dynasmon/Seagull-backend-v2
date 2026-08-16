SHELL := /bin/bash
GO ?= go
MODULE := github.com/dynasmon/Seagull-v2
DIST ?= dist
PKI ?= .local/pki
COMPOSE := docker compose -f deploy/compose.yaml
COMPOSE_TEST := docker compose -f deploy/compose.yaml -f deploy/compose.test.yaml
COMPONENTS := ingest-gateway control-api
VERSION ?= dev
REVISION ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
TEST_BROKERS ?= 127.0.0.1:19092

.PHONY: help fmt fmt-check vet mod-check lint test test-race test-integration \
        build images vulncheck dev-pki up down logs clean verify

help:
	@echo "fmt                 format the module"
	@echo "fmt-check           fail when the module is not formatted"
	@echo "vet                 run go vet over every build tag"
	@echo "mod-check           verify the dependency graph and checksums"
	@echo "lint                fmt-check and vet"
	@echo "test                run the unit, architecture and end-to-end suites"
	@echo "test-race           run the same suites under the race detector"
	@echo "test-integration    run the backbone suite against a live Redpanda"
	@echo "build               build every component into $(DIST)"
	@echo "images              build the container image of every component"
	@echo "dev-pki             mint development certificates into $(PKI)"
	@echo "up                  start the local stack"
	@echo "down                stop the local stack and drop its volumes"
	@echo "vulncheck           scan reachable dependencies"
	@echo "verify              the full gate: lint, mod-check, tests"

fmt:
	$(GO) fmt ./...

fmt-check:
	@out="$$(gofmt -l cmd internal tests tools)"; \
	if [ -n "$$out" ]; then echo "unformatted files:"; echo "$$out"; exit 1; fi

vet:
	$(GO) vet ./...
	$(GO) vet -tags integration ./tests/...

mod-check:
	$(GO) mod verify
	@tmp="$$(mktemp -d)"; cp go.mod go.sum "$$tmp/"; status=0; \
	$(GO) mod tidy || status=1; \
	diff -u "$$tmp/go.mod" go.mod || status=1; \
	diff -u "$$tmp/go.sum" go.sum || status=1; \
	cp "$$tmp/go.mod" go.mod; cp "$$tmp/go.sum" go.sum; rm -rf "$$tmp"; exit "$$status"

lint: fmt-check vet

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./internal/... ./tests/...

test-integration:
	$(COMPOSE_TEST) up -d --wait redpanda
	SEAGULL_TEST_BROKERS=$(TEST_BROKERS) $(GO) test -tags integration -count=1 ./tests/integration/...

build:
	@mkdir -p $(DIST)
	@for component in $(COMPONENTS); do \
	  echo "building $$component"; \
	  CGO_ENABLED=0 $(GO) build -trimpath \
	    -ldflags "-s -w -X $(MODULE)/internal/platform/buildinfo.version=$(VERSION) -X $(MODULE)/internal/platform/buildinfo.revision=$(REVISION)" \
	    -o $(DIST)/$$component ./cmd/$$component || exit 1; \
	done

images:
	@for component in $(COMPONENTS); do \
	  docker build -f deploy/Dockerfile \
	    --build-arg COMPONENT=$$component \
	    --build-arg VERSION=$(VERSION) \
	    --build-arg REVISION=$(REVISION) \
	    -t seagull-v2/$$component:$(VERSION) . || exit 1; \
	done

vulncheck:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...

dev-pki:
	$(GO) run ./tools/devpki -directory $(PKI)

up: dev-pki
	SEAGULL_RUNTIME_USER="$$(id -u):$$(id -g)" $(COMPOSE) up -d --build

down:
	$(COMPOSE) down --volumes --remove-orphans

logs:
	$(COMPOSE) logs -f

clean:
	rm -rf $(DIST)

verify: lint mod-check test test-race
