SHELL := /bin/bash
GO ?= go
MODULE := github.com/dynasmon/Seagull-backend-v2
DIST ?= dist
PKI ?= .local/pki
COMPOSE := docker compose -f deploy/compose.yaml
COMPOSE_TEST := docker compose -f deploy/compose.yaml -f deploy/compose.test.yaml
COMPONENTS := ingest-gateway control-api query-api analysis-engine event-writer detection-writer alert-writer inventory-projector status-projector assessment-projector advisory-importer advisory-writer store-migrator backbone-migrator control-migrator
VERSION ?= dev
REVISION ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
REPOSITORY ?= dynasmon/Seagull-backend-v2
GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@v1.9.0
GOSEC := github.com/securego/gosec/v2/cmd/gosec@v2.30.0
SCANNER := SEAGULL_RUNTIME_USER="$$(id -u):$$(id -g)" $(COMPOSE_TEST) run --rm --no-deps grype
TEST_BROKERS ?= 127.0.0.1:19092
TEST_EVENT_STORE ?= 127.0.0.1:19000
TEST_ALERT_STORE ?= 127.0.0.1:15432

.PHONY: help fmt fmt-check vet mod-check lint test test-race test-integration \
        test-load test-alerts bench build images scan-images scan-infrastructure \
        vulncheck gosec verify-tag check-protection dev-pki up down logs clean verify

help:
	@echo "fmt                 format the module"
	@echo "fmt-check           fail when the module is not formatted"
	@echo "vet                 run go vet over every build tag"
	@echo "mod-check           verify the dependency graph and checksums"
	@echo "lint                fmt-check and vet"
	@echo "test                run the unit, architecture and end-to-end suites"
	@echo "test-race           run the same suites under the race detector"
	@echo "test-integration    run the data plane suites against a live Redpanda, ClickHouse and PostgreSQL"
	@echo "test-load           run the ingest load scenarios against a live Redpanda"
	@echo "test-alerts         evaluate the operational alert rules against recorded series"
	@echo "bench               run the hot-path benchmarks"
	@echo "build               build every component into $(DIST)"
	@echo "images              build the container image of every component"
	@echo "scan-images         refuse a built image holding a fixable high or critical vulnerability"
	@echo "scan-infrastructure report what is known of the images this project runs and builds on"
	@echo "dev-pki             mint development certificates into $(PKI)"
	@echo "up                  start the local stack"
	@echo "down                stop the local stack and drop its volumes"
	@echo "vulncheck           refuse a known vulnerability in any package this module links"
	@echo "gosec               refuse what the static security rules find"
	@echo "verify-tag          refuse TAG unless a signer main names signed it"
	@echo "check-protection    compare the rules GitHub enforces on main with the ones declared here"
	@echo "verify              the full gate: lint, mod-check, tests"

fmt:
	$(GO) fmt ./...

fmt-check:
	@out="$$(gofmt -l cmd internal tests tools)"; \
	if [ -n "$$out" ]; then echo "unformatted files:"; echo "$$out"; exit 1; fi

vet:
	$(GO) vet ./...
	$(GO) vet -tags integration ./tests/...
	$(GO) vet -tags load ./tests/...

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
	$(COMPOSE_TEST) up -d --wait redpanda clickhouse postgres
	SEAGULL_TEST_BROKERS=$(TEST_BROKERS) \
	SEAGULL_TEST_EVENT_STORE=$(TEST_EVENT_STORE) \
	SEAGULL_TEST_ALERT_STORE=$(TEST_ALERT_STORE) \
	  $(GO) test -tags integration -count=1 ./tests/integration/...

test-load:
	$(COMPOSE_TEST) up -d --wait redpanda
	SEAGULL_TEST_BROKERS=$(TEST_BROKERS) \
	SEAGULL_TEST_BROKER_STOP="$(COMPOSE_TEST) stop redpanda" \
	SEAGULL_TEST_BROKER_START="$(COMPOSE_TEST) start redpanda" \
	  $(GO) test -tags load -count=1 -timeout 20m -v ./tests/load/...

test-alerts:
	$(COMPOSE_TEST) run --rm --no-deps promtool check rules detection-state.yml agent-roster.yml
	$(COMPOSE_TEST) run --rm --no-deps promtool test rules detection-state.test.yml agent-roster.test.yml

bench:
	$(GO) test -run '^$$' -bench . -benchmem ./internal/...

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

scan-images:
	@mkdir -p $(DIST)/images $(DIST)/grype
	@for component in $(COMPONENTS); do \
	  echo "scanning $$component"; \
	  docker save -o $(DIST)/images/$$component.tar seagull-v2/$$component:$(VERSION) || exit 1; \
	  $(SCANNER) docker-archive:/images/$$component.tar --fail-on high --only-fixed || exit 1; \
	  rm -f $(DIST)/images/$$component.tar; \
	done

scan-infrastructure:
	@mkdir -p $(DIST)/images $(DIST)/grype
	@for image in $$($(COMPOSE_TEST) --profile alerts --profile scan config --images | grep '@sha256:'; \
	  sed -n 's/^FROM \([^ ]*@sha256:[0-9a-f]*\).*/\1/p' deploy/Dockerfile); do \
	  echo "scanning $$image"; \
	  $(SCANNER) registry:$$image --only-fixed || exit 1; \
	done

vulncheck:
	$(GO) run $(GOVULNCHECK) -scan package ./...

gosec:
	$(GO) run $(GOSEC) -quiet -conf .gosec.json -exclude=G115 ./...

verify-tag:
	@test -n "$(TAG)" || { echo "name the tag: make verify-tag TAG=v1.2.3"; exit 1; }
	@mkdir -p $(DIST)
	@git show origin/main:.github/allowed_signers > $(DIST)/allowed_signers
	@git -c gpg.format=ssh -c gpg.ssh.allowedSignersFile=$(DIST)/allowed_signers -c gpg.minTrustLevel=fully \
	  verify-tag "$(TAG)"

check-protection:
	@summary='{rules: (map(.type) | unique), checks: ([.[] | select(.type == "required_status_checks") | .parameters.required_status_checks[].context] | sort)}'; \
	declared="$$(jq -c ".rules | $$summary" .github/rulesets/main.json)"; \
	enforced="$$(gh api repos/$(REPOSITORY)/rules/branches/main | jq -c "$$summary")"; \
	if [ "$$declared" != "$$enforced" ]; then \
	  echo "main is declared as $$declared"; echo "and enforced as   $$enforced"; exit 1; \
	fi; echo "main is enforced as declared"

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
