# The host needs only Docker: Go runs in a pinned toolchain container, which also
# makes a CI runner build exactly what a laptop builds.

VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
REVISION ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
IMAGE    ?= rcs-platform
# The Go version is pinned in deploy/toolchain.Dockerfile (pinned Go image + gcc) (deploy/toolchain.Dockerfile); rebuilt when the file changes.
GOIMAGE  ?= rcs-platform-go:$(shell cat deploy/toolchain.Dockerfile 2>/dev/null | sha256sum | cut -c1-12)
DOCKER   ?= docker
ACTIONLINT_IMAGE ?= rhysd/actionlint:1.7.12@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667
# Stand-ins for S3 and DynamoDB in `make test-integration`, pinned like the
# toolchain so a run tests the same server code every time.
S3MOCK_IMAGE   ?= adobe/s3mock:5.2.3@sha256:ab01a6946750f451ca215a47e91030695b260e4003b8a5a6201d25029b8fca92
DDBLOCAL_IMAGE ?= amazon/dynamodb-local:3.3.2@sha256:6ada631ec7aa5fc83446855eb17233e3dad184fec47477e8140c6c569cfe0c86
# The acs release the local stack runs (ADR 0006), from GHCR. Raise the
# version and its digest together: with both given, Docker pulls by digest.
ACS_VERSION ?= 1.4.0
ACS_DIGEST  ?= sha256:00956e9fe4d5865cf5e39292122ec1df78e34993f5c9d07928fff836af5f33b2
ACS_IMAGE   ?= ghcr.io/jeonghun-app/auto-configuration-server:$(ACS_VERSION)@$(ACS_DIGEST)

# VERSION and REVISION reach recipes only as environment variables and are always
# quoted there, so a tag such as v1.0.0-`cmd` cannot run anything.
export VERSION REVISION
CHECK_VERSION = case "$$VERSION" in ''|[.-]*|*[!0-9A-Za-z._+-]*) \
	  echo "invalid VERSION: must be [0-9A-Za-z._+-] and not start with . or -" >&2; \
	  exit 1;; esac

LDFLAGS := -s -w -X github.com/jeonghun-app/rcs-platform/internal/buildinfo.Version=$$VERSION

GOCACHE_VOL := rcs-platform-gocache
GOMOD_VOL   := rcs-platform-gomodcache

RUNGO = $(DOCKER) run --rm \
	-u $(shell id -u):$(shell id -g) \
	-v $(CURDIR):/src -w /src \
	-v $(GOCACHE_VOL):/gocache \
	-v $(GOMOD_VOL):/gomodcache \
	-e GOCACHE=/gocache -e GOMODCACHE=/gomodcache -e HOME=/tmp \
	-e GOFLAGS=-buildvcs=false -e CI

# Seconds each fuzz target runs in `make fuzz`; CI uses the default.
FUZZTIME ?= 10s

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: toolchain
toolchain:
	@$(DOCKER) image inspect $(GOIMAGE) >/dev/null 2>&1 || \
	  $(DOCKER) build -q -f deploy/toolchain.Dockerfile -t $(GOIMAGE) deploy >/dev/null

# The cache volumes are created root-owned; hand them to the calling user once so
# the toolchain container can run unprivileged. Every target runs this, and a
# chown -R over a full cache takes minutes when several makes run at once (#360),
# so it runs only while a volume root or one of its top-level entries belongs to
# someone else. Anything deeper that a root container wrote is not looked for;
# `make clean` drops the volumes.
.PHONY: volumes
volumes: toolchain
	@$(DOCKER) run --rm -v $(GOCACHE_VOL):/gocache -v $(GOMOD_VOL):/gomodcache \
	  $(GOIMAGE) sh -c 'u=$(shell id -u); g=$(shell id -g); \
	    for d in /gocache /gomodcache; do \
	      if [ "$$(stat -c %u:%g "$$d")" != "$$u:$$g" ] || \
	        [ -n "$$(find "$$d" -maxdepth 1 \( ! -user "$$u" -o ! -group "$$g" \) | head -n 1)" ]; then \
	        echo "volumes: handing $$d to $$u:$$g"; chown -R "$$u:$$g" "$$d"; \
	      fi; \
	    done'

.PHONY: tidy
tidy: volumes ## Resolve dependencies and write go.sum
	$(RUNGO) $(GOIMAGE) go mod tidy

.PHONY: fmt
fmt: volumes ## Format Go sources in place
	$(RUNGO) $(GOIMAGE) gofmt -w .

.PHONY: fmt-check
fmt-check: volumes ## Fail if any Go source is not gofmt-formatted
	$(RUNGO) $(GOIMAGE) sh -c 'files=$$(gofmt -l .); test -z "$$files" || { printf "%s\n" "$$files"; exit 1; }'

.PHONY: vet
vet: volumes ## go vet
	$(RUNGO) $(GOIMAGE) go vet ./...

.PHONY: test
test: volumes ## Unit tests with coverage summary
	$(RUNGO) $(GOIMAGE) go test ./... -count=1 -cover

.PHONY: race
race: volumes ## Unit tests under the race detector
	$(RUNGO) -e CGO_ENABLED=1 $(GOIMAGE) go test -race ./... -count=1

# cfn-lint and the platform policy checks (scripts/check_infra.py) in a pinned
# tools image, built once per change of its Dockerfile or requirements, like
# the Go toolchain.
INFRAIMAGE ?= rcs-platform-infra:$(shell cat deploy/infra-tools.Dockerfile deploy/infra-tools.requirements.txt 2>/dev/null | sha256sum | cut -c1-12)

.PHONY: infra-tools
infra-tools:
	@$(DOCKER) image inspect $(INFRAIMAGE) >/dev/null 2>&1 || \
	  $(DOCKER) build -q -f deploy/infra-tools.Dockerfile -t $(INFRAIMAGE) deploy >/dev/null

.PHONY: infra-lint
infra-lint: infra-tools ## cfn-lint and the policy checks on infra/*.yaml (no AWS access)
	$(DOCKER) run --rm -u $(shell id -u):$(shell id -g) -v $(CURDIR):/src:ro -w /src \
	  -e HOME=/tmp -e PYTHONDONTWRITEBYTECODE=1 $(INFRAIMAGE) sh -c '\
	    set -e; cfn-lint infra/ecr.yaml infra/platform.yaml; \
	    python3 -m unittest discover -s scripts -p "test_check_infra.py"; \
	    python3 scripts/check_infra.py infra/platform.yaml'

# The storage backends against an S3-compatible container and DynamoDB Local
# on a private network: ft-server's (internal/ftserver/awsstore), msrp-relay's
# (internal/msrprelay/dynamostore), the HSS's (internal/hss/awsstore, and
# two HSS tasks issuing AKA vectors at once), rcs-as's
# (internal/rcsas/awsstore, and two rcs-as tasks sharing one queue), and the
# compose stack's table bootstrap (tools/stack-init). Names carry the shell's
# PID so parallel runs on one host do not meet; the trap removes everything
# however the run ends. Not part of `check`: it pulls two images and starts
# two JVMs.
.PHONY: test-integration
test-integration: volumes ## Storage backends against S3 and DynamoDB containers
	@set -eu; id=rcs-platform-it-$$$$; \
	trap '$(DOCKER) rm -f "$$id-s3" "$$id-ddb" >/dev/null 2>&1 || true; $(DOCKER) network rm "$$id" >/dev/null 2>&1 || true' EXIT; \
	$(DOCKER) network create "$$id" >/dev/null; \
	$(DOCKER) run -d --rm --name "$$id-s3" --network "$$id" $(S3MOCK_IMAGE) >/dev/null; \
	$(DOCKER) run -d --rm --name "$$id-ddb" --network "$$id" $(DDBLOCAL_IMAGE) >/dev/null; \
	$(RUNGO) --network "$$id" \
	  -e FT_IT_S3_ENDPOINT="http://$$id-s3:9090" -e FT_IT_DYNAMODB_ENDPOINT="http://$$id-ddb:8000" \
	  -e RELAY_IT_DYNAMODB_ENDPOINT="http://$$id-ddb:8000" -e HSS_IT_DYNAMODB_ENDPOINT="http://$$id-ddb:8000" \
	  -e SCSCF_IT_DYNAMODB_ENDPOINT="http://$$id-ddb:8000" -e RCSAS_IT_DYNAMODB_ENDPOINT="http://$$id-ddb:8000" \
	  -e AWS_REGION=us-east-1 -e AWS_ACCESS_KEY_ID=local -e AWS_SECRET_ACCESS_KEY=local \
	  $(GOIMAGE) sh -c 'for url in "$$FT_IT_S3_ENDPOINT" "$$FT_IT_DYNAMODB_ENDPOINT"; do \
	      n=0; until wget -S -O /dev/null "$$url/" 2>&1 | grep -q "HTTP/"; do \
	        n=$$((n + 1)); [ "$$n" -lt 120 ] || { echo "$$url did not start" >&2; exit 1; }; sleep 1; done; \
	    done; \
	    go test -tags integration -count=1 -v -run Integration ./internal/ftserver/... ./internal/msrprelay/... ./internal/hss/... ./internal/rcsas/... ./internal/scscf/... ./tools/stack-init/'

# rcs-sim against the built ft-server and msrp-relay binaries
# (tools/rcs-sim/e2e). Not part of `check`: it builds and starts three
# binaries and runs every scenario, a few seconds of real traffic.
.PHONY: e2e
e2e: volumes ## End-to-end: rcs-sim against ft-server and msrp-relay
	$(RUNGO) -e CGO_ENABLED=0 $(GOIMAGE) go test -tags e2e -count=1 -v ./tools/rcs-sim/e2e/

# The local compose stack (deploy/docker-compose.yml, docs/local-stack.md):
# the platform image from `make image`, DynamoDB Local, S3Mock and the pinned
# acs, with secrets in deploy/compose.env (scripts/compose-env.sh writes it
# once). The images reach compose only through these variables, so the pins
# above stay the only ones.
#
# COMPOSE_PROJECT names the stack: its containers, its network
# ($(COMPOSE_PROJECT)_default) and its stack-init image. A second stack on
# the same host, from another worktree say, needs a name and host ports of
# its own (docs/local-stack.md).
COMPOSE_PROJECT ?= rcs-local
COMPOSE_ENV     ?= deploy/compose.env
COMPOSE = RCS_IMAGE="$(IMAGE):$$(printf %s "$$VERSION" | tr + _)" \
	DDBLOCAL_IMAGE="$(DDBLOCAL_IMAGE)" S3MOCK_IMAGE="$(S3MOCK_IMAGE)" ACS_IMAGE="$(ACS_IMAGE)" \
	STACK_INIT_IMAGE="$(COMPOSE_PROJECT)-stack-init" RCS_BRIDGE_IMAGE="$(COMPOSE_PROJECT)-rcs-bridge" \
	$(DOCKER) compose -p $(COMPOSE_PROJECT) -f deploy/docker-compose.yml --env-file $(COMPOSE_ENV)
# Passed to `docker compose logs`, e.g. make logs LOGS="-f hss".
LOGS ?= --tail=200

.PHONY: compose-env
compose-env:
	@scripts/compose-env.sh $(COMPOSE_ENV)

.PHONY: up
up: image compose-env ## Start the local stack and wait until every service is healthy
	$(COMPOSE) up -d --build --wait --wait-timeout 300
	$(COMPOSE) run --rm stack-seed

# rcs-bridge (docs/rcs-bridge.md) on the stack make up starts, in the
# compose profile bridge: built from deploy/rcs-bridge.Dockerfile, published
# on 127.0.0.1:RCS_BRIDGE_HOST_PORT (8720), with the token RCS_BRIDGE_TOKEN
# of deploy/compose.env.
.PHONY: bridge-up
bridge-up: up ## Start the local stack and rcs-bridge, and wait until it is healthy
	$(COMPOSE) --profile bridge up -d --build --wait --wait-timeout 120 rcs-bridge

# The rcs-bridge test of make e2e-compose run against the compose service
# make bridge-up started (RCS_BRIDGE_E2E_URL), so that its image, its
# settings and its health check are checked too, not only the bridge the
# test builds itself.
.PHONY: e2e-bridge
e2e-bridge: volumes ## End-to-end: the rcs-bridge test against the compose service
	@$(DOCKER) network inspect $(COMPOSE_PROJECT)_default >/dev/null 2>&1 && [ -f $(COMPOSE_ENV) ] || \
	  { echo "no local stack $(COMPOSE_PROJECT) is running: run make bridge-up first" >&2; exit 1; }
	$(RUNGO) --network $(COMPOSE_PROJECT)_default --env-file $(COMPOSE_ENV) -e CGO_ENABLED=0 \
	  -e RCS_BRIDGE_E2E_URL=http://rcs-bridge:8720 \
	  $(GOIMAGE) go test -tags e2ecompose -count=1 -v -run '^TestE2EBridgeOnTheComposeStack$$' ./tools/rcs-sim/e2e/

.PHONY: down
down: compose-env ## Stop the local stack and remove its containers and data
	$(COMPOSE) --profile seed --profile bridge down -v --remove-orphans

.PHONY: logs
logs: compose-env ## Logs of the local stack (LOGS="-f hss" to follow one service)
	$(COMPOSE) --profile bridge logs $(LOGS)

# rcs-sim and acs checks against the stack `make up` started
# (tools/rcs-sim/e2e, build tag e2ecompose), from the toolchain container on
# the stack's network, so it reaches every service by its compose name.
.PHONY: e2e-compose
e2e-compose: volumes ## End-to-end: rcs-sim against the running local stack
	@$(DOCKER) network inspect $(COMPOSE_PROJECT)_default >/dev/null 2>&1 && [ -f $(COMPOSE_ENV) ] || \
	  { echo "no local stack $(COMPOSE_PROJECT) is running: run make up first" >&2; exit 1; }
	$(RUNGO) --network $(COMPOSE_PROJECT)_default --env-file $(COMPOSE_ENV) -e CGO_ENABLED=0 \
	  $(GOIMAGE) go test -tags e2ecompose -count=1 -v ./tools/rcs-sim/e2e/

# Every Fuzz* function in the module runs for FUZZTIME; see scripts/fuzz.sh.
.PHONY: fuzz
fuzz: volumes ## Run every fuzz target for FUZZTIME each
	$(RUNGO) -e FUZZTIME=$(FUZZTIME) $(GOIMAGE) scripts/fuzz.sh

.PHONY: build
build: volumes ## Compile every service binary into bin/
	@$(CHECK_VERSION)
	$(RUNGO) -e CGO_ENABLED=0 -e VERSION $(GOIMAGE) sh -c 'set -e; mkdir -p bin; \
	  go build ./...; \
	  for d in cmd/*/; do [ -d "$$d" ] || continue; n=$$(basename "$$d"); \
	    go build -trimpath -ldflags "$(LDFLAGS)" -o "bin/$$n" "./$$d"; echo "bin/$$n"; done'

# Docker tags cannot contain "+", which VERSION may (semver build metadata).
.PHONY: image
image: ## Build the service image: every cmd/* binary on distroless, non-root
	@$(CHECK_VERSION)
	$(DOCKER) build -f deploy/Dockerfile \
	  --build-arg VERSION="$$VERSION" --build-arg REVISION="$$REVISION" \
	  -t "$(IMAGE):$$(printf %s "$$VERSION" | tr + _)" .

.PHONY: vuln
vuln: volumes ## Verify modules and scan reachable vulnerabilities
	$(RUNGO) $(GOIMAGE) go mod verify
	$(RUNGO) $(GOIMAGE) go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...

.PHONY: lint-actions
lint-actions: ## Lint GitHub Actions workflows
	$(DOCKER) run --rm -v $(CURDIR):/repo -w /repo $(ACTIONLINT_IMAGE) -color

.PHONY: docs
docs: ## Check relative links and anchors in Markdown
	python3 scripts/check-links.py

.PHONY: privacy
privacy: ## Refuse long numeric identifiers that are not on the allow-list
	scripts/check_identifiers.sh

.PHONY: printguard
printguard: volumes ## Refuse print calls that can show a SIP message's content (#599)
	$(RUNGO) $(GOIMAGE) go run ./tools/printguard

.PHONY: check
check: fmt-check vet test race build printguard docs privacy ## Everything the CI test job runs

.PHONY: clean
clean:
	rm -rf bin
	-$(DOCKER) volume rm $(GOCACHE_VOL) $(GOMOD_VOL)
