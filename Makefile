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
	-e GOFLAGS=-buildvcs=false

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
# the toolchain container can run unprivileged.
.PHONY: volumes
volumes: toolchain
	@$(DOCKER) run --rm -v $(GOCACHE_VOL):/gocache -v $(GOMOD_VOL):/gomodcache \
	  $(GOIMAGE) chown -R $(shell id -u):$(shell id -g) /gocache /gomodcache

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

# The storage backends against an S3-compatible container and DynamoDB Local
# on a private network: ft-server's (internal/ftserver/awsstore), msrp-relay's
# (internal/msrprelay/dynamostore) and the HSS's (internal/hss/awsstore, and
# two HSS tasks issuing AKA vectors at once). Names carry the shell's PID so
# parallel runs on one host do not meet; the trap removes everything however
# the run ends. Not part of `check`: it pulls two images and starts two JVMs.
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
	  -e AWS_REGION=us-east-1 -e AWS_ACCESS_KEY_ID=local -e AWS_SECRET_ACCESS_KEY=local \
	  $(GOIMAGE) sh -c 'for url in "$$FT_IT_S3_ENDPOINT" "$$FT_IT_DYNAMODB_ENDPOINT"; do \
	      n=0; until wget -S -O /dev/null "$$url/" 2>&1 | grep -q "HTTP/"; do \
	        n=$$((n + 1)); [ "$$n" -lt 120 ] || { echo "$$url did not start" >&2; exit 1; }; sleep 1; done; \
	    done; \
	    go test -tags integration -count=1 -v -run Integration ./internal/ftserver/... ./internal/msrprelay/... ./internal/hss/...'

# rcs-sim against the built ft-server and msrp-relay binaries
# (tools/rcs-sim/e2e). Not part of `check`: it builds and starts three
# binaries and runs every scenario, a few seconds of real traffic.
.PHONY: e2e
e2e: volumes ## End-to-end: rcs-sim against ft-server and msrp-relay
	$(RUNGO) -e CGO_ENABLED=0 $(GOIMAGE) go test -tags e2e -count=1 -v ./tools/rcs-sim/e2e/

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

.PHONY: check
check: fmt-check vet test race build docs privacy ## Everything the CI test job runs

.PHONY: clean
clean:
	rm -rf bin
	-$(DOCKER) volume rm $(GOCACHE_VOL) $(GOMOD_VOL)
