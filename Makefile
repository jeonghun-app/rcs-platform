# The host needs only Docker: Go runs in a pinned toolchain container, which also
# makes a CI runner build exactly what a laptop builds.

VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
REVISION ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
IMAGE    ?= rcs-platform
# The Go version is pinned in deploy/toolchain.Dockerfile (pinned Go image + gcc) (deploy/toolchain.Dockerfile); rebuilt when the file changes.
GOIMAGE  ?= rcs-platform-go:$(shell cat deploy/toolchain.Dockerfile 2>/dev/null | sha256sum | cut -c1-12)
DOCKER   ?= docker
ACTIONLINT_IMAGE ?= rhysd/actionlint:1.7.12@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667

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
