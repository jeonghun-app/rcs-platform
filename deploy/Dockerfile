# The one image every service ships in (docs/architecture.md §3): each cmd/*
# binary is in /usr/local/bin and the ECS task definition chooses the command.
#
# Build with `make image`, which passes VERSION and REVISION. Base images are
# pinned by digest so a rebuild of the same commit uses the same bytes; update a
# digest deliberately, in its own pull request.

# The toolchain matches deploy/toolchain.Dockerfile and the go directive in
# go.mod; GOTOOLCHAIN=local makes a mismatch fail instead of downloading a
# different Go at build time.
FROM golang:1.26.9-alpine3.23@sha256:6750308561953d451210ed1a8086d36c8c8bdcbf672d38d9d0d424b8a7a0216c AS build
ENV CGO_ENABLED=0 GOFLAGS=-buildvcs=false GOTOOLCHAIN=local
WORKDIR /src

# Modules first, so a source-only change reuses the download layer. go.sum is
# optional while the module has no dependencies.
COPY go.mod go.su[m] ./
RUN go mod download

COPY . .
ARG VERSION=dev
# VERSION goes into -ldflags as one word; the same rule as the Makefile keeps a
# stray space or quote from becoming another linker flag.
RUN case "$VERSION" in ''|[.-]*|*[!0-9A-Za-z._+-]*) \
      echo "invalid VERSION: must be [0-9A-Za-z._+-] and not start with . or -" >&2; exit 1;; \
    esac; \
    set -e; mkdir -p /out; n=0; \
    for d in cmd/*/; do \
      [ -d "$d" ] || continue; \
      go build -trimpath \
        -ldflags "-s -w -X github.com/jeonghun-app/rcs-platform/internal/buildinfo.Version=$VERSION" \
        -o "/out/$(basename "$d")" "./$d"; \
      n=$((n + 1)); \
    done; \
    [ "$n" -gt 0 ] || { echo "no cmd/* binary to build" >&2; exit 1; }; \
    ls -l /out

# distroless static: no shell, no package manager, CA certificates and tzdata
# only, which is all a static Go binary needs. The nonroot variant runs as
# uid/gid 65532.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="rcs-platform" \
      org.opencontainers.image.source="https://github.com/jeonghun-app/rcs-platform" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"
COPY --from=build /out/ /usr/local/bin/
# Numeric, so a platform can tell the user is not root without reading the
# image's /etc/passwd.
USER 65532:65532
CMD ["rcs-version"]
