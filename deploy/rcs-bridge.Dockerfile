# rcs-bridge for the local compose stack (docs/rcs-bridge.md): the HTTP and
# WebSocket bridge an application sends and receives standalone messages
# through. A development tool like stack-init, so not part of the service
# image, which ships what runs in AWS only. The base images are the service
# image's (deploy/Dockerfile), pinned by the same digests; update all three
# Dockerfiles together.
FROM golang:1.26.10-alpine3.23@sha256:a07f231c19b03e6106cf442f02a5bcf262147e744d15b7b5e4b6d81d420c70a0 AS build
ENV CGO_ENABLED=0 GOFLAGS=-buildvcs=false GOTOOLCHAIN=local
WORKDIR /src
COPY go.mod go.su[m] ./
RUN go mod download
COPY . .
ARG VERSION=dev
# The same rule as the Makefile's and deploy/Dockerfile's, so that VERSION
# stays one word of -ldflags.
RUN case "$VERSION" in ''|[.-]*|*[!0-9A-Za-z._+-]*) \
      echo "invalid VERSION: must be [0-9A-Za-z._+-] and not start with . or -" >&2; exit 1;; \
    esac; \
    go build -trimpath \
      -ldflags "-s -w -X github.com/jeonghun-app/rcs-platform/internal/buildinfo.Version=$VERSION" \
      -o /out/rcs-bridge ./tools/rcs-sim/cmd/rcs-bridge

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/rcs-bridge /usr/local/bin/rcs-bridge
USER 65532:65532
EXPOSE 8720
ENTRYPOINT ["rcs-bridge"]
