# tools/stack-init for the local compose stack (deploy/docker-compose.yml):
# the one-shot that creates the tables and the bucket and seeds the test
# subscriber. It is not part of the service image, which ships what runs in
# AWS only. The base images are the service image's (deploy/Dockerfile),
# pinned by the same digests; update both together.
FROM golang:1.26.10-alpine3.23@sha256:a07f231c19b03e6106cf442f02a5bcf262147e744d15b7b5e4b6d81d420c70a0 AS build
ENV CGO_ENABLED=0 GOFLAGS=-buildvcs=false GOTOOLCHAIN=local
WORKDIR /src
COPY go.mod go.su[m] ./
RUN go mod download
COPY . .
RUN go build -trimpath -ldflags "-s -w" -o /out/stack-init ./tools/stack-init

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/stack-init /usr/local/bin/stack-init
USER 65532:65532
ENTRYPOINT ["stack-init"]
