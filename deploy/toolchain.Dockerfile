# Build toolchain for `make`: the pinned Go image plus a C compiler, which the race
# detector needs. Building it once lets every target run as the calling user and
# work offline afterwards.
FROM golang:1.26.10-alpine3.23
RUN apk add --no-cache gcc musl-dev
