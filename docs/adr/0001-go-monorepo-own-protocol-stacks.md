# ADR 0001 — Go monorepo with every protocol stack written here

**Status:** accepted

## Context

The platform needs SIP, SDP, Diameter, MSRP, CPIM, IMDN, Milenage and HTTP file
transfer. Mature open-source cores exist (Kamailio and OpenSIPS for the CSCFs,
freeDiameter, Open5GS/PyHSS for the HSS). The product owner chose to implement the
IMS core and the RCS services directly so that behaviour, licensing and the
deployment model are fully under the project's control.

## Decision

- One repository, one Go module (`github.com/jeonghun-app/rcs-platform`), one
  binary per service under `cmd/`.
- SIP, SDP, Diameter, MSRP, CPIM, IMDN and Milenage are implemented in `internal/`.
- Runtime dependencies are the Go standard library and `aws-sdk-go-v2`. Any other
  runtime dependency needs an ADR.
- Go is pinned to a toolchain image (`golang:1.26.10-alpine3.23`, plus gcc for the race detector in `deploy/toolchain.Dockerfile`)
  and runs in a container, so the host needs only Docker.

## Rationale

Go handles many long-lived TCP connections (SIP flows, MSRP sessions) cheaply,
produces static binaries for a distroless image, and the standard library already
covers TLS, HTTP, crypto (AES for Milenage, MD5/SHA-256 for Digest) and XML.

## Consequences

- The protocol stacks are the riskiest code in the project; every parser is fuzzed
  and every state machine has table-driven tests against the timer values in
  RFC 3261 §17 and RFC 6733.
- Interoperability with commercial clients must be shown, not assumed: the
  conformance registry records what was tested against what.
- No IPsec sec-agree (TS 33.203 §7) in the first releases: clients reach `pcscf`
  over TLS, which is what RCS clients without an IMS APN use. Recorded as a
  limitation.
