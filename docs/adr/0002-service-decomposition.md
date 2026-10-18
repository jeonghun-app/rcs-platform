# ADR 0002 — One service per IMS/RCS functional entity

**Status:** accepted

## Context

The request is a microservice platform where IMS and RCS functions deploy and
scale independently.

## Decision

Services follow the 3GPP and GSMA functional entities: `pcscf`, `icscf`, `scscf`,
`hss`, `rcs-as`, `msrp-relay`, `ft-server`, plus `acs` from its own repository.
Services talk to each other only over the standard reference points (SIP, Diameter
Cx/Sh, MSRP) or over a documented internal HTTP API (relay control, HSS
provisioning). No service reads another service's table.

## Rationale

Using the standard interfaces between our own services means each one can be
replaced by, or interworked with, a commercial node: an operator can keep its own
HSS and use only `rcs-as`, or put our `pcscf` in front of another core.

## Consequences

- Seven deployables share one image and one release version.
- Cross-service behaviour is tested end to end in the compose stack with
  `tools/rcs-sim`, not by importing packages across services.
- The internal HTTP APIs are versioned under `/v1/` and documented in
  `docs/api/`.
