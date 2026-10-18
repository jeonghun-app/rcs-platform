# ADR 0006 — acs stays in its own repository and is deployed from a pinned release

**Status:** accepted

## Context

The Auto Configuration Server already exists as
[jeonghun-app/auto-configuration-server](https://github.com/jeonghun-app/auto-configuration-server)
with its own release process, CI and conformance registry. It provisions the
P-CSCF address, IMS identities, the conference factory URI and the file transfer
URLs, and must hand out credentials the platform's `hss` accepts.

## Decision

- `acs` is not copied into this repository. `infra/platform.yaml` runs it as an
  ECS service in the platform VPC from an image built from a pinned `acs` release
  tag (`ACS_VERSION` in `scripts/deploy.sh`).
- The platform sets the `acs` environment so that the provisioned values point at
  the deployed `pcscf`, `ft-server` and `rcs-as` URIs.
- Credential hand-off: `acs` asks `hss` to issue the subscriber's IMS credentials
  through the HSS provisioning API. The change lives in the `acs` repository and
  ships as an `acs` release; the platform then raises the pinned version.

## Rationale

Keeping one owner per component avoids two diverging copies of the ACS and keeps
its conformance and release history intact.

## Consequences

- Platform end-to-end tests run against a released `acs` image, so an `acs` change
  is usable here only after an `acs` release.
- The `acs` repository gains a documented, optional dependency on an HSS
  provisioning API.
