# ADR 0007 — Plain transport inside the VPC, authenticated per caller

**Status:** accepted

## Context

Services talk to each other inside the platform VPC: SIP between the CSCFs and
`rcs-as`, Diameter Cx between the CSCFs and `hss`, MSRP between `msrp-relay` and
`rcs-as`, and internal HTTP APIs (HSS provisioning, relay control). Cloud Map
names (`hss.<namespace>`) cannot get a public certificate, and running a private
CA (ACM Private CA costs a monthly fee per CA) adds rotation and trust
distribution to every service. Public traffic is already protected: clients reach
the platform only through the NLB and ALB with TLS (ADR 0003).

## Decision

- Traffic between platform services inside the VPC uses plain TCP (SIP, Diameter,
  MSRP, HTTP) in the first releases.
- Every internal HTTP API requires a **bearer token per caller**: an operator
  admin token and one service token per calling service (for example
  `ft-server` → `hss`), each from Secrets Manager, compared in constant time. A
  service refuses to start in `staging`/`prod` without its tokens.
- A service accepts plain `http://` for an internal API only when the host is a
  private name or address (a Cloud Map name or an RFC 1918 / ULA address);
  anything else must be `https://`.
- Diameter peers are accepted only by realm, host pattern and source CIDR
  (`internal/diameter` peer rules); SIP and MSRP listeners facing the core are
  bound to private subnets.
- Security groups allow each internal port only from the services that need it.

## Rationale

The VPC boundary, security groups and per-caller tokens keep internal APIs
unreachable and unusable from outside, without a CA. Diameter over TLS
(RFC 6733 §13) and SIP/TLS between CSCFs are what operators expect between
networks, not inside one deployment.

## Consequences

- A compromised task inside the VPC can read internal traffic, which includes
  credentials in MAA and HA1 in the FT credential API. Mitigations: least-privilege
  security groups, no shell in the image, read-only root file system, and short
  task lifetimes. Recorded in the threat model.
- Interconnecting with another operator's node (an external HSS or I-CSCF) needs
  TLS or IPsec on that link; that is out of scope until requested.
- Moving to mTLS later (ACM Private CA or a service mesh) changes configuration
  only; every client already takes a URL and a token.
