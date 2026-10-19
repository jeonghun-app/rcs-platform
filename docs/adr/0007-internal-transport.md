# ADR 0007 — Plain transport inside the VPC, authenticated and scoped per caller

**Status:** accepted

## Context

Services talk to each other inside the platform VPC: SIP between the CSCFs and
`rcs-as`, Diameter Cx between the CSCFs and `hss`, MSRP between `msrp-relay` and
`rcs-as`, and internal HTTP APIs (HSS provisioning, relay control). Cloud Map
names (`hss.<namespace>`) cannot get a public certificate, and a private CA (ACM
Private CA: $400 per CA per month in general-purpose mode, $50 in short-lived
certificate mode) adds rotation and trust distribution to every service.

Client traffic is protected only up to the load balancers: TLS ends at the NLB
and ALB (ADR 0003), so every hop after them is inside the VPC.

Inside a VPC, AWS does not deliver one ENI's traffic to another, so the practical
threat is not passive eavesdropping but **active, unauthenticated calls**: any
task the security groups let through can claim a Diameter Origin-Host, put any
`P-Asserted-Identity` on a SIP request, or call an internal API. No in-transit
encryption is assumed for task-to-task traffic: Nitro encryption applies only to
some instance types and not through load balancers, and Fargate does not let us
choose instance types. Traffic between AZs is encrypted at the physical layer;
traffic within an AZ is not assumed to be.

## Decision

1. Traffic between platform services inside the VPC uses plain TCP (SIP,
   Diameter, MSRP, HTTP) in the first releases. The rule in ADR 0003 that refuses
   unencrypted listeners in `staging`/`prod` applies to **public** listeners.
2. **Security groups are the primary control.** Each service has its own security
   group; ingress rules reference source security groups only (no CIDRs), egress
   is restricted, and the NLB is created with a security group so targets can
   reference it. The port matrix:

   | Destination (port) | Allowed sources |
   |---|---|
   | `hss` Diameter | `icscf`, `scscf` (and `rcs-as` once it uses Sh) |
   | `hss` HTTP API | `ft-server`, `acs`, the operator path |
   | `icscf`, `scscf` SIP | `pcscf`, `rcs-as`, each other |
   | `pcscf` core SIP (separate listener) | `scscf` |
   | `rcs-as` SIP | `scscf`, `icscf` (direct routing to the conference factory and other PSIs, TS 24.229 §5.3.2.1) |
   | `rcs-as` MSRP | `msrp-relay` |
   | `msrp-relay` control HTTP | `pcscf` |
   | `pcscf` client SIP, `msrp-relay` MSRP (public) | NLB |
   | `acs`, `ft-server` HTTP (public) | ALB |
   | every admin port (health) | its load balancer only, where one is attached |

   `acs` and `ft-server` reach no SIP or Diameter port. `pcscf` runs **two SIP
   listeners**: the client listener behind the NLB (PROXY protocol, untrusted)
   and a core listener on another port that only the core's security groups
   reach; the core-facing `Path` and `Record-Route` name the core listener. The
   security group, not application logic, is the trust-domain boundary. The infrastructure
   templates are checked against this matrix by a policy test (Phase 7).
3. **Every internal HTTP API requires a bearer token per caller, scoped to that
   caller's endpoints.** The scope table lives in `docs/api/` next to each API;
   a token used outside its scope gets 403. For the HSS API:

   | Caller | Allowed |
   |---|---|
   | operator (admin token) | all provisioning, including writing keys; keys are never returned |
   | `acs` | issue and read the IMS and FT credentials of subscriptions marked `acs_managed`; every issue is audit-logged and rate-limited per token |
   | `ft-server` | read the FT credential (HA1 for the FT realm and the owning IMPU) |

4. Tokens are random, at least 256 bits, distinct per caller and from the admin
   token; services refuse to start in `staging`/`prod` otherwise. Receivers hash
   presented and accepted tokens with SHA-256 and compare all accepted digests in
   constant time. Each receiver accepts **two tokens per caller** (current and
   next) so tokens rotate without downtime: add next on the receiver, deploy;
   switch the caller, deploy; remove the old one, deploy (runbook). Tokens come
   from Secrets Manager through the task **execution** role, which can read only
   that service's secret ARNs; task roles have no `secretsmanager:GetSecretValue`.
5. A service accepts plain `http://` for an internal API only when the host is
   inside the configured Cloud Map namespace (label-exact suffix match), an
   RFC 1918 address or an IPv6 unique local address (ULA, `fc00::/7`, RFC 4193;
   assigned ULAs are in `fd00::/8`); link-local (including the task metadata
   address), loopback and public hosts are refused in `staging`/`prod`.
   Internal clients never follow redirects. IPv6 GUAs are refused (fails safe on
   dual-stack VPCs). (Amended in #64: ULAs were always accepted by the code and
   are now named here.) In `staging`/`prod` internal HTTP clients, `https://`
   ones included, also check the address a name resolves to when they connect
   (`runtime.InternalDialer`) and connect only to RFC 1918 or ULA addresses, so
   a record in the namespace cannot send a token elsewhere. The `-healthcheck`
   probe of a task's own admin port on loopback is not an internal API client
   and carries no token; it is exempt. (Amended in #87.)
   Operators reach the HSS API only from inside the VPC (a task or an internal
   ALB with TLS); it is never on the public ALB.
6. Diameter: in `staging`/`prod` every accept rule must restrict `Networks`, and
   a rule without one refuses to start. Because all services share the private
   subnets, the source CIDR only bounds traffic to the VPC; security groups are
   what keep non-CSCF tasks off the Cx port. Restricting which command codes a
   peer may use (for example UAR/LIR only for `icscf`) is a follow-up.
7. SIP trust domain (RFC 3325): only `pcscf` accepts requests from clients, and it
   removes the headers only the network may set (TS 24.229 §5.2):
   `P-Asserted-Identity`, `P-Served-User`, `P-Asserted-Service`,
   `P-Charging-Vector`, `P-Charging-Function-Addresses`, `P-Visited-Network-ID`,
   `P-Associated-URI`, `P-Called-Party-ID`. The core SIP ports trust
   `P-Asserted-Identity` because security groups admit only platform services
   there.
8. The FT digest realm must differ from the IMS digest realm (startup refuses
   equal realms), so an FT credential can never authenticate a SIP registration.
9. Task definitions use `readonlyRootFilesystem: true`, `enableExecuteCommand:
   false`, no `privileged`, and drop all Linux capabilities; the image has no
   shell (distroless, non-root). VPC Flow Logs and GuardDuty Runtime Monitoring
   for Fargate are enabled in `prod`.

## Rationale

The VPC boundary, a security group per service with a source-referenced port
matrix, and scoped per-caller tokens keep internal interfaces unreachable from
outside and limit what a compromised internet-facing service can do, without a
CA. Diameter over TLS (RFC 6733 §13) and SIP/TLS between CSCFs are what operators
expect between networks, not inside one deployment.

## Consequences

- What crosses the VPC in clear, and who can see it:

  | Data | Hop | Visible to |
  |---|---|---|
  | Ki/OPc, digest credentials, admin token | operator → `hss` API | the two endpoints |
  | IMS and FT credentials, service tokens | `acs`/`ft-server` ↔ `hss` | the two endpoints |
  | AKA vectors (RAND, AUTN, XRES, CK, IK), HA1 | `hss` → `scscf` (MAA) | `hss`, `scscf` |
  | relay control token, MSRP binding ids | `pcscf` → `msrp-relay` | the two endpoints |
  | IMS credentials and OTP in configuration responses | ALB → `acs` | `acs` |
  | SIP signalling incl. IMPI/IMPU, MSISDN, MESSAGE bodies | NLB → `pcscf` → core | every SIP service on the path |
  | MSRP message content | NLB → `msrp-relay` → `rcs-as` | relay and `rcs-as` |
  | file content | ALB → `ft-server` → S3 (TLS to S3) | `ft-server` |

- A compromised task sees all traffic it is a party to and can make any call its
  security group and token scope allow; it cannot read other tasks' traffic. The
  reach of each internet-facing service is in `docs/threat-model.md`.
- Interconnecting with another operator's node (an external HSS or I-CSCF) needs
  TLS or IPsec on that link; out of scope until requested.
- Moving to mTLS later is a configuration change for HTTP (CA bundle and client
  certificate settings), but a code change for Diameter (TLS and certificate
  identity bound to Origin-Host), SIP (`sips`/`transport=tls` in Path and
  Record-Route) and MSRP (`msrps` paths). ACM Private CA short-lived mode is the
  cost-effective option for it.
- `acs` (another repository) must implement the token and http/https rules as a
  caller; tracked there.
