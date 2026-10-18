# ADR 0003 — ECS Fargate behind an NLB and an ALB, one CloudFormation stack

**Status:** accepted

## Context

Every service must deploy to AWS without manual steps. SIP and MSRP are long-lived
TCP (and SIP also UDP) connections; ACS and file transfer are HTTPS.

## Decision

- ECS Fargate for every service, in private subnets across two AZs, with NAT for
  egress.
- A public **NLB** for SIP (TCP 5060, TLS 5061, optional UDP 5060) to `pcscf` and
  for MSRP (TCP 2855, TLS 2856) to `msrp-relay`. TLS terminates on the NLB with an
  ACM certificate when one is given.
- A public **ALB** for `acs` and `ft-server` (path or host routing), HTTPS when a
  certificate is given.
- Cloud Map private DNS for service discovery inside the VPC; Diameter peers and
  internal SIP hops use those names.
- DynamoDB (on-demand, PITR) and S3 (SSE, lifecycle expiry) for state.
- Every NLB target group uses **Proxy Protocol v2**. Fargate targets are IP targets,
  for which the NLB does not preserve the client address on TLS listeners, and
  `pcscf` needs the real client address for `received`/`rport` and for flow
  identity. The SIP and MSRP transports require the PPv2 header when
  `RCS_PROXY_PROTOCOL=true` and refuse a connection without one, so a
  misconfigured target group fails loudly instead of seeing every client as the
  load balancer. NLB health checks are sent with a PPv2 `LOCAL` command (no
  client address); the transport accepts those and closes them after the health
  check without creating a flow. `RCS_PROXY_PROTOCOL=false` is refused in
  `staging`/`prod`.
- Idle timeouts. The NLB idle timeout is configurable only on TCP listeners
  (raised to 1800 s there); on TLS listeners it is fixed at 350 s. Every keep-alive
  is therefore sized for 350 s:
  - `pcscf` returns `Flow-Timer: 120` (RFC 5626 §4.4.1, §10) in the REGISTER 200,
    so clients send a CRLF ping at least every two minutes on SIP flows.
  - `rcs-as` and `msrp-relay` send an empty MSRP SEND on a session idle for
    240 s.
  - Server-side idle timeouts are a little longer than the NLB's, so the NLB, not
    the service, is what ends a dead connection.
  - Kernel TCP keep-alive is off on client-facing listeners (it wakes the radio and
    is not what keeps the NLB entry alive) and on for core-facing connections.
- `infra/ecr.yaml` for repositories, `infra/platform.yaml` for everything else;
  `scripts/deploy.sh` builds, pushes and deploys.

## Rationale

Fargate keeps the operational surface small. An NLB is the only AWS load balancer
that passes raw TCP/UDP and preserves the client source address, which `pcscf`
needs for `received`/`rport` and flow handling. One stack keeps "one command"
true; it can be split into nested stacks later without changing service code.

## Consequences

- Terminating requests must reach the `pcscf` task that holds the connection, so
  `pcscf` puts its task address in `Path` and `Record-Route` (ADR 0005).
- With TLS on the NLB, `pcscf` sees TCP; it trusts the NLB's listener port to
  know the client used TLS and puts `sips`/`transport=tls` semantics in `Path`
  accordingly.
- Unencrypted SIP and MSRP listeners are refused in `staging`/`prod`.
- Load balancer connection draining does not help long-lived SIP and MSRP
  connections: when a `pcscf` or `msrp-relay` task stops, its clients reconnect and
  re-register. Rolling updates therefore replace one task at a time
  (`minimumHealthyPercent` 100 and `maximumPercent` 100 + 100/N rounded up, e.g.
  150 for two tasks, so ECS adds and then retires one task per step;
  deregistration delay 30 s),
  a stopping `pcscf` closes its flows gradually over the task's stop timeout
  (120 s) rather than all at once, and `hss` and `scscf` are sized for the
  resulting re-registration burst (full authentication for every client of one
  task). The runbook documents the expected burst.
