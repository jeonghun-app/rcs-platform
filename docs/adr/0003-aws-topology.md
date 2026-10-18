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
