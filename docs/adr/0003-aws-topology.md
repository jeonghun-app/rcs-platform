# ADR 0003 — ECS Fargate behind an NLB and an ALB, one CloudFormation stack

**Status:** accepted

## Context

Every service must deploy to AWS without manual steps. SIP and MSRP are long-lived
TCP (and SIP also UDP) connections; ACS and file transfer are HTTPS.

## Decision

- ECS Fargate for every service, in private subnets across two AZs, with NAT for
  egress.
- A public **NLB** for SIP (TCP 5060, TLS 5061; UDP 5060 in dev/test only) to `pcscf` and
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
  (raised to 1800 s there); TLS listeners keep a fixed 350 s and UDP flows a fixed
  120 s. Every keep-alive is therefore sized for 350 s on TCP and TLS:
  - Clients using outbound (RFC 5626) get `Flow-Timer: 120` in the REGISTER 200
    (with `Require: outbound`, RFC 5626 §4.4, §5.4, §10), so they send a CRLF
    ping at least every two minutes.
  - Clients that ask for keep-alive with the Via `keep` parameter (RFC 6223
    §4.4) get `keep=120` (the same value as Flow-Timer, §5).
  - A client that uses neither cannot be made to send keep-alives (§10). On TLS
    `pcscf` closes its connection after 340 s of silence; terminating requests from then until the client registers again get
    430 from `pcscf` and are stored by `rcs-as` (ADR 0005). `pcscf` bounds that
    window by lowering the `Expires` of such a client's REGISTER (and of the
    contact in the 200) to at most 600 s, so the gap is at most about 260 s per
    registration. The cost is a re-registration, with a full authentication, every
    10 minutes per such client; the runbook includes it in HSS sizing.
  - `rcs-as` and `msrp-relay` send an empty MSRP SEND on a session idle for
    240 s.
  - Server-side idle timeouts are longer than the keep-alive interval of the
    protocol on that listener, so an endpoint that keeps to it is never cut by
    the service: `pcscf` 180 s on TLS and 1900 s on TCP for flows that
    negotiated a keep-alive (SIP keep-alive 120 s, RFC 5626 §5.4), and 340 s for
    flows that did not, just under the NLB's 350 s so the client sees a clean
    close rather than a later reset; `msrp-relay` and `rcs-as` 300 s (MSRP keep-alive 240 s).
    Idle connections longer than 350 s are not expected to survive even on TCP
    listeners: the target ENI's connection tracking on Fargate is not
    configurable and may not match the NLB's longer timeout. The NLB does
    not close a connection when its own timer expires; it stops tracking it and a
    later packet gets a reset, which the client treats as a flow failure.
  - Kernel TCP keep-alive is **disabled** on client-facing listeners
    (`net.ListenConfig{KeepAlive: -1}`; Go enables it at 15 s by default). A TCP
    keep-alive restarts the NLB idle timer, and on TLS listeners it makes the NLB
    start its own keep-alives to both sides every 20 s, which keeps the client's
    radio awake. Core-facing connections keep it enabled.
- SIP over UDP is for dev and test only and refused in `staging`/`prod`: the NLB's
  fixed 120 s UDP flow timeout would route a client's packets to another `pcscf`
  task after a quiet period, and UDP keep-alive needs STUN rather than CRLF.
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
