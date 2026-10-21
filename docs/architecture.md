# Architecture

This document is the blueprint every service in the repository is built against.
When code and this document disagree, one of them is a bug: fix the code, or
change the document in the same pull request with the reason in the body.

## 1. What the platform is

A GSMA RCS (Universal Profile) service platform: everything an operator needs
between an RCS client on a phone and the messages it exchanges, built as small
services that deploy to AWS with one command.

```
                       ┌──────────────────────── AWS VPC ─────────────────────────────────┐
  RCS client           │  public subnets                 private subnets                  │
 ┌─────────┐  HTTPS    │  ┌─────┐   ┌──────────┐                                          │
 │         │──────────────▶│ ALB │──▶│ acs      │ (auto-configuration-server, separate repo)│
 │         │           │  │     │──▶│ ft-server│──▶ S3 (file content)                      │
 │         │           │  └─────┘   └──────────┘                                          │
 │         │ SIP TCP/TLS  ┌─────┐   ┌──────────┐ SIP  ┌───────┐ SIP ┌───────┐ SIP ┌──────┐ │
 │         │──────────────▶│ NLB │──▶│ pcscf    │─────▶│ icscf │────▶│ scscf │────▶│rcs-as│ │
 │         │           │  │     │   └────┬─────┘      └───┬───┘ Cx  └───┬───┘     └──┬───┘ │
 │         │ MSRP TCP/TLS │     │   ┌────▼─────┐          └────▶┌─────┐◀─┘ Cx        │MSRP │
 │         │──────────────▶│     │──▶│msrp-relay│────────────────│ hss │              │     │
 └─────────┘           │  └─────┘   └────┬─────┘                └─────┘              │     │
                       │                 └────────────── MSRP (relay connects) ──────┘     │
                       │   DynamoDB: subscribers, registrations, messages, bindings, files │
                       └───────────────────────────────────────────────────────────────────┘
```

## 2. Services

| Service | Role | Speaks | Specifications (clause numbers only, see §9) |
|---|---|---|---|
| `pcscf` | Proxy-CSCF: the only SIP entry point for clients. Holds client connections, asserts identity, anchors MSRP through `msrp-relay` by rewriting SDP | SIP (clients, I/S-CSCF), HTTP (relay control) | TS 24.229 §5.2, RFC 3261, RFC 3327, RFC 3608, RFC 3325, RFC 5626 (flow tokens) |
| `icscf` | Interrogating-CSCF: picks the S-CSCF for a REGISTER and finds the serving S-CSCF for a terminating request | SIP, Diameter Cx (UAR, LIR) | TS 24.229 §5.3, TS 29.228/29.229 |
| `scscf` | Serving-CSCF: registrar, authentication (IMS AKA and SIP Digest), initial filter criteria evaluation, routing to application servers and terminating contacts | SIP, Diameter Cx (MAR, SAR) | TS 24.229 §5.4, TS 33.203, TS 29.228/29.229, TS 29.328 (iFC) |
| `hss` | Home Subscriber Server: subscriber identities, credentials, service profiles (iFC), S-CSCF assignment. Also an HTTP provisioning API for operators and for `acs` | Diameter Cx/Dx server, Diameter Sh server, HTTP | TS 29.228/29.229, TS 29.328/29.329, TS 35.206 (Milenage) |
| `rcs-as` | RCS messaging application server: originating and terminating participating function for 1-to-1 Chat and Standalone Messaging, controlling function (conference focus) for Group Chat, store-and-forward, delivery and display notifications | SIP, MSRP, CPIM, IMDN | GSMA RCC.07, RCC.11, OMA CPM, RFC 4975, RFC 3862, RFC 5438, RFC 4575, RFC 3428 |
| `msrp-relay` | MSRP media anchor at the edge, controlled by `pcscf`. Clients connect to it from the internet; it connects onward to `rcs-as` inside the VPC | MSRP, HTTP (control) | RFC 4975, RFC 6135, TS 23.334 (IMS-ALG/IMS-AGW model), RFC 4976 (optional relay mode) |
| `ft-server` | HTTP content server for File Transfer via HTTP: upload with resume, file info document, download | HTTP | GSMA RCC.07 FT via HTTP |
| `acs` | Auto Configuration Server, [jeonghun-app/auto-configuration-server](https://github.com/jeonghun-app/auto-configuration-server). Tells the client where `pcscf`, `ft-server` and the conference factory are, and hands out IMS credentials provisioned in `hss` | HTTP | GSMA RCC.14, RCC.07 |

The platform is deliberately **not** built on Kamailio, OpenSIPS, freeDiameter or
a SIP library: every protocol stack is in this repository (ADR 0001). Only the
Go standard library and the AWS SDK are runtime dependencies unless an ADR says
otherwise.

## 3. Repository layout

What is on `main` today:

```
cmd/<service>/              main package per service; wiring only (ft-server,
                            msrp-relay, rcs-version)
internal/
  buildinfo/                release version stamped into every binary
  runtime/                  shared service runtime: env config, slog JSON logger,
                            EMF metrics, /healthz + /readyz, graceful shutdown,
                            -version and -healthcheck modes
  runtime/runtimetest/      a *runtime.Runtime for service tests, manual clock
  pii/                      redaction of IMSI, MSISDN, IMEI, SIP/tel URIs in logs
  proxyproto/               PROXY protocol v2 parser shared by every service
                            behind the NLB (ADR 0003)
  sip/                      RFC 3261 message model, parser, serializer, URIs, headers
  sip/digest/               SIP/HTTP Digest (RFC 7616, RFC 8760) and AKA (RFC 3310)
  sip/dialog/               one side of a dialog as plain data: in-dialog requests,
                            subscriptions and notifications (RFC 3261 §12, RFC 6665)
  sip/reginfo/              RFC 3680 registration information (reg event NOTIFY bodies)
  milenage/                 TS 35.206 f1–f5*, AUTN/RES/CK/IK/AK, resync (AUTS)
  sdp/                      RFC 8866 parser and serializer, MSRP media attributes,
                            offer/answer and relay rewrite
  diameter/                 RFC 6733 codec, dictionary, peers (CER/CEA, DWR/DWA, DPR)
  diameter/cx, diameter/sh  Cx and Sh application dictionaries and typed messages
  ifc/                      IMS user profile (Cx User-Data) and iFC evaluation
  msrp/                     RFC 4975 codec, chunking, reports, connections, Bridge
  cpim/, imdn/              message/cpim wrapper and IMDN notifications
  conference/               RFC 4575 conference-info documents
  ftserver/                 ft-server service logic
  ftserver/store/           ft-server storage interfaces, memory backends,
                            storetest contract
  ftserver/awsstore/        ft-server S3 and DynamoDB backends
  msrprelay/                msrp-relay service logic: control API and data path
  msrprelay/store/          binding store interface, memory backend, storetest
                            contract
  msrprelay/dynamostore/    msrp-relay DynamoDB backend (`msrp-bindings`)
deploy/                     Dockerfile (service image), toolchain.Dockerfile,
                            docker-compose.yml (the local stack, docs/local-stack.md)
                            and stack-init.Dockerfile (its bootstrap)
infra/                      CloudFormation (empty until Phase 7)
scripts/                    fuzz, privacy and docs-link checks, compose-env.sh
tools/rcs-sim/              Go client simulator used by end-to-end tests and smoke tests
tools/stack-init/           creates the local stack's tables and seeds its test subscriber
docs/                       this file, ADRs, threat model, service docs
                            (ft-server.md, msrp-relay.md, pcscf.md), api/ (OpenAPI)
```

Planned, not on `main` yet:

```
internal/sip/transport/     UDP, TCP and TLS listeners and connection table (flows)
internal/sip/transaction/   client and server transaction state machines and timers
internal/<service>/         pcscf/, icscf/, scscf/, hss/, rcsas/: service logic,
                            each with its own store/ and AWS backend as above
infra/                      ecr.yaml, platform.yaml
scripts/                    deploy.sh, teardown.sh
docs/                       runbook, conformance, aws-deployment.md
```

A service keeps its storage interface in `internal/<service>/store` and is the
only importer of its AWS backend package, so its logic is tested against memory
backends and the backend against local containers (`make test-integration`).

One container image holds every service binary; the ECS task definition picks the
command. Services never import another service's package: shared behaviour lives in
a library package under `internal/`.

## 4. Identities and the home domain

- Home network domain: `ims.mnc<MNC>.mcc<MCC>.3gppnetwork.org`, configured once
  (`RCS_IMS_DOMAIN`). Local and test deployments use MCC 001 / MNC 01.
- Private user identity (IMPI): `<IMSI>@<domain>` for SIM-based clients, or any
  `user@domain` for Digest-only clients.
- Public user identities (IMPU): `sip:+<E.164>@<domain>` and `tel:+<E.164>`, sharing
  one implicit registration set.
- The domain is a logical name. Inside the VPC services find each other through
  Cloud Map DNS (`<service>.<namespace>`); clients find `pcscf` through the address
  `acs` provisions (the NLB DNS name or an operator FQDN).

## 5. Signalling flows

### 5.1 Registration

1. Client → `pcscf` REGISTER. `pcscf` adds `Path` with its own instance address and
   a signed flow token naming the client connection (RFC 5626 §5.2, ADR 0005), and
   forwards to `icscf`.
2. `icscf` → `hss` UAR, receives the S-CSCF name or capabilities, forwards to that
   `scscf`.
3. `scscf` → `hss` MAR, stores the vector in `auth-challenges` and challenges with
   401 (AKA: RAND/AUTN; Digest: nonce). The second REGISTER may reach another
   `scscf` instance, which finds the vector there.
4. Client re-REGISTERs with credentials; `scscf` verifies, sends SAR, stores the
   binding (contacts, Path, instance id, expiry) in the registrations table and
   returns 200 with `Service-Route` and `P-Associated-URI`.
5. `scscf` performs third-party REGISTER to application servers whose iFC match
   REGISTER (RCS-AS learns the client is online, flushes stored messages).
6. `pcscf` keeps the 200's `Service-Route` and `P-Associated-URI` for the flow in
   instance memory, gives an outbound client a `Flow-Timer` for its keep-alives,
   and subscribes to the user's reg event at `scscf` (TS 24.229 §5.2.3): a NOTIFY
   that ends a binding ends that registration on the task ([pcscf](pcscf.md)).

### 5.2 Originating and terminating requests

- Originating: client → `pcscf` (asserts `P-Asserted-Identity`, enforces the
  `Service-Route` learned at registration) → `scscf` (originating iFC; RCS service
  requests go to `rcs-as`) → terminating side.
- Terminating: `icscf` (LIR) → serving `scscf` (terminating iFC; RCS requests go to
  `rcs-as` terminating function) → registered contacts via their stored `Path`, i.e.
  the exact `pcscf` instance and flow holding the client's connection.
- Unregistered terminating user: `scscf` evaluates unregistered-state iFC so the
  `rcs-as` can store-and-forward; without a matching AS it answers 480.
- Requests `rcs-as` sends itself (stored messages delivered later, network
  notifications, terminating chat legs): `rcs-as` → `scscf` as terminating
  requests, without `orig` and with `P-Served-User: <user>;sescase=term`, which
  the default profile's triggers exclude (docs/hss.md), so they reach the
  user's contacts rather than `rcs-as` again (#137).

### 5.3 Capability discovery

SIP OPTIONS end to end, with feature tags from RCC.07 (chat, FT via HTTP, group
chat, standalone messaging, chatbot). `scscf` answers 480/404 for unregistered or
unknown users. Presence-based discovery is out of scope for the first release.

## 6. Media plane: MSRP anchoring

MSRP between a client on the internet and `rcs-as` inside the VPC goes through
`msrp-relay`, which `pcscf` controls the way a P-CSCF controls an IMS access gateway
(ADR 0004):

- `pcscf` rewrites each SDP offer and answer that carries `m=message` so that the
  client sees the relay's public `a=path` and the core sees the relay's core
  address. No offer carries `passive` (RFC 6135 §4.2.2); answers choose the
  direction so that **clients connect to the relay and the relay connects to
  `rcs-as`**. ADR 0004 has the full table.
- So the relay never accepts connections from the core and never opens
  connections to clients, which works behind any NAT, needs no internet egress
  and lets any relay instance behind the NLB serve any session.
- `pcscf` allocates a binding through the relay control API. Bindings live in
  DynamoDB with a TTL, keyed by the SHA-256 of the session id in the relay's
  client-side MSRP URI, so the task that receives the client connection does not
  need to be the task that allocated it, and a copy of the table does not let
  anyone connect as the client.
- The relay reads the client's address from the PROXY protocol v2 header the NLB
  sends (`internal/proxyproto`, the one PROXY parser for every service behind the
  NLB) and applies its per-source limits to it.

`rcs-as` terminates MSRP for every session: it needs the content for
store-and-forward, IMDN and group fan-out.

## 7. State, scaling and failure

| State | Owner | Where | Notes |
|---|---|---|---|
| Subscribers, credentials, service profiles, S-CSCF assignment | `hss` | DynamoDB `subscribers` | Secrets (Ki, OPc, digest HA1) encrypted at rest; never logged |
| Registration bindings | `scscf` | DynamoDB `registrations` | Any `scscf` instance can serve any user; `Service-Route` names the service, not the instance |
| Authentication challenges, reg-event subscriptions | `scscf` | DynamoDB `auth-challenges`, `reg-subscriptions` | Second REGISTER and NOTIFY numbering work across instances (ADR 0005) |
| Position in the iFC chain | `scscf` | signed parameter in the `Route` back to `scscf` | Original dialog identifier, HMAC with a key shared by `scscf` instances |
| Client connections (flows) | `pcscf` | instance memory | `Path` and core-facing `Record-Route` name the instance; flow tokens are HMACs under a per-start key, unknown ones get 430 (ADR 0005) |
| Registrations as the edge sees them, reg-event subscriptions | `pcscf` | instance memory | Per flow: identities, `Service-Route`, contacts; a task's subscriptions end with it, and a client's next REGISTER through another task sets them up there |
| SIP transactions | every SIP service | instance memory | Responses follow `Via` back to the instance that sent the request |
| Stored messages, group chat state | `rcs-as` | DynamoDB `messages`, `groupchats` | |
| MSRP bindings | `msrp-relay` | DynamoDB `msrp-bindings`, expiry checked on read, TTL for cleanup | Keyed by the SHA-256 of the client-side session id, which is never stored; strongly consistent reads; one conditional claim per binding across tasks; a client that connects before `pcscf` has recorded its path waits up to `RELAY_PATH_WAIT` ([msrp-relay](msrp-relay.md)) |
| Files | `ft-server` | S3 (content) + DynamoDB `files` (metadata, expiry) | Lifecycle rule deletes expired content |

Every service runs at least two tasks across two AZs in production. Losing a
`pcscf` task drops the connections it held; clients re-register (RFC 5626 recovery)
through the NLB to a surviving task. Every other service is stateless apart from
its tables.

Every table has a memory backend for unit tests and local runs; the compose stack
([local-stack.md](local-stack.md)) uses DynamoDB Local and S3Mock.

## 8. Cross-cutting rules

- **Configuration**: environment variables only, prefixed per service
  (`PCSCF_`, `HSS_`, …) plus shared `RCS_` values. A production-unsafe setting
  (memory store, no TLS on the public listener, no admin token) refuses to start
  when `RCS_ENV` is `staging` or `prod`.
- **Logging**: JSON lines through `log/slog`. SIP URIs, `tel:` URIs, IMSI, IMEI and
  MSISDN pass through `internal/pii` before they are logged. Client IP
  addresses, private ones included, are logged only as their network, through
  `pii.ClientIP` or the sip and msrp log values (IPv4 /24, IPv6 /48). Every
  `http.Server` logs its errors through `runtime.HTTPErrorLog`, which does the
  same for the addresses `net/http` writes into them (`pii.TruncateIPsIn`).
  Message bodies, credentials, nonces, RAND/AUTN, keys and tokens are never
  logged.
- **Metrics**: CloudWatch Embedded Metric Format lines on stdout, so no agent is
  needed. They are aggregated in memory and written once a minute, when
  shutdown starts and when it ends, one line per metric, so log volume does
  not grow with traffic; a crash loses at most the last minute. Counts are
  sums and gauges the last value. A timing is written as at most 100 values
  (every value, or quantiles within the exact minimum and maximum) with
  companions `<name>.count` and `<name>.sum` holding its exact number and
  total. No identifier is ever a metric dimension. Alarms on these metrics:
  - use a period of 60 s or more and M of N datapoints with N of 2 or more:
    a minute's values arrive up to a minute late, stamped when written, and a
    task's flushes are not aligned to the minute;
  - set `treatMissingData` explicitly: a task writes no line for a count
    nothing incremented, so for counts missing means zero;
  - alarm on latency with a timing's Maximum, which is exact, with the
    exact average `<name>.sum / <name>.count` by metric math, or with the
    Count of timeouts and errors. Never use a timing's SampleCount, Sum or
    Average, which describe at most 100 values per task and minute, and
    treat its percentiles with care: with `Service` as the only dimension
    CloudWatch pools every task's values, so they weigh each task's minute
    alike, not each request, and a slow task serving most requests can hide
    behind fast idle ones;
  - alarm on `EMFValidationErrors` and `EMFParsingErrors` (namespace
    `AWS/Logs`) for each service's log group: a line CloudWatch cannot
    extract loses a whole minute of that metric.
- **Health**: every service serves `/healthz` (process alive) and `/readyz`
  (dependencies reachable) on its admin port, and supports `-healthcheck` so a
  distroless image can run an ECS container health check. A service whose
  start-up waits on remote services and ends at a start-up deadline (hss) sets
  `Service.LiveAfterReady`, so that `/healthz` fails until it is ready.
- **Parsing**: every parser is fuzzed (`go test -fuzz`), has a size limit, is
  linear in its input (a test parses a maximum-size adversarial input), and never
  repairs content it does not own: message bodies such as CPIM and MSRP payloads
  are forwarded byte for byte, and only the headers and SDP lines a service is
  responsible for (Via, Record-Route, the `m=message` lines `pcscf` anchors) are
  rewritten. Receivers
  may *interpret* common deviations leniently where interoperability needs it
  (e.g. bare LF, extra whitespace) and count them; senders are strict. Anything
  ambiguous, or a security risk (control characters, invalid UTF-8, mixed line
  endings, limits), is rejected. XML parsers never resolve entities.
- **Time and randomness** are injected so timers and nonces are testable.

## 9. Specifications

GSMA and 3GPP specifications are referenced by number and clause only; their
text is never copied into the repository. `docs/spec-references.md` lists the
editions targeted. Behaviour implemented from a public description rather than a
specification held by the author is marked as such in `docs/conformance.md`.

## 10. AWS deployment

`scripts/deploy.sh` builds the image (and the pinned `acs` image), pushes both to
ECR and deploys `infra/platform.yaml`: VPC across two AZs, ECS Fargate cluster,
Cloud Map namespace, a public NLB (SIP TCP 5060, SIP TLS 5061, MSRP TCP/TLS), a
public ALB (ACS and file transfer, HTTPS when a certificate is given), DynamoDB
tables, the S3 bucket, CloudWatch alarms and log groups. `scripts/teardown.sh`
removes it. See `docs/aws-deployment.md` (written with the infrastructure).
