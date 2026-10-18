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

```
cmd/<service>/              main package per service; flags, wiring, nothing else
internal/
  runtime/                  shared service runtime: env config, slog JSON logger,
                            /healthz + /readyz, graceful shutdown, -healthcheck flag
  pii/                      redaction of IMSI, MSISDN, IMEI, SIP/tel URIs in logs
  sip/                      RFC 3261 message model, parser, serializer, URIs, headers
  sip/transport/            UDP, TCP and TLS listeners and connection table (flows)
  sip/transaction/          client and server transaction state machines and timers
  sip/digest/               SIP/HTTP Digest (RFC 7616, RFC 8760) and AKA (RFC 3310)
  sdp/                      RFC 4566/8866 parser and serializer, MSRP media attributes
  diameter/                 RFC 6733 codec, peer state machine (CER/CEA, DWR/DWA, DPR)
  diameter/cx, diameter/sh  application dictionaries and typed messages
  milenage/                 TS 35.206 f1–f5*, AUTN/RES/CK/IK/AK, resync (AUTS)
  msrp/                     RFC 4975 codec, chunking, session, connection reuse
  cpim/, imdn/              message/cpim wrapper and IMDN notifications
  conference/               RFC 4575 conference-info documents
  ifc/                      initial filter criteria model and evaluation
  store/                    storage interfaces; memory and DynamoDB backends
  <service>/                service logic (pcscf/, scscf/, rcsas/, …), testable without network
deploy/                     Dockerfile, docker-compose.yml for the full local stack
infra/                      CloudFormation: ecr.yaml, platform.yaml
scripts/                    deploy.sh, teardown.sh, privacy and docs checks
tools/rcs-sim/              Go client simulator used by end-to-end tests and smoke tests
docs/                       this file, ADRs, protocol notes, runbook, conformance
```

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

### 5.2 Originating and terminating requests

- Originating: client → `pcscf` (asserts `P-Asserted-Identity`, enforces the
  `Service-Route` learned at registration) → `scscf` (originating iFC; RCS service
  requests go to `rcs-as`) → terminating side.
- Terminating: `icscf` (LIR) → serving `scscf` (terminating iFC; RCS requests go to
  `rcs-as` terminating function) → registered contacts via their stored `Path`, i.e.
  the exact `pcscf` instance and flow holding the client's connection.
- Unregistered terminating user: `scscf` evaluates unregistered-state iFC so the
  `rcs-as` can store-and-forward; without a matching AS it answers 480.

### 5.3 Capability discovery

SIP OPTIONS end to end, with feature tags from RCC.07 (chat, FT via HTTP, group
chat, standalone messaging, chatbot). `scscf` answers 480/404 for unregistered or
unknown users. Presence-based discovery is out of scope for the first release.

## 6. Media plane: MSRP anchoring

MSRP between a client on the internet and `rcs-as` inside the VPC goes through
`msrp-relay`, which `pcscf` controls the way a P-CSCF controls an IMS access gateway
(ADR 0004):

- `pcscf` rewrites each SDP offer and answer that carries `m=message`: the client
  side sees the relay's public `a=path` and `a=setup:passive`; the core side sees
  the relay as `a=setup:active`.
- So the relay never accepts connections from the core and never opens
  connections to clients: **clients always connect to the relay, the relay always
  connects to `rcs-as`**. This works behind any NAT and lets any relay instance
  behind the NLB serve any session.
- `pcscf` allocates a binding through the relay control API. Bindings live in
  DynamoDB with a TTL, keyed by the session id in the relay's MSRP URI, so the task
  that receives the client connection does not need to be the task that allocated
  it.

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
| SIP transactions | every SIP service | instance memory | Responses follow `Via` back to the instance that sent the request |
| Stored messages, group chat state | `rcs-as` | DynamoDB `messages`, `groupchats` | |
| MSRP bindings | `msrp-relay` | DynamoDB `msrp-bindings` with TTL | |
| Files | `ft-server` | S3 (content) + DynamoDB `files` (metadata, expiry) | Lifecycle rule deletes expired content |

Every service runs at least two tasks across two AZs in production. Losing a
`pcscf` task drops the connections it held; clients re-register (RFC 5626 recovery)
through the NLB to a surviving task. Every other service is stateless apart from
its tables.

Every table has a memory backend for unit tests and local runs; the compose stack
uses DynamoDB Local and a local S3.

## 8. Cross-cutting rules

- **Configuration**: environment variables only, prefixed per service
  (`PCSCF_`, `HSS_`, …) plus shared `RCS_` values. A production-unsafe setting
  (memory store, no TLS on the public listener, no admin token) refuses to start
  when `RCS_ENV` is `staging` or `prod`.
- **Logging**: JSON lines through `log/slog`. SIP URIs, `tel:` URIs, IMSI, IMEI and
  MSISDN pass through `internal/pii` before they are logged. Message bodies,
  credentials, nonces, RAND/AUTN, keys and tokens are never logged.
- **Metrics**: CloudWatch Embedded Metric Format lines on stdout, so no agent is
  needed. No identifier is ever a metric dimension.
- **Health**: every service serves `/healthz` (process alive) and `/readyz`
  (dependencies reachable) on its admin port, and supports `-healthcheck` so a
  distroless image can run an ECS container health check.
- **Parsing**: every parser is fuzzed (`go test -fuzz`), has a size limit, and
  rejects rather than repairs malformed input. XML parsers never resolve entities.
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
