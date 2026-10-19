# Threat model

The platform's assets are subscriber credentials (Ki/OPc, digest and FT
credentials, AKA vectors), subscriber identities (IMSI, MSISDN, IMPI/IMPU),
message and file content, and the ability to send as a subscriber. This document
lists the threats the design addresses and where; ADR 0007 has the transport and
access decisions it relies on. Each entry: threat, what an attacker gains, control,
and status — **implemented** (in code on `main`) or **planned** (decided, with the
issue that implements it). Linked from `SECURITY.md`.

## T1 — Diameter peer impersonation

A task the security groups admit to the `hss` Cx port claims a CSCF Origin-Host
and sends MAR (gains any subscriber's authentication vectors) or SAR (moves a
subscriber's S-CSCF assignment and diverts terminating traffic).
**Control:** only `icscf` and `scscf` security groups reach the Cx port
(ADR 0007 §2); accept rules require `Networks` in production (§6); Origin-Host is
not authenticated without TLS.
**Status:** peer rules implemented (`internal/diameter`); production `Networks`
requirement and security groups planned (#12, Phase 7 infrastructure); per-peer
command restrictions open.

## T2 — SIP trust domain (RFC 3325)

Anything that reaches a core SIP port can send as any subscriber by setting
`P-Asserted-Identity`.
**Control:** only `pcscf` faces clients and strips client-supplied
`P-Asserted-Identity` and the other network-only headers, on a client listener
separate from its core listener; core SIP ports admit only platform services
(ADR 0007 §2, §7).
**Status:** planned (#16, Phase 7 infrastructure).

## T3 — MSRP session access on `rcs-as`

MSRP session ids act as capabilities (ADR 0004). A task that reaches the `rcs-as`
MSRP port and learns a session id could read or inject chat content.
**Control:** only `msrp-relay` reaches that port; session ids carry ≥128 random
bits and never appear in logs or errors. On the client side of the relay
([msrp-relay](msrp-relay.md)):
- a session id not in the issued form (32 lower-case base32 characters, 160
  bits) gets 481 without a store lookup;
- bindings are keyed by the SHA-256 of the client-side session id, which is
  never stored or logged, so a copy of the table does not let anyone connect as
  the client;
- one client connection claims a binding with a conditional write, on whichever
  task it reaches; a second connection gets 403 and is logged (ADR 0004);
- lookups that find nothing are rate-limited per source address (IPv6 /64) and
  survive reconnects (`RELAY_FAILED_LOOKUPS_PER_SOURCE`), and unknown sessions
  per connection are capped (`RELAY_MAX_UNKNOWN_SESSIONS`);
- the relay connects only to hosts in `RELAY_CORE_NETWORKS` (private ranges)
  or the Cloud Map namespace, on ports in `RELAY_CORE_PORTS`, and checks the
  resolved address again before dialling.

The table still holds `rcs-as`'s core-side session id in `core_path`, so read
access to it must stay with the relay task role.
**Status:** implemented in `internal/msrp` (session ids, no ids in logs) and
`msrp-relay` (the controls above). Security groups that keep everything but
`msrp-relay` off the `rcs-as` MSRP port, and the IAM policy test for the
table, are planned (#56, Phase 7 infrastructure).

## T4 — Compromise of an internet-facing service

`pcscf`, `msrp-relay`, `ft-server` and `acs` parse untrusted input. If one is
compromised, its reach is what its security group and tokens allow:

| Service | Can reach | Cannot |
|---|---|---|
| `pcscf` | core SIP ports, relay control | `hss`, MSRP on `rcs-as` |
| `msrp-relay` | `rcs-as` MSRP, binding table | SIP core, `hss` |
| `ft-server` | `hss` FT-credential read, its S3 bucket and table | keys, provisioning writes, SIP, Diameter |
| `acs` | `hss` credential issue/read for subscribers it provisions | keys, Cx, SIP |

**Control:** ADR 0007 §2–§4; parsers are fuzzed, bounded and linear
(architecture §8).
**Status:** parser rules implemented for merged libraries. Per service:

| Service | Implemented in the service | Planned |
|---|---|---|
| `pcscf` | nothing yet: the service is not built | the service (#16), security groups (#56) |
| `msrp-relay` | dials only `RELAY_CORE_NETWORKS` hosts on `RELAY_CORE_PORTS`, rechecked after name resolution, and never a client; the control API accepts only `pcscf`'s token ([msrp-relay](msrp-relay.md)) | security groups (#56); a task role limited to the binding table, with its IAM policy test (Phase 7) |
| `ft-server` | reaches the HSS only with its own token, over `https` or over `http` to a private host, and in staging and prod only at an RFC 1918 or ULA address, rechecked after name resolution ([ft-server](ft-server.md)) | HSS token scope enforced by `hss` (#12); security groups (#56); a task role limited to its bucket and table (Phase 7) |
| `acs` | in its own repository | token and http/https rules as a caller (auto-configuration-server#68) |

`acs` can re-issue credentials of
every `acs_managed` subscription; the audit log and rate limit bound and reveal
that, they do not prevent it.

## T5 — Admin ports

Every service serves `/healthz` and `/readyz` without authentication.
**Control:** the admin server serves nothing else unless a service mounts it, and
a mounted handler must authenticate itself (`Admin.Handle` does not enforce it;
review rule); admin ports are reachable only from their load balancer (ADR 0007
§2).
**Status:** health endpoints implemented (`internal/runtime`); security groups
planned (Phase 7).

## T6 — Token leakage, reuse and rotation

A leaked service token lets its holder call the APIs in that token's scope.
**Control:** scoped tokens (ADR 0007 §3), ≥256 bits, distinct per caller, read
only by the execution role, two-token rotation with a runbook procedure; tokens
are never logged.
**Status:** planned (#12 for the HSS side, auto-configuration-server#68 for
`acs`).

## T7 — AWS control plane

An IAM principal that can change security groups, read Secrets Manager or change
task definitions can undo every control above.
**Control:** a least-privilege deploy role and CloudTrail; each operator decides
who may assume it.
**Status:** planned (Phase 7), including alarms on security group and secret
changes.

## T8 — Subscriber identifiers in logs and metrics

**Control:** `internal/pii` masking and the privacy check in CI; no identifier as a
metric dimension (architecture §8).
**Status:** implemented.

## T9 — Resource exhaustion from clients

**Control:** every listener and parser has size, count, time and per-source limits;
reviews check maximum-size inputs (architecture §8).
**Status:** implemented for merged libraries; each service adds its own.
