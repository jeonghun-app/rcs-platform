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

## T10 — Forged receipts, routes and floods through `rcs-as`

`rcs-as` stores messages for absent recipients and carries delivery and display
notifications (IMDN) back to senders. A subscriber could:

- send notifications about messages it never received (a false "read" or
  "failed");
- write `IMDN-Record-Route` or `IMDN-Route` headers that make `rcs-as` send a
  request from inside the network to a host of its choosing;
- fill another subscriber's queue, or resend one notification without end.

The store also keeps a record of who wrote to whom, which is communication
metadata.

**Control** ([rcs-as](rcs-as.md)):

- **Notifications.**
  - A notification is accepted only from a recipient of the message it names,
    or from a configured intermediary reporting processing or failure.
  - It must name a message its addressee sent, and a disposition that message
    asked for.
  - It is accepted once per notifier and kind.
  - Who sent it is the identity the network asserted (T2), never the CPIM
    `From`.
- **Routes.** IMDN routes are followed only when the whole URI is one of
  `RCSAS_TRUSTED_ROUTES`. A host check is not used, because a user part, a
  `maddr` or URI headers could make it pass a URI that leads elsewhere. Other
  entries are dropped from generated notifications and ignored in forwarded
  ones.
- **Floods.** These are bounded:
  - per-recipient queues, by count and bytes, across tasks;
  - each sender's share of a queue (an eighth by default), so that no sender
    can lock the others out, whether it writes 1-to-1 or in groups; 1-to-1
    notifications are bounded by the sent records and by being accepted once
    instead, group notifications by one share per group and a quarter of the
    queue for all groups together (T11);
  - is-composing forwarding, per leg;
  - per-sender rates for messages and notifications;
  - the size of notifications;
  - store keys built from client input, which are limited in length.
- **Display names.** Names copied from CPIM are escaped, bidirectional
  controls included. They are for display only, never an asserted identity.
- **Metadata.** Sent-message records hold sender, recipients, Message-ID and
  the dispositions asked for, and no content. They are kept for
  `RCSAS_SENT_TTL`, which defaults to `RCSAS_STORE_TTL` plus one day (8 days),
  and DynamoDB's TTL deletes them at their own expiry. Queued message bodies
  are removed when delivered or swept, with a one-day TTL backstop.

**Status:** implemented in `internal/rcsas` (#59). The SIP-layer contracts
(`Delivery.Route`, `Delivery.SenderName`) apply when the SIP layer is built.

## T11 — Forged roster changes and mass-add spam in group chats

`rcs-as` runs group chats ([rcs-as](rcs-as.md#group-chat)). A subscriber could:

- remove or add others in a group it is not in, or as an ordinary participant
  remove others;
- read a group's roster without being in it;
- write as someone else in a group;
- put strangers in groups (spam), or flood a group so that every participant's
  device and queue fills.

**Control:**

- **Authorisation.** Every operation is checked against the stored roster:
  - only joined participants add, and only the chairman removes;
  - someone who left or was removed returns only when added again, and
    someone removed only when the chairman adds them back, so that no
    participant can undo the chairman's removal. A removed identity is kept
    after the roster forgets its entry (up to 200 a group), and the roster
    forgets those who left first;
  - only current participants read the roster;
  - only joined participants write.

  Who asks is the identity the network asserted (T2). Every change is a
  conditional write on the revision it was computed from, so no concurrent
  change is lost or reordered.
- **Authorship.** A group message's CPIM header block is rebuilt with one
  `From`, the writer's asserted identity under its roster name, and one `To`,
  the group. No other header that any receiver could read as a `From` or `To`
  survives, whatever its case, prefix or namespace, so nobody writes as
  someone else by address. Nor by name: a name another participant,
  current or former, goes by, compared without case, extra space and
  characters that show as nothing, is dropped, and its owner joins under
  its identity alone; nobody is kept out for a name. A 1-to-1 message,
  forwarded unchanged, is refused if it has such a header.
  Residual risk: names are not normalized (NFC), so canonically equivalent
  spellings (an é composed or decomposed) compare different, and look-alike
  letters of other scripts are not folded; such a name can still look like
  another's, next to a different identity.
- **Notifications.** They are matched by the group's own record of the
  message, in the group or sent to the author outside it, accepted only from
  participants it went to, for themselves (`recipient-uri`), once per kind.
- **Floods and spam.** These are bounded:
  - group size (`RCSAS_GROUP_MAX_PARTICIPANTS`);
  - per user, groups created and participants added per minute;
  - per participant and group, messages and renames per minute;
  - per group, a fan-out budget of deliveries per minute, of which one
    sender may use at most a quarter, so that no participant can silence a
    group by writing at its own full rate. The burst lets one sender send 10
    messages in a row to a full group. Residual risk: four accounts in one
    group, each writing at its full share, use up the whole budget, and a
    fifth participant then has about a quarter of its messages refused;
  - each recipient's queue as in 1-to-1 chat, where a group message counts
    against its author's share, the one its 1-to-1 messages use; each
    group's notifications hold one share, and all groups' together a quarter
    of the queue, beyond which they are dropped;
  - names 100 bytes, subject and Conversation-ID 256 bytes; identities must
    be SIP or tel URIs, compared in canonical form, and names XML-safe text,
    so that one bad value cannot make the stored roster unwritable;
  - the roster's size: the limits are such that the largest roster they
    allow stays within what `internal/conference` reads back (256 KiB),
    checked when the service starts, so no combination of allowed values
    makes it unreadable either, and no Leave or Remove is ever refused for
    size;
  - former participants, at most as many as the size limit and as the
    roster bound leaves room for; adding and removing stranger after
    stranger cannot grow a group's stored item past DynamoDB's limit and
    break the group.
- **Metrics.** None names a group or a participant.
- **Roster privacy.** The roster keeps former participants (up to the size
  limit), so a participant who joins later sees who was in the group before.
  This is accepted: it is how RFC 4575 rosters and RCS clients show who left.
  Only current participants read the roster.

**Status:** implemented in `internal/rcsas/group` (#108). The SIP layer must:

- pass asserted identities;
- send roster NOTIFYs only to subscriptions `Roster` accepted;
- map a 603 Decline of the focus's INVITE to `Leave`, so that someone who
  declines a group of strangers leaves it rather than being invited again;
- end the session and the conference subscriptions of a participant who
  leaves or is removed, so that it receives no later message or roster
  change.

The engine asks the group whether someone is still a participant before it
invites them back to deliver a queued copy, and gives up the copies of
anyone who left.
