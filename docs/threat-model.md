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

The other direction: whoever answers on the Cx port at an address the CSCFs
discover for `hss` (by adding an instance to the Cloud Map service, T7, or
running a task the security groups admit) receives every UAR, MAR and SAR, with
IMPIs and AUTS, and can send RTR (deregister any user) and PPR (push User-Data
whose iFC route a user's sessions to an application server it controls).
**Control:** the CSCFs connect only to addresses Cloud Map lists for `hss` and
only reach them through the security group from `icscf`/`scscf` to the `hss`
port; the CEA must name the HSS realm; `cxclient` sends no request to, and
refuses RTR and PPR from, a peer whose Origin-Host does not match
`HSSHostPattern` (`hss-*.<namespace>`, ADR 0005). Origin-Host is still not
authenticated without TLS, so the pattern guards against a misdirected peer,
and Cloud Map and IAM integrity (T7) against a planted one.
**Status:** Origin-Host pattern implemented (`internal/ims/cxclient`, #76);
security groups planned (Phase 7 infrastructure).

## T2 — SIP trust domain (RFC 3325)

Anything that reaches a core SIP port can send as any subscriber by setting
`P-Asserted-Identity`.
**Control:** only `pcscf` faces clients and strips client-supplied
`P-Asserted-Identity` and the other network-only headers, on a client listener
separate from its core listener; core SIP ports admit only platform services
(ADR 0007 §2, §7). The same holds for `P-Served-User`, which also makes the
default profile skip `rcs-as` (docs/hss.md): a client that could set it would send
messages that bypass `rcs-as` and its checks (T10), so `pcscf` must strip it.
`scscf` reads it only on a terminating request that did not come from a
`pcscf` core listener, removes the one it inserted toward application servers
before the request leaves for the terminating side or a contact, and carries
a request's place in the iFC chain back from a server only in a Route
parameter it signed (HMAC over the position, the Call-ID and an expiry, ADR
0005), refusing any other with 403 (#14).
**Status:** planned (#16, Phase 7 infrastructure).
**Residual risk (accepted, #208, narrowed in #221):** `pcscf` checks
in-dialog requests against its own Record-Route values only, keeping no
dialog state. The core-facing value binds the flow token to the Call-ID and
the dialog's icid with a MAC under a key drawn at every start, and a request
from the core inside a dialog reaches the flow only with the value written
for its Call-ID, and is answered 403 with any other while the flow is alive. The MAC is checked
only on requests inside a dialog (with a To tag): an initial request comes
along the client's `Path` and is not bound to a dialog. The binding covers
the Call-ID and not the tags: `pcscf` writes the value into
the request that sets up the dialog, before the callee has chosen its tag,
and a value it rewrote in the response would differ between the two route
sets unless it kept state. The peer of a call has seen that value, so it can
go on sending requests with the same Call-ID after the call has ended, for
as long as the flow lives, but not reach the client with any other. `pcscf` fixes only the first hop of a
client's in-dialog request, to `scscf`; whether such requests then reach
`rcs-as`, which records itself in the dialog, depends on `scscf`, which
checks it as an acceptance criterion of
[#14](https://github.com/jeonghun-app/rcs-platform/issues/14). `scscf`
signs its own Record-Route value when it sets up a dialog: a key ID and a MAC,
under a key every `scscf` task shares (current and previous, for rotation),
over the Call-ID, its name and each of the dialog's hops next to it (scheme,
user, host, port, transport). It sends a request inside a dialog on only to
a hop that value signs, at a `pcscf` core port or an application server's
port, and never to itself (`internal/scscf/routing`, #322); a client that
names any other core address, or drops an application server's entry from
its route set, gets 403. No host or subnet list is involved: every core task
shares the private subnets, and task addresses change. `scscf` records, and
signs, only requests that set up a dialog (INVITE, SUBSCRIBE, REFER), which
`pcscf` record-routes too, so the hop toward a client is always `pcscf`'s
value; the sender's Contact stands in only for a core service that records
no route, as `rcs-as` does for the requests it sends for its users. As with `pcscf`'s
value, the binding covers the Call-ID and not the tags, so a peer can go on
sending to the dialog's own hops with that Call-ID after the call has ended.
The client's in-dialog requests are checked against the same MAC, so a
client cannot change the icid its dialog's requests are charged to (review
of #221; this closes the #208 residual risk that it could).

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
| `pcscf` | the listeners and edge rules: PROXY v2 required and plain TCP and UDP refused in staging and prod, the network-only headers removed from every client message, client flows limited per client (IPv4 address or IPv6 /64) and in total, and each listener's connections limited from accept, the PROXY header and TLS handshake included, so the core listener keeps its room (#193); registration, with the client's Path and Route dropped; a client's requests: outside a dialog only over a registered flow, along its Service-Route, with an identity its registration allows and a per-client rate; inside a dialog only along a route this `pcscf` recorded for that flow, to `scscf`'s service name alone and never back into the task; a request from the core only over the client flow of this task its Route names, else 430; the reg event: a NOTIFY only from the core, to a subscription's random Contact and in its dialog, acting only on that user's registrations on the task; MSRP anchored through `msrp-relay` with its token from Secrets Manager, at most two MSRP lines an offer, its bindings limited per client flow, apart for the client's offers and for `rcs-as`'s toward it, and per task, and those each creates in a minute, a body it cannot split in one way only refused, no core address shown to a client, and never end to end, a client's Record-Route not kept so that a BYE `pcscf` sends follows only the core's route ([pcscf](pcscf.md)); residual risk: the per-minute limit is per flow, so a client that opens many flows creates that many times as many bindings, which the flow limit per client address and the per-client rate of initial requests bound | security groups (#56), a dialog-state check in `scscf` (T2 residual risk) |
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
`rcs-as` bounds its SIP sessions, each with its MSRP leg, per task
(`RCSAS_MAX_SESSIONS`, invitations waiting for an answer included) and per
user each way (`RCSAS_MAX_OUTGOING_SESSIONS_PER_USER`,
`RCSAS_MAX_INCOMING_SESSIONS_PER_USER`), so other users' messages cannot take a
user's own room; one sender has one large-mode session at a time with one
recipient. In time, a leg that no msrp-relay connection binds within
`RCSAS_ANSWER_TIMEOUT` is closed and its session ended, so a client that
answers or offers and never connects cannot hold a place.
`pcscf` bounds the `msrp-relay` bindings of each client flow by the side
whose offer made them: the client's own offers
(`PCSCF_MAX_BINDINGS_PER_FLOW`, `PCSCF_BINDINGS_PER_MINUTE`) and `rcs-as`'s
toward it (`PCSCF_MAX_CORE_OFFER_BINDINGS_PER_FLOW`, at least
`RCSAS_MAX_INCOMING_SESSIONS_PER_USER`, and
`PCSCF_CORE_OFFER_BINDINGS_PER_MINUTE`) each have their own room and rate,
so that invitations sent to a user, answered or not, cannot keep the user
from starting a chat; only the task's `PCSCF_MAX_BINDINGS` is shared
(#315).

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
    queue for all groups together, and their summaries by an eighth (T11);
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
  someone else by address: the `From` address is the asserted identity
  and cannot be forged. A name is weaker. It is first come, first served
  and unverified: whoever takes a name first in a group keeps it, and
  nothing checks that it is the person's. A later name that another
  participant, current or former, goes by (compared without case, extra
  space and characters that show as nothing) is dropped. Its owner keeps
  the name it had, or joins under its identity alone; nobody is kept out
  for a name. A 1-to-1 message, forwarded unchanged, is refused if it has
  such a header.
  Residual risk: names are not normalized (NFC), so canonically equivalent
  spellings (an é composed or decomposed) compare different. Look-alike
  letters of other scripts are not folded, nor are visible symbols that
  look blank (U+2800 BRAILLE PATTERN BLANK, and the like), which are not
  default-ignorable. Such a name can still look like another's, next to a
  different identity.
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
    of the queue; beyond that they are summarized as one queue item per
    message, at most an eighth of the queue in all, sent from the marks of
    notifications already accepted, so the summary adds nothing a participant
    did not report. A participant who sends receipts for many of the author's
    messages fills at most that eighth, and the author's 1-to-1 messages keep
    the rest;
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
- **Chat identity.** RCS clients name a group chat by its Contribution-ID
  (rcsjta's chat ID), which its creator chooses, and would take a new group
  under a known ID for the old one. So a Contribution-ID names one live
  group: the conference URI is made from it, and an INVITE to the factory
  under an ID a live group has is refused (403) unless it is that group's
  creator trying again before the group is established, which takes up the
  same group (#279). A participant the chairman removed cannot make a group
  that its former members' clients would merge into the one it was removed
  from. An ended group frees its ID. Residual risk: once a group has ended,
  anyone who knows its Contribution-ID can make a group under it first, and
  a former member's restart under that ID then gets 403. The conference URI
  is no secret from anyone who knows the ID, the group's participants; it
  grants nothing, as every request to it is checked against the roster.
- **Roster privacy.** The roster keeps former participants (up to the size
  limit), so a participant who joins later sees who was in the group before.
  This is accepted: it is how RFC 4575 rosters and RCS clients show who left.
  Only current participants read the roster.
- **Invitee domains.** An invitee, in a new group's list or a REFER, may be
  any SIP or tel URI: `rcs-as` does not restrict its domain. The focus's
  INVITE always goes to the core (`RCSAS_CORE_URI`), never to the invitee's
  host: the stored identity is canonical, without `maddr`, `transport` or
  other parameters, and an invitee with a port or URI headers is refused
  (400) or left out of a list. Residual risk: once the S-CSCF routes off-net (BGCF, NNI), a
  participant can have the focus call a URI outside the network. Where an
  invitee may be is decided with that routing (#337, #14 PR F).

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

## T12 — Authentication floods against one subscriber

Every REGISTER without credentials costs the S-CSCF a MAR, and the HSS
answers it under that subscriber's lock, updating the AKA sequence number. A
distributed flood of REGISTERs for one (IMPI, IMPU) pair, from addresses
the P-CSCF's per-source limits each let through, would starve the
subscriber's own MAR; a forged AUTS, which anyone holding a challenge can
send (`digest.SyncFailure`), would do the same through resynchronisation. A
limit on that must not itself become the cheap way to lock the subscriber
out.

**Control:** the registrar counts the challenges of each IMPI in fixed
windows shared by every `scscf` instance (DynamoDB atomic counters beside the
challenges, with TTL), split by the P-CSCF flow token in the REGISTER's Path,
which only the P-CSCF writes: #198 removes any Path a client sends
(`networkOnlyHeaders`) and puts its own on top (`prepareRegister`), and the
token, an HMAC of the connection, cannot be guessed. A REGISTER over the flow
of a live binding, the registered UE refreshing while it stays on that flow,
counts in a budget of that flow alone, so a flood from elsewhere cannot use
it up. Any other REGISTER counts in a small
per-flow budget and in the IMPI's shared one. Over a budget the answer is
500 with Retry-After (RFC 3261 §21.5.1), without a MAR: not 503, which an
upstream proxy would read as the whole S-CSCF being out of service (§21.5.4)
and the P-CSCF would retry at other I-CSCFs. A challenge allows one
resynchronisation; an IMPI three per challenge lifetime, the registered UE's
flow apart. An AUTS that answers a challenge over the flow it was issued to
counts in the shared budget only, the flow having paid for the challenge. A
challenge or resynchronisation whose MAR never reached the HSS (no HSS task
connected) gives its counts and slot back; one the HSS
answered DIAMETER_TOO_BUSY, or that timed out, keeps them, so that the limit
does not loosen while the HSS is loaded. An
instance that saw a count over its limit refuses the rest of the window from
memory, without a write. Metrics `registrar.challenge_limited` and
`registrar.resync_limited` carry no identifier; the first is to be alarmed
on (`docs/scscf-state.md`).

**Risk left:**
- A subscriber with no live binding, registering for the first time or
  after its registration expired, has no flow of its own yet: a flood of
  some ten first registrations a minute from other flows, by anyone who
  knows its IMPI, holds that registration back until the flood stops. The
  alarm is the answer to it.
- So does a registered UE that reconnects: a switch between Wi-Fi and
  cellular, a NAT rebinding, or a P-CSCF drained on a deploy gives it a new
  connection and so a new flow token, which matches no live binding. Until
  the flood stops it cannot refresh, its old flow being gone, and its
  binding runs out. Before authentication the S-CSCF cannot tell it from
  the flood (a better signal is #246); hence the alarm, and no
  P-CSCF deploy or drain while it is raised.
- Likewise, forged AUTSs from other flows can use up the IMPI's three
  resynchronisations a lifetime, so a UE with no live binding whose SQN is
  out of step is refused until the flood stops; a registered UE on its flow
  resyncs on its own budget.
- While the HSS is slow (busy answers, timeouts), a UE's MARs keep their
  counts, so its flow's three a minute can run out sooner.
- Windows are fixed: twice a budget gets through across an edge.
- The shared count is observable: a client that probes it near a window's
  end learns from where it is refused whether others were challenged in that
  window, that is, roughly whether the subscriber's UE registered then. It
  learns nothing about the registered UE's own flow, which counts apart.
- The flow token is trusted as the P-CSCF wrote it, which rests on #198
  removing the client's Path and putting its own on top. A P-CSCF that let
  a client choose its Path, or anyone with access to the core listeners,
  could spend the registered UE's budget.

**Status:** implemented in `internal/scscf/registrar` (#201); wired to a
listener with `cmd/scscf` (#14 PR F).

