# rcs-as messaging core

`rcs-as` is the RCS messaging application server
([architecture](architecture.md) §2). This document describes its messaging
core: how 1-to-1 chat and standalone messages are accepted, stored, delivered
and answered with disposition notifications (IMDN, RFC 5438). The SIP side
(INVITE and MESSAGE handling, SDP, the third-party REGISTER from `scscf`) is a
later issue. The core is driven through interfaces so that it can be built and
tested first.

The code:

- `internal/rcsas/messaging`: the engine. It has no SIP and no AWS code.
- `internal/rcsas/store`: the `Store` interface, the memory backend and the
  contract test (`storetest`) that every backend passes.
- `internal/rcsas/awsstore`: the DynamoDB backend.
- `internal/rcsas`: the `RCSAS_` settings.

## How the SIP layer drives the engine

| SIP event | Engine call |
|---|---|
| A client's INVITE for a chat or large-mode session is answered (rcs-as answers `passive`, [ADR 0004](adr/0004-msrp-anchoring.md)) | `OpenLeg` with a zero `Local`: the answer carries the new leg's `Local()` as `a=path` |
| rcs-as starts a terminating session (`Deliverer.Invite`) | `LocalURI` for the `actpass` offer, then `OpenLeg` with that URI once the answer comes, or `InviteFailed` |
| `msrp-relay` connects to the MSRP listener | `Serve` / `ServeConn` binds the connection to the leg named in the To-Path |
| A pager-mode MESSAGE arrives (RFC 3428) | `Submit` with `Pager: true` and the `message/cpim` body |
| A registration, possibly on a new flow | `UserRegistered` |
| The BYE with `Reason: SIP;cause=488;text="MSRP direction not supported"` before any MSRP traffic (ADR 0004) | `InviteFailed` with `ErrNoSessions` |
| The SIP session ends | `Leg.Close` |

The SIP layer implements `Deliverer`:

- `Pager` sends one pager-mode MESSAGE and returns once it is answered.
  `ErrOffline` (not registered, or every contact failed with 430, [ADR
  0005](adr/0005-shared-state-and-instance-addressing.md)) keeps the message
  stored. `ErrUndeliverable` gives up on it.
- `Invite` starts a terminating session and returns without waiting for the
  answer. `ErrNoSessions` says the contact takes no terminating sessions on
  its current flow.

The SIP layer also reads the `Conversation-ID`, `Contribution-ID` and
`InReplyTo-Contribution-ID` headers with `ParseConversationHeaders`. It must
give `Origin.Sender` the identity the network asserted, never one the client
chose, and it must name each user in one canonical form (the queue and the
sent-message records are keyed by that string).

## The pipeline

Every message goes through the same steps, whether it arrived in an MSRP chat
session, a large-mode MSRP session or a pager-mode MESSAGE:

1. A pager-mode body larger than `RCSAS_PAGER_LIMIT` is refused.
2. The body must be `message/cpim` of at most `RCSAS_MAX_MESSAGE_SIZE` bytes
   and must parse (`internal/cpim`, `internal/imdn`). Layout deviations the
   parser tolerates are counted.
3. The sender's rate is checked: messages and notifications have separate
   token buckets, per task.
4. The CPIM `From` must be one of the sender's asserted identities or the
   anonymous URI `sip:anonymous@anonymous.invalid`, which RCS clients put in
   1-to-1 chat.
5. A message that asks for notifications gets a sent-message record
   (sender, Message-ID, recipients, dispositions asked for). It is kept for
   `RCSAS_SENT_TTL`. A resend with the same Message-ID to the same recipient
   is accepted, and clients drop the duplicate. The same Message-ID to someone
   else is refused.
6. The message is queued for its recipient and the recipient's queue is
   delivered.

A refused message is answered with a `Rejection`. Over MSRP its code is 413
for size, 415 for type, 400 for what does not parse, and 403 for the rest. A
store failure is an ordinary error, which MSRP answers with 403. Pager-mode
answers are the SIP layer's choice.

Content is forwarded byte for byte. The one change is in a notification whose
top `IMDN-Route` names rcs-as (`RCSAS_SELF_URIS`): that entry is removed
(RFC 5438 §8), and the notification is written in canonical form.

## Notifications

A notification is accepted only when all of these hold:

- the recipient of the notification (the original sender) has a sent-message
  record for its Message-ID;
- the identity that sent it is one of that message's recipients, or one of
  `RCSAS_IMDN_INTERMEDIARIES` reporting processing or a failed delivery (only
  the recipient can say a message was delivered or displayed);
- the original sender asked for that kind of notification.

Anything else is refused as `imdn_unknown`, `imdn_forged` or
`imdn_not_requested`. Without this check anyone could tell a sender that its
message was read or had failed ([threat model](threat-model.md)). A
notification is never answered with another one.

rcs-as generates a notification itself:

- when a message expires or is undeliverable, a negative delivery
  notification, if the sender asked for one;
- when the SIP layer reports a disposition (`Engine.Report`), for example for
  an interworking recipient.

These notifications are from the recipient. They answer the message's
`DateTime` verbatim and copy its `IMDN-Record-Route` into `IMDN-Route`
(RFC 5438 §7.2.1).

## Delivery

Each task has a fixed pool of delivery workers (`Workers`). A recipient's
queue is delivered by one worker at a time and oldest first. For each queued
message the worker does the first of these that applies:

1. **An open leg** of the recipient with the sender as peer, in the message's
   mode: the message is sent with `Success-Report: yes`. It is delivered once
   success reports cover the whole body. A failure report of 400, 403, 413 or
   415 gives up on it. Anything else (timeout, closed leg, other codes) leaves
   it queued. Notifications may use a chat leg or a standalone one.
2. **Pager mode**, for a notification, for a standalone message within the
   pager limit, and for a chat message within the pager limit to a recipient
   that takes no terminating sessions.
3. **A terminating session** (`Invite`), at most once per recipient, peer and
   mode within `RCSAS_INVITE_TIMEOUT` or until the next registration. The
   message stays queued and goes out when the leg opens.

A recipient that takes no terminating sessions (ADR 0004) gets what fits by
pager mode. Larger content waits for a session the client opens itself, or
for its next registration, until it expires. The marker is kept per task, and
the SIP layer may also return `ErrNoSessions` from `Invite` when it knows the
flow.

A failure that says the recipient is unreachable (`ErrOffline`, a failed leg)
stops the worker for that queue. A message that waits for a session of its
own does not stop it, so a large message does not hold up small ones behind
it. Queued messages are tried again on these events:

- a new message for the recipient;
- a registration;
- a leg opening;
- a failed invitation that marks the recipient pager-only.

Two tasks can deliver the same queue at once. Each message is claimed with a
conditional write before it is sent. The claim's lease is three times
`RCSAS_DELIVERY_TIMEOUT`, so it outlasts the attempt. Exactly one task wins
the claim, so a message goes out once. If a task loses its lease while
delivering, the message may go out twice. Clients drop the duplicate by
Message-ID.

`Run` sweeps every `RCSAS_SWEEP_INTERVAL`. It claims messages that have
expired after `RCSAS_STORE_TTL` and gives up on them. The negative
notification is queued before the message is removed, under an ID derived
from the message's. So a failure in between repeats the same queue item
rather than losing it.

## Settings

Shared `RCS_` settings are described in `internal/runtime`. The `RCSAS_`
settings:

| Variable | Default | Meaning |
|---|---|---|
| `RCSAS_MSRP_HOST` | required | This task's address in MSRP paths ([ADR 0005](adr/0005-shared-state-and-instance-addressing.md)) |
| `RCSAS_MSRP_LISTEN_ADDR` | `:2855` | MSRP listener for `msrp-relay`; its port is the advertised one |
| `RCSAS_MSRP_KEEPALIVE` | `240s` | Idle time before an empty SEND, below the NLB's 350 s TLS idle timeout ([ADR 0003](adr/0003-aws-topology.md)) |
| `RCSAS_STORE` | `dynamodb` | `dynamodb` or `memory` (refused in staging and prod) |
| `RCSAS_DYNAMODB_TABLE` | `messages` | Queue and sent-message table |
| `RCSAS_DYNAMODB_ENDPOINT` | AWS | Local containers only (refused in staging and prod) |
| `RCSAS_SELF_URIS` | none | URIs by which notifications are routed through rcs-as (`IMDN-Route`) |
| `RCSAS_IMDN_INTERMEDIARIES` | none | Identities that may send processing and failed-delivery notifications about any message |
| `RCSAS_MAX_MESSAGE_SIZE` | `262144` (256 KiB) | Largest CPIM body, at most 389120 with `dynamodb` (one item) |
| `RCSAS_PAGER_LIMIT` | `1300` | Largest body in pager mode, both ways |
| `RCSAS_STORE_TTL` | `168h` | How long an undelivered message is kept |
| `RCSAS_SENT_TTL` | `720h` | How long notifications about a sent message are accepted; at least `RCSAS_STORE_TTL` |
| `RCSAS_SENDER_RATE`, `RCSAS_SENDER_BURST` | `60`, `30` | Messages per minute and burst, per sender and task. `0` turns the limit off |
| `RCSAS_NOTIFICATION_RATE`, `RCSAS_NOTIFICATION_BURST` | `600`, `300` | The same for notifications. A client that comes back online answers each stored message with up to two |
| `RCSAS_DELIVERY_TIMEOUT` | `30s` | One delivery attempt: a pager request, or an MSRP send and its success report |
| `RCSAS_INVITE_TIMEOUT` | `2m` | How long an invitation is waited for before another is sent |
| `RCSAS_STORE_TIMEOUT` | `5s` | Each store call |
| `RCSAS_SWEEP_INTERVAL` | `1m` | How often expired messages are swept |

Durations use Go syntax (`168h`, not `7d`).

## DynamoDB `messages` table

There is one table with partition key `pk` and sort key `sk` (both strings).
`ttl` is the TTL attribute.

| Item | `pk` | `sk` |
|---|---|---|
| Queued message | `q#<len>#<recipient>` | queue ID: enqueue time in hex, then random |
| Sent-message record | `s#<len>#<sender>` | IMDN Message-ID |

- **Length prefix.** The identity's length goes in front, so that one identity
  can never be a prefix of another's key.
- **Partitions.** A recipient's queue is one partition, read in sort-key
  order, which is enqueue order.
- **Consistent reads.** Every read is strongly consistent.
- **Claims.** A claim is a conditional update: unclaimed, or the lease over.
  Release and removal are conditional on the claim's owner.
- **Expiry.** Items carry their own expiry and every read checks it. `ttl` is
  the expiry plus 7 days and only keeps the table small, because TTL deletion
  can lag by days.
- **Expired scan.** Finding expired messages scans the table, page by page,
  within `RCSAS_STORE_TIMEOUT`. An expiry index is the follow-up once the
  table grows (see below).

The task role needs these actions on the table:

- `dynamodb:GetItem`, `PutItem`, `UpdateItem`, `DeleteItem`;
- `dynamodb:Query`, `Scan`;
- `dynamodb:DescribeTable` (readiness).

`make test-integration` runs the store contract against DynamoDB Local. It also
runs two engines that share one table and must deliver each message once.

## Metrics and logs

Counts are written as CloudWatch EMF. The only dimension is `Service`, and no
identifier ever appears in a metric name.

| Metric | Counts |
|---|---|
| `message.accepted`, `message.accepted.notification`, `message.resent` | Accepted messages, notifications, resends |
| `message.rejected.<reason>` | Refusals: `too_large`, `rate_limited`, `content_type`, `malformed`, `from_mismatch`, `message_id_reused`, `imdn_malformed`, `imdn_unknown`, `imdn_forged`, `imdn_not_requested` |
| `cpim.rejected.<reason>` | The CPIM parser's reason for `malformed` (`internal/cpim` `Reason`) |
| `cpim.deviation.<name>` | Accepted layout deviations: `bare-lf`, `spacing`, `trailing-ws`, `empty-value` |
| `imdn.incomplete_request` | Messages asking for notifications without a Message-ID or DateTime; delivered without them |
| `delivery.msrp`, `delivery.pager`, `delivery.msrp_failed`, `delivery.pager_failed` | Delivery attempts |
| `delivery.refused`, `delivery.undeliverable`, `message.expired` | Messages given up on |
| `delivery.claimed_elsewhere` | A message another task held |
| `imdn.generated.<status>`, `imdn.generate_failed` | Notifications rcs-as generated |
| `invite.sent`, `invite.failed`, `invite.no_sessions`, `invite.untracked` | Terminating session requests |
| `leg.opened` | MSRP legs |
| `store.failed` | Store calls that failed |

Logs never carry message content. Identities appear only through
`internal/pii`. MSRP session ids never appear: they are capabilities ([threat
model](threat-model.md) T3).

Signals to alarm on (Phase 7):

| Signal | Meaning |
|---|---|
| `store.failed` > 0 | DynamoDB fails; messages are refused or stay queued |
| `message.rejected.imdn_forged` > 0 | Someone sends notifications about messages it did not receive |
| `invite.no_sessions` sustained | Clients answering `passive`; their large content waits (ADR 0004) |
| `message.expired` rising | Recipients unreachable for `RCSAS_STORE_TTL` |
| `invite.untracked` > 0 | More pending invitations than a task tracks (100 000); messages wait for the next event instead of an invitation |

## Assumptions and limitations

- **Conversation identifiers.** RCC.07 gives no grammar for them beyond SIP,
  so each must be one RFC 3261 token of at most 256 characters. Clients
  generate UUIDs or hex strings.
- **Legs are per task.** A message is delivered on a leg of the task that
  works on its queue. That holds for the B2BUA model, where both legs of a
  chat live on the task whose instance address the SIP dialog names (ADR
  0005). When a different task handles the queue, it asks for a new session.
- **Success reports.** A delivery over MSRP counts once success reports cover
  the whole body. A client that never sends them leaves the message queued
  until expiry, and RFC 4975 §7.1.2 requires them when asked.
- **Network-generated notifications are from the recipient.** That is how
  rcs-as can generate them on the recipient's behalf.
- **The rate limit is per task.** A sender spread over N tasks gets N times
  the rate.
- **No processing notifications.** rcs-as does not send "stored" processing
  notifications on its own.
- **No IMDN-Record-Route entry.** rcs-as does not add itself to
  `IMDN-Record-Route`, since content is forwarded unchanged and rcs-as is on
  the path of every notification anyway.
- **The answer and the relay race.** In a session rcs-as starts, the client
  connects to `msrp-relay` once it has answered, and the relay connects
  onward. That can happen before the answer has reached rcs-as through the
  CSCFs, and a request for a session that `OpenLeg` has not yet created is
  answered with 481. The SIP layer issue must close this gap, for example
  with a binder that waits briefly for a URI that `LocalURI` handed out.
- **Large-mode sessions.** The SIP layer ends a large-mode session once its
  message has been delivered. The engine does not decide that.
- **The expired scan reads the whole table.** That is fine for the first
  releases. An index on expiry (sparse, queue items only) is the follow-up
  before the table grows large.
- **Not checked against a licensed copy of RCC.07.** The anonymous CPIM
  `From` and `To` in 1-to-1 chat, and the IMDN behaviour of chat sessions,
  follow the public reference client (rcsjta).
