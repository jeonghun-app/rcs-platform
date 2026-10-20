# rcs-as messaging core

`rcs-as` is the RCS messaging application server
([architecture](architecture.md) §2). This document describes its messaging
core: how 1-to-1 chat, group chat and standalone messages are accepted,
stored, delivered and answered with disposition notifications (IMDN, RFC
5438), and how group chats are run ([Group chat](#group-chat)). Of the SIP
side, pager-mode MESSAGE is served ([The SIP layer](#the-sip-layer)); INVITE
and SDP, the group chat focus over SIP and the third-party REGISTER from
`scscf` come in later parts of #137. The core is driven through interfaces so
that it can be built and tested first.

The code:

- `internal/rcsas/messaging`: the engine. It has no SIP and no AWS code.
- `internal/rcsas/store`: the `Store` interface, the memory backend and the
  contract test (`storetest`) that every backend passes.
- `internal/rcsas/group`: the group chat focus: rules, rosters, and who a
  group message goes to. No SIP code either.
- `internal/rcsas/groupstore`: the groups' `Store` interface, memory backend
  and contract test.
- `internal/rcsas/awsstore`: the DynamoDB backends of both.
- `internal/rcsas/sipas`: the SIP layer: the proxy's `Router`, which serves
  what rcs-as terminates, and the engine's `Deliverer`.
- `internal/rcsas`: the `RCSAS_` settings and the service (`cmd/rcs-as`).

## How the SIP layer drives the engine

| SIP event | Engine call |
|---|---|
| A client's INVITE for a chat or large-mode session is answered (rcs-as answers `passive`, [ADR 0004](adr/0004-msrp-anchoring.md)) | `OpenLeg` with the offer's `a=path` and `Direction: Originating`; the answer carries the leg's `Local()` as `a=path` |
| `Deliverer.Invite` asks for a terminating session | `Offer` (`Direction: Terminating`, and the invitation's `QueueID` for large mode) for the `actpass` offer's `a=path`; then `Leg.Answer` with the answer's path, or `InviteFailed` and `Leg.Close` |
| `msrp-relay` connects to the MSRP listener | `Serve` / `ServeConn` binds the connection to the leg named in the To-Path |
| A pager-mode MESSAGE arrives (RFC 3428) | `Submit` with `Pager: true` and the `message/cpim` body |
| A registration | `UserRegistered`, saying whether it is on a new flow |
| The BYE with `Reason: SIP;cause=488;text="MSRP direction not supported"` before any MSRP traffic (ADR 0004) | `InviteFailed` with `ErrNoSessions` |
| A terminating large-mode leg is `Finished` | a BYE |
| The SIP session ends | `Leg.Close` |

The SIP layer implements `Deliverer`:

- `Pager` sends one pager-mode MESSAGE and returns once it is answered.
  `ErrOffline` (not registered, or every contact failed with 430, [ADR
  0005](adr/0005-shared-state-and-instance-addressing.md)) keeps the message
  stored. `ErrUndeliverable` gives up on it.
- `Invite` starts a terminating session and returns without waiting for the
  answer. `ErrNoSessions` says the contact takes no terminating sessions on
  its current flow.
- `Delivery.Route`, when set, is the next hop of a notification. The engine
  sets it only to one of the URIs in `RCSAS_TRUSTED_ROUTES`, compared exactly.
  The SIP layer never routes on IMDN headers of its own reading.
- `Delivery.SenderName` is display text the sender chose. It may be the
  display name of `From` only, never of `P-Asserted-Identity` or another
  header the network vouches for.

The SIP layer reads the `Conversation-ID`, `Contribution-ID` and
`InReplyTo-Contribution-ID` headers with `ParseConversationHeaders`.
Notifications in pager mode come without them (rcsjta), which gives an empty
`Conversation`. The SIP layer must give `Origin.Sender` the identity the
network asserted, never one the client chose. It must name each user in one
canonical form, since the queue and the sent-message records are keyed by
that string.

Legs offer and answer with `AcceptTypes(mode)`:

- chat: `message/cpim` and `application/im-iscomposing+xml`;
- large mode: `message/cpim`.

### The answer and the relay race

In a session rcs-as starts, the client connects to `msrp-relay` once it has
answered, and the relay connects onward at once. That can happen before the
answer has come back to rcs-as through the CSCFs.

`Offer` therefore makes the leg's session reachable before the answer:

- The relay's connection binds to the leg at once, and the client may already
  send on it.
- rcs-as sends nothing on the leg until `Answer` gives it the client's path.
  This uses the `msrp.SessionConfig.RemoteLater` option.
- An offer that gets no answer within `RCSAS_ANSWER_TIMEOUT` closes its leg.
  The default is 32 s, the INVITE transaction's limit.

## The SIP layer

`rcs-as` is a `proxy.Proxy` (`internal/sip/proxy`) on one TCP listener, which
only the core reaches ([ADR 0007](adr/0007-internal-transport.md) §2). Its
`Router` (`sipas.Server`) decides per request:

| Request | What rcs-as does |
|---|---|
| `MESSAGE` outside a dialog (pager mode, RFC 3428) | `Submit` with `Pager: true`, `Mode: Standalone`; answered as below |
| `MESSAGE` in a dialog | 481: pager mode has no dialog |
| `OPTIONS` | forwarded along its `Route`, back to `scscf`: the default profile hands it to `rcs-as` with SESSION_CONTINUED, and capability discovery must not stop there |
| anything else | 405 with `Allow: MESSAGE, OPTIONS`; INVITE comes with the next part of #137 |

A request that rcs-as originated itself and that comes back to it is answered
482 Loop Detected and counted (`sip.loop`). It is known by its `From` tag,
which starts with `rcsas-` on every task, so a request sent by one task and
returned to another is caught too. That happens when a profile sends rcs-as's
terminating requests to rcs-as again, lacking the default profile's
`P-Served-User` exclusion ([HSS](hss.md)); rcs-as would otherwise take its own
delivery for a new message and send it once more without end. A client that
writes such a tag only has its own request refused.

scscf hands rcs-as a request with the AS URI of the iFC on top of its `Route`
(TS 24.229 §5.4.3.2), `HSS_RCS_AS_URI` (`sip:rcs-as.<RCS_SERVICE_NAMESPACE>` by
default), and its own entry below. rcs-as takes as its own, and removes, a
`Route` naming its service name (`RCSAS_SERVICE_NAME`, which must be the host
of `HSS_RCS_AS_URI`) or its instance address (`RCSAS_SIP_HOST`), on
the listener's port or 5060, compared as written, before any DNS lookup. What
it forwards then goes on to `scscf` rather than to rcs-as again.

### Who sends, and to whom

The sender is the user the core asserted in `P-Asserted-Identity` (RFC 3325
§9.1), never a header the client wrote. rcs-as takes what pcscf asserts (#208):
one identity, or a SIP identity with the tel URI of its implicit registration
set (#16 decision 5), which are one user whether the SIP identity is a number
(`sip:+...@<domain>`) or a name (`sip:alice@<domain>`). A SIP identity whose
user part is a telephone number, at any host, with `user=phone` or without a
`user` parameter, must be the tel URI's number: otherwise a client could name
itself by a number it does not hold, in a CPIM `From` or a notification. A name,
or a number marked `user=ip`, pairs freely. The user is the tel URI when one is
asserted, and the SIP identity otherwise. More than two identities, two of one
scheme, or a SIP number other than the tel URI's are refused with 403 and counted (`sip.asserted.refused`), as is a MESSAGE with
none. Every asserted identity is one the sender may name in its CPIM `From`, in
any of the forms below, and a notification from the user finds a message
written to any of them. The recipient is the Request-URI.

Each user is named in one form (`messaging.UserOf`), since the queues, a sender's
share of them and the sent-message records are keyed by that string. A global
telephone number is `tel:+` and its digits (RFC 3261 §19.1.6), whether written
as a tel URI, as a SIP URI with `user=phone`, or as a SIP URI at the home
domain (`RCS_IMS_DOMAIN`) whose user part is the number, with or without
`user=phone`. The platform gives each subscriber `sip:+<E.164>@<domain>` and
`tel:+<E.164>` as one implicit registration set ([architecture](architecture.md)
§4), pcscf asserts either or both, and rcsjta addresses a peer as a tel URI or
as `sip:...;user=phone`. Any other identity is `identity.CanonicalIMPU`'s form.
So `tel:+1-555-0100`, `sip:+15550100@host;user=phone` and
`sip:+15550100@<domain>` are one user, holding one share, and a notification
sent to any of them finds the message. The engine compares the address a client
writes for itself, a CPIM `From` or an IMDN recipient, the same way. This is
rcs-as's key only: `scscf` keeps the SIP and tel URIs as two identities of the
set.

### Answers

| Outcome | Status |
|---|---|
| stored | 202 Accepted (RFC 3428 §7) |
| a `Require` option tag (rcs-as supports none for MESSAGE) | 420, with `Unsupported` (RFC 3261 §8.2.2.3) |
| an empty or unreadable `Require` | 400 |
| not `message/cpim` | 415, with `Accept: message/cpim` |
| no asserted identity, or not as above | 403 |
| a Request-URI that names no user | 404 |
| unreadable `Conversation-ID` or `Contribution-ID` | 400 |
| refused for its size / type / syntax (`Rejection`) | 413 / 415 / 400; the 415 without `Accept`, since the client sent `message/cpim` already |
| any other refusal (rates, queue full, forged or unrequested notification, ...) | 403 |
| the store busy after its retries (`store.ErrBusy`) | 500 with `Retry-After: 1` |
| any other store failure | 500 |

The busy store gets a 500, not a 503, because `scscf` is a proxy on the way
back: it would answer a 503 from rcs-as with a 500 of its own and drop the
`Retry-After` (RFC 3261 §16.7 step 6), while it passes a 500 on as it is,
`Retry-After` included (§20.33).

### What rcs-as sends

`Deliverer.Pager` sends a MESSAGE to `RCSAS_CORE_URI` (`scscf`), or through
the trusted `Delivery.Route` of a notification, as a terminating request for
the recipient: its `Route` has no `orig`, and it carries
`P-Served-User: <recipient>;sescase=term`. Every trigger of the default
profile excludes requests with that header ([HSS](hss.md)), so the request goes
on to the recipient's contacts, not back to `rcs-as`, which would store it and
send it again. It also carries:

- `P-Asserted-Identity: <sender>`, without a display name;
- `From` with the sender's CPIM name as its display name, escaped by the engine
  (`EscapeDisplayName`) and written as a quoted string, its backslashes escaped
  again;
- `P-Asserted-Service` and `Accept-Contact` with the standalone messaging ICSI
  (`urn:urn-7:3gpp-service.ims.icsi.oma.cpm.msg`);
- the conversation headers when the message has them, and the CPIM body as
  `message/cpim`.

The final status tells the engine what became of it: a 2xx delivered it; 404
or 604 is a recipient that does not exist (`ErrUndeliverable`); 408, 430, 480,
503, a next hop that cannot be resolved or a request that cannot be sent is a
recipient not reachable now (`ErrOffline`); any other status is a failure the
engine tries again later. A name in `RCSAS_CORE_URI` is looked up only inside
`RCS_SERVICE_NAMESPACE`, and only its private addresses are used ([ADR
0007](adr/0007-internal-transport.md) §5). A next hop written as an address must
be a private or loopback one too, for what rcs-as sends and for what it
forwards.

`Deliverer.Invite` fails until terminating sessions are served; the engine then
waits for the next invitation as after any failed one.

## The pipeline

Every message goes through the same steps, whether it arrived in an MSRP chat
session, a large-mode MSRP session or a pager-mode MESSAGE:

1. **Identities and size.**
   - The identities must be at most 256 bytes.
   - A pager-mode body larger than `RCSAS_PAGER_LIMIT` is refused, and so is a
     notification of that size, however it came.
2. **Parsing.**
   - The body must be `message/cpim` of at most `RCSAS_MAX_MESSAGE_SIZE` bytes
     and must parse (`internal/cpim`, `internal/imdn`).
   - IMDN Message-IDs must be at most 128 bytes.
   - Layout deviations the parser tolerates are counted.
3. **Rate.** The sender's rate is checked. Messages and notifications have
   separate token buckets, per task.
4. **CPIM From.** It must be one of the sender's asserted identities, or the
   anonymous URI `sip:anonymous@anonymous.invalid` that RCS clients put in
   1-to-1 chat. Identities are compared as written and in canonical form
   (`identity.CanonicalIMPU`), so `;user=phone` or a host's case does not make
   a client's own provisioned URI someone else's. It must also be the only header that a receiver could read as
   a From, and at most one header may read as a To: a second `From`, a `from`
   or `FROM`, a prefixed `x.From` (whatever namespace the prefix is bound
   to), a `From` after an NS header that changes the default namespace, and
   a content header named `From` or `To` are all refused as `malformed`. The
   message is forwarded unchanged, so a receiver that compares header names
   loosely or reads namespaces differently from `internal/cpim` would
   otherwise read a sender the engine never checked.
5. **Sent-message record.** A message that asks for notifications gets one:
   sender, Message-ID, recipients, the dispositions asked for. It is kept for
   `RCSAS_SENT_TTL`. A resend with the same Message-ID to the same recipient
   is accepted, and clients drop the duplicate. The same Message-ID to someone
   else is refused.
6. **Queueing.** The message is queued for its recipient and the recipient's
   queue is delivered.
   - Each queue holds at most `RCSAS_MAX_QUEUE_MESSAGES` messages and
     `RCSAS_MAX_QUEUE_BYTES` bytes, across tasks.
   - Each sender may hold `1/RCSAS_QUEUE_SENDER_SHARE` of either (an eighth
     by default). One sender therefore cannot fill a queue and lock the others
     out.
   - A 1-to-1 notification counts toward the queue but not toward a share.
     What one notifier can put in a queue is already bounded: it needs a
     message the queue's owner sent it, and is accepted once per kind. A
     recipient catching up answers each message with up to two. Group traffic
     has shares of its own (see [Fan-out](#fan-out)).
   - Beyond these bounds the message is refused as `queue_full` or
     `queue_share_full`, and the sender gets the negative delivery
     notification it asked for. A refusal from a full share affects that
     sender only.

A refused message is answered with a `Rejection`. Over MSRP its code is:

- 413 for size;
- 415 for type;
- 400 for what does not parse;
- 403 for the rest, which the client must not retry unchanged.

A message rcs-as could not store (the store failed) is answered over MSRP with
`StatusTryAgain` (500). RFC 4975 defines no code for a passing failure of the
receiver. A 5xx code is not one a client takes as a verdict on the message, so
the user can send it again. A write that kept meeting a concurrent transaction
on the same item (`store.ErrBusy`, see the DynamoDB notes) is answered with
`StatusBusy` (503) instead: it will go through a moment later. Pager-mode
answers are the SIP layer's choice: for `ErrBusy`, 500 with `Retry-After: 1`
(see [Answers](#answers)).

Content is forwarded byte for byte. The one change is in a notification whose
top `IMDN-Route` names rcs-as (`RCSAS_SELF_URIS`): that entry is removed
(RFC 5438 §8), and the notification is written in canonical form.

Is-composing indications (RFC 3994) in a chat session are not stored. Each
one goes, as it is, to the peer's open chat leg on the same task, under two
limits:

- one forwarded per leg at a time;
- 60 a minute per sending leg, with a burst of 5.

The rest are dropped. They are answered with 200 either way: the state they
report lasts seconds, and the reference client ends the session on a refusal.

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
message was read or had failed ([threat model](threat-model.md) T10).

Each notifier's notification of each kind is accepted once per message. The
record marks it with a conditional write. A repeat (a client's retransmission,
or a flood) is answered as accepted and dropped (`imdn.duplicate`). A mark
whose notification could not be queued is taken back, so the client's retry
goes through. A notification is never answered with another one.

rcs-as generates a notification itself:

- when a message expires, is undeliverable, or finds its queue full: a
  negative delivery notification, if the sender asked for one;
- when the SIP layer reports a disposition (`Engine.Report`), for example for
  an interworking recipient.

These notifications are from the recipient. They answer the message's
`DateTime` verbatim and copy its `IMDN-Record-Route` into `IMDN-Route`
(RFC 5438 §7.2.1). Only entries that are one of `RCSAS_TRUSTED_ROUTES` are
copied (`imdn.route_dropped` counts the rest). A client writes these headers,
and a route rcs-as followed blindly would let any subscriber pick where rcs-as
sends a request from inside the network (T10).

Whole URIs are compared, not hosts read out of them. A host check would have
to agree with every SIP parser the request later meets on these points:

- where a user part that holds `;` or `?` ends;
- what `maddr` does (it redirects the request, RFC 3261 §19.1.1);
- what URI headers such as `?Route=` add.

An exact list leaves nothing to interpret.

## Delivery

Each task has a fixed pool of delivery workers (`Workers`). A recipient's
queue is delivered by one worker at a time and oldest first. For each queued
message the worker does the first of these that applies:

1. **An open chat leg.** For a chat message or a notification: a chat leg of
   the recipient with the sender as peer.
   - The message is sent with `Success-Report: yes`. It is delivered once
     success reports cover the whole body.
   - A failure report of 400, 403, 413 or 415 gives up on it.
   - Anything else (timeout, closed leg, other codes) leaves it queued.
2. **Pager mode.** For a notification, for a standalone message within the
   pager limit, and for a chat message within the pager limit to a recipient
   that takes no terminating sessions.
3. **A terminating session** (`Invite`), at most once per recipient, peer and
   mode within `RCSAS_INVITE_TIMEOUT`, or until a registration on a new flow.
   - **Chat.** A chat session carries everything queued for it.
   - **Large mode.** A larger standalone message gets a large-mode session of
     its own, named by `Invitation.QueueID`. That leg delivers that message
     and nothing else, then is `Finished`, and the SIP layer ends the session.

A large-mode session the user opened (`Originating`) only carries what the
user sends. Nothing queued for the user goes on it.

A recipient that takes no terminating sessions (ADR 0004) gets what fits by
pager mode. Larger content waits for a session the client opens itself, or for
a registration on a new flow, until it expires. A refresh on the same flow
keeps the marker. The marker is kept per task, and the SIP layer may also
return `ErrNoSessions` from `Invite` when it knows the flow.

### When a queue is read again

What the last pass over a queue found decides what reads it again:

| Last pass | A new message | Reads the whole queue |
|---|---|---|
| Everything went | reads the queue (one read when nothing waits) | any new message, registration or leg |
| Messages wait for a session | is tried on its own | a leg opening, a registration on a new flow, a failed invitation that makes pager mode the way, the retry timer |
| The recipient was unreachable (`ErrOffline`, another pager failure, a failed leg) | waits; one that comes in while a pass runs is read once that pass gets through, and a pass of single messages that gets through has the whole queue read again | any registration, a leg, the retry timer |

The retry timer starts at `RCSAS_RETRY_INTERVAL` and doubles up to
`RCSAS_MAX_RETRY_INTERVAL` while the queue stays held. A recipient that never
comes back costs a read an hour, not one per message sent to it. The reads of
a queue grow with its messages, not with their square.

### Claims and shutdown

Two tasks can deliver the same queue at once. Each message is claimed with a
conditional write before it is sent. The claim's lease is three times
`RCSAS_DELIVERY_TIMEOUT`, so it outlasts the attempt. Exactly one task wins
the claim, so a message goes out once. If a task loses its lease while
delivering, the message may go out twice, and clients drop the duplicate by
Message-ID.

`Close` takes no new work, then lets the attempts in progress finish, for at
most a delivery and two store calls, before it cancels the rest. The store
calls that record an outcome survive the cancellation. A message delivered
during a rolling update is therefore removed, not left claimed for another
task to send again.

### Expiry

`Run` sweeps every `RCSAS_SWEEP_INTERVAL`. It claims messages that have
expired after `RCSAS_STORE_TTL` and gives up on them.

- **Order.** The negative notification is queued before the message is
  removed, under an ID derived from the message's. A failure in between
  therefore repeats the same queue item rather than losing it.
- **Paging.** Each sweep goes on from where the last one stopped (a cursor per
  task). Messages another task holds do not keep it from the ones after them.
- **Partial reads.** A read that fails part-way still hands over what it
  found.

## Group chat

`rcs-as` is the controlling function of RCC.07 Group Chat: a conference focus
that the conference factory URI reaches. Each group has a conference URI of its
own, `sip:chat-<128 random bits>@RCSAS_CONFERENCE_HOST`, and every participant
has a session with it: a leg of mode `group` whose peer is that URI.

Group mode is single-task for now: run it on one rcs-as task until
[#121](https://github.com/jeonghun-app/rcs-platform/issues/121) anchors each
group on one task (see [Assumptions and
limitations](#assumptions-and-limitations)).

### How the SIP layer drives it

| SIP event | Call |
|---|---|
| An INVITE to the conference factory, with a resource list | `group.Service.Create` (the creator is joined; the invitees are invited, and the SIP layer invites them). A list of more than `RCSAS_GROUP_MAX_PARTICIPANTS` entries is refused (`ErrTooMany`) before any entry is read; the SIP layer should bound the resource-list body it parses to about that many entries too |
| A participant's session with the group is set up (its INVITE, or its answer to the focus's) | `Join`, then `OpenLeg` / `Offer` and `Leg.Answer` with `Mode: store.Group` and the conference URI as `Peer`. If `Join` refuses, the session is refused and no leg opened |
| A BYE on that session | `Leave`, and `Leg.Close` |
| A 603 Decline to the focus's INVITE | `Leave`, not `InviteFailed`. The reference client declines the first INVITE of a group it left while offline (RCC.07 6.3.3.1; rcsjta `isGroupChatNextInviteRejected`), and accepts later ones as a new addition. Other failures stay `InviteFailed` |
| A REFER adding someone | `Add`. A list of more than `RCSAS_GROUP_MAX_PARTICIPANTS` − 1 is refused unread, as for `Create` |
| A REFER with `method=BYE` removing someone | `Remove`, then a BYE on the removed participant's session and `Leg.Close` |
| `Leave` or `Remove` succeeds | end that participant's subscriptions to the conference event package (a final NOTIFY with `Subscription-State: terminated`), so that it learns no later roster change |
| A SUBSCRIBE to the conference event package | `Roster`: the full document for the first NOTIFY |
| `Notifier.RosterChanged` | a NOTIFY with the document to each subscription |
| `Deliverer.Invite` with `Mode: store.Group` | an INVITE that brings the participant back into the group. The engine asks `Member` first, so it is only ever for a current participant |

### Rules

These are this implementation's reading of RCC.07 Group Chat and OMA CPM
group sessions. They have not been checked against the licensed texts.

| Operation | Who may | Conditions |
|---|---|---|
| Create | anyone | 1 to `RCSAS_GROUP_MAX_PARTICIPANTS` − 1 others; the creator becomes chairman, joined; rate per creator, and the invitees count toward its add rate |
| Join | a current (invited or joined) participant | someone who left or was removed must be added again; a joined participant joining again only updates its name, at its group rate |
| Leave | a current participant | the chairman's role passes to the participant joined longest (counted from its last join, not its first), else the one invited longest ago; the last one out ends the group |
| Add | a joined participant | within the size limit, at its add rate; current participants are left alone, former ones invited again. Someone the chairman removed is added back only by the chairman |
| Remove | the chairman | not itself (that is Leave); the target must be current |
| Write | a joined participant | at `RCSAS_GROUP_SENDER_RATE` per group, within a quarter of the group's fan-out budget and within the budget |
| Read the roster | a current participant | |

Every value is checked before anything is stored, and the roster documents are
built before each write, so that no request can store a group whose roster
cannot be written. A bad creator, subject or Conversation-ID refuses the
request (`invalid`); a bad invitee or name never does:

- **Identities** must be SIP or tel URIs that name a user, at most 255 bytes
  (`identity.MaxLength`), without `&` or `'`, which XML would escape in the
  roster. An invitee in `Create` or `Add` whose identity is not one is left
  out (`group.invitee_skipped`) and the others are invited; the SIP layer
  finds who was in the group returned. A list with nobody left is
  `invalid`.
  They are stored and compared in canonical form (`identity.CanonicalIMPU`,
  the form the HSS provisions): a SIP URI keeps its user part, loses its
  parameters and has its host in lower case; a tel URI is a global number
  without visual separators. One person added as `tel:+1-555-…` and joining
  as `tel:+1555…` is one participant. The SIP layer passes asserted
  identities in the same form, as the CSCFs assert them. The engine puts a
  group leg's `User`, and a group message's sender, in that form too, so a
  leg opened under another spelling still gets its participant's copies.
- **Names** are at most 100 bytes and **the subject** at most 256 bytes of
  UTF-8 that XML can carry, without control characters.
- **A name is one participant's, and never keeps anyone out.** A name that is
  too long, is not valid text, or that another participant, current or
  former, goes by, is dropped (`group.name_dropped`): `Create` and `Add` store
  that participant without a name, and `Join` keeps the name it had, if any,
  as a rename that is no change and uses none of the renaming rate. Without
  a name, its roster entry and the `From` of what it writes carry its
  identity alone. Names are first come, first served, and unverified. Names are not cut
  short, which could make two equal. They are compared without case, extra
  white space, and every character that shows as nothing (Unicode format
  characters and the other default-ignorable code points: bidirectional
  controls, zero-width characters, the soft hyphen, variation selectors,
  tags, Hangul fillers). The author's roster name is in the `From` of every
  group message, so one participant cannot pass for another by name. Names
  are not normalized (NFC), and look-alike letters of different scripts are
  not folded.
- **The Conversation-ID** is one RFC 3261 token of at most 256 characters, as
  in 1-to-1 chat.

### Fan-out

A message a joined participant writes goes through the same pipeline as 1-to-1
chat (size, CPIM parse, `From` check, per-sender rate). Then:

- **Rate and budget.** The group applies the sender's rate in this group and
  the group's fan-out budget, which counts one delivery per recipient. Each
  sender may use at most a quarter of the budget (`group.FanoutSenderShare`),
  in rate and in burst. Without that, one participant of a full group writing
  as fast as its own rate allows would use the whole budget, and the others'
  messages would be refused. The burst is sized so that a quarter of it still
  carries 10 messages in a row to a full group
  (`group.FanoutSenderMessages`): people send a few short messages in quick
  succession, and the reference client ends its session with the group when
  one is refused.
- **CPIM rewrite.** rcs-as builds the header block anew: `From`, the sender's
  asserted identity under its display name in the roster (not the one its
  client wrote), then `To`, the group, then every other header in its order.
  Any header a receiver could take for a `From` or `To` is left out, in any
  case, prefix or namespace, and both come before any NS header, so they are
  in the core namespace. It then queues one copy for every other current
  participant, invited ones included:
  - each copy has `Sender` = the group and `Author` = the writer;
  - each recipient's queue is bounded as in 1-to-1 chat, and a copy counts
    against its author's share of it, the same share the author's 1-to-1
    messages to that recipient use: one person holds one share of a queue,
    however many groups it writes in;
  - a full queue costs that recipient the copy, with the negative delivery
    notification if the author asked for one, and nobody else anything.
- **Delivery.** Each copy goes on the recipient's own session with the group,
  by its own worker:
  - a slow participant holds up its own queue only;
  - an absent one has its copy kept while the engine asks the SIP layer to
    bring it back (`Invite`, mode `group`), each time after asking the group
    (`GroupHandler.Member`) whether it is still a participant;
  - a copy for someone who is no longer a participant is given up
    (`delivery.not_participant`), with the negative delivery notification if
    the author asked for one. `Leave`, `Remove` and a refused `Join` tell the
    engine at once (`ParticipantLeft`), and it gives up that participant's
    copies from the group even while its session is still open. Another
    task finds out when it would invite the participant;
  - pager mode is never used, since a client cannot place a group message
    that arrives outside the group.
- **Is-composing.** Indications go to the joined participants' open sessions
  on this task, unstored, with `From` rewritten, at 60 a minute with a burst
  of 5 per participant and group. With no other session of the group open on
  the task, one is dropped without reading the group. rcsjta sends them wrapped in
  CPIM in a group; a bare one is wrapped.

### Notifications in a group

Each participant's delivery and display notifications are forwarded to the
author one by one, in the author's session with the group. They are not
aggregated: RFC 5438 §8.3 aggregation is optional and `internal/imdn` does not
decode it.

A group message that asks for notifications gets two sent-message records:

- the group's, keyed by the group and the Message-ID. It matches a
  notification sent in the group whatever form of the author's identity the
  notifier's client writes in its To, and holds the marks of the
  notifications accepted;
- the author's own, keyed by the author and naming the group. A notification
  sent outside the group finds it. rcsjta sends display notifications as a
  SIP MESSAGE to the author, with anonymous From and To, once the group
  session is gone (`ChatServiceImpl.sendGroupChatDisplayedDeliveryReport`).
  It also means that an author's Message-ID names one message: the same ID
  in a group and in a 1-to-1 message is refused as `message_id_reused`.

A notification, in the group or outside it, is accepted only when all of these
hold:

- the group's record of the message exists. It is read before the group, so
  a notification about nothing costs no read of the group's item;
- the notifier is one of the participants the message went to;
- its `recipient-uri`, if it has one, is the notifier's identity (or the
  anonymous URI): no participant reports for another;
- the author asked for that kind;
- it is the first of its kind from that notifier, whichever way it came.

It goes to the author in the group. Its header block is rebuilt as for a
message: `From` the notifier's asserted identity and `To` the author, as the
group's record names it, whatever the notifier wrote there. A client takes a
notification in a group only when it is `To` itself (rcsjta).

Every message an author writes is answered by every other participant, up to
twice. So the notifications about one group's messages in a queue, from any
notifier, share one sender's share of it (`#group-notifications <group>`, an
eighth by default), so that one busy group does not crowd out another's. All
group notifications in a queue together, from every group, hold at most a
quarter of it (`#group-notifications`, 250 by default): an author in many
large groups is not locked out of 1-to-1 messages by receipts. A notification
beyond its group's share or the total is taken (200), not refused: the
reference client ends its session with the group when one is refused.

What does not fit is summarized, not lost (#166). The group's sent-message
record already holds a mark for every notification accepted, with the status
it reported, so it is the summary; the author's queue gets one **summary item**
per message (queue ID `r-<Message-ID>`, no body). Summaries count toward no
share and not toward the notifications' total, but toward a total of their own:
all of a queue's summaries hold at most an eighth of it (`#group-summaries`,
125 by default). Notifications and summaries together thus leave at least
five-eighths of the queue to 1-to-1 messages.

When the summary is delivered, on the author's session with the group, rcs-as
reads the record and sends, for each participant that reported, its strongest
notification (display before delivery before processing) as a notification of
its own: `From` the participant, `To` the author, the message's `DateTime`
echoed. The reference client takes notifications in a group only that way: one
`message/imdn+xml` per CPIM message, the status the `From`'s
(`GroupChatSession`); it ignores an RFC 5438 §8.3 aggregate
(`multipart/mixed`). The MSRP reports they ask for:

- all but the last: `Failure-Report: no` and no `Success-Report`, so they cost
  no round trip;
- the last: `Success-Report: yes` and `Failure-Report` left out (yes), like any
  queued message. One session delivers in order over one connection, so its
  success report says every one of them reached the client.

That is a transport guarantee: nothing was lost on the way. It does not say
the client took each one, since a client that refuses one in the middle sends
no report for it under `Failure-Report: no`. Neither the reference client nor
msrp-relay refuses a single notification within a session.

The summary is removed only once that report says 200, and only if no
notification was marked since the record was read (the record counts its
marks). Any other answer, no answer within `RCSAS_DELIVERY_TIMEOUT`, or the
session ending releases it for the next attempt. New marks release it too, and
it goes again at once, to the participants whose notification changed since
the last pass the client confirmed (the task remembers, up to
`Config.MaxTracked` summaries); the author's client takes a repeat as the same
status. A removal that fails otherwise releases it for the queue's retry.
A busy store (`store.ErrBusy`, writes to the record that kept conflicting)
does not count against it, since those writes are mostly the marks
themselves. After three other failures in a row, the record is read again:
if notifications were merged into the summary since the pass read it, the
count starts over and the summary goes again with them. Otherwise it is given
up (`group.summary.abandoned`). A summary expires with the record
(`RCSAS_SENT_TTL`), without a notification. A notification is dropped
(`group.notification.dropped`) only when the summaries' total or the queue
itself is full.

Notifications rcs-as generates (expiry, full queue) go to the author the same
way, from the recipient.

### Roster events

The roster is a conference-info document (RFC 4575, `internal/conference`)
with one user per participant, current or former, and one endpoint each:

| Participant | Endpoint status | Disconnection method |
|---|---|---|
| invited | `dialing-out` | |
| joined | `connected` | |
| left | `disconnected` | `departed` |
| removed | `disconnected` | `booted` |

A group keeps at most as many former participants as
`RCSAS_GROUP_MAX_PARTICIPANTS`, and fewer where that many could take the roster
beyond 256 KiB (`conference.MaxDocumentSize`, what `internal/conference` reads
back). Beyond that, whoever left longest ago leaves the roster, as a
`state="deleted"` user in the partial document of the change that pushed it
out; those who left go before those who were removed. A removed participant
that leaves the roster is still kept, identity only, in the group's
`removed` list (up to 200, oldest forgotten first), which is not part of the
roster: only the chairman adds them back, however many have left since.

The roster's size is bounded by the limits, not checked as it grows, so that no
Leave or Remove can be refused for it. When the service starts, it builds the
largest full document its limits allow: every identity at 255 bytes, every name
at 100 bytes of `&` (each escaped to `&amp;`), the longest subject, role and
endpoint. That is about 1.2 KB a participant. It keeps as many former
participants as fit with a full group (100 for a group of 100, 9 for a group of
200) and refuses a size limit whose current participants alone would not fit.
A partial document never holds more than the full one.

Former participants are in the roster that every current participant reads,
including those who join after they left. So someone who joins a group learns
the identities and names of people who were in it before, up to that limit, as
clients show who left. This is RFC 4575's model of a conference roster. It is
communication metadata (threat model T11).

The roles are `chairman` and `participant`. Creating a group produces a full
document at version 1. Every change after that writes the group conditionally
on the revision it was computed from (`groupstore.Store.Update`) and raises the
version by exactly one. Two tasks changing one group therefore never lose a
change and never reuse a version.

Each change is sent as a partial document: `<users state="partial">` with each
changed user whole (`state="full"`), which RFC 4575 §4.6 merges by entity.
Versions count per group across tasks, so a subscription that misses one sees
the gap and refreshes for a full document. A task that stops between writing a
change and notifying it leaves exactly such a gap.

## Settings

Shared `RCS_` settings are described in `internal/runtime`. rcs-as needs
`RCS_IMS_DOMAIN`, the home domain at which a SIP URI names a telephone number
([Who sends, and to whom](#who-sends-and-to-whom)). The `RCSAS_` settings:

| Variable | Default | Meaning |
|---|---|---|
| `RCSAS_MSRP_HOST` | required | This task's address in MSRP paths ([ADR 0005](adr/0005-shared-state-and-instance-addressing.md)) |
| `RCSAS_MSRP_LISTEN_ADDR` | `:2855` | MSRP listener for `msrp-relay`; its port is the advertised one |
| `RCSAS_SIP_LISTEN_ADDR` | `0.0.0.0:5060` | SIP listener (TCP), which only the core reaches; port 0 is refused, since the HSS's AS URI names a fixed port |
| `RCSAS_SIP_HOST` | the task's one private IPv4 address | This task's address, in the Via and Call-ID of what it sends ([ADR 0005](adr/0005-shared-state-and-instance-addressing.md)) |
| `RCSAS_CORE_URI` | `sip:scscf.<RCS_SERVICE_NAMESPACE>;transport=tcp;lr` | Where rcs-as sends the requests it originates: a SIP URI of a host with `transport=tcp` and `lr`, a private or loopback address or a name inside the namespace. Required without `RCS_SERVICE_NAMESPACE` |
| `RCSAS_SERVICE_NAME` | `rcs-as.<RCS_SERVICE_NAMESPACE>`, none without a namespace | The host of the AS URI the iFC name rcs-as by (`HSS_RCS_AS_URI`), which rcs-as takes as its own in a `Route`. Change both together, or an OPTIONS scscf hands rcs-as comes back to it (482) |
| `RCSAS_MSRP_KEEPALIVE` | `240s` | Idle time before an empty SEND, below the NLB's 350 s TLS idle timeout ([ADR 0003](adr/0003-aws-topology.md)) |
| `RCSAS_STORE` | `dynamodb` | `dynamodb` or `memory` (refused in staging and prod) |
| `RCSAS_DYNAMODB_TABLE` | `messages` | Queue and sent-message table |
| `RCSAS_DYNAMODB_ENDPOINT` | AWS | Local containers only (refused in staging and prod) |
| `RCSAS_SELF_URIS` | none | URIs by which notifications are routed through rcs-as (`IMDN-Route`) |
| `RCSAS_TRUSTED_ROUTES` | none | The URIs, compared exactly, a notification may be routed through: the platform's own application servers and CSCFs, as they write themselves into `IMDN-Record-Route`. With none, no IMDN route is followed |
| `RCSAS_IMDN_INTERMEDIARIES` | none | Identities that may send processing and failed-delivery notifications about any message |
| `RCSAS_MAX_MESSAGE_SIZE` | `262144` (256 KiB) | Largest CPIM body. At most 389120 with `dynamodb` (one item) |
| `RCSAS_PAGER_LIMIT` | `1300` | Largest body in pager mode, both ways, and largest notification |
| `RCSAS_MAX_QUEUE_MESSAGES` | `1000` | Messages one recipient's queue holds |
| `RCSAS_MAX_QUEUE_BYTES` | `16777216` (16 MiB) | Bytes one recipient's queue holds. At least `RCSAS_MAX_MESSAGE_SIZE` |
| `RCSAS_QUEUE_SENDER_SHARE` | `8` | Each sender may hold this fraction (1/N) of a queue's messages and bytes. `1` lets one sender fill it. `RCSAS_MAX_QUEUE_BYTES` / N must be at least `RCSAS_MAX_MESSAGE_SIZE` |
| `RCSAS_STORE_TTL` | `168h` | How long an undelivered message is kept |
| `RCSAS_SENT_TTL` | `RCSAS_STORE_TTL` + `24h` | How long notifications about a sent message are accepted, and how long the record of who wrote to whom is kept. At least `RCSAS_STORE_TTL` |
| `RCSAS_SENDER_RATE`, `RCSAS_SENDER_BURST` | `60`, `30` | Messages per minute and burst, per sender and task. `0` turns the limit off |
| `RCSAS_NOTIFICATION_RATE`, `RCSAS_NOTIFICATION_BURST` | `600`, `300` | The same for notifications. A client that comes back online answers each stored message with up to two |
| `RCSAS_DELIVERY_TIMEOUT` | `30s` | One delivery attempt: a pager request, or an MSRP send and its success report |
| `RCSAS_INVITE_TIMEOUT` | `2m` | How long an invitation is waited for before another may be sent |
| `RCSAS_ANSWER_TIMEOUT` | `32s` | How long an offered leg waits for its answer |
| `RCSAS_RETRY_INTERVAL`, `RCSAS_MAX_RETRY_INTERVAL` | `1m`, `1h` | First and longest wait before a held queue is read again |
| `RCSAS_STORE_TIMEOUT` | `5s` | Each store call |
| `RCSAS_SWEEP_INTERVAL` | `1m` | How often expired messages are swept |
| `RCSAS_CONFERENCE_HOST` | required | Host of the conference URIs the focus allocates; must route to `rcs-as` |
| `RCSAS_GROUPCHATS_TABLE` | `groupchats` | Groups table, with `RCSAS_STORE=dynamodb` |
| `RCSAS_GROUP_MAX_PARTICIPANTS` | `100` | Current participants of one group, at most 200. Former participants are kept up to the same number, fewer above 104, so that the roster stays within 256 KiB (see [Roster events](#roster-events)) |
| `RCSAS_GROUP_IDLE_TTL` | `720h` | A group not used for this long ends |
| `RCSAS_GROUP_SENDER_RATE`, `RCSAS_GROUP_SENDER_BURST` | `60`, `30` | Messages per minute one participant writes in one group, per task; also renames |
| `RCSAS_GROUP_FANOUT_RATE`, `RCSAS_GROUP_FANOUT_BURST` | `6000`, 4 × 10 × (`RCSAS_GROUP_MAX_PARTICIPANTS` − 1) (`3960` for 100), at least `1000` | Deliveries per minute one group makes, a message counting once per recipient, per task. One sender may use a quarter of the rate and of the burst, and a quarter of the burst must cover 10 messages to a full group. With the defaults, one sender in a full group of 100 may send 10 messages at once and then 15 a minute; in a full group of 200, 10 at once and then 7 a minute |
| `RCSAS_GROUP_ADD_RATE`, `RCSAS_GROUP_ADD_BURST` | `30`, `100` or `RCSAS_GROUP_MAX_PARTICIPANTS` − 1 if more | Participants one user adds per minute, in groups it creates too. The burst must cover a full group's invitees, so that the largest group can be created at once |
| `RCSAS_GROUP_CREATE_RATE`, `RCSAS_GROUP_CREATE_BURST` | `5`, `10` | Groups one user creates per minute |

A rate of `0` turns that limit off.

Durations use Go syntax (`168h`, not `7d`).

## DynamoDB `messages` table

There is one table with partition key `pk` and sort key `sk` (both strings).
`ttl` is the TTL attribute.

| Item | `pk` | `sk` |
|---|---|---|
| Queued message | `q#<len>#<recipient>` | queue ID: enqueue time in hex, then random |
| Queue size | `c#<len>#<recipient>` | `n` |
| A sender's share of a queue | `c#<len>#<recipient>` | `s#<len>#<sender>` |
| Sent-message record | `s#<len>#<sender>` | IMDN Message-ID; for a group message, one under the group and one under the author, which names the group (`group`) |

There is one global secondary index, `expiry`:

- partition key `xb` (string), sort key `expires` (number);
- projection `INCLUDE` of `owner` and `lease_until`.

The table's properties:

- **Length prefix.** The identity's length goes in front, so that one identity
  can never be a prefix of another's key.
- **Partitions.** A recipient's queue is one partition, read in sort-key
  order, which is enqueue order.
- **Bounds.** The queue's size item and the sender's share item count messages
  and bytes. Both are written in the same transaction as each enqueue and
  removal, and the enqueue is conditional on both bounds. A 1-to-1
  notification has no share item. A group message counts in its author's
  share item, a group notification in its group's, named
  `#group-notifications <group>`, and in the total of all group notifications,
  `#group-notifications`; a summary only in the total of summaries,
  `#group-summaries`. No identity can be any of these. An enqueue moves a size
  item's TTL to its message's, which
  only lengthens it, since messages are enqueued in time order with one
  lifetime. A removal leaves the TTL alone. Each queue item
  carries its own `size`. The SDK's idempotency token makes its own retry of a
  transaction safe.
- **Drift.** The sizes are kept by rcs-as, so a queue item deleted another way
  (by DynamoDB's TTL, or by hand) would count until it was corrected. An
  enqueue that a bound refuses therefore counts the queue once (a consistent
  query of the partition, projecting what decides an item's share and its
  size). It lowers each size
  item that says more than it found, conditional on the item being unchanged
  since it was read, and tries the enqueue again. A count reads the whole
  partition, so each queue is counted at most once per 10 minutes: a
  conditional update of `recounted_at` on the queue's size item decides which
  task counts, and later refusals within the interval are not counted.
- **Expiry index.** Only queue items carry `xb`, one of 16 values chosen by
  recipient. The index is sparse and spreads its writes. A sweep queries it
  bucket by bucket instead of reading the table.
- **Consistent reads.** Every table read is strongly consistent. Index reads
  cannot be, and need not be, since the claim checks again.
- **Claims.** A claim is a conditional update: unclaimed, or the lease over.
  Release and removal are conditional on the claim's owner. A repeat of a
  write that took effect succeeds:
  - a claim by the same owner with the same lease;
  - a release of a message no one holds;
  - a removal of a message already gone.
- **Notifications seen.** A sent-message record holds a map of the
  notifications accepted. Each entry is set with a condition and holds the
  token of the attempt that set it and the status it reported; `marks` counts
  the entries ever set, in the same update, and only grows. A group
  message's record also holds its `datetime`.
- **Summaries.** A summary is a queue item with `summary` set and no body. Its
  removal is one transaction: the `Delete`, the queue size, the summaries'
  total, and a `ConditionCheck` that the sent-message record's `marks` is the
  count the summary was expanded from, or that the record is gone.
- **Transaction conflicts.** While that transaction runs, DynamoDB refuses a
  notifier's mark on the same record with `TransactionConflictException`, and
  cancels a transaction that meets another with the reason
  `TransactionConflict`; the SDK retries neither. `MarkNotified` and
  `RemoveSummary` try such a write three times at most, 10–20 ms and then
  20–40 ms apart, and then report `store.ErrBusy`. A repeated mark is safe:
  the same token is the attempt's own.
- **Expiry.** Items carry their own expiry and every read checks it. `ttl` is
  only the backstop that keeps the table small, because TTL deletion can lag
  by days:
  - for queue and size items: the expiry plus one day;
  - for sent-message records: their expiry.

The task role needs these IAM actions:

| Action | Resource | Used by |
|---|---|---|
| `dynamodb:GetItem` | table | `Sent`; reads after a refused conditional write; recounts |
| `dynamodb:PutItem` | table | `RecordSent`, and the `Put` inside the enqueue transaction |
| `dynamodb:UpdateItem` | table | `Claim`, `Release`, `MarkNotified`, `UnmarkNotified`, size corrections, and the `Update`s inside both transactions |
| `dynamodb:DeleteItem` | table | the `Delete` inside the removal transactions |
| `dynamodb:ConditionCheckItem` | table | the `ConditionCheck` inside a summary's removal |
| `dynamodb:Query` | table | `Pending`, recounts |
| `dynamodb:Query` | `<table ARN>/index/expiry` | `Expired` |
| `dynamodb:DescribeTable` | table | readiness |

There is no IAM action for a transaction itself. Each item inside one is
allowed by the action of its kind (`PutItem`, `UpdateItem`, `DeleteItem`,
`ConditionCheckItem`).

`make test-integration` runs the store contract against DynamoDB Local. It
also runs two engines that share one table and must deliver each message
once.

## DynamoDB `groupchats` table

The `groupchats` table has the same key schema as `messages` (`pk`, `sk`,
TTL attribute `ttl`) and no index. Each group is one item:

| `pk` | `sk` |
|---|---|
| `g#<len>#<conference URI>` | `group` |

- **Contents.** The item holds the subject, creator, Conversation-ID, roster
  version, times, the participants as a list, and the identities of removed
  participants the roster no longer lists (`removed`, at most 200). A group of 100 is about 15
  KB, and the item limit is 400 KB. A group holds at most 400 participants,
  current and former, which is about 340 KB with every field at its longest
  (`groupstore.MaxEntries`; `RCSAS_GROUP_MAX_PARTICIPANTS` is therefore at most
  200).
- **Writes.** Every change rewrites the item on the condition that its `rev`
  is the one the change was computed from. A token (`wtoken`) tells a repeat
  of the write from another writer's; `Create` uses one too.
- **Touch.** At most once an hour per task, and not within an hour of a
  change, a group in use has its `active`, `expires` and `ttl` moved forward,
  without changing `rev`. The update is conditional on the stored `active`
  being older, so a touch that arrives after a later write (which may have
  ended the group) changes nothing. Creating a group and every change set
  `expires` to `RCSAS_GROUP_IDLE_TTL` from then.
- **Expiry.** `ttl` is the group's expiry plus a day; every read checks the
  expiry itself.
- **IAM.** The task role needs `GetItem`, `PutItem`, `UpdateItem` and
  `DescribeTable` on the table.

Each group message costs one strongly consistent read of the group item and,
per recipient, the enqueue transaction of the `messages` table. The fan-out
budget bounds that per group. A notification costs a read of its sent-message
record first, and of the group item only when the record exists; an
is-composing indication reads the group item only when another participant
has a session with the group on the same task, within its rate.

## Metrics and logs

Counts are written as CloudWatch EMF. The only dimension is `Service`, and no
identifier ever appears in a metric name.

| Metric | Counts |
|---|---|
| `message.accepted`, `message.accepted.notification`, `message.resent` | Accepted messages, notifications, resends |
| `sip.message.<status>` | Pager-mode MESSAGEs rcs-as answered, by status |
| `sip.asserted.refused` | Requests whose `P-Asserted-Identity` is not one user's, as pcscf asserts it, refused with 403 |
| `sip.pager.<status>`, `sip.pager.timeout`, `sip.pager.unsent`, `sip.pager.unresolved` | MESSAGEs rcs-as sent, by final status, and those that got none, could not be sent or found no next hop |
| `sip.loop` | Requests rcs-as originated that came back to it, answered 482 |
| `sip.refused.method`, `sip.respond_failed`, `sip.invite.unserved` | Requests of a method rcs-as does not take, answers the transport did not take, invitations not sent |
| `message.rejected.<reason>` | Refusals: `too_large`, `rate_limited`, `content_type`, `malformed`, `from_mismatch`, `message_id_reused`, `queue_full`, `queue_share_full`, `imdn_malformed`, `imdn_unknown`, `imdn_forged`, `imdn_not_requested` |
| `cpim.rejected.<reason>` | The CPIM parser's reason for `malformed` (`internal/cpim` `Reason`) |
| `cpim.deviation.<name>` | Accepted layout deviations: `bare-lf`, `spacing`, `trailing-ws`, `empty-value` |
| `imdn.incomplete_request` | Messages asking for notifications without a Message-ID or DateTime; delivered without them |
| `imdn.duplicate` | Notifications dropped as repeats |
| `imdn.route_untrusted`, `imdn.route_dropped` | IMDN routes not followed: in a forwarded notification, and in a generated one's record route |
| `delivery.msrp`, `delivery.pager`, `delivery.msrp_failed`, `delivery.pager_failed` | Delivery attempts |
| `delivery.refused`, `delivery.undeliverable`, `delivery.notification_too_large`, `delivery.not_participant`, `message.expired` | Messages given up on; `not_participant`: group copies for someone no longer in the group |
| `delivery.claimed_elsewhere` | A message another task held |
| `imdn.generated.<status>`, `imdn.generate_failed`, `imdn.dropped.queue_full` | Notifications rcs-as generated, could not build, or could not queue |
| `invite.sent`, `invite.failed`, `invite.no_sessions`, `invite.untracked` | Terminating session requests |
| `leg.opened`, `leg.unanswered` | MSRP legs, and offers that got no answer |
| `iscomposing.forwarded`, `iscomposing.dropped` | Is-composing indications |
| `msrp.accept_failed` | Failed accepts on the MSRP listener |
| `store.failed` | Store calls that failed |
| `group.created`, `group.roster_changed`, `group.update_conflict`, `group.touched` | Group lifecycle |
| `group.rejected.<reason>` | Group operations refused: `not_participant`, `not_chairman`, `too_many`, `invalid`, `rate_limited` |
| `group.name_dropped`, `group.invitee_skipped` | Names stored as none (too long, not text, or someone else's), and invitees left out for an identity the group cannot hold |
| `group.notification.summarized`, `group.summary.expanded`, `group.summary.sent`, `group.summary.abandoned` | Notifications that went to a summary for want of room, summaries delivered, the notifications they sent, and summaries given up after three failed removals with nothing new to send |
| `group.message.accepted`, `group.notification.accepted`, `group.notification.dropped`, `group.fanout.deliveries`, `group.fanout.queue_full`, `group.fanout.timed_out`, `group.fanout_budget_exceeded`, `group.fanout_share_exceeded` | Group messages; `dropped` counts notifications taken but neither queued nor summarized, the summaries' total or the queue being full; `share_exceeded` messages refused for their sender's quarter of the budget; `timed_out` recipients a message was not queued for within `FanoutTimeout` |

Logs never carry message content. Identities appear only through
`internal/pii`. MSRP session ids never appear: they are capabilities ([threat
model](threat-model.md) T3).

Signals to alarm on (Phase 7):

| Signal | Meaning |
|---|---|
| `store.failed` > 0 | DynamoDB fails; messages are refused or stay queued |
| `message.rejected.imdn_forged` > 0 | Someone sends notifications about messages it did not receive |
| `message.rejected.queue_full` sustained | A recipient is away much longer than usual, or flooded by many senders |
| `message.rejected.queue_share_full` sustained | One sender keeps writing to a recipient who does not take its messages: a flood |
| `imdn.route_untrusted`, `imdn.route_dropped` > 0 | Clients write IMDN routes; check `RCSAS_TRUSTED_ROUTES` if a partner network expects them followed |
| `invite.no_sessions` sustained | Clients answering `passive`; their large content waits (ADR 0004) |
| `message.expired` rising | Recipients unreachable for `RCSAS_STORE_TTL` |
| `msrp.accept_failed` > 0 | The MSRP listener ran out of file descriptors or the like |
| `sip.loop` > 0 | A profile sends rcs-as's own requests back to it: it lacks the `P-Served-User` exclusion ([HSS](hss.md)), and those users' messages are not delivered |
| `invite.untracked` > 0 | More pending invitations than a task tracks (100 000); messages wait for the retry timer instead of an invitation |
| `group.fanout_budget_exceeded` sustained | A group writing beyond its budget: a flood, or the budget is too small for real groups |
| `group.fanout_share_exceeded` sustained | One participant writing to a large group as fast as it may: a flood |
| `group.rejected.rate_limited` sustained | Users creating groups or adding people faster than allowed: mass-add spam |

## Assumptions and limitations

- **Conversation identifiers.** RCC.07 gives no grammar for them beyond SIP,
  so each must be one RFC 3261 token of at most 256 characters. Clients
  generate UUIDs or hex strings.
- **Legs are per task.** A message is delivered on a leg of the task that
  works on its queue. That holds for the B2BUA model, where both legs of a
  chat live on the task whose instance address the SIP dialog names (ADR
  0005). When a different task handles the queue, it asks for a new session.
  Is-composing indications reach a peer on the same task only.
- **Success reports.** A delivery over MSRP counts once success reports cover
  the whole body. A client that never sends them leaves the message queued
  until expiry. RFC 4975 §7.1.2 requires them when they are asked for, and the
  reference client sends them.
- **Network-generated notifications are from the recipient.** That is how
  rcs-as can generate them on the recipient's behalf.
- **Notifications are accepted for `RCSAS_SENT_TTL`.** A display notification
  for a message read more than a day after it could have expired is refused
  as `imdn_unknown`.
- **Per-task state.** The rate limit, the pager-only marker and the retry
  timers are per task. A sender spread over N tasks gets N times the rate.
- **No processing notifications.** rcs-as does not send "stored" processing
  notifications on its own.
- **No IMDN-Record-Route entry.** rcs-as does not add itself to
  `IMDN-Record-Route`, since content is forwarded unchanged and rcs-as is on
  the path of every notification anyway.
- **The 500 for store failures, and the 503 for a busy store.** RFC 4975
  defines neither (see the pipeline). How clients other than the reference one
  treat them is unverified.
- **The queue size is kept by rcs-as.** A queue item that DynamoDB's TTL
  deletes, because no sweep reached it, still counts until the next refusal
  recounts the queue.
- **Group delivery is per task like 1-to-1 chat.** A participant's session
  with a group lives on the task its SIP dialog names, and group mode needs
  them all on one (below). Is-composing reaches only participants on the same
  task. The delivery workers are shared, so more slow participants than
  `Workers` (32) at once slow everyone, by up to `RCSAS_DELIVERY_TIMEOUT`
  each.
- **Receipts for an offline author come back summarized.** While the author has
  no session, its queue keeps at most a share (125 by default) of one group's
  notifications, and 250 of all groups' together; the rest are summarized
  (#166), one summary per message, 125 at most. Beyond that, receipts are
  dropped as before: an author offline while more than 125 of its messages
  get receipts beyond the caps sees only some of them read by all. One message to a full group of 100 that asks for both kinds is
  answered with 198: 125 are queued, and once back the author also gets the
  summary's 99, each participant's strongest, so the reference client shows
  the message read by all (`GroupChatImpl.isDisplayedByAllRecipients`). The
  author may get a participant's notification twice; a delivery notification
  that a display one made redundant is not sent again.
- **Group fan-out is sequential.** A group message is queued for its
  recipients one enqueue transaction after another, on the sender's session,
  before the sender's answer. A message to 99 others at 10 ms an enqueue takes
  about a second. Past 20 s (`Config.FanoutTimeout`, within the 30 s an MSRP
  client waits) the remaining recipients are left out
  (`group.fanout.timed_out` counts them), and the sender gets `StatusTryAgain`.
  The reference client does not resend by itself: it marks the message failed
  and ends its session with the group, and the user may send it again.
  Recipients that already have it drop the repeat by Message-ID. Each message
  starts at a random recipient, so the ones left out are not the same every
  time. Other sessions are not held up.
- **Leaving is known per task.** The task that ran `Leave` or `Remove` gives up
  that participant's queued copies at once. Another task gives them up only
  when it would invite the participant back, so a session the SIP layer has
  not ended yet may still carry them there. A client that takes no sessions
  has its copies given up when it registers on a new flow, or when they
  expire.
- **Group rates are per task**, like the 1-to-1 ones.
- **Group mode runs on one task until
  [#121](https://github.com/jeonghun-app/rcs-platform/issues/121).** Every
  participant's session with a group, its deliveries and its roster
  notifications must be on the same task. With two or more tasks, a
  participant's session would land on whichever task its SIP dialog names: a
  message written on one task would invite participants whose session is on
  another instead of delivering to it, and a roster change would reach only
  the subscriptions of the task that made it. #121 anchors each group's focus
  on one task (an owner lease, ADR 0005 amendment); until then, deploy
  rcs-as with group chat on a single task.
- **Not checked against a licensed copy of RCC.07.** These follow the public
  reference client (rcsjta) and publicly documented behaviour:
  - the anonymous CPIM `From` and `To` in 1-to-1 chat;
  - the IMDN behaviour of chat sessions;
  - is-composing outside CPIM in 1-to-1 chat, and inside CPIM in a group;
  - one message per large-mode session;
  - the group rules above, and the author taken from a group message's CPIM
    `From`;
  - one `From` and at most one `To` per message: RFC 3862 §4.2 allows
    several `To` headers, but RCS clients write one.
