# rcs-as messaging core

`rcs-as` is the RCS messaging application server
([architecture](architecture.md) §2). This document describes its messaging
core: how 1-to-1 chat, group chat and standalone messages are accepted,
stored, delivered and answered with disposition notifications (IMDN, RFC
5438), and how group chats are run ([Group chat](#group-chat)). Of the SIP
side ([The SIP layer](#the-sip-layer)), pager-mode MESSAGE, 1-to-1 and
large-mode sessions, the third-party REGISTER from `scscf` and the group chat
focus (sessions, the conference event package and REFER) are served. The core
is driven through interfaces so
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
| A registration (scscf's third-party REGISTER) | `UserRegistered`, saying whether it is on a new flow, as far as rcs-as can tell ([Sessions](#sessions)) |
| The BYE with `Reason: SIP;cause=488;text="MSRP direction not supported"` before any MSRP traffic (ADR 0004) | `InviteFailed` with `ErrNoSessions` |
| A group's invitees are to be invited, nothing being queued for them yet ([Group chat](#group-chat)) | `Invite` with the invitation, which the engine counts as its own and passes to `Deliverer.Invite`, so that a message queued meanwhile waits for that session |
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
`InReplyTo-Contribution-ID` headers with `ParseConversationHeaders`. rcsjta
sends pager-mode messages and notifications without them, which gives an
empty `Conversation`. A `Conversation-ID` or an `InReplyTo-Contribution-ID`
without a `Contribution-ID` is refused (400). OMA CPM requires a sender to
include `Conversation-ID` (Conversation Functions, Appendix C.1.1), but
rcsjta, a pre-CPM client, sends a `Contribution-ID` alone with its INVITEs.
rcs-as takes that as a leniency (#298): the engine gives such a 1-to-1
message the pair's `Conversation-ID`, a name-based UUID of the two users'
keys in sorted order (`PairConversationID`), so that every message between
the same two keys, either way, threads together, and delivers it with that
ID, as the sender C.1.1 asks it to be. A subscriber reached by a SIP name
identity and by its tel URI has two keys (`UserOf` folds only a number's SIP
and tel forms), and its messages so get two IDs. The ID is an unsalted hash
of the two identities, so it is personal data, as they are, if it is ever
logged. The SIP layer must give `Origin.Sender` the
identity the network asserted, never one the client chose. It must name each
user in one canonical form, since the queue and the sent-message records are
keyed by that string.

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
| any request to the conference factory or a conference URI, outside a dialog | a group chat's, told apart before anything else: an `INVITE` creates or joins the group, a `SUBSCRIBE` subscribes to its roster ([Group chat](#group-chat)), on the task that owns the group, to which another task forwards it ([Which task serves a group](#which-task-serves-a-group)); another task's wake `MESSAGE` has the owner read a queue; any other method is 405 with `Allow` |
| `INVITE` outside a dialog | a chat or large-mode session, answered as in [Sessions](#sessions) |
| `REGISTER` (scscf's third-party registration) | 200, and `UserRegistered` (see [Sessions](#sessions)) |
| `OPTIONS` outside a dialog | forwarded along its `Route`, back to `scscf`: the default profile hands it to `rcs-as` with SESSION_CONTINUED, and capability discovery must not stop there |
| any request in a dialog | served in its session (`BYE`, `INVITE`, `UPDATE`, `OPTIONS`, and `REFER` in a session with a group; any other method 405), or in its subscription to a group's roster (`SUBSCRIBE`); one to a conference URI whose dialog this task does not hold goes to the group's owner; 481 when there is no such session, as for a `MESSAGE` in a dialog, since pager mode has none |
| `ACK` | the ACK of a 2xx rcs-as sent is taken by its UAS; one to a conference URI goes to the group's owner; any other is dropped |
| anything else | 405 with `Allow` |

A request that rcs-as originated itself and that comes back to it is answered
482 Loop Detected and counted (`sip.loop`). It is known by its `From` tag,
which starts with `rcsas-` on every task, so a request sent by one task and
returned to another is caught too. That happens when a profile sends rcs-as's
terminating requests to rcs-as again, lacking the default profile's
`P-Served-User` exclusion ([HSS](hss.md)); rcs-as would otherwise take its own
delivery for a new message and send it once more without end. A client that
writes such a tag only has its own request refused.

The focus's INVITEs to a group's participants carry no such tag: with #121, a
group's requests pass from one task to the one that owns the group, which must
serve them. One that comes back is known by its `From`, a conference URI, and
is answered 482 and counted the same way; taken for a 1-to-1 chat from the
group to the participant, it would loop as a delivery does. A request to the
conference factory or a conference URI is a group chat's whatever it carries,
so that none, a rejoin `INVITE` without a resource list say, becomes a 1-to-1
chat with a conference URI (security review on #252).

scscf hands rcs-as a request with the AS URI of the iFC on top of its `Route`
(TS 24.229 §5.4.3.2), `HSS_RCS_AS_URI` (`sip:rcs-as.<RCS_SERVICE_NAMESPACE>;transport=tcp` by
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

A notification is matched to its message by the identities asserted with it
only. A sender that addressed the recipient by a name-form SIP URI
(`sip:alice@<domain>`) keys the message by that name; if the recipient's
notification asserts only its tel URI, rcs-as cannot tell that the two are
one user without the asserted pair, and refuses the notification
(`imdn_forged`).

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
| unreadable `Conversation-ID` or `Contribution-ID`, or either of `Conversation-ID` and `InReplyTo-Contribution-ID` without a `Contribution-ID` | 400 |
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
- `P-Asserted-Service` with the standalone messaging ICSI
  (`urn:urn-7:3gpp-service.ims.icsi.oma.cpm.msg`), and `Accept-Contact` with
  the same ICSI and `;require;explicit`, so that `scscf` forks it only to the
  contacts that registered that ICSI, not to a device without CPM (RFC 3841,
  #332);
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

`Deliverer.Invite` sends an INVITE the same way: to `RCSAS_CORE_URI`, with
`P-Served-User: <recipient>;sescase=term` and `P-Asserted-Identity: <peer>`,
`From` the peer. `Accept-Contact`, `P-Asserted-Service` and the `Contact`
feature tag name the chat ICSI (`...icsi.oma.cpm.session`) or, for a
large-mode session, `...icsi.oma.cpm.largemsg`. Its SDP offers `actpass` with
the leg's path at this task's `RCSAS_MSRP_HOST` ([ADR
0004](adr/0004-msrp-anchoring.md)). It carries no `Supported: timer`, so
rcs-as is never asked to refresh. `Invite` returns once the INVITE is sent;
then:

| What the INVITE gets | What rcs-as does |
|---|---|
| a 2xx | ACK (again for each retransmission), and `Leg.Answer` with the answer's `a=path`; the relay connects for the client, which answered through `pcscf` as `active` |
| a 2xx whose answer is `passive`, or has no `a=setup` (RFC 4145 §4: passive) | ACK, then BYE with `Reason: SIP;cause=488;text="MSRP direction not supported"`, and `InviteFailed` with `ErrNoSessions`: the relay never dials a client |
| a 2xx with an answer rcs-as cannot use otherwise | ACK, BYE, `InviteFailed` |
| a 2xx from a second fork | ACK and BYE in that dialog (RFC 3261 §13.2.2.4); the first session stands |
| a final failure | `InviteFailed`: 404 and 604 with `ErrUndeliverable`, 408, 430, 480 and 503 with `ErrOffline`, any other with an error of its own |
| no final answer before the leg's `RCSAS_ANSWER_TIMEOUT` | CANCEL; the 487 is the failure; without one, the transaction is ended 32 s later (RFC 3261 §9.1) and the failure is `ErrOffline` |

A group invitation is the focus's INVITE ([Group chat](#group-chat)): from the
conference URI, without the `rcsas-` tag, a 2xx joining the participant before
`Leg.Answer`, and a 603 Decline leaving the group rather than going to
`InviteFailed`.

### Sessions

`rcs-as` is a B2BUA: each client has its own SIP session with rcs-as, and its
own MSRP leg on the engine. In every session pcscf has anchored the client's
MSRP on `msrp-relay`, which offers or answers rcs-as `active` with the
relay's core path ([ADR 0004](adr/0004-msrp-anchoring.md)). rcs-as therefore
always answers `passive` and listens: `msrp-relay` connects to
`RCSAS_MSRP_LISTEN_ADDR`, where the engine's `Serve` binds the connection to
the leg its To-Path names.

A client's INVITE (the originating session):

| Check | Refused with |
|---|---|
| a `Require` option tag other than `timer` | 420 with `Unsupported` (RFC 3261 §8.2.2.3) |
| none of the chat ICSI, the OMA SIMPLE IM tag `+g.oma.sip-im` (with which rcsjta, the reference client, asks for a chat) or the large-mode ICSI in `Accept-Contact`, `P-Asserted-Service` or `P-Preferred-Service`; or an offer with `a=file-selector` (RFC 5547 §6), a file transfer, which rcsjta asks for with the same `+g.oma.sip-im` tag. File transfer is not served here | 403 |
| no asserted identity, or not as for MESSAGE | 403 |
| a Request-URI that names no user | 404 |
| unreadable `Conversation-ID` or `Contribution-ID`, or either of `Conversation-ID` and `InReplyTo-Contribution-ID` without a `Contribution-ID` | 400 |
| `Session-Expires` below 90 s from a client with `Supported: timer` | 422 with `Min-SE: 90` (RFC 4028 §6); a client without the extension, which could not act on a 422, gets no timer instead |
| a body that is not an SDP offer, or a `multipart/mixed` one other than one SDP part and at most one `message/cpim` part (a resource list, which only a group chat's INVITE carries, two descriptions, a nested multipart); no offer (a late offer); no MSRP line; an offer of `passive` (RFC 6135 §4.2.2); no type in common; a first message in a large-mode INVITE | 488 |
| a first message the engine refuses | as a pager MESSAGE's (413, 415, 400, 403, 500 with `Retry-After: 1`), and no session; the session's place is given back |
| this task holds `RCSAS_MAX_SESSIONS` sessions, those still waiting for an answer included | 500 with `Retry-After: 1`, as for a busy store: the client may try again, and another task may take it |
| the user has opened `RCSAS_MAX_OUTGOING_SESSIONS_PER_USER` sessions | 486 Busy Here |

Otherwise rcs-as opens the leg with `OpenLeg` (the sender is the asserted
identity, the peer the Request-URI, as for pager mode) and answers 200. The
answer is `passive`, with the leg's path, `c=` at `RCSAS_MSRP_HOST`, the leg's
`AcceptTypes` and `a=max-size` of `RCSAS_MAX_MESSAGE_SIZE`; its `Contact` is
this task's SIP address with the service's feature tag. Messages on the leg go
through the pipeline, are stored and are delivered to the peer: on the peer's
own leg if it has one, or in a session rcs-as starts (store-and-forward).

A chat INVITE may carry the chat's first message (rcsjta does when the user
starts a chat by writing): a `multipart/mixed` body with the SDP part and a
`message/cpim` part (RFC 5621). rcs-as finds the SDP part as pcscf does, and
submits the message as the session's first, before the 200. The session takes
its place under the bounds first: an INVITE past them is refused (486 or 500)
with nothing stored, so a client that sends it again does not deliver it
twice.

In every session:

- **Session timers** (RFC 4028). rcs-as never refreshes. When the client
  supports the extension and asks for a timer, rcs-as takes it with the client
  as refresher (`Session-Expires: <n>;refresher=uac`, `Require: timer`), or
  chooses so itself when the client named no refresher. It ends a session left
  unrefreshed with a BYE, min(32 s, interval/3) before the interval runs out
  (§10). A client that asks rcs-as to refresh (`refresher=uas`), which the UAS
  cannot change (§9, Table 2), or that does not support the extension, which
  would leave refreshing to rcs-as, gets no timer, as from a UAS without the
  extension. The INVITEs rcs-as sends ask for no timer (no `Supported: timer`,
  no `Session-Expires`); a 2xx that sets one with the client refreshing
  (`refresher=uas`) is kept the same way, and one that names rcs-as the
  refresher (`refresher=uac`) gets no timer.
- **Refreshes.** A re-INVITE or UPDATE whose offer keeps the MSRP path gets the
  same answer, with the same `o=` version unless the answer changed (RFC 3264
  §8), and restarts the timer. A re-INVITE without an offer (rcsjta's refresh)
  gets the session's last SDP as the offer in its 2xx (RFC 3261 §14.2, RFC 4028
  §7.4), with every MSRP line `actpass`, since an offer is never `passive` (RFC
  6135 §4.2.2): in a session the client started, rcs-as's last SDP is its
  `passive` answer, so that offer takes the next `o=` version (RFC 3264 §8);
  unchanged, it keeps the version. The answer in its ACK must keep the path, or
  the session ends. An UPDATE without an offer is a plain refresh, its 2xx
  without SDP (RFC 3311 §5.2). An offer with another path is refused with 488:
  a leg does not move. The session goes on.
- **Ending.** A BYE from the other side ends the session and closes its leg. A
  leg that ends on its own (the relay dropped its connection), a leg no
  connection binds within `RCSAS_ANSWER_TIMEOUT` of its peer's path being known
  (a client that never connects to the relay), a 2xx without an ACK (RFC 3261
  §13.3.1.4), an unrefreshed timer and a terminating large-mode leg that is
  `Finished` each end the session with a BYE from rcs-as. So does shutdown,
  before the transport closes, in this order: it takes no new session; it lets
  a session still being answered (a client's INVITE whose first message is
  being stored, or rcs-as's ACK to a client's 2xx) send that answer first,
  so that no BYE ever comes before its dialog's 2xx (#270); then it ends every
  session with a BYE, each once its dialog is confirmed: the client's ACK of
  rcs-as's 2xx has come, or rcs-as has sent its own ACK, since a callee must
  not send a BYE before the ACK (RFC 3261 §15). The answers and the ACKs share
  one bound of 2 s, and a BYE is sent when it runs out, ACK or not; a session
  answered after it ends itself the same way, from its own path, and while
  shutdown still waits for its own BYEs' answers it waits for those too. The
  BYEs' answers have a bound of 2 s of their own, so shutdown takes at most
  4 s here. Calls after the first wait for it, and end nothing twice.
- **The MSRP direction.** A BYE with SIP cause 488 in its `Reason`, in a session
  rcs-as started that has carried no message yet, tells the engine
  `ErrNoSessions`: it is how pcscf ends a session whose client answered
  `passive` (ADR 0004). A session that carried messages was served, whatever
  its BYE says.
- **Bounds** (threat model T9). `RCSAS_MAX_SESSIONS` bounds a task's sessions,
  those waiting for an answer included. A user's sessions are bounded each way
  apart: those it opens (`RCSAS_MAX_OUTGOING_SESSIONS_PER_USER`, 486 past it),
  and those rcs-as opens to it (`RCSAS_MAX_INCOMING_SESSIONS_PER_USER`), so
  that other users' messages cannot take the user's own room. A user's
  subscriptions to group rosters are bounded across its groups
  (`RCSAS_MAX_SUBSCRIPTIONS_PER_USER`, 486 past it), so that one account in
  many groups cannot take the task's room for subscriptions, which
  `RCSAS_MAX_SESSIONS` bounds too, from everyone else. One sender has
  at most one large-mode session open to one recipient at a time; the next
  message waits for it. A session rcs-as cannot start for a bound waits as for
  a recipient offline.

A third-party REGISTER from scscf (TS 24.229 §5.4.1.7) names the user in
`To` and the expiry in `Expires`; one without `Expires` is refused with 400.
rcs-as answers 200 and calls `UserRegistered`. The REGISTER does not say which
flow the client registered on: its `Contact` is scscf's, and the default
profile does not ask for the client's REGISTER in its body. So rcs-as counts a
registration as one on a new flow when it has not heard of a live one for that
user (none, or one that has run out), and as a refresh otherwise. A
de-registration (`Expires: 0`) only forgets the user.

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
own, `sip:chat-<32 hex digits>@RCSAS_CONFERENCE_HOST` (made from its Contribution-ID, or random without one), and every participant
has a session with it: a leg of mode `group` whose peer is that URI.

Group chat is off unless `RCSAS_GROUP_CHAT_ENABLED=true`. While it is off, a
request to the conference factory or to a URI at the conference host is
answered 404 (`sip.group.disabled`), before anything is read or created; it is
not taken for a 1-to-1 request either. Group messages already queued are kept:
their recipients are taken as offline, so the messages wait up to
`RCSAS_STORE_TTL` and go once group chat is on again. Each group is served by one
task, its owner ([Which task serves a group](#which-task-serves-a-group)).

How the SIP layer serves it:

- **Create.** A client's INVITE to the conference factory
  (`RCSAS_CONFERENCE_FACTORY_URI`, the `ConfFctyURI` ACS provisions, its
  user part compared with escapes undone and without case, its host without
  case or a trailing dot) may
  carry `Require: recipient-list-invite`, as rcsjta's does, which rcs-as
  supports; it carries a `multipart/mixed` body of its SDP and
  a resource list (RFC 5366, RFC 4826), which `internal/resourcelists` reads
  as a stream, stopping at the first entry beyond `RCSAS_GROUP_MAX_PARTICIPANTS`
  (403). An entry whose `uri` is missing or no URI a client means (not text,
  or with white space or control characters) is left out
  (`sip.group.invitee_skipped.malformed`), and so is an entry for the
  factory or at the conference host, whose focus INVITE would come back as a
  loop (`sip.group.invitee_skipped.loop`); a bad entry never refuses the
  list, and every entry counts toward the bound. The subject is its
  `Subject`, the creator's name its `From` display name, and its
  `Contribution-ID`, which every session with the group
  carries, is required (400 without): rcsjta takes it as the chat's identity,
  and sends no `Conversation-ID`, which the group then makes. Every part of
  the request is read, and the session's place held, before the group is
  stored. A first message in it is refused (488): it could only be stored
  once the group is, and then be refused after the group was made.
- **One group per Contribution-ID.** The conference URI is made from the
  `Contribution-ID` (`chat-` and the first 32 hex digits of its SHA-256), so
  the same ID always names the same group. A new group lasts 2 minutes until
  its creator's session is set up (`group.Service.Established`, once the
  200's ACK has come), then `RCSAS_GROUP_IDLE_TTL` from its last use. If
  writing that fails, it is tried three more times, after 0.1, 0.4 and
  1.6 s; if it still fails, the creator's session ends with a BYE and nobody
  is invited, so that the client makes the group again rather than keep a
  session with one that ends within minutes
  (`sip.group.establish_abandoned`). Until the group is established, the
  creator's INVITE tried again under that ID, after a CANCEL, a failure or
  a 200 the client never got, takes up the group it made; a group no
  session came of ends on its own.
  Any other INVITE to the factory naming an ID a live group has, from someone
  else or once the group is established, is 403, and no group is made: a
  participant the chairman removed could otherwise make a group its members'
  clients take for the first one (threat model T11). A group that has ended
  frees its ID.
- **The answer.** A session with a group is answered as a 1-to-1 chat is,
  with `Contact: <conference URI>;isfocus` (RFC 4579 §5.2) and the chat
  feature tag: rcsjta keeps that URI to rejoin the group, and tells a group's
  INVITE from a 1-to-1 one by `isfocus`.
- **The invitations.** Once the creator's session is set up, its ACK in,
  the focus invites each invitee through the engine (`Engine.Invite`), which
  counts the invitation like its own, so that a message queued meanwhile
  waits for that session rather than ringing the client again. The INVITE is a terminating
  request as for 1-to-1 chat, from the conference URI, asserted as it, with
  the same `Contact`, the group's `Subject`, `Conversation-ID` and the
  creator's `Contribution-ID`, and `Referred-By` naming who brings the
  participant in: the creator, or the author of the message a later
  invitation is for. rcsjta takes the inviter from `Referred-By`, and
  declines an INVITE that names none it can read. A 2xx is `Join`, then
  `Leg.Answer`; a 603 is `Leave` (below). A 404, 604 or 482 says the
  invitation will never reach the participant: what is queued for it from
  the group is given up (`delivery.undeliverable`) until it opens a session
  with the group itself or is added again. A 404 or 604 that comes after
  the participant registered on a new flow is not taken so, as the
  registration shows it exists now (#384); a 482, a loop, always is.
- **Feature tags.** Every INVITE rcs-as sends for a chat, 1-to-1 or in a
  group, has both the CPM chat ICSI and the OMA SIMPLE IM tag
  `+g.oma.sip-im` in `Contact`, and one `Accept-Contact` for each, so that a
  contact with either matches (RFC 3841): rcsjta takes a chat session by the
  latter, a CPM client by the former.
- **Join.** An INVITE to a conference URI, with only an SDP body, is `Join`:
  404 for a group that has ended, which rcsjta takes as the end of the group,
  and 403 for someone who is not a participant. A Request-URI at the
  conference host whose user part is not `chat-` and 32 lower-case hex digits,
  the form groups are given, is 404 before the store is read.
- **Leave.** A BYE with `Reason: SIP;cause=200`, which rcsjta sends when its
  user closes the chat, is `Leave`; any other BYE, as for a session idle too
  long, ends the session only, and the participant rejoins or is invited back
  for the next message (the lead's decision on #137). A 603 to the focus's
  INVITE is `Leave` too.
- **The roster.** A participant's SUBSCRIBE to the conference URI with
  `Event: conference` (RFC 4575) is answered 200 with `Expires` and the
  conference URI as `Contact`, and its first NOTIFY carries the full roster
  (`Roster`); each change then comes as the partial document `RosterChanged`
  gives, one version up. A subscription that would see a gap in the versions,
  as when two changes race to it, gets the full roster instead. A refresh in
  the subscription's dialog gets the full roster too; `Expires: 0` ends the
  subscription, and an initial SUBSCRIBE with `Expires: 0` fetches the roster
  once (RFC 6665 §4.1.2). A subscription lasts at most 3600 s, the default,
  and at least 60 s (423 with `Min-Expires` below). Only a current participant
  may subscribe (403), to a group that exists (404); another event package is
  489 with `Allow-Events: conference`, and an `Accept` without
  `application/conference-info+xml` 406. A participant holds at most 4
  subscriptions to one group and `RCSAS_MAX_SUBSCRIPTIONS_PER_USER` across
  its groups (486 beyond either), and a task at most `RCSAS_MAX_SESSIONS`
  (500 with `Retry-After`). A NOTIFY that times out, or is answered 404, 405,
  410, 416, 480 to 485, 489, 501 or 604 (RFC 6665 §4.2.2) or 430 (RFC 5626),
  ends the subscription without another. Any other failure, as a 503 from a
  busy proxy, keeps it (`sip.subscription.stale`): the subscriber missed a
  document, so the next change sends the full roster, unless a refresh,
  answered as usual with the full roster, brought it up to date first. A participant who leaves, declines or is removed gets
  the change that says so, and its subscriptions end with it. On
  shutdown each subscription ends with `reason=deactivated`, so that the
  subscriber may subscribe again at once, to another task. Subscriptions are
  kept in the memory of the task that owns the group.
- **REFER.** A participant adds someone by a REFER in its session with the
  group (RFC 4579 §5.5, rcsjta's `GroupChatSession.inviteParticipants`):
  `Refer-To` naming them, or a `cid:` URI with `Require: multiple-refer` and a
  resource list as the body (RFC 5368), read no further than
  `RCSAS_GROUP_MAX_PARTICIPANTS` − 1 entries. It is `Add`, answered 202, and
  the focus invites each one the group now holds invited (`Engine.Invite`).
  `Refer-To` naming a participant with `method=BYE` is `Remove` (RFC 4579
  §5.11), which only the chairman may: the removed participant's sessions with
  the group get a BYE and its subscriptions end. With `Refer-Sub: false` (RFC
  4488), as rcsjta sends, the 202 says so and there is no implicit
  subscription. Without it, the subscription (`Event: refer`,
  `message/sipfrag`, RFC 3515 §2.4.4) starts with `SIP/2.0 100 Trying` and
  ends with `200 OK` or `480 Temporarily Unavailable`. For a REFER that adds
  one person not yet in the group, it is `200 OK` once the focus's INVITE is
  answered 2xx and the session is up, and `480` for any failure. For a
  removal, a list, or someone in the group already, it is `200 OK` once the
  group has changed. One that hears nothing for 2 minutes ends with `480`,
  as for someone invited already whom the focus does not ring again. The
  invitee's own answer is never passed on: it would tell the referrer
  whether a number is a subscriber and whether it is online. A REFER outside a
  session, or in a 1-to-1 one, is 405.
- Other answers: 403 for a rate limit or a group too large, 400 for a request
  the group cannot take (nobody else in the list), 500 with `Retry-After: 1`
  when the group kept changing under the request or the store was busy.

### Which task serves a group

Each group has one owner task (#121, the amendment to
[ADR 0005](adr/0005-shared-state-and-instance-addressing.md); the store side is
under [DynamoDB `groupchats` table](#dynamodb-groupchats-table)), and everything the group has
on rcs-as is there: its participants' sessions and MSRP legs, its roster
subscriptions, its fan-out and the invitations for its queued copies. The core
may give a group's request to any task, a dialog's included: the Contact of a
group's sessions and subscriptions is its conference URI.

- **Forwarding.** A task that gets a request for a group another task owns,
  alive, forwards it to the owner's SIP instance address, once
  (`group.forwarded`): an `INVITE` or `SUBSCRIBE` to the conference URI, an
  `INVITE` to the factory whose `Contribution-ID` names an existing group
  (the creator's tried again, or anyone else's, which the owner refuses), and a
  request in one of the group's dialogs, its `ACK` included, that this task does
  not hold. The forwarded request carries a `Route` to the owner marked
  `rcsas-fwd`, and no `Record-Route`; the owner serves it as any other, and the
  responses come back the same way. A task that does not know the group, or
  owns it, serves the request itself; one whose owner has stopped takes it over
  first.
- **No 404 for a group that exists.** A request that cannot reach the owner
  now is answered 500 with `Retry-After` (`group.forward_refused`): one
  forwarded here already, which is never forwarded again, so that two tasks
  whose views of the owner differ for a moment cannot pass it between them; one
  that arrives while this task's own heartbeat has lapsed, in a dialog it does
  not hold too (never 481); one whose owner's stored address is not a private
  address (RFC 1918, or IPv6 unique local, mapped addresses compared unmapped,
  none with an interface zone) on rcs-as's own SIP port, which is checked
  before anything is sent there (`group.forward_refused.address`); and one
  forwarded to an owner that does not answer it, a closed port or a dial that
  times out, whose 408 or the proxy's own 5xx becomes 500 with
  `Retry-After` (the owner's own answers, a 404 for an ended group among
  them, go as they are). rcsjta takes a 404 to its rejoin
  for the group's end and restarts it at the factory, where the group's live
  Contribution-ID is refused (403) and the chat fails; any other failure it
  tries again later.
- **A task that loses a group** ends what it holds of it: the sessions with
  a BYE, once their 2xx is acknowledged (RFC 3261 §15) or Timer H has run
  out, the subscriptions with `reason=deactivated` (`group.owner_lost`,
  `sip.group.disowned.sessions`). The participants rejoin, and subscribe
  again, through the owner. It loses a group when another task took it over,
  when it drops the group from those it remembers owning, at
  100 000 of them (`group.owned_dropped`), and every group when its
  own lease runs out with no beat stored: at the first beat that fails past
  `RCSAS_TASK_LEASE` less `RCSAS_TASK_SKEW` after the last one stored,
  whether the store is out for every task or for this one alone, as the
  sessions can deliver nothing meanwhile (the lead's decision on #464), or
  when a beat is stored that late.
- **Wake.** A task's queue pass that finds a copy of another task's group
  leaves it alone (`delivery.group_not_owned`), and has the owner read the
  participant's queue: as when the participant registers on that task, which
  the owner would otherwise only learn of at its next retry. It sends the
  owner a `MESSAGE` to the conference URI, with the same marked `Route`, its
  own address in `From` (never a conference URI or rcs-as's `rcsas-` tag,
  which the loop guard refuses), and an
  `application/vnd.rcsplatform.group-wake+json` body naming the participant,
  and saying whether it registered on a new flow there since the last wake;
  at most once per participant and group every `RCSAS_INVITE_TIMEOUT`, and
  at once after such a registration (`group.wake_sent`,
  `sip.group.wake.<status>`). The wake goes off the queue pass, at most 16 at
  a time. The owner answers 200 and reads the queue (`sip.group.woken`); for
  a registration, it first forgets the invitation it last asked for the
  participant in the group and its pager-only mark, as a registration on a
  new flow there would, so that it invites at once.
- **Cost.** Where a group is served is remembered for a heartbeat: a task
  reads the group and owner items for it at most once per
  `RCSAS_TASK_HEARTBEAT`, and an INVITE to the factory costs one more read of
  the group item first, unless its creator is over `RCSAS_GROUP_CREATE_RATE`,
  which refuses it unread. That there is no such group is remembered for a
  second, up to 10 000 of them; whatever then serves the request reads the
  group itself, so a group made meanwhile is not taken for none.
- **Limits.** The per-user bounds on sessions and subscriptions are per task
  (the lead's decision on #121): with a user's groups owned by several tasks,
  a user may hold up to that many on each.

### How the SIP layer drives it

| SIP event | Call |
|---|---|
| An INVITE to the conference factory, with a resource list | `group.Service.Create` (the creator is joined; the invitees are invited, and the SIP layer invites them). A list of more than `RCSAS_GROUP_MAX_PARTICIPANTS` entries is refused (`ErrTooMany`) before any entry is read; the SIP layer should bound the resource-list body it parses to about that many entries too |
| A participant's session with the group is set up (its INVITE, or its answer to the focus's) | `Join`, then `OpenLeg` / `Offer` and `Leg.Answer` with `Mode: store.Group` and the conference URI as `Peer`. If `Join` refuses, the session is refused and no leg opened |
| A BYE on that session with `Reason: SIP;cause=200` | `Leave`, and `Leg.Close`. rcsjta ends a session its user closes with that Reason ("Call completed") |
| Any other BYE on that session | `Leg.Close` only: a session idle too long ends without the participant leaving, and it rejoins by an INVITE to the conference URI, or the focus invites it back for the next message (RCC.07 rejoin). A participant that had left could do neither |
| A 603 Decline to the focus's INVITE | `Leave`, not `InviteFailed`. The reference client declines the first INVITE of a group it left while offline (RCC.07 6.3.3.1; rcsjta `isGroupChatNextInviteRejected`), and accepts later ones as a new addition. Other failures stay `InviteFailed` |
| A REFER adding someone | `Add`. A list of more than `RCSAS_GROUP_MAX_PARTICIPANTS` − 1 is refused unread, as for `Create` |
| A REFER with `method=BYE` removing someone | `Remove`, then a BYE on the removed participant's session and `Leg.Close` |
| `Leave` or `Remove` succeeds | end that participant's subscriptions to the conference event package (a final NOTIFY with `Subscription-State: terminated;reason=rejected`, without a document), so that it learns no later roster change; no NOTIFY follows it |
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
  They are stored and compared in the one form rcs-as names users in
  (`messaging.UserOf` at `RCS_IMS_DOMAIN`, above): a telephone number is its
  tel URI, however it is written, and any other SIP URI keeps its user part,
  loses its parameters and has its host in lower case. One person added as
  `tel:+1-555-…` or `sip:+1555…@<domain>` and joining as `tel:+1555…` is one
  participant. The SIP layer passes asserted identities in the same form. The
  engine puts a group leg's `User`, and a group message's sender, in that form
  too, so a leg opened under another spelling still gets its participant's
  copies, and a participant's copies are queued where its 1-to-1 messages are.
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
  in 1-to-1 chat. A group created without one gets one in the UUID form OMA
  CPM asks of a Conversation-ID (Conversation Functions, Appendix C.1.1):
  - with a `Contribution-ID`, as rcsjta sends, a name-based UUID (version 5,
    in a namespace of rcs-as's groups, not the pairs') of the
    `Contribution-ID` alone, as the conference URI is made from it. rcsjta
    starts a group that ended again under its `Contribution-ID`, from
    whichever participant writes next; the new group gets the same
    conference URI and the same Conversation-ID, so that it stays one
    thread;
  - without one, a random UUID (version 4), which never equals a version 5
    one.

  Groups made before #305 keep the 32 hex digits they were given: the value
  is opaque, and read and compared as stored.

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
| `RCSAS_SIP_HOST` | the task's one private IPv4 address | This task's address, in the Via and Call-ID of what it sends ([ADR 0005](adr/0005-shared-state-and-instance-addressing.md)). Refused in staging and prod with `RCSAS_GROUP_CHAT_ENABLED`: a group's owner is known by its address too, and two tasks given one would take each other's groups (#121) |
| `RCSAS_CORE_URI` | `sip:scscf.<RCS_SERVICE_NAMESPACE>;transport=tcp;lr` | Where rcs-as sends the requests it originates: a SIP URI of a host with `transport=tcp` and `lr`, a private or loopback address or a name inside the namespace. Required without `RCS_SERVICE_NAMESPACE` |
| `RCSAS_SERVICE_NAME` | `rcs-as.<RCS_SERVICE_NAMESPACE>`, none without a namespace | The host of the AS URI the iFC name rcs-as by (`HSS_RCS_AS_URI`), which rcs-as takes as its own in a `Route`. Change both together, or an OPTIONS scscf hands rcs-as comes back to it (482) |
| `RCSAS_MAX_SESSIONS` | `20000` | SIP sessions this task holds, each with its MSRP leg; an INVITE beyond it is answered 500 with `Retry-After: 1` ([threat model](threat-model.md) T9) |
| `RCSAS_MAX_OUTGOING_SESSIONS_PER_USER` | `32` | Sessions one user opens on this task; an INVITE beyond it is answered 486 |
| `RCSAS_MAX_INCOMING_SESSIONS_PER_USER` | `32` | Sessions rcs-as opens to one user on this task; a delivery beyond it waits |
| `RCSAS_MAX_SUBSCRIPTIONS_PER_USER` | `32` | Subscriptions to group rosters one user holds on this task, across its groups; a SUBSCRIBE beyond it is answered 486 |
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
| `RCSAS_ANSWER_TIMEOUT` | `32s` | How long an offered leg waits for its answer, and how long a leg whose peer's path is known waits for msrp-relay's connection before it is closed and its session ended |
| `RCSAS_RETRY_INTERVAL`, `RCSAS_MAX_RETRY_INTERVAL` | `1m`, `1h` | First and longest wait before a held queue is read again |
| `RCSAS_STORE_TIMEOUT` | `5s` | Each store call |
| `RCSAS_SWEEP_INTERVAL` | `1m` | How often expired messages are swept |
| `RCSAS_CONFERENCE_HOST` | required | Host of the conference URIs the focus allocates; must route to `rcs-as`, and must not be `RCS_IMS_DOMAIN`, whose users' requests would all be taken for a group's |
| `RCSAS_GROUP_CHAT_ENABLED` | `false` | Group chat at the conference factory and the conference URIs; off, they are answered 404, and queued group messages wait (up to `RCSAS_STORE_TTL`) instead of being given up. On, each group is served by the task that owns it ([Which task serves a group](#which-task-serves-a-group)) |
| `RCSAS_CONFERENCE_FACTORY_URI` | `sip:conf-factory@<RCS_IMS_DOMAIN>` | Where clients create group chats: the `ConfFctyURI` ACS provisions. A SIP URI with a user; its user is compared with escapes undone and without case, its host without case |
| `RCSAS_GROUPCHATS_TABLE` | `groupchats` | Groups table, with `RCSAS_STORE=dynamodb` |
| `RCSAS_GROUP_MAX_PARTICIPANTS` | `100` | Current participants of one group, at most 200. Former participants are kept up to the same number, fewer above 104, so that the roster stays within 256 KiB (see [Roster events](#roster-events)) |
| `RCSAS_GROUP_IDLE_TTL` | `720h` | A group not used for this long ends |
| `RCSAS_GROUP_SENDER_RATE`, `RCSAS_GROUP_SENDER_BURST` | `60`, `30` | Messages per minute one participant writes in one group, per task; also renames |
| `RCSAS_GROUP_FANOUT_RATE`, `RCSAS_GROUP_FANOUT_BURST` | `6000`, 4 × 10 × (`RCSAS_GROUP_MAX_PARTICIPANTS` − 1) (`3960` for 100), at least `1000` | Deliveries per minute one group makes, a message counting once per recipient, per task. One sender may use a quarter of the rate and of the burst, and a quarter of the burst must cover 10 messages to a full group. With the defaults, one sender in a full group of 100 may send 10 messages at once and then 15 a minute; in a full group of 200, 10 at once and then 7 a minute |
| `RCSAS_GROUP_ADD_RATE`, `RCSAS_GROUP_ADD_BURST` | `30`, `100` or `RCSAS_GROUP_MAX_PARTICIPANTS` − 1 if more | Participants one user adds per minute, in groups it creates too. The burst must cover a full group's invitees, so that the largest group can be created at once |
| `RCSAS_GROUP_CREATE_RATE`, `RCSAS_GROUP_CREATE_BURST` | `5`, `10` | Groups one user creates per minute |
| `RCSAS_TASK_HEARTBEAT`, `RCSAS_TASK_LEASE`, `RCSAS_TASK_SKEW` | `5s`, `20s`, `2s` | With group chat on, how often a task beats, how far ahead each beat holds its groups, and the margin for the tasks' clocks (#121): a task stops writing groups `RCSAS_TASK_LEASE` less `RCSAS_TASK_SKEW` after its last stored beat, and another takes them `RCSAS_TASK_SKEW` after that beat's `alive_until`. The lease must be more than the other two together |

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
| `dynamodb:ConditionCheckItem` | the `groupchats` table | the `ConditionCheck` of a group's owner inside a group message copy's enqueue (#121) |
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
TTL attribute `ttl`) and no index. Each group is one item, with a small
item that names its owner next to it (#121), and each rcs-as task with group
chat on has a heartbeat item:

| `pk` | `sk` | Holds |
|---|---|---|
| `g#<len>#<conference URI>` | `group` | The group |
| `g#<len>#<conference URI>` | `owner` | The owner task's id (`task`, random at every start), its SIP instance address (`sip`), `epoch`, `wtoken` |
| `t#<len>#<task id>` | `task` | The task's SIP instance address, `alive_until` |

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
- **Ownership** (#121). One task owns each group: the one that made it,
  or the one that took it over. `Create` writes the group and its owner item,
  at epoch 1, in one transaction. Every change and every touch is a
  transaction of the group's write and an update of the owner item's `ttl`
  on the condition that it still names the writer's task and epoch: a task
  that lost the group, even one paused and unaware of it, writes nothing,
  and gives the group up (`group.fenced`). A task takes a group over by a
  conditional update of the owner item (same task, same epoch; epoch one
  up), only once the owner's heartbeat item says `alive_until` plus
  `RCSAS_TASK_SKEW` has passed, or at once when the owner's address is its
  own and its task id is not (the address was reused, so the owner is
  gone); a group stored before #121, without an owner item, is taken from
  none. A task beats every `RCSAS_TASK_HEARTBEAT`, `alive_until`
  `RCSAS_TASK_LEASE` ahead, and stops writing groups once its last stored
  beat is `RCSAS_TASK_LEASE` less `RCSAS_TASK_SKEW` old; it beats once more
  at its present time on shutdown, after its sessions have ended, so that
  another task takes its groups at once. A task remembers the groups it
  owns, so that a change of one costs no more reads than before. It forgets
  them all when its last stored beat's hold (`RCSAS_TASK_LEASE` less
  `RCSAS_TASK_SKEW`) runs out with no beat stored since, at the first beat
  that fails then, or when a beat is stored that late, as when it was paused
  unaware, and forgets one when the store refuses a write or a message's copy
  for it, or when the group has ended. Whether to invite a participant for a group's
  queued copies, which the store does not fence, it asks the owner item
  again once what it remembers is `RCSAS_TASK_HEARTBEAT` old: a task that
  lost a group stops inviting for it within a heartbeat, even one that
  writes nothing to it. A request for a group another task owns goes to
  that task ([Which task serves a group](#which-task-serves-a-group)).
- **A replacement task waits for the old one's lease.** Even with one task,
  a task that replaces another, on a new address, may not change the old
  task's groups until the old one's last heartbeat has run out: after a
  crash, up to `RCSAS_TASK_LEASE` plus `RCSAS_TASK_SKEW` (22 s by default)
  after the old task's last beat; after a clean shutdown, which stores a last
  beat at its present time, `RCSAS_TASK_SKEW` (2 s). Meanwhile a change to
  one of those groups is answered 500 with `Retry-After`, which clients try
  again, and a message written in one is refused as one not stored
  (`StatusTryAgain`), as its copies are queued under the owner's fence;
  a task on the old one's address takes its groups at once. Before
  #121, a replacement changed them at once. Deployments stop tasks cleanly.
- **Touch.** At most once an hour per task, and not within an hour of a
  change, a group in use has its `active`, `expires` and `ttl` moved forward,
  without changing `rev`. The update is conditional on the stored `active`
  being older, so a touch that arrives after a later write (which may have
  ended the group) changes nothing. Creating a group and every change set
  `expires` to `RCSAS_GROUP_IDLE_TTL` from then.
- **Expiry.** `ttl` is the group's expiry plus a day; every read checks the
  expiry itself. The owner item's `ttl` moves with the group's; a task's
  heartbeat item's is its last `alive_until` plus a day.
- **IAM.** The task role needs `GetItem`, `PutItem`, `UpdateItem` and
  `DescribeTable` on the table; `TransactWriteItems` writes with them.
- **Cost** (#121). A change or a touch is a transaction of two items, which
  DynamoDB bills at twice the write units of each. A task's heartbeat is one
  small write every `RCSAS_TASK_HEARTBEAT`. A task's first change of a group
  it does not know reads the owner item, and the owner's heartbeat item if
  another task holds it. Whether to invite for a group's queued copies reads
  the group and owner items at most once per group every
  `RCSAS_TASK_HEARTBEAT`.

Each group message costs one strongly consistent read of the group item and,
per recipient, the enqueue transaction of the `messages` table, which also
checks the group's owner item in `groupchats` (#121): one more item in the
transaction, so each copy costs about 2 more write units. A copy is queued
only while the owner item still names the task that queues it, so a task that
lost the group queues none (the fan-out stops at the first refused copy,
`group.fanout.not_owner`, and the sender is answered as for a store failure).
The copies queued before the refused one stay. When the sender's client sends
the message again, now to the new owner, those recipients get it twice, as
after a fan-out that ran past `FanoutTimeout`: the clients drop the repeat by
its Message-ID (the lead's decision on #440).
The other group-mode items are not fenced, as two tasks cannot both queue one:
a participant's notification for the author is queued once its mark is
stored, which only one writer does (`MarkNotified`); a summary has an ID
fixed by the message it reports on (`r-<Message-ID>`), so a second is
refused as existing; and a fan-out's failure notice for a full queue follows
a copy refused with its fence held (the store checks the fence first), so
only the owner queues one.
Only the owner invites a participant for its queued copies
(`delivery.group_not_owned` counts those another task's queue pass left
alone); the owner reads the queue again on `Engine.Wake`, which another
task's wake message calls ([Which task serves a group](#which-task-serves-a-group)). The fan-out
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
| `sip.loop` | Requests rcs-as originated that came back to it, answered 482: by their `rcsas-` tag, or from a conference URI |
| `sip.group.invitee_skipped.malformed`, `sip.group.invitee_skipped.loop`, `sip.group.establish_failed`, `sip.group.establish_abandoned`, `group.create_retried`, `group.rejected.taken`, `invite.undeliverable` | Resource-list entries left out for a uri no client means, and for one at the factory or the conference host; writes of a new group's establishment that failed, and groups given up after four, whose creator's session ended; creators' INVITEs tried again that took up their group; INVITEs to the factory refused for another group's Contribution-ID; group invitations that will never reach the participant |
| `sip.group.created`, `sip.group.joined`, `sip.group.refused`, `sip.group.offer_refused`, `sip.group.service_refused`, `sip.group.list_too_long`, `sip.group.list_refused` | Clients' INVITEs to a group: groups created, joins, refusals by the group, and refusals for the offer (488), the service (403), a resource list too long (403) or unreadable (400) |
| `sip.group.declined`, `sip.group.left`, `sip.group.leave_failed`, `sip.group.join_refused` | Participants who left by a 603 to the focus's INVITE or by a BYE that says so, Leaves that failed, and 2xx answers to the focus whose Join the group refused |
| `sip.group.added`, `sip.group.removed`, `sip.group.invite_failed` | REFERs that added or removed, and additions whose invitations could not be sent for want of the group |
| `sip.subscription.started`, `sip.subscription.refreshed`, `sip.subscription.fetched`, `sip.subscription.expired`, `sip.subscription.ended.<reason>`, `sip.subscription.bad_event`, `sip.subscription.task_limit`, `sip.subscription.user_limit` | Subscriptions to the conference event package, by what became of them; `user_limit` counts those refused for a participant's 4 in one group and for `RCSAS_MAX_SUBSCRIPTIONS_PER_USER` |
| `sip.subscription.notified`, `sip.subscription.notify_failed`, `sip.subscription.stale`, `sip.subscription.notify_unsent`, `sip.subscription.notify_after_refusal`, `sip.subscription.resynced`, `sip.subscription.roster_failed`, `sip.subscription.unfinished_at_stop` | NOTIFYs sent, refused or unanswered, refused for a passing reason (whose subscription stands, to get the full roster next), not built, not sent because the subscriber had refused one (RFC 6665 §4.2.2), full rosters sent for a gap or after a failure, rosters that could not be read for one, and subscriptions a stop gave up on at its bound, their last NOTIFY unanswered or their lock held by a slow roster read |
| `sip.group.disabled`, `sip.refer.notified`, `sip.refer.notify_failed`, `sip.refer.notify_after_refusal` | Requests to the factory or a conference URI answered 404 while `RCSAS_GROUP_CHAT_ENABLED` is off; REFER subscriptions ended with their outcome; REFER NOTIFYs whose answer, or timeout, ended the subscription (RFC 6665 §4.2.2); and NOTIFYs not sent after that, the outcome among them |
| `sip.refused.method`, `sip.respond_failed` | Requests of a method rcs-as does not take, and answers the transport did not take |
| `proxy.hook_panics` | Panics recovered while rcs-as routed or served a request: it was answered 500 if it had no answer yet (#428); alarm on any |
| `sip.invite.answered`, `sip.invite.offer_refused`, `sip.invite.service_refused` | Clients' INVITEs answered 200, refused for their offer (488), and refused for their service (403) |
| `sip.invite.sent`, `sip.invite.accepted`, `sip.invite.<status>`, `sip.invite.timeout`, `sip.invite.cancelled`, `sip.invite.unsent`, `sip.invite.unresolved`, `sip.invite.unusable_answer`, `sip.invite.no_dialog`, `sip.invite.fork_dropped` | INVITEs rcs-as sent: sent, set up, failed by final status, without a final answer, cancelled, not sent, without a next hop, answered with an SDP it could not use, answered without a dialog, and second forks ended |
| `sip.session.task_limit`, `sip.session.user_limit` | Sessions refused for `RCSAS_MAX_SESSIONS` and for a user's own bound, either way |
| `sip.invite.first_message.<status>`, `sip.invite.answer_ignored` | First messages in a client's INVITE, by the status a pager MESSAGE would get; retransmitted 2xx responses that set up no dialog |
| `leg.unbound` | Legs closed because no connection bound them in time |
| `sip.session.expired`, `sip.session.no_ack` | Sessions rcs-as ended for an unrefreshed timer, and for a 2xx without an ACK |
| `sip.bye.sent`, `sip.bye.received`, `sip.refresh.answered`, `sip.refresh.refused` | Session ends and refreshes |
| `sip.dialog.unresolved`, `sip.dialog.unsent` | Requests in a dialog (ACK, BYE) without a next hop, or not sent |
| `sip.register.taken`, `sip.register.ended` | Third-party registrations and de-registrations |
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
| `invite.sent`, `invite.failed`, `invite.failed_overtaken`, `invite.no_sessions`, `invite.untracked` | Terminating session requests; `failed_overtaken` counts failures of invitations asked before the recipient's latest registration on a new flow, which leave no mark (the registration had the queue read already); a group's 482 is never one |
| `leg.opened`, `leg.unanswered` | MSRP legs, and offers that got no answer |
| `iscomposing.forwarded`, `iscomposing.dropped` | Is-composing indications |
| `msrp.accept_failed` | Failed accepts on the MSRP listener |
| `store.failed` | Store calls that failed |
| `group.created`, `group.roster_changed`, `group.update_conflict`, `group.touched` | Group lifecycle |
| `group.owner_takeover`, `group.fenced`, `group.owner_lapsed`, `task.heartbeat_failed` | Ownership (#121): groups this task took over, writes the store refused because another task had taken the group (which this task then gives up), writes refused because this task's own heartbeat had lapsed, and heartbeats that failed |
| `group.rejected.<reason>` | Group operations refused: `not_participant`, `not_chairman`, `too_many`, `invalid`, `rate_limited` |
| `group.name_dropped`, `group.invitee_skipped` | Names stored as none (too long, not text, or someone else's), and invitees left out for an identity the group cannot hold |
| `group.notification.summarized`, `group.summary.expanded`, `group.summary.sent`, `group.summary.abandoned` | Notifications that went to a summary for want of room, summaries delivered, the notifications they sent, and summaries given up after three failed removals with nothing new to send |
| `group.fanout.not_owner`, `delivery.group_not_owned`, `group.wake` | #121: fan-outs stopped because another task took the group over; group copies a task that does not own the group did not invite for; queue reads the owner was asked for |
| `group.forwarded`, `group.forward_refused`, `group.forward_refused.address`, `group.owner_lost`, `group.owned_dropped`, `sip.group.disowned.sessions` | #121: requests forwarded to a group's owner; requests answered 500 with `Retry-After` for want of an owner to forward to, and of those, the ones whose owner's address rcs-as does not forward to; groups this task gave up, those of them it dropped at the bound on the groups it remembers owning, and the sessions it ended with them |
| `group.wake_sent`, `group.wake_failed`, `sip.group.wake.<status>`, `sip.group.wake.timeout`, `sip.group.woken` | #121: wake messages sent to a group's owner, those that could not be sent, their answers, and the wakes an owner acted on |
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
| `sip.session.task_limit` > 0 | A task holds `RCSAS_MAX_SESSIONS`: scale out, or a flood of sessions |
| `sip.session.no_ack`, `sip.dialog.unsent` sustained | Requests in a dialog do not get through the core |
| `sip.loop` > 0 | A profile sends rcs-as's own requests back to it: it lacks the `P-Served-User` exclusion ([HSS](hss.md)), and those users' messages are not delivered |
| `invite.untracked` > 0 | More pending invitations than a task tracks (100 000); messages wait for the retry timer instead of an invitation |
| `group.fanout_budget_exceeded` sustained | A group writing beyond its budget: a flood, or the budget is too small for real groups |
| `group.fanout_share_exceeded` sustained | One participant writing to a large group as fast as it may: a flood |
| `group.rejected.rate_limited` sustained | Users creating groups or adding people faster than allowed: mass-add spam |

## Assumptions and limitations

- **Conversation identifiers.** RCC.07 gives no grammar for them beyond SIP,
  so each must be one RFC 3261 token of at most 256 characters. Clients
  generate UUIDs or hex strings. A request with a `Contribution-ID` and no
  `Conversation-ID`, as rcsjta sends, is taken although OMA CPM Appendix
  C.1.1 requires the latter, and gets the pair's (above). Residual: a CPM
  client that names its own Conversation-ID and an rcsjta client that
  answers it without one see two threads, the CPM client's and the pair's;
  joining them would need rcs-as to remember the ID a pair last used.
  Groups made before #305 keep the 32 hex digits they were given as their
  Conversation-ID, rather than the UUID form C.1.1 asks for, until they end.
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
- **rcs-as never refreshes a session.** A client that asks rcs-as to refresh
  (`refresher=uas`), or that does not support session timers, gets no timer
  (see [Sessions](#sessions)), and its session lasts until its MSRP connection
  or a BYE ends it.
- **A new flow is guessed.** The third-party REGISTER does not carry the
  client's REGISTER (the default profile does not ask for it), so a client
  that moves to a new flow before its registration runs out looks like one
  refreshing. It keeps a pager-only marker until it de-registers, misses a
  refresh, or opens a session itself; and what is queued for it after a
  delivery on the old flow failed waits for the invitation's
  `RCSAS_INVITE_TIMEOUT` (2 min) or the queue's retry interval (1 min and
  growing) instead of going at once. Registrations are remembered per task, up
  to 100 000 users.
- **Large messages from one sender go one session at a time.** The next one to
  the same recipient waits for the queue's next pass after the session ends.
- **One user per registration.** `UserRegistered` gets the identity in the
  third-party REGISTER's `To`; queues kept under another identity of the
  same implicit registration set wait for their own retry.
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
