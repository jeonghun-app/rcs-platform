# ADR 0005 — Shared state in DynamoDB, instance addressing only where a connection lives

**Status:** accepted

## Context

Every service scales to several tasks. SIP routing is address based: a response
follows `Via`, a terminating request follows `Path`, an in-dialog request follows
`Record-Route`.

## Decision

- Registration bindings, subscriber data, stored messages, group state, MSRP
  bindings and file metadata are in DynamoDB. A service instance keeps only
  transactions, connections and caches in memory.
- `scscf` advertises its **service** name in `Service-Route` and `Record-Route`
  and to the HSS as the S-CSCF name, so any instance can serve any user. Each
  instance still has its **own Diameter identity** (`Origin-Host` =
  `scscf-<task id>.<namespace>`), because the HSS keeps one connection per peer
  identity (RFC 6733 §5.6.4); only the S-CSCF *name* (`Server-Name`) is shared.
  State `scscf` must carry across requests is therefore shared or carried in the
  message, never kept in instance memory:
  - **Authentication challenges**: the vector (or digest nonce state) issued with
    a 401 is stored in DynamoDB `auth-challenges`, keyed by IMPI and the challenge
    nonce, with a short expiry checked on read; the second REGISTER can land on
    any instance. Reads are strongly consistent; a vector is deleted on first use
    (conditional delete) so a RES cannot be replayed.
  - **Position in the iFC chain**: when `scscf` forwards to an application server
    it adds a `Route` back to itself whose URI parameter carries the original
    dialog identifier (TS 24.229 §5.4.3.2/§5.4.3.3): the served user, session
    case and next iFC priority, HMAC-signed with a key shared by all `scscf`
    instances (Secrets Manager). Any instance can resume filter evaluation; a bad
    signature is rejected with 403. Because the signature covers the request
    (its Call-ID, method and CSeq number),
    an application server acting as a B2BUA that sends the request on in a
    dialog of its own, with a new Call-ID, is not supported: its requests come
    back with a position signed for another Call-ID and get 403, though TS
    24.229 lets the S-CSCF go on with them (§5.4.3.4, §5.4.3.2 NOTE 8).
    rcs-as, the platform's own B2BUA, sends its legs as new requests without
    the position (#137). Who goes on with a position first, the server's
    return or the default handling after its branch failed, is settled in the
    store, so only one copy of the request goes on. (Amended in #359.)
  - **reg event subscriptions** (RFC 3680): stored in DynamoDB
    `reg-subscriptions`; the NOTIFY CSeq and the reginfo `version` are allocated
    with conditional atomic counters so two instances cannot reuse a number.
- `hss` tasks have their own Diameter identity as well (`Origin-Host` =
  `hss-<random>.<namespace>`, drawn at every start). The CSCFs reach `hss`
  through its service name and send to it by Destination-Realm, so nothing needs
  a shared name; a shared one would make an S-CSCF that reconnects to another
  task after its HSS task died wait about a minute in the watchdog's REOPEN state
  (RFC 3539 §3.4.1), which only applies when the same Origin-Host comes back.
- `pcscf` advertises its **instance** address (task private IP) in `Path` and in
  the core-facing `Record-Route`, because the client's connection lives on that
  instance. The flow token in `Path` (RFC 5626 §5.2) is an HMAC over the
  connection identity (source address and port as reported by Proxy Protocol,
  listener, and a per-connection counter) keyed by a **random key generated at
  every start**. ECS can hand a dead task's IP to a new task; with a fresh key the
  new task cannot mistake an old token for one of its own connections.
  - An unknown or invalid token, or a token for a closed connection, is answered
    with **430 Flow Failed** (RFC 5626 §5.3).
  - On 430 `scscf` removes only that binding (contact + flow) from the
    registration and tries the user's remaining contacts.
  - When every contact fails, `rcs-as` stores the message for later delivery
    instead of failing it.
  - The client-facing `Record-Route` (the one the client copies into its route
    set) names the public `pcscf` address, and the core-facing entry names the
    instance (double Record-Route, RFC 5658). The client sees that private
    address in its route set but cannot use it: it reaches only the public
    address, and `pcscf` forwards its in-dialog requests to `scscf` alone.
    (Amended in #208: this said the client never sees a private IP.)
- `rcs-as` advertises its instance address in `Record-Route`/`Contact` and in
  MSRP paths, because the MSRP session lives on that instance.

## Rationale

Instance addressing exactly where a connection exists, and nowhere else, gives
horizontal scaling without sticky load balancing.

## Consequences

- A `pcscf` or `rcs-as` task that stops drops its connections and sessions;
  clients recover by re-registering and re-establishing sessions, which RCS
  clients already do.
- Rolling updates replace connection-holding tasks one at a time (ADR 0003) so
  an update never cuts every connection at once.
- HSS-initiated Cx requests (RTR, PPR) are sent by Destination-Realm to any
  connected `scscf` peer, not to the Origin-Host recorded at SAR time: that task
  may be gone, and every instance can act on any registration because the state
  is in DynamoDB. Since `hss` only answers connections, it can send them
  only over connections `scscf` opened to that `hss` task, so every `scscf` task
  keeps a Cx connection to every `hss` task (every address of `hss.<namespace>`,
  resolved again periodically); otherwise a change provisioned on a task no
  `scscf` is connected to cannot be pushed.
- The signed iFC-position parameter covers the request, by its Call-ID, method
  and CSeq number, and an expiry (default 32 s, Timer B/F) as well as served
  user, session case and next priority, so it cannot be replayed on another
  request, another of the same dialog included, or later. (Amended in #359:
  the Call-ID alone let one request's position serve another of its dialog.)
- In-dialog requests from the core reach the client the same way terminating
  initial requests do: the core-facing `Record-Route` entry `pcscf` inserts
  carries the same signed flow token as `Path`.

## Amendment (#121): one owner per group chat

**Context.** A group chat's participants hold their MSRP sessions with the
group's conference focus. With more than one `rcs-as` task, each task knew only
the sessions it held, so a message written on one task re-invited participants
whose sessions lived on another, and roster NOTIFYs reached only the
subscribers of the task that made the change.

**Decision.**

- Each group has exactly one **owner task**. All of the group's MSRP legs,
  conference subscriptions, fan-out, roster NOTIFYs and invitations for its
  queued copies live on the owner.
- Ownership is recorded in DynamoDB `groupchats`:
  - an **owner item** per group (`sk` = `owner`) holding the owner's task id,
    its SIP instance address and an **epoch** that every takeover raises by
    one;
  - a **heartbeat item** per task, whose `alive_until` the task renews every
    `RCSAS_TASK_HEARTBEAT` (5 s) to `RCSAS_TASK_LEASE` (20 s) ahead. Task ids
    are random per start, so a task that reuses a dead task's IP is never
    taken for it.
- A task that receives a request for a group it does not own, initial or in
  one of the group's dialogs (whose Contact is the conference URI, so the core
  may give their requests to any task), forwards it once to the owner's
  instance address over internal SIP (ADR 0007), with a `Route` marked
  `rcsas-fwd`, adds no `Record-Route`, and does not serve it. A forwarded
  request that reaches a task that is not the owner is not forwarded again: it
  is answered 500 with `Retry-After`, never 404, which the reference client
  takes for the group's end. The owner's address is used only if it is a
  private address on `rcs-as`'s SIP port.
- A task takes a group over with a conditional write on the owner item (same
  owner, same epoch), only once the owner's `alive_until` plus
  `RCSAS_TASK_SKEW` (2 s) has passed, or at once when the owner's address is its
  own and the task id is not.
- **Fencing.** Every write that changes a group (roster changes, activity) and
  every enqueue of a group message's copy is a transaction that includes a
  condition check on the owner item: this task, this epoch. A task that has
  lost a group therefore cannot change it or fan a message out, whatever its
  clock or pauses; its write is refused, never applied twice, and it gives the
  group up. A task whose heartbeat has not succeeded within `RCSAS_TASK_LEASE`
  minus `RCSAS_TASK_SKEW` writes no group until a beat lands, and gives up
  every group it held then, at its first failed beat past it: whether the
  store is out for every task or for this one alone, its sessions can deliver
  nothing meanwhile, as every copy is queued under the owner's fence. Decisions the store does not fence (whether to invite
  for a queued copy, where to forward a request) read the owner item again
  once a heartbeat old.
- A task that gives a group up ends the sessions and subscriptions it holds
  of it, the sessions with a BYE and the subscriptions with
  `reason=deactivated`, so that the participants rejoin through the owner.
- A task whose queue pass finds a copy of another task's group, as when the
  participant registers there, sends the owner an internal `MESSAGE` that has
  it read the queue, at most once per participant and group every
  `RCSAS_INVITE_TIMEOUT`.

**Choices made in implementing it** (accepted by the lead on #121):

- **A wake, not a forwarded receipt.** The design forwarded a notification
  that arrives by pager `MESSAGE` on a task that does not own its group. The
  wake covers that case and a registration on such a task with one mechanism.
  The notification is unique by its mark wherever it is queued, and the task
  whose queue pass then finds it wakes the owner, which delivers it.
- **500 with `Retry-After`, not 503.** A request that cannot reach the owner
  now gets the answer D1 gives a group another task owns. A proxy must not
  pass a 503 on unchanged (RFC 3261 §16.7), and scscf passes a 500 as it is.
  rcsjta treats every failure to rejoin other than 404 the same: it keeps the
  chat and tries again.
- **A plain `rcsas-fwd` flag, without the epoch.** The task that receives a
  forwarded request decides by whether it owns the group now, read from the
  store; the epoch the forwarder saw would not change that decision.
- **Only private IPv4 and IPv6 unique local owners.** A task forwards only
  to an owner address in RFC 1918 or `fc00::/7`, on rcs-as's own SIP port.
  The tasks run in a VPC on private addresses (ADR 0003), and a stored
  address outside them is not a task to send a participant's request to.
  A deployment on global IPv6 addresses would need this widened, and until
  then answers such requests 500 with `Retry-After`.

**Consequences.**

- When an owner task stops, its groups' sessions and subscriptions drop with
  it, as any `rcs-as` session does; the next request for a group takes it over,
  and clients rejoin as they do an idle group (RCC.07). Rolling updates release
  a task's heartbeat on shutdown so that takeover takes `RCSAS_TASK_SKEW`
  rather than the lease.
- `rcs-as` reaches `rcs-as` on its SIP port (ADR 0007 security group matrix).
- Each copy of a group message costs one more transactional condition check
  (about 2 WCU); each task writes its heartbeat every 5 s; a request for a
  group costs a read of the group and owner items at most once per group every
  heartbeat on each task.
- The task role needs `dynamodb:ConditionCheckItem` on `groupchats`.
