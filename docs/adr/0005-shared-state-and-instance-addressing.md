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
    signature is rejected with 403. Because the signature covers the Call-ID,
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
- The signed iFC-position parameter covers the Call-ID and an expiry (default
  32 s, Timer B/F) as well as served user, session case and next priority, so it
  cannot be replayed on another request or later.
- In-dialog requests from the core reach the client the same way terminating
  initial requests do: the core-facing `Record-Route` entry `pcscf` inserts
  carries the same signed flow token as `Path`.
