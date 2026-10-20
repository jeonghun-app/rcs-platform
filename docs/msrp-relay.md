# msrp-relay

`msrp-relay` anchors MSRP at the edge ([ADR 0004](adr/0004-msrp-anchoring.md)).
Clients on the internet connect to it through the NLB, and it connects onward
to `rcs-as` in the private subnets. `pcscf` controls it the way a P-CSCF
controls an IMS access gateway (TS 23.334): while it rewrites the
`m=message` SDP of a session, it allocates a binding through the relay's
control API. The relay is an MSRP back-to-back relay. Each side is a hop of
its own, and message bodies are forwarded byte for byte.

The code is in `internal/msrprelay` (service), `internal/msrprelay/store`
(the binding store interface, a memory backend and the shared contract
tests), `internal/msrprelay/dynamostore` (DynamoDB) and `internal/proxyproto`
(PROXY protocol v2). The MSRP stack, including the `Bridge` that joins the
two sessions, is `internal/msrp`. `cmd/msrp-relay` only wires them together.

## How a session is anchored

The client always connects to the relay, and the relay always connects to
`rcs-as`. The relay never dials a client. What changes between the two rows
of ADR 0004's table is the order in which `pcscf` learns the two endpoint
paths:

| Session | `pcscf` on the offer | `pcscf` on the answer | Then |
|---|---|---|---|
| Client originates | `POST /v1/bindings` with `client_endpoint_path` (the client's `a=path`). Offer to `rcs-as`: `core_path_local`, `active`, port 9 | `PATCH` with `core_path` (rcs-as's `a=path`). Answer to the client: `client_path`, `passive` | The client connects and sends its first SEND |
| `rcs-as` originates | `POST` with `core_path`. Offer to the client: `client_path`, `actpass` | `PATCH` with `client_endpoint_path`. Answer to `rcs-as`: `core_path_local`, `active` | The client connects as soon as it has answered |

In the second row the client may connect before `pcscf` has recorded its
path. The relay then re-reads the binding for up to `RELAY_PATH_WAIT` (2 s by
default), with backoff, before it refuses the session.

When the client's first SEND arrives, `Bind` (the `msrp.Binder` of the client
connection) does the following:

1. It checks the To-Path. It must name the relay's public authority
   (`RELAY_PUBLIC_*`), and the session id must have the form the relay
   issues: 32 characters of lower-case base32. Anything else gets 481
   without a lookup.
2. It takes a token from the source's lookup budget
   (`RELAY_FAILED_LOOKUPS_PER_SOURCE`, see
   [Limits](#limits-and-robustness)). Only a lookup that finds nothing keeps
   the token.
3. It takes one of `RELAY_MAX_CONCURRENT_BINDS` bind slots, waiting up to
   250 ms for one.
4. It reads the binding with a strongly consistent read. The id is SHA-256
   of the session id in the To-Path. A missing or expired binding gets 481.
   A binding this same connection claimed, whose bridge has ended (most
   likely from the core side), also gets 481, counted as
   `Refused.EndedSession`: the session is over, and this is no second
   connection.
5. It claims the binding with a conditional write
   (`attribute_not_exists(claimed_by)`), naming this task and connection. A
   binding claimed already by another connection, on any task, gets
   **403**, and the refusal is logged (ADR 0004). RFC 4975 §5.4 would answer
   506, which fits a session held on the same node, not a claim made by
   another task. A claim the SDK retries after it had landed finds its own
   name and succeeds.
6. It releases the slot, builds the two sessions, joins them with
   `msrp.Bridge`, and opens the core one toward `rcs-as` (`msrp.Pool`, one
   connection per `rcs-as` address, RFC 4975 §5.4) within
   `RELAY_CORE_CONNECT_TIMEOUT`. A failure, including `rcs-as` answering
   481, gets 481. The slot covers only the store calls, so one unreachable
   `rcs-as` cannot use up every slot.

The bridge then runs until either side ends. When the expiry it saw at claim
time comes, the relay reads the binding again. `pcscf` extends the expiry on
every session refresh, so a live session survives. A binding that has expired
or been released ends the bridge. If the store cannot be read at that moment,
the relay tries again 30 s later and does not cut the chat.

## Control API

[`docs/api/msrp-relay.yaml`](api/msrp-relay.yaml) is the contract:
`POST /v1/bindings`, `PATCH /v1/bindings/{id}` and
`DELETE /v1/bindings/{id}` with `pcscf`'s bearer token. It is served on
`RELAY_CONTROL_ADDR`, a port separate from the admin port, and only `pcscf`'s
security group reaches it ([ADR 0007](adr/0007-internal-transport.md) §2).

- **Tokens.** The relay accepts `RELAY_PCSCF_TOKEN` and
  `RELAY_PCSCF_TOKEN_NEXT`, so a token rotates without downtime: add next on
  the relay and deploy, switch `pcscf` and deploy, then remove the old token
  and deploy. Presented and accepted tokens are compared as SHA-256 digests in
  constant time, every accepted digest every time. Staging and prod refuse to
  start without a token or with one under 43 characters (256 bits in base64).
- **Unauthenticated callers** get 401 on every path. With no token configured
  (dev and test only), every call gets 503 rather than an open API.
- **Request bodies.** One JSON object, at most 4 KiB, with the field names
  exactly as documented. Field names are case-sensitive, although Go's
  `encoding/json` alone would not make them so.
- **Paths.** Each path holds exactly one URI with a port, a session id and
  transport `tcp`. RFC 4976 relays in a path are not supported. `core_path` must be `msrp:`.
  Its host must be an address in `RELAY_CORE_NETWORKS` (RFC 1918 and ULA by
  default) or a name inside `RCS_SERVICE_NAMESPACE` (whole labels), and its
  port must be in `RELAY_CORE_PORTS` (2855, the MSRP port rcs-as listens on,
  by default). So a compromised `pcscf` cannot make the relay connect to the
  task metadata address, the internet, loopback or another service's port
  (ADR 0007 §5). The dialer checks the resolved address and the port again
  before it connects. `client_endpoint_path` is never
  dialled, so any host is accepted.
- **Set once.** A path can be set at creation or by PATCH, once. The same
  value again is accepted, so `pcscf` may retry. Another value gets 409: a new
  path is a new session (RFC 4975 §8.4) and needs a new binding.
- **Session ids.** The two sides have separate 160-bit session ids
  (`internal/msrp`, base32). The core-side id passes through the core's SIP
  signalling and logs. It must not let anyone into the session as the client.
  The client-side id is returned once, in `client_path`. The relay never
  stores it, never logs it and never uses it in a URL: the binding id is its
  SHA-256, so neither a table export nor an access log lets anyone connect as
  the client.
- **core_path_local** is `msrp://<RELAY_CORE_HOST>:9/<id>;tcp`. The relay
  does not listen on the core side, so it offers `active` with port 9 there
  (RFC 6135 §4.2.2), and RFC 4975 §8.1 makes the URI's port match the `m=`
  line. The address names the task that allocated the binding. Any task may
  open the core leg, so `rcs-as` must not compare it with the source address
  of the connection.

## The bindings table

DynamoDB table `msrp-bindings` (`RELAY_DYNAMODB_TABLE`): partition key `pk`
(string), no sort key and no index, TTL on `ttl`. Every access is by id, and
reads must be strongly consistent, which a global secondary index cannot be.

| Attribute | Type | Content |
|---|---|---|
| `pk` | S | binding id |
| `core_path` | S | `rcs-as`'s `a=path`, absent until known |
| `client_endpoint_path` | S | the client's `a=path`, absent until known |
| `core_local` | S | the relay's core-side URI |
| `expires_at` | N | expiry, epoch milliseconds, checked on every access |
| `ttl` | N | expiry, epoch seconds rounded up, for TTL cleanup only (TTL deletion may lag by days) |
| `claimed_by` | S | `<task instance>/<connection>`, absent until claimed |

Every rule is a condition on the one write that needs it: create
`attribute_not_exists(pk)`; update `expires_at > :now` plus "path absent or
equal" for each path set; claim `expires_at > :now AND
attribute_not_exists(claimed_by) AND attribute_exists(core_path) AND
attribute_exists(client_endpoint_path)`. A refused write returns the old item
(`ReturnValuesOnConditionCheckFailure`), which tells "expired" from "claimed"
from "incomplete" without a second read. It also tells a write the SDK
retried after the first attempt had landed: a claim that finds its own
claimant, or a create that finds its own `core_local` (a random session id),
succeeds. The task role needs
`dynamodb:GetItem`, `PutItem`, `UpdateItem`, `DeleteItem` and `DescribeTable`
(for `/readyz`) on this table only.

## Data path

- **Listener.** Plain TCP on `RELAY_LISTEN_ADDR`. TLS ends at the NLB, and
  `client_path` is `msrps:` (ADR 0003). Kernel TCP keep-alive is off on this
  listener and on in the dialer toward `rcs-as` (ADR 0003).
- **PROXY protocol v2.** With `RCS_PROXY_PROTOCOL=true` (refused as false in
  staging and prod), every connection must start with a v2 header within 5 s.
  A connection without one is closed and counted. A `LOCAL` header (NLB health
  check) and a connection that sends nothing at all are closed without being
  counted as refusals. The header gives the client address for the
  per-source cap. `internal/proxyproto` is the platform's PROXY parser; the
  SIP transport (#35) is to use it as well.
- **Keep-alive and idle.** Each side of a bridge sends a bodiless SEND after
  240 s of quiet (`RELAY_KEEPALIVE_INTERVAL`). An unanswered one closes the
  connection, and a refusal ends the session (`internal/msrp`). A client
  connection with no byte in either direction for 300 s
  (`RELAY_IDLE_TIMEOUT`) is closed. Both directions count, as they do for
  the NLB's own timer: `rcs-as` may send with `Failure-Report: no` or
  `partial`, which the client does not answer (RFC 4975 §7.1.2), so a client
  that only receives sends nothing at all. Both timeouts stay inside the NLB
  TLS listener's fixed 350 s (ADR 0003).
- **A client that vanishes.** A client gone without a FIN or RST is caught
  by the unanswered keep-alive when its session is quiet, and by the write
  timeout once the send buffer fills. Neither applies to a session that
  rcs-as keeps feeding small chunks nobody answers. For that case client
  sockets carry `TCP_USER_TIMEOUT` (`RELAY_TCP_USER_TIMEOUT`, 60 s; the user
  timeout of RFC 5482 §1): data unacknowledged that long ends the
  connection, instead of the kernel's retransmissions running out after
  about 15 minutes. It sends no packets of its own, so it does not conflict
  with kernel keep-alive being off. The limit applies to the relay's TCP
  peer. Behind an NLB TCP listener that is the client. Behind the TLS
  listener it is the NLB, which acknowledges data itself, so there the
  vanished client is noticed when the NLB gives up on its client side and
  closes toward the relay. Messages sent with `Failure-Report: no` or
  `partial` in that window are lost without a report, which those modes
  accept (RFC 4975 §7.1.2).
- **Connections without a session.** A new connection must name a session
  within 30 s (the active side sends its first SEND at once, RFC 4975 §5.4),
  or it is closed (`ClientsClosedUnbound`). A connection whose last bridge
  has ended, say because `rcs-as` went away, is kept like any quiet one,
  until `RELAY_IDLE_TIMEOUT`, so the client can reuse it for its next
  session. A request for the ended session gets 481.
- **Never toward clients.** The relay opens connections only to
  `core_path` hosts, after the checks above.

## Settings

Environment variables with the `RELAY_` prefix, plus the shared ones of
`internal/runtime`. "Refused" means `RCS_ENV=staging` or `prod` will not
start with that value.

| Variable | Default | Meaning |
|---|---|---|
| `RELAY_LISTEN_ADDR` | `:2855` | public MSRP listener (NLB target) |
| `RELAY_CONTROL_ADDR` | `:8082` | control API listener |
| `RELAY_PUBLIC_HOST` | required | host of every `client_path`: the NLB name or an operator FQDN |
| `RELAY_PUBLIC_PORT` | `2856`, or `2855` with `RELAY_PUBLIC_TLS=false` | port of every `client_path`: the NLB's MSRP TLS (or TCP) listener |
| `RELAY_PUBLIC_TLS` | `true` | `msrps:` in `client_path`; `false` is refused |
| `RELAY_CORE_HOST` | this task's one private IPv4 | address in `core_path_local` |
| `RELAY_CORE_NETWORKS` | `10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7` | where the relay may connect; a non-private prefix is refused |
| `RELAY_CORE_PORTS` | `2855` | the only ports the relay connects to |
| `RCS_SERVICE_NAMESPACE` | none | Cloud Map namespace; names in it may appear in `core_path` |
| `RCS_PROXY_PROTOCOL` | `false` | require PROXY v2; `false` is refused |
| `RELAY_STORE` | `dynamodb` | `dynamodb` or `memory`; `memory` is refused |
| `RELAY_DYNAMODB_TABLE` | `msrp-bindings` | table name |
| `RELAY_DYNAMODB_ENDPOINT` | AWS | endpoint override, for DynamoDB Local |
| `RELAY_STORE_TIMEOUT` | `2s` | bound on one store call, SDK retries included |
| `RELAY_PCSCF_TOKEN`, `RELAY_PCSCF_TOKEN_NEXT` | none | `pcscf`'s tokens; missing or short ones are refused |
| `RELAY_MAX_EXPIRES_IN` | `2h` | largest `expires_in`, whole seconds |
| `RELAY_MAX_CONNECTIONS` | `10000` | client connections per task |
| `RELAY_MAX_CONNECTIONS_PER_SOURCE` | `256` | client connections per source address (IPv4) or /64 (IPv6) |
| `RELAY_MAX_CONCURRENT_BINDS` | `64` | binds in their store calls (lookup and claim) per task; a bind waits up to 250 ms for a slot |
| `RELAY_FAILED_LOOKUPS_PER_SOURCE` | `120` | lookups that find no binding, per source (IPv4 address or IPv6 /64) per minute, with a burst of the same size; kept across connections |
| `RELAY_MAX_UNKNOWN_SESSIONS` | `3` | requests for unknown sessions a client connection may make per minute, plus one per session bound on it (`msrp.Config.MaxFailedBinds`) |
| `RELAY_PATH_WAIT` | `2s` | how long a client may wait for `pcscf` to record its path |
| `RELAY_CORE_CONNECT_TIMEOUT` | `5s` | connecting to `rcs-as` and its 200 to the binding SEND |
| `RELAY_KEEPALIVE_INTERVAL` | `240s` | MSRP keep-alive; must be shorter than the idle timeout |
| `RELAY_IDLE_TIMEOUT` | `300s` | close a client connection silent this long |
| `RELAY_TCP_USER_TIMEOUT` | `60s` | `TCP_USER_TIMEOUT` on client sockets: give up on data unacknowledged this long |
| `RELAY_DRAIN_TIMEOUT` | `15s` | how long bridges are kept after SIGTERM; plus 3 s (control API shutdown and the last flush) it must not exceed `RCS_SHUTDOWN_TIMEOUT` |
| `RELAY_METRICS_INTERVAL` | `1m` | how often counters are written |

For production, `RCS_SHUTDOWN_TIMEOUT` and `RELAY_DRAIN_TIMEOUT` should use
most of the ECS stop timeout (at most 120 s), for example 115 s and 100 s, so
that clients are not all cut at once on a rolling update.

## Metrics

EMF lines through `internal/runtime`, with `Service` as the only dimension.
Counters accumulate in the relay and are handed to the runtime every
`RELAY_METRICS_INTERVAL`; the runtime writes one line per metric a minute
(docs/architecture.md §8), so a busy relay writes a few dozen lines a minute,
not one per event. Counts handed over within a minute are summed; the gauges
are the last value, so a `RELAY_METRICS_INTERVAL` shorter than a minute does
not multiply them. Names come from fixed sets and never carry an identifier.

| Metric | Kind | Meaning |
|---|---|---|
| `BindingsCreated`, `BindingsReleased` | count | control API POST and DELETE |
| `BindingsClaimed` | count | bindings a client connection claimed |
| `BindingsExpired` | count | bridges ended because their binding expired or was released |
| `ActiveBridges`, `ClientConnections` | gauge, the last value of each minute | use Average or Maximum |
| `BytesFromClients`, `BytesToClients` | Bytes | octets on client connections, MSRP framing included |
| `ProxyHealthChecks` | count | PROXY `LOCAL` connections |
| `ClientsClosedIdle` | count | client connections closed by `RELAY_IDLE_TIMEOUT` |
| `ClientsClosedUnbound` | count | client connections closed for naming no session within 30 s |
| `StoreErrors` | count | store calls that failed or timed out (not those cut short by a stop) |
| `LookupBudgetUntracked` | count | lookups let through uncounted because the budget's table of sources was full |
| `Refused.<reason>` | count | `ConnectionLimit`, `SourceLimit`, `ProxyHeader`, `SourceLookupBudget`, `BindOverload`, `UnknownSession`, `EndedSession`, `IncompleteBinding`, `AlreadyClaimed`, `CoreUnreachable`, `StoreUnavailable`, `Draining`, `ControlUnauthorized`, `ControlForbidden`, `ControlInvalid` |
| `Client.Refused.<code>`, `Core.Refused.<code>` | count | MSRP requests refused on client connections or toward `rcs-as` (`internal/msrp` events) |
| `Client.Dropped.<reason>`, `Client.Closed.<reason>`, `Core.…` | count | drops and connection ends by `internal/msrp` reason (`KeepAliveTimeout`, `PeerNotReading`, `TooManyUnknownSessions`, …). `Dropped.KeepAliveNotSent` is a keep-alive the relay could not build (its random source failed); it is also logged at error level, and the next interval tries again |

Alarm candidates for Phase 7, each to get a runbook section:

- `Refused.AlreadyClaimed` as a ratio of `BindingsClaimed`, outside deploy
  windows. A client that lost its connection (NAT rebinding, a relay task
  replaced) and comes back on a new one with the same `client_path` is
  refused 403 by design (ADR 0004), so a few refusals are normal. A sustained
  ratio means session ids are reused or leaked. A rebind on the connection
  that held the binding is `EndedSession`, not this.
- `StoreErrors`, and `Refused.BindOverload` with `Refused.SourceLookupBudget`
  (lookup pressure). `Refused.Draining` is the expected noise of a stop.
- `Refused.CoreUnreachable` and `Core.Closed.*` (rcs-as connections failing).
- The table's `ConsumedReadCapacityUnits` against a budget (CloudWatch,
  DynamoDB namespace).

## Limits and robustness

What a client can make one task hold, and what happens at each bound:

| Bound | At the bound |
|---|---|
| `RELAY_MAX_CONNECTIONS` (counted from accept, PROXY header read included) | new connections are closed at once |
| `RELAY_MAX_CONNECTIONS_PER_SOURCE`, by PROXY source address (/64 for IPv6, since each mobile bearer gets a whole /64, RFC 6459 §5.2) | the connection is closed after its header |
| PROXY header within 5 s, at most 1 KiB of address and TLVs | the connection is closed |
| session id not in the issued form (32 lower-case base32 characters) | 481, no store call |
| `RELAY_FAILED_LOOKUPS_PER_SOURCE` per source per minute, across connections | the connection is closed without a store call* |
| `RELAY_MAX_UNKNOWN_SESSIONS` per connection per minute | `internal/msrp` closes the connection |
| `RELAY_MAX_CONCURRENT_BINDS` binds in their store calls, after a 250 ms wait | the connection is closed* |
| `RELAY_STORE_TIMEOUT` per store call | the connection is closed*, `StoreErrors` |
| `RELAY_CORE_CONNECT_TIMEOUT` | 481 |
| everything `internal/msrp` bounds per connection and session (header and message size, queued output, relay backlog, in-flight requests, write timeout) | see `internal/msrp` |

\* On a connection that already carries a bridge, only the new session is
refused, with 481, and the connection stays (see below).

Choices worth knowing:

- **Overload and store failures close the connection rather than answer.**
  MSRP has no "try later" (RFC 4975 §10): 481 or 403 would end a session that
  may well exist. A closed connection looks like any transport failure, and
  the client recovers from it with a new INVITE, as it would if the task had
  gone. A connection that already carries bridges is not closed, for their
  sake (a client may reuse one connection for several sessions, RFC 4975
  §5.4); the new session alone gets 481.
- **A release does not cut a running bridge at once.** A running bridge looks
  at its binding again only when the expiry it last saw comes, so a DELETE
  or a shortened expiry takes effect then (at most `RELAY_MAX_EXPIRES_IN`
  later). In practice the endpoints end the session first: after BYE, the
  next request or keep-alive toward `rcs-as` gets 481, which ends the bridge
  within one keep-alive interval.
- **Per-source cap and carrier-grade NAT.** Many subscribers share one
  public IPv4 address behind an operator's NAT, so the default is generous.
  An operator that sees `Refused.SourceLimit` from legitimate traffic should
  raise it rather than drop it.
- **Memory.** Each client connection may hold up to what `internal/msrp`
  allows for queued output (16 MiB by default) before it is cut off as not
  reading, and the write timeout (30 s) cuts a client that stops reading
  first. The worst case, all `RELAY_MAX_CONNECTIONS` at that bound at once, is
  far above any task size. The task is sized for the expected connections,
  and `RELAY_MAX_CONNECTIONS` is set to match.
- **Lookups for unknown sessions are rate-limited per source.** Each one
  that reaches the store costs one strongly consistent read (one RCU) and a
  bind slot for its duration. `RELAY_MAX_UNKNOWN_SESSIONS` limits them per
  connection, but a client resets that by reconnecting, and the connection
  caps limit concurrency, not rate. So each source (IPv4 address or IPv6
  /64) also has a token bucket of `RELAY_FAILED_LOOKUPS_PER_SOURCE` a minute
  that survives reconnects. Only lookups that find nothing keep their token,
  so clients naming sessions `pcscf` handed out do not use the budget up,
  even many of them behind one carrier-grade NAT address. A lookup still
  needs a token to start, though: once one client behind a shared address
  has emptied the bucket, every new bind from that address is refused
  (`Refused.SourceLookupBudget`) until it refills, at one token every half
  second by default. This is the same trade-off as the per-source
  connection cap, and the harm stays with that one address. Refusals
  concentrated on one address point to a shared CGNAT address with one
  misbehaving client, and `RELAY_FAILED_LOOKUPS_PER_SOURCE` can be raised
  (runbook, #54). Session ids not in the issued
  form never reach the store. The worst case per task is then the number of
  sources times the per-source rate. The table remembers at most 65,536
  sources short of tokens; beyond that, lookups are let through uncounted
  (`LookupBudgetUntracked`), since a source spread that wide is not held
  back by a per-source budget anyway.
- **Clocks.** Expiry is compared with each task's clock (Amazon Time Sync on
  Fargate). Skew between tasks shifts expiry by that much.
- **The client's From-Path is not checked.** RFC 4975 §5.4 has the passive
  side infer who connected from the session description. `msrp.Binder` sees
  only the To-Path, so the relay does not compare the first request's
  From-Path with `client_endpoint_path`. The session id in the To-Path
  (160 bits) is what admits a connection. Everything the relay sends goes
  to the stored path.
- **Binds during the drain.** A client connection that survives into the
  drain may still bind new sessions until it is closed. Binds cut short by
  the stop count as `Refused.Draining`, not as store errors.

## Shutdown

On SIGTERM the relay stops accepting and keeps existing bridges for the first
half of `RELAY_DRAIN_TIMEOUT` (or until the last client leaves). It then
closes the client connections left one at a time, at even steps over the
second half, so that their clients do not all reconnect at the same moment
(a burst of POST, PATCH and claims against the table), and finally closes the
connections toward `rcs-as`. The control API keeps
answering until then, because `pcscf` releases and extends bindings that
other tasks may hold. Clients reconnect through a new INVITE, which `pcscf`
anchors on another task ([ADR 0003](adr/0003-aws-topology.md)). `/readyz`
answers 503 from the start of the stop.

## Security notes

- `msrp-relay` can reach the `rcs-as` MSRP port and the bindings table, and
  nothing else ([threat model](threat-model.md) T3, T4). The control API
  makes sure a binding names only a private address and a port in
  `RELAY_CORE_PORTS`, and the dialer checks both again after name
  resolution. The security groups (ADR 0007 §2) remain the primary control.
- A compromised `pcscf` holding the token can create bindings without limit
  (store cost) and point them at the `RELAY_CORE_PORTS` of any address inside
  `RELAY_CORE_NETWORKS`. It cannot read content: only the client holding
  `client_path` can connect.
- **The table holds rcs-as session capabilities.** `core_path` carries
  rcs-as's session id, which lets anyone who reaches the rcs-as MSRP port
  into that session (T3). Only the client-side id is hashed. Read access to
  the table must therefore be the relay task role's alone, and table exports
  stay off. Phase 7 IAM and policy tests check both.
- Logs carry binding ids, never session ids, message bodies or client
  addresses. An MSRP URI that reaches a log (`internal/msrp`'s log values,
  for example a client's `a=path` in a message's `From-Path`) shows an IP
  address host as its network only, IPv4 /24 or IPv6 /48 without the port,
  as SIP's hosts do (#36, #80). A client's source address is not logged. A
  log of it must go through `pii.ClientIP`.

## Testing

`make check` runs the unit tests: the control API, the store contract on the
memory backend, the DynamoDB adapter against a scripted client, and the relay
end to end over loopback TCP. In those tests a fake client (`internal/msrp`)
reaches the relay and a fake `rcs-as` (`internal/msrp`) behind it, for both
rows of ADR 0004's table, with limits, PROXY v2, expiry, the claim race
between two relay tasks and the drain. `make test-integration` runs the
store contract and the two-task claim race against DynamoDB Local. TTL stays
off on those test tables: the tests run at fixed past times, and DynamoDB
Local really deletes items whose `ttl` is due, which would make them flaky.
TTL is no part of the store contract.
