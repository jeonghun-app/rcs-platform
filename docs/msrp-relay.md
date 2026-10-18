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

1. It checks that the To-Path names the relay's public authority
   (`RELAY_PUBLIC_*`). Anything else gets 481 without a lookup.
2. It takes one of `RELAY_MAX_CONCURRENT_BINDS` lookup slots. If none is
   free, it closes the connection (see [Limits](#limits-and-robustness)).
3. It reads the binding with a strongly consistent read. The id is SHA-256
   of the session id in the To-Path. A missing or expired binding gets 481.
4. It claims the binding with a conditional write
   (`attribute_not_exists(claimed_by)`), naming this task and connection. A
   binding claimed already, by any task, gets **403**, and the refusal is
   logged (ADR 0004). RFC 4975 §5.4 would answer 506, which fits a session
   held on the same node, not a claim made by another task.
5. It builds the two sessions, joins them with `msrp.Bridge`, and opens the
   core one toward `rcs-as` (`msrp.Pool`, one connection per `rcs-as`
   address, RFC 4975 §5.4) within `RELAY_CORE_CONNECT_TIMEOUT`. A failure,
   including `rcs-as` answering 481, gets 481.

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
- **Paths.** Each path holds exactly one URI with a port and a session id.
  RFC 4976 relays in a path are not supported. `core_path` must be `msrp:`.
  Its host must be an address in `RELAY_CORE_NETWORKS` (RFC 1918 and ULA by
  default) or a name inside `RCS_SERVICE_NAMESPACE` (whole labels), so a
  compromised `pcscf` cannot make the relay connect to the task metadata
  address, the internet or loopback (ADR 0007 §5). The dialer checks the
  resolved address again before it connects. `client_endpoint_path` is never
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
from "incomplete" without a second read. The task role needs
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
  per-source cap. `internal/proxyproto` is a small parser of its own, kept
  apart from the SIP stack; the SIP transport has its own copy in review
  (#35).
- **Keep-alive and idle.** Each side of a bridge sends a bodiless SEND after
  240 s of quiet (`RELAY_KEEPALIVE_INTERVAL`). An unanswered one closes the
  connection, and a refusal ends the session (`internal/msrp`). A client
  connection with no byte from the client for 300 s (`RELAY_IDLE_TIMEOUT`) is
  closed. Both stay inside the NLB TLS listener's fixed 350 s (ADR 0003).
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
| `RELAY_PUBLIC_PORT` | `2856` | port of every `client_path`: the NLB's MSRP TLS listener |
| `RELAY_PUBLIC_TLS` | `true` | `msrps:` in `client_path`; `false` is refused |
| `RELAY_CORE_HOST` | this task's one private IPv4 | address in `core_path_local` |
| `RELAY_CORE_NETWORKS` | `10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7` | where the relay may connect; a non-private prefix is refused |
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
| `RELAY_MAX_CONCURRENT_BINDS` | `64` | binding lookups in flight per task |
| `RELAY_MAX_UNKNOWN_SESSIONS` | `3` | requests for unknown sessions a client connection may make per minute, plus one per session bound on it (`msrp.Config.MaxFailedBinds`) |
| `RELAY_PATH_WAIT` | `2s` | how long a client may wait for `pcscf` to record its path |
| `RELAY_CORE_CONNECT_TIMEOUT` | `5s` | connecting to `rcs-as` and its 200 to the binding SEND |
| `RELAY_KEEPALIVE_INTERVAL` | `240s` | MSRP keep-alive; must be shorter than the idle timeout |
| `RELAY_IDLE_TIMEOUT` | `300s` | close a client connection silent this long |
| `RELAY_DRAIN_TIMEOUT` | `15s` | how long bridges are kept after SIGTERM; must be shorter than `RCS_SHUTDOWN_TIMEOUT` |
| `RELAY_METRICS_INTERVAL` | `1m` | how often counters are written |

For production, `RCS_SHUTDOWN_TIMEOUT` and `RELAY_DRAIN_TIMEOUT` should use
most of the ECS stop timeout (at most 120 s), for example 115 s and 100 s, so
that clients are not all cut at once on a rolling update.

## Metrics

EMF lines through `internal/runtime`, with `Service` as the only dimension.
Counters accumulate and are written every `RELAY_METRICS_INTERVAL`, so a busy
relay writes a few dozen lines a minute, not one per event. Names come from
fixed sets and never carry an identifier.

| Metric | Kind | Meaning |
|---|---|---|
| `BindingsCreated`, `BindingsReleased` | count | control API POST and DELETE |
| `BindingsClaimed` | count | bindings a client connection claimed |
| `BindingsExpired` | count | bridges ended because their binding expired or was released |
| `ActiveBridges`, `ClientConnections` | gauge, written every interval | use Average or Maximum |
| `BytesFromClients`, `BytesToClients` | count | octets on client connections, MSRP framing included |
| `ProxyHealthChecks` | count | PROXY `LOCAL` connections |
| `ClientsClosedIdle` | count | client connections closed by `RELAY_IDLE_TIMEOUT` |
| `StoreErrors` | count | store calls that failed or timed out |
| `Refused.<reason>` | count | `ConnectionLimit`, `SourceLimit`, `ProxyHeader`, `BindOverload`, `UnknownSession`, `IncompleteBinding`, `AlreadyClaimed`, `CoreUnreachable`, `StoreUnavailable`, `ControlUnauthorized`, `ControlForbidden`, `ControlInvalid` |
| `Client.Refused.<code>`, `Core.Refused.<code>` | count | MSRP requests refused on client connections or toward `rcs-as` (`internal/msrp` events) |
| `Client.Dropped.<reason>`, `Client.Closed.<reason>`, `Core.…` | count | drops and connection ends by `internal/msrp` reason (`KeepAliveTimeout`, `PeerNotReading`, `TooManyUnknownSessions`, …) |

Useful alarms: `Refused.AlreadyClaimed` above zero (a session id was reused
or leaked), `StoreErrors`, `Refused.BindOverload`, and `Core.Closed.*`
(rcs-as connections failing).

## Limits and robustness

What a client can make one task hold, and what happens at each bound:

| Bound | At the bound |
|---|---|
| `RELAY_MAX_CONNECTIONS` (counted from accept, PROXY header read included) | new connections are closed at once |
| `RELAY_MAX_CONNECTIONS_PER_SOURCE`, by PROXY source address (/64 for IPv6, since each mobile bearer gets a whole /64, RFC 6459 §5.2) | the connection is closed after its header |
| PROXY header within 5 s, at most 1 KiB of address and TLVs | the connection is closed |
| `RELAY_MAX_UNKNOWN_SESSIONS` per connection per minute | `internal/msrp` closes the connection |
| `RELAY_MAX_CONCURRENT_BINDS` lookups in flight | the connection is closed |
| `RELAY_STORE_TIMEOUT` per store call | the connection is closed, `StoreErrors` |
| `RELAY_CORE_CONNECT_TIMEOUT` | 481 |
| everything `internal/msrp` bounds per connection and session (header and message size, queued output, relay backlog, in-flight requests, write timeout) | see `internal/msrp` |

Choices worth knowing:

- **Overload and store failures close the connection rather than answer.**
  MSRP has no "try later" (RFC 4975 §10): 481 or 403 would end a session that
  may well exist. A closed connection looks like any transport failure, and
  the client recovers from it with a new INVITE, as it would if the task had
  gone.
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
- **Junk lookups cost reads.** Every request for an unknown session id costs
  one strongly consistent read (one RCU). This is bounded per connection by
  `RELAY_MAX_UNKNOWN_SESSIONS` and per task by the connection caps.
- **Clocks.** Expiry is compared with each task's clock (Amazon Time Sync on
  Fargate). Skew between tasks shifts expiry by that much.
- **The client's From-Path is not checked.** RFC 4975 §5.4 has the passive
  side infer who connected from the session description. `msrp.Binder` sees
  only the To-Path, so the relay does not compare the first request's
  From-Path with `client_endpoint_path`. The session id in the To-Path
  (160 bits) is what admits a connection. Everything the relay sends goes
  to the stored path.
- **Binds during the drain.** A client connection that survives into the
  drain may still bind new sessions until the drain timeout closes it.

## Shutdown

On SIGTERM the relay stops accepting, keeps existing bridges for
`RELAY_DRAIN_TIMEOUT` (or until the last client leaves), then closes every
client connection and the connections toward `rcs-as`. The control API keeps
answering until then, because `pcscf` releases and extends bindings that
other tasks may hold. Clients reconnect through a new INVITE, which `pcscf`
anchors on another task ([ADR 0003](adr/0003-aws-topology.md)). `/readyz`
answers 503 from the start of the stop.

## Security notes

- `msrp-relay` can reach the `rcs-as` MSRP port and the bindings table, and
  nothing else ([threat model](threat-model.md) T3, T4). The control API
  makes sure a binding names only a private `rcs-as` address, and the dialer
  checks again after name resolution. The security groups (ADR 0007 §2)
  remain the primary control. The relay does not restrict ports.
- A compromised `pcscf` holding the token can create bindings without limit
  (store cost) and point them at any MSRP port inside `RELAY_CORE_NETWORKS`.
  It cannot read content: only the client holding `client_path` can connect.
- Logs carry binding ids, never URIs, session ids, message bodies or client
  addresses (#36 tracks address truncation platform-wide).

## Testing

`make check` runs the unit tests: the control API, the store contract on the
memory backend, the DynamoDB adapter against a scripted client, and the relay
end to end over loopback TCP. In those tests a fake client (`internal/msrp`)
reaches the relay and a fake `rcs-as` (`internal/msrp`) behind it, for both
rows of ADR 0004's table, with limits, PROXY v2, expiry, the claim race
between two relay tasks and the drain. `make test-integration` runs the
store contract and the two-task claim race against DynamoDB Local.
