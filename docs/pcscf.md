# pcscf

`pcscf` is the Proxy-CSCF: the only SIP entry point for clients (TS 24.229
§5.2). It holds their connections behind the NLB, asserts their identity and
keeps their flows (RFC 5626). It runs the proxy core of `internal/sip/proxy`
over `internal/sip/transport`; the service is `internal/pcscf`, and
`cmd/pcscf` only wires it to `internal/runtime`.

`pcscf` is built in steps (#16). This page describes what is in place: the
listeners, the edge rules, registration, a client's requests and the
shutdown. Terminating routing and the reg event follow. Until they land, a
request from the core is answered 430 Flow Failed.

## Listeners

`pcscf` runs two kinds of SIP listener ([ADR 0007](adr/0007-internal-transport.md)):

| Listener | Who reaches it | Rules |
|---|---|---|
| client (`PCSCF_CLIENT_ADDR`, TCP or TLS) | clients, through the NLB | PROXY protocol v2 required when `RCS_PROXY_PROTOCOL=true`, and the NLB's `LOCAL` health checks accepted without a flow ([ADR 0003](adr/0003-aws-topology.md)); client-facing: no kernel TCP keep-alive, no connection opened to a client's Via; closed after `PCSCF_CLIENT_IDLE_TIMEOUT` of silence |
| client UDP (`PCSCF_CLIENT_UDP_ADDR`) | clients, dev and test only | refused in staging and prod; its Via names its own port |
| core (`PCSCF_CORE_ADDR`, TCP) | `scscf` only, by security group | trusted; core TCP keep-alive |

`PCSCF_CLIENT_TRANSPORT` says what the client's connection is:

- `tls`: `pcscf` terminates TLS with `PCSCF_TLS_CERT_FILE` and `PCSCF_TLS_KEY_FILE`.
- `nlb-tls`: the NLB terminates TLS, and `pcscf` sees TCP, on port 5061 by
  default.
- `tcp`: plain TCP end to end, for dev and test. It is refused in staging and prod.

## Edge rules

- **Route.** `pcscf` takes a Route value as its own when it names one of
  these, on the public port or on 5060 or 5061:
  - the public host (`PCSCF_PUBLIC_HOST`);
  - the NLB's public addresses (`PCSCF_PUBLIC_ADDRS`);
  - this task's address (`PCSCF_CORE_HOST`).

  A URI without a port means 5060 for `sip` and 5061 for `sips` or
  `transport=tls`. A client puts the address it got from P-CSCF discovery in
  its first Route (TS 24.229 §5.1.2A.1.1 a). That is an IP address, since a
  discovered name is resolved at discovery (NOTE 15), so behind the NLB it is
  one of the NLB's public addresses. rcsjta writes
  `<sip:<address>:<port>;transport=tls;lr>`. Some clients write the name.
  The core listener's port at the task's address is what `Path` and the
  core-facing `Record-Route` name
  ([ADR 0005](adr/0005-shared-state-and-instance-addressing.md)).
- **Network-only headers.** Every request and response a client sends loses
  every header only the network may set, on arrival, before anything routes
  it ([ADR 0007](adr/0007-internal-transport.md) §7):
  `P-Asserted-Identity`, `P-Served-User`, `P-Asserted-Service`,
  `P-Charging-Vector`, `P-Charging-Function-Addresses`,
  `P-Visited-Network-ID`, `P-Associated-URI`, `P-Called-Party-ID`,
  `P-Media-Authorization`, `Feature-Caps`, `P-Private-Network-Indication`,
  `P-Profile-Key` and `Path`, which a registrar would keep. It also loses
  every `P-Access-Network-Info` value with the `network-provided` parameter.
- **Flows per client.** One client holds at most `PCSCF_MAX_FLOWS_PER_IP`
  client flows. A client is the address in the PROXY header behind the NLB:
  an IPv4 address, or the /64 of an IPv6 one. A flow beyond that is refused
  when it is accepted. The default is high because mobile clients share
  public addresses behind carrier-grade NAT. Core flows are not counted.
- **Flows in all.** Client flows take at most `PCSCF_MAX_CLIENT_FLOWS` of the
  transport's `PCSCF_MAX_CONNECTIONS`. At least `PCSCF_CORE_CONNECTIONS` of
  the rest stay for the core listener, so clients cannot keep `scscf` out.
  A connection counts once its PROXY header is read, so its TLS handshake
  is counted; connections still sending the PROXY header are not yet, and
  per-listener limits for them are #193.

## Registration

A client's REGISTER goes to `icscf` (`PCSCF_ICSCF_URI`, by default
`sip:icscf.<RCS_SERVICE_NAMESPACE>;transport=tcp;lr`), out of the core
listener (TS 24.229 §5.2.2.1):

- **Route.** `icscf` is the only Route. `pcscf` chooses the I-CSCF, so a
  Route the client wrote below `pcscf`'s own is dropped.
- **Path.** `pcscf` adds `Path: <sip:<flow token>@<task address>:<core
  port>;transport=tcp;lr>`, with `ob` when the client uses outbound (RFC 5626
  §5.1), and `Require: path`. The flow token is the transport's flow ID,
  an HMAC under a key drawn at every start
  ([ADR 0005](adr/0005-shared-state-and-instance-addressing.md)). A `Path`
  the client wrote is gone already, with the other network-only headers.
- **Network headers.** `pcscf` adds `P-Visited-Network-ID`
  (`PCSCF_VISITED_NETWORK_ID`, the home domain by default), from which
  `icscf` takes the Visited-Network-Identifier of its UAR, and
  `P-Charging-Vector` with a new `icid-value` for each REGISTER.
- **Failover.** `pcscf` tries `icscf`'s addresses in a random order. An
  address it cannot connect to, that does not answer within 8 s, or that
  answers 3xx, 480 or 503 gives way to the next, up to three (§5.2.2.1 7)).
  The client gets 504 when all of them have failed, or when the lookup
  failed, well before its own 32 s timeout.
- **The 200.** `pcscf` keeps the following in instance memory, for each
  public identity registered over each flow:
  - the client's contacts on that flow that the 200 lists;
  - the expiry, the shortest of those contacts' expiries;
  - `Service-Route` (RFC 3608);
  - `P-Associated-URI`, whose first URI is the default public identity
    (RFC 7315).

  A 200 that lists none of those contacts, after a removal, forgets the
  registration. So does the flow closing (RFC 5626 §5.3), even when it
  closes before the 200 arrives. A REGISTER without `Contact` only fetches
  the bindings and changes nothing.
- **Keep-alive** ([ADR 0003](adr/0003-aws-topology.md)):

  | The client | It gets | Flow idle timeout |
  |---|---|---|
  | uses outbound: `Supported: outbound` or `Require: outbound`, and `+sip.instance` and `reg-id` on every contact, and the registrar's 200 has `Require: outbound` (RFC 5626 §5.4) | `Flow-Timer: 120` in the 200 | 180 s with TLS to the NLB, 1740 s with `tcp` |
  | asks with the Via `keep` parameter (RFC 6223) | `keep=120` in its Via of the 200 | the same |
  | does neither | its expiries capped to 600 s, in the REGISTER and in the 200 | `PCSCF_CLIENT_IDLE_TIMEOUT` (340 s) |
- **Limits.** A client address may send `PCSCF_REGISTER_RATE` REGISTERs a
  second, with a burst of `PCSCF_REGISTER_BURST`. A task keeps at most
  `PCSCF_MAX_REGISTRATIONS` registrations. A REGISTER takes its slot before
  it is forwarded and gives it back if it ends unregistered, so a new one
  past the limit is refused at once rather than after a 200 `pcscf` could not
  keep. Refusals are 503 with `Retry-After: 1`.

Core hops such as `icscf` are resolved by `proxy.DNSResolver`:

- It looks up only names inside `RCS_SERVICE_NAMESPACE`, whole labels
  compared ([ADR 0007](adr/0007-internal-transport.md) §5), so a name a
  client wrote costs no lookup.
- It looks up A and AAAA records, keeps each answer for 10 s, and gives every
  address, in a new random order each time.
- When a lookup fails, the last answer is still used for 5 minutes. A failed
  lookup is logged once, then at most once a minute while it keeps failing,
  with its class: `not found` (a missing record, so a configuration error),
  `timeout` or `error`.
- It uses only private addresses. Dev and test also accept loopback.
- A Cloud Map answer holds at most eight records, chosen at random when more
  instances are registered. That is enough for CSCF fleets of that size.

## A client's requests

**Outside a dialog** (no To tag, TS 24.229 §5.2.6.3.3), a request needs a
registration over the flow it comes on; without one it is answered 403.

- **Route.** The request goes along the `Service-Route` its registration
  received, which replaces whatever Route the client wrote below `pcscf`'s
  own. A registration without a `Service-Route` is answered 500, since the
  next hop would otherwise be a core address the client chose.
- **Identity.** `pcscf` removes `P-Preferred-Identity` and asserts one
  identity in `P-Asserted-Identity` (#16 decision 5):
  - the first `P-Preferred-Identity` value that a registration over the
    flow lists in its `P-Associated-URI`, which holds no barred identity;
    the request then goes along that registration's `Service-Route`;
  - otherwise the default public identity, the first `P-Associated-URI` of
    the flow's first registration.

  A SIP or SIPS identity is joined by the registration's first tel URI
  (RFC 3325 §9.1 allows one of each). Parameters other than `user` are
  dropped.
- **Charging.** `P-Charging-Vector` gets a new `icid-value` for each request.
- **Record-Route.** `pcscf` records two values (RFC 5658), topmost first:
  `<sip:<flow token>@<task address>:<core port>;transport=tcp;lr>`, with `ob`
  when the client's Contact has it, for the core, and
  `<sip:<PCSCF_PUBLIC_HOST>:<PCSCF_PUBLIC_PORT>;transport=tls;lr>` (`tcp`
  with `tcp`) for the client. The dialog's later requests come back through
  this task on both sides.
- **Limit.** A client address may send `PCSCF_INITIAL_RATE` such requests a
  second, with a burst of `PCSCF_INITIAL_BURST`, beside its REGISTERs. Past
  that it gets 503 with `Retry-After: 1`.

**Inside a dialog** (#16 decision 6): `pcscf` keeps no dialog state, so the
route a request carries must show that the dialog was set up through this
`pcscf` and this flow. It is forwarded as its Route says only if:

- both of `pcscf`'s Record-Route values were among the Route values it
  consumed: one naming the public host or an NLB address, and one naming
  this task's core listener;
- the core one's flow token is the flow the request came on;
- the next hop, the Route below them or else the Request-URI, resolves to a
  private address, a name being looked up only inside
  `RCS_SERVICE_NAMESPACE`.

Anything else is answered 403, so a client cannot aim a request at a core
address of its choosing past the services that should see it. An ACK for a
2xx follows the same rule. No registration is needed, so a call can still
be ended after the client deregisters.

## Settings

Environment variables with the `PCSCF_` prefix, plus the shared ones of
`internal/runtime`. "Refused" means `RCS_ENV=staging` or `prod` will not
start with that value.

| Variable | Default | Meaning |
|---|---|---|
| `PCSCF_PUBLIC_HOST` | required | the name clients dial: the NLB name or an operator FQDN; a trailing dot is dropped |
| `PCSCF_PUBLIC_ADDRS` | none | the NLB's public addresses, comma-separated, from the stack; unset is refused |
| `PCSCF_PUBLIC_PORT` | `5061`, or `5060` with `tcp` | the port clients dial |
| `PCSCF_CLIENT_TRANSPORT` | `tls` | `tls`, `nlb-tls` or `tcp`; `tcp` is refused |
| `PCSCF_CLIENT_ADDR` | `0.0.0.0:5061`, or `:5060` with `tcp` | client listener (NLB target) |
| `PCSCF_TLS_CERT_FILE`, `PCSCF_TLS_KEY_FILE` | none | certificate of `tls`, required with it |
| `PCSCF_CLIENT_UDP_ADDR` | none | UDP client listener; refused |
| `PCSCF_CORE_ADDR` | `0.0.0.0:5070` | core listener |
| `PCSCF_CORE_HOST` | this task's one private IPv4 | the task address `pcscf` names itself by |
| `RCS_PROXY_PROTOCOL` | `false` | require PROXY v2 on the client listener; `false` is refused |
| `PCSCF_MAX_FLOWS_PER_IP` | `1024` | client flows per client (IPv4 address or IPv6 /64) |
| `PCSCF_ICSCF_URI` | `sip:icscf.<RCS_SERVICE_NAMESPACE>;transport=tcp;lr` | the Route of a REGISTER: a `sip` URI with `transport=tcp` and `lr`, of an address or a name inside `RCS_SERVICE_NAMESPACE`; required without a namespace |
| `PCSCF_VISITED_NETWORK_ID` | `RCS_IMS_DOMAIN` | `P-Visited-Network-ID` of REGISTERs, one network identifier (RFC 7315 §4.3); required without `RCS_IMS_DOMAIN` |
| `PCSCF_REGISTER_RATE`, `PCSCF_REGISTER_BURST` | `50`, `200` | REGISTERs a second per client address, and the burst |
| `PCSCF_INITIAL_RATE`, `PCSCF_INITIAL_BURST` | `50`, `200` | requests outside a dialog a second per client address, and the burst |
| `PCSCF_MAX_REGISTRATIONS` | `100000` | registrations kept by one task |
| `PCSCF_MAX_CONNECTIONS` | `10000` | connections the transport accepts |
| `PCSCF_MAX_CLIENT_FLOWS` | `9000` | client flows among them; plus `PCSCF_CORE_CONNECTIONS` it must not exceed `PCSCF_MAX_CONNECTIONS` |
| `PCSCF_CORE_CONNECTIONS` | `256` | connections kept for the core listener |
| `PCSCF_CLIENT_IDLE_TIMEOUT` | `340s` | close a client connection silent this long, just under the NLB TLS listener's 350 s |
| `PCSCF_DRAIN_TIMEOUT` | `RCS_SHUTDOWN_TIMEOUT` less 5 s | how long a stop spreads the closing of client flows over; plus 5 s it must not exceed `RCS_SHUTDOWN_TIMEOUT` |

For production, set `RCS_SHUTDOWN_TIMEOUT` to most of the ECS stop timeout,
for example `115s`, so that the drain spreads over about 110 s.

## Shutdown

On SIGTERM `pcscf` stops accepting client connections and closes the client
flows one by one, evenly spread over `PCSCF_DRAIN_TIMEOUT`. A flow that
already ended takes no time of its own. The core listener stays open until
the end, so `scscf` can still reach the clients not yet closed. A stopping task's
clients then reconnect to another task and re-register over the stop
timeout, not all at once, and `hss` and `scscf` are sized for that burst
([ADR 0003](adr/0003-aws-topology.md)).
