# pcscf

`pcscf` is the Proxy-CSCF: the only SIP entry point for clients (TS 24.229
§5.2). It holds their connections behind the NLB, asserts their identity and
keeps their flows (RFC 5626). It runs the proxy core of `internal/sip/proxy`
over `internal/sip/transport`; the service is `internal/pcscf`, and
`cmd/pcscf` only wires it to `internal/runtime`.

`pcscf` is built in steps (#16). This page describes what is in place: the
listeners, the edge rules, registration and the shutdown. Originating and
terminating routing and the reg event follow. Until they land, a client's
request other than REGISTER is answered 403 and a request from the core 430
Flow Failed.

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
  `P-Media-Authorization`, `Feature-Caps`, `P-Private-Network-Indication` and
  `P-Profile-Key`. It also loses every `P-Access-Network-Info` value with the
  `network-provided` parameter.
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

- **Path.** `pcscf` adds `Path: <sip:<flow token>@<task address>:<core
  port>;transport=tcp;lr>`, with `ob` when the client uses outbound (RFC 5626
  §5.1), and `Supported: path`. The flow token is the transport's flow ID,
  an HMAC under a key drawn at every start
  ([ADR 0005](adr/0005-shared-state-and-instance-addressing.md)).
- **Headers.** The network-only headers are removed, as from every client
  request.
- **The 200.** `pcscf` keeps the following in instance memory, for each
  public identity registered over each flow:
  - the client's contacts on that flow that the 200 lists;
  - the expiry, the shortest of those contacts' expiries;
  - `Service-Route` (RFC 3608);
  - `P-Associated-URI`, whose first URI is the default public identity
    (RFC 7315).

  A 200 that lists none of those contacts, after a removal, forgets the
  registration. So does the flow closing (RFC 5626 §5.3).
- **Keep-alive** ([ADR 0003](adr/0003-aws-topology.md)):

  | The client | It gets | Flow idle timeout |
  |---|---|---|
  | uses outbound: `Supported: outbound`, and `+sip.instance` and `reg-id` on every contact | `Flow-Timer: 120` and `Require: outbound` in the 200 | 180 s with TLS to the NLB, 1740 s with `tcp` |
  | asks with the Via `keep` parameter (RFC 6223) | `keep=120` in its Via of the 200 | the same |
  | does neither | its expiries capped to 600 s, in the REGISTER and in the 200 | `PCSCF_CLIENT_IDLE_TIMEOUT` (340 s) |
- **Limits.** A client address may send `PCSCF_REGISTER_RATE` REGISTERs a
  second, with a burst of `PCSCF_REGISTER_BURST`. A task keeps at most
  `PCSCF_MAX_REGISTRATIONS` registrations, and a new one past that is
  refused. Refusals are 503 with `Retry-After: 1`.

Core hops such as `icscf` are resolved by `proxy.DNSResolver`:

- It looks up A and AAAA records, keeps each answer for 10 s, and spreads
  branches over its addresses.
- It uses only private addresses. Dev and test also accept loopback.
- A Cloud Map answer holds at most eight records, chosen at random when more
  instances are registered. That is enough for CSCF fleets of that size.

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
| `PCSCF_ICSCF_URI` | `sip:icscf.<RCS_SERVICE_NAMESPACE>;transport=tcp;lr` | first Route of a REGISTER; required without a namespace |
| `PCSCF_REGISTER_RATE`, `PCSCF_REGISTER_BURST` | `50`, `200` | REGISTERs a second per client address, and the burst |
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
