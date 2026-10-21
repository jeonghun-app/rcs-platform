# pcscf

`pcscf` is the Proxy-CSCF: the only SIP entry point for clients (TS 24.229
§5.2). It holds their connections behind the NLB, asserts their identity and
keeps their flows (RFC 5626). It runs the proxy core of `internal/sip/proxy`
over `internal/sip/transport`; the service is `internal/pcscf`, and
`cmd/pcscf` only wires it to `internal/runtime`.

`pcscf` is built in steps (#16). This page describes what is in place: the
listeners, the edge rules, registration, a client's requests, requests from
the core and the shutdown. The reg event follows.

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
- **Flows in all.** The client listener holds at most
  `PCSCF_MAX_CLIENT_FLOWS` connections of the transport's
  `PCSCF_MAX_CONNECTIONS`, and the core listener `PCSCF_CORE_CONNECTIONS`;
  together they must fit under the total, so clients at their limit cannot
  keep `scscf` out (#193). A connection counts from accept, while it is
  still sending its PROXY header (at most 2 s) or in its TLS handshake, and
  as a flow after. `pcscf` opens no stream listener without a limit.
- **Listener metrics.** Every sweep (30 s) exports what the transport
  counts, the counts as the change since the last sweep:

  | Metric | Kind | What it counts |
  |---|---|---|
  | `transport.listener_connections.client`, `.core` | gauge | connections each listener holds, to see one near its limit before it refuses |
  | `transport.client_listener_rejected` | count | connections refused at `PCSCF_MAX_CLIENT_FLOWS` |
  | `transport.core_listener_rejected` | count | connections refused at `PCSCF_CORE_CONNECTIONS`: `scscf` kept out, to alarm on |
  | `transport.rejected` | count | connections refused at `PCSCF_MAX_CONNECTIONS` |
  | `transport.proxy_header_timeouts` | count | PROXY headers that did not arrive within 2 s |
  | `transport.proxy_header_errors` | count | PROXY headers begun and then malformed or cut: a peer that is not the NLB, or an NLB not sending them |
  | `transport.proxy_header_empty` | count | connections closed or reset before any byte: clients or scanners that gave up, never the NLB, whose health checks send a LOCAL header (ADR 0003) |

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
  `P-Charging-Vector` with a new `icid-value` for each REGISTER and
  `RCS_IMS_DOMAIN` as the type 1 `orig-ioi` (§5.2.2.1 3)).
- **Credentials.** `pcscf` owns the `integrity-protected` parameter of
  `Authorization` (§5.2.2.1). It sets none, so `scscf` always challenges,
  and removes whatever value a client wrote. A REGISTER whose
  `Authorization` cannot be parsed is answered 400.
- **Failover.** `pcscf` tries `icscf`'s addresses in a random order. An
  address it cannot connect to, that does not answer in time, or that
  answers 3xx, 480 or 503 gives way to the next, up to three (§5.2.2.1 7)).
  The first attempt may take 12 s, longer than the core's own retry of an
  HSS (two attempts of 5 s), so a slow but working core is not taken for a
  dead one; the next ones share what is left of 30 s, which is usually one
  more. The client gets 504 when all of them have failed, or when the lookup
  failed, before its own 32 s timeout. A 200 that arrives after its attempt
  was cut short is dropped, and the client's next REGISTER recovers.
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
  keep. One flow may have REGISTERs under way for at most eight
  identities, and one client address (or IPv6 /64) for at most
  `PCSCF_MAX_PENDING_REGISTERS_PER_IP` over all its flows, so a client
  cannot hold slots by writing new To values while the core is slow. The
  address bound is higher because carrier-grade NAT puts many phones behind
  one address. Every REGISTER the core will see costs it
  a UAR and an authentication vector, so once it has parsed the task as a
  whole takes at most `PCSCF_MAX_REGISTER_RATE` a second, with a burst of
  `PCSCF_MAX_REGISTER_BURST`, and counts the ones it refuses in
  `register.refused_task_rate`. New registrations may use three quarters of
  that; the rest is kept for refreshes of registrations the flow holds, so
  a flood of new ones does not make clients lose theirs. Refusals are 503
  with `Retry-After: 1`.

Core hops such as `icscf` are resolved by `proxy.DNSResolver`:

- It looks up only names inside `RCS_SERVICE_NAMESPACE`, whole labels
  compared ([ADR 0007](adr/0007-internal-transport.md) §5), so a name a
  client wrote costs no lookup.
- It looks up A and AAAA records, keeps each answer for 10 s, and gives every
  address, in a new random order each time.
- A name is looked up by one lookup at a time, which no request waits on
  while there is an answer to use: past its TTL the last answer is used at
  once while it is refreshed, for up to 5 minutes. After a failed refresh
  the next waits 5 s, doubling to a minute while they keep failing. A name
  with no answer at all is looked up again every 5 s, so a new stack or a
  recovering service is found soon, and gets the last error in between. A failed lookup is logged once,
  then at most once a minute while it keeps failing, with its class: `not
  found` (a missing record, so a configuration error), `timeout` or
  `error`.
- It uses only private addresses. Dev and test also accept loopback.
- A Cloud Map answer holds at most eight records, chosen at random when more
  instances are registered. That is enough for CSCF fleets of that size.

## Reg event

`pcscf` subscribes to the reg event of the users it serves (TS 24.229
§5.2.3, RFC 3680), so that it learns when the network ends a registration
(§5.2.5.2). The #16 plan E decisions shape it:

- **One per user.** A task keeps one subscription for each default public
  identity (the first `P-Associated-URI`, or the registered identity
  without one) that a flow of the task has registered. The first 200 to a
  REGISTER of that user sets it up; the others leave it alone.
- **The SUBSCRIBE.** It goes along the registration's `Service-Route` to the
  user's `scscf` (§5.2.3 1B)):
  - Request-URI and `To` the default public identity, `From`
    `sip:<PCSCF_PUBLIC_HOST>`;
  - `Event: reg`, `Accept: application/reginfo+xml`, and `Expires` twice the
    registration's time left, at least 1200 s;
  - `P-Asserted-Identity` the `Path` URI `pcscf` wrote for that
    registration, which `scscf` checks against the `Path` it keeps
    (§5.2.3 1) f)), and a `P-Charging-Vector` with a new icid;
  - `Contact: <sip:reg.<random id>@<task address>:<core port>;transport=tcp>`.
    A flow token never has a dot, so the two never meet.

  A registration without a `Service-Route` has no way to `scscf` and is not
  subscribed for.
- **Refresh and end.** Every sweep (30 s) refreshes a subscription 600 s
  before it expires, or half way when granted for less than 1200 s, in its
  dialog, with the `Path` of the user's registration that expires last. A
  subscription whose user has no registration left on the task is ended
  with `Expires: 0`, and forgotten at once. Every SUBSCRIBE asserts a
  `Path`, the refreshes and the end too (the last one asserted). An active
  NOTIFY without `expires` (RFC 6665 §4.2.2 requires one) leaves the
  subscription for what was granted, or asked for, so a refresh is always
  due.
- **NOTIFY.** A request from the core whose Request-URI is a subscription's
  `Contact` is answered by `pcscf` itself; a client never reaches it, and
  any other request from the core goes to the client flow its Route names.
  The first NOTIFY sets up the dialog (RFC 6665 §4.4.1) only with the
  SUBSCRIBE's Call-ID, compared exactly, and its `From` tag as `To` tag,
  compared without case; later ones must be in that dialog and in order
  (RFC 3261 §12.2.2), a lower CSeq refused. A NOTIFY for no subscription is
  481 before its body is read. Another dialog or Call-ID is 481, a NOTIFY
  out of order 500, another event or an event `id` 489, a body other
  than `application/reginfo+xml` 415, and a missing `Subscription-State` or
  a document that does not parse 400; none of them changes anything. Other
  methods are 405. The 200 carries a `P-Charging-Vector` with the
  NOTIFY's icid and `RCS_IMS_DOMAIN` as `term-ioi`.
- **Deregistration** (#16 plan E, decision 5). A document newer than the
  last one (RFC 3680 §5.2) acts on the registrations of the subscription's
  user on this task. Identities are found as `reginfo` finds them, in the
  canonical IMPU form; a contact of a registration is its binding in the
  document: the contact with its `+sip.instance` and, when both have one,
  its `reg-id`, or without an instance the contact at its URI (RFC 5626 §6;
  scscf writes one contact per binding, #14):
  - an identity not active, or a contact whose binding is not active,
    ends; a registration whose identity or every contact ended is ended;
  - an associated identity not active, or none of whose bindings with the
    registration's contacts is active, may no longer be asserted, and a
    registration with none of its associated identities left is ended;
  - a partial document ends only what it lists; a full one is the whole
    state, so what it does not list is ended too, after a lost
    subscription or a missed document alike, but only if an earlier
    document of the user, on this subscription or one before it, showed
    it active (the record goes with the user when a document ends the
    default identity and another identity becomes the key). A binding
    whose 200 overtook a full document made before
    it is not ended for being left out; a document that lists it ended,
    or its expiry, ends it. A registered identity no document has listed,
    such as a barred one scscf leaves out of reginfo, is judged by its
    bindings wherever the document lists them under an active
    registration. A partial document that
    skips a version makes the next sweep refresh the subscription, which
    brings a full one.

  Each registration ended is counted in `regevent.deregistered`. The flow
  stays open, so the client, which learns of it from its own subscription,
  can register again over it. Ending reg-id 1 of a device leaves the
  registration of its reg-id 2 flow. A registration is removed only if it
  is still the one the document was read against, so a REGISTER's 200
  saved meanwhile stays.
- **Failures.** None of them deregisters anyone; each SUBSCRIBE that
  fails is counted in `regevent.subscribe_failed`, the alarm that network
  deregistration has stopped working.
  - A first SUBSCRIBE that fails, is refused, gets a 2xx without
    `Expires`, or gets no NOTIFY within Timer N (64×T1, 32 s, RFC 6665
    §4.1.2.4) ends the subscription. It is set up again after a backoff of
    30 s, doubling with each failure in a row up to an hour, or after its
    `Retry-After` if longer. A refusal that will not change (404, 405,
    410, 416, 489, 501, 603, 604) waits an hour. A 403 backs off like a
    failure: `scscf` answers it to any SUBSCRIBE for an identity it has no
    registration of, which a SUBSCRIBE sent before the registration is
    stored is too (#256). A NOTIFY resets the backoff.
  - A refresh that fails leaves the subscription valid until it expires
    (TS 24.229 §5.2.3, RFC 6665 §4.1.2.2): its NOTIFYs are still taken, and
    the refresh is tried again after the same backoff and no sooner than
    its `Retry-After`; a refresh that succeeds starts the count again.
    Only the codes that end a subscription (404, 405, 410, 416, 480 to 485,
    489, 501, 604) end it, 481 included, and it is set up again as above.
    One whose refreshes kept failing lapses at its expiry. A user's count
    of failures goes with its last registration on the task.
  - One the notifier ends is set up again after 30 s, or its
    `retry-after` if longer, and after an hour if ended as `rejected`,
    `noresource` or `invariant` (RFC 6665 §4.1.3).
  - One sweep sets up at most 500 subscriptions and sends at most 500
    refreshes, so the task does not send one SUBSCRIBE per user at once
    after an outage of `scscf`.

Subscriptions live in instance memory, as registrations do. When a task
stops, `scscf`'s next NOTIFY fails, and `scscf` ends the subscription.

## A client's requests

**Outside a dialog** (no To tag, TS 24.229 §5.2.6.3.3):

- **Registration.** A request needs a registration over the flow it comes
  on. Without one it is discarded with no response at all, and counted in
  the `requests.unregistered_discarded` metric. A client whose registration
  `pcscf` lost then times out and registers again (§5.2.6.3.2A). An
  INVITE's 100 Trying may already have gone if routing took over 200 ms.
- **Route.** The request goes along the `Service-Route` its registration
  received, which replaces whatever Route the client wrote below `pcscf`'s
  own. A registration without a `Service-Route` is answered 500, since the
  next hop would otherwise be a core address the client chose.
- **Identity.** `pcscf` removes `P-Preferred-Identity` and asserts
  `P-Asserted-Identity` (§5.2.6.3.1, #16 decision 5):
  - the identity is the first `P-Preferred-Identity` value that a
    registration over the flow lists in its `P-Associated-URI`, which holds
    no barred identity; the request then goes along that registration's
    `Service-Route`. A later value that same registration lists is the
    alternative identity, asserted beside it if it is of the other kind
    (RFC 3325 §9.1 allows one SIP or SIPS and one tel URI);
  - with no match, the identity is the default public identity, the first
    `P-Associated-URI` of the flow's first registration;
  - values are matched without case in the host, with the user part
    unescaped and a tel number without visual separators. A `user=phone`
    SIP URI with a `+` number also matches the tel URI of that number;
  - without an alternative, a SIP identity is joined by a tel URI of the
    same registration: for a `user=phone` one, the tel URI of the same
    number, or none if there is no such one, so no other number is asserted
    beside it; otherwise the first tel URI (#16 decision 5);
  - the values asserted are the registration's, with parameters other than
    `user` dropped.
- **Charging.** `P-Charging-Vector` gets a new `icid-value` for each request
  and `RCS_IMS_DOMAIN` as the type 1 `orig-ioi` (§5.2.6.3.3 7)).
- **Record-Route.** For a request that sets up a dialog, INVITE, SUBSCRIBE
  or REFER, `pcscf` records two values (RFC 5658), topmost first:
  `<sip:<flow token>@<task address>:<core port>;transport=tcp;lr;icid=<icid>;dlg=<MAC>>`,
  with `ob` when the client's Contact has it, for the core, and
  `<sip:<PCSCF_PUBLIC_HOST>:<PCSCF_PUBLIC_PORT>;transport=tls;lr>` (`tcp`
  with `tcp`) for the client. The dialog's later requests come back through
  this task on both sides. A standalone request, such as MESSAGE or
  OPTIONS, is not recorded (§5.2.6.3.7), so capability discovery and pager
  messages never carry the flow token.
- **Limit.** A client address may send `PCSCF_INITIAL_RATE` requests a
  second outside or inside a dialog, with a burst of `PCSCF_INITIAL_BURST`,
  beside its REGISTERs. Past that it gets 503 with `Retry-After: 1`.

**Inside a dialog** (#16 decision 6, narrowed in the review of #208):
`pcscf` keeps no dialog state, so the route a request carries must show that
the dialog was set up through this `pcscf` and this flow, and it may go only
to `scscf`. It is forwarded as its Route says only if:

- both of `pcscf`'s Record-Route values were among the Route values it
  consumed: one naming the public host or an NLB address, and one naming
  this task's core listener, its address written in any form;
- the core one's flow token is the flow the request came on, and its `dlg`
  MAC is the one written for that flow, the request's Call-ID and the icid
  the value carries;
- the next hop, the Route below them or else the Request-URI, is `scscf`'s
  service name (`PCSCF_SCSCF_HOST`) on `PCSCF_SCSCF_PORT` with
  `transport=tcp`: `scscf` records that name in every dialog `pcscf` is in
  ([ADR 0005](adr/0005-shared-state-and-instance-addressing.md)). An address
  is never accepted, and no other name is looked up;
- that name resolves to a private address other than this task's own.

Anything else is answered 403, so a client cannot aim a request at a core
address of its choosing past `scscf`. A failed lookup of `scscf` is 503 with
`Retry-After: 1`. Requests count against the client's initial-request limit; an ACK
for a 2xx, which cannot be answered 503, is dropped past it and counted in
`requests.ack_rate_discarded`, and follows the route rule too. No registration is needed, so a call can still be ended after the
client deregisters.

The forwarded request gets a `P-Charging-Vector` with the dialog's icid,
read back from the core-facing Record-Route value in its route, and the
`orig-ioi` (§5.2.6.3.5 7), §5.2.6.3.9 3)). The client holds that value, but
the MAC covers the icid, so a copy with the icid changed, added or removed
is 403. A value written without an icid gets a new one: `pcscf` writes none
it could not read back (more than 256 bytes, or control characters), and a
core icid like that is replaced by a new one in the route and in every
answer alike.

No core hop of any request, REGISTER and initial requests included, ever
resolves to this task's own address, however it is written, and every form
of that address in a Route is taken as `pcscf`'s own. The check is on the
address, whatever the port, so on a dev stack on one host set
`PCSCF_CORE_HOST` to an address distinct from `icscf`'s and `scscf`'s.

## Requests from the core

A request on the core listener goes to a client over one flow, and nowhere
else (TS 24.229 §5.2.6.4, #16 plan D). `pcscf` keeps no dialog state: the
flow is the token of a consumed Route naming this task's core listener. For
a request outside a dialog that is the `Path` of the client's registration;
for one inside, the core-facing Record-Route value `pcscf` wrote. The
request is sent over that flow whatever its Route or Request-URI say below.

- **430.** A request whose Route names no flow, or a flow that is not a live
  client flow of this task (closed, from an earlier start, or a core
  connection), is answered 430 Flow Failed, and so is one whose flow is
  already gone when it is to be sent. One whose flow closes while it is
  under way may not get 430 yet
  ([#234](https://github.com/jeonghun-app/rcs-platform/issues/234)). The
  430 reaches `scscf` as it is, so that it tries the client's other flows
  (RFC 5626 §5.3). Flow tokens are an HMAC under a key
  drawn at every start, so a token outlives neither its flow nor the task,
  even when a new flow comes from the same address.
- **Record-Route.** A request outside a dialog that sets one up (INVITE,
  SUBSCRIBE, REFER) gets `pcscf`'s two values,
  the client-facing one on top, so that the dialog's requests come back
  through this task on both sides: the client's along the route rule above,
  the core's to the flow. The core-facing one keeps the `Path`'s `ob` and
  the request's icid (§5.2.6.4.4 3)), percent-escaped where it is not a
  token, so any icid the core chose survives in the route. A 1xx or 2xx
  from the client that does not return the request's Record-Route values,
  `pcscf`'s and the core's, as they were has them put back (§5.2.6.4.4 3)
  b)), so the client cannot change the route the core keeps. When the
  core's own Record-Route does not parse, nothing is put back: the
  answer's goes up as the client wrote it, counted in
  `terminating.record_route_malformed`.
- **Dialogs.** The core-facing Record-Route value, of a dialog either side
  set up, binds the flow to the dialog: `dlg` is a MAC over the flow token,
  the Call-ID and the icid, each after its length, under a key drawn at
  every start. A request from the
  core inside a dialog reaches the flow only with the value written for its
  Call-ID. The `Path`, another dialog's value or a changed one is 403 when
  the flow is alive, and 430 only when it is not, so `scscf` does not take
  a wrong route for a failed flow; a peer that saw the token cannot reach
  the client outside its dialog. Only requests inside a dialog are checked:
  an initial request comes along the `Path` and is not bound to a dialog.
- **Network headers.** `P-Served-User` and `P-Profile-Key`, whom the core
  served and the profile it chose, are removed toward the client.
- **Privacy.** `P-Asserted-Identity` is removed toward the client when the
  request's `Privacy` has `id`, and so is it from a response to the client
  that asks so (RFC 3323 §4.2, RFC 3325 §9.3).
- **Charging.** The network's charging data, `P-Charging-Vector` and
  `P-Charging-Function-Addresses`, never goes to a client, in a request
  from the core or a response to the client's own request (TS 24.229
  §5.2.1).
- **Responses.** The client's responses get a `P-Charging-Vector` with the
  request's `icid-value` and `orig-ioi`, quoted as they came; a request
  inside a dialog without one takes the dialog's icid from the core-facing
  Record-Route value, and any other request without one a new icid. The
  vector names `RCS_IMS_DOMAIN` as the type 1 `term-ioi` (§5.2.6.4.4 6)).
  The identity the request was for, its `P-Called-Party-ID`, is asserted in
  place of any `P-Preferred-Identity` in a 1xx or 2xx to a request that sets
  up a dialog (§5.2.6.4.4 1)) and in every response, 1xx to 6xx, to a
  standalone request outside a dialog such as MESSAGE (§5.2.6.4.8 2)).
  `P-Preferred-Identity` is removed from every response, toward the core
  and toward the client alike: it is a client's preference for its own
  requests (RFC 3325 §9.2). A
  request without `P-Called-Party-ID` gets no asserted identity in its
  responses, and is counted in `terminating.pai_omitted`: the
  Request-URI or the flow's registration is not the network's assertion of
  whom the core reached. The client's own network-only headers are gone
  already, removed on arrival.

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
| `PCSCF_SCSCF_HOST` | `scscf.<RCS_SERVICE_NAMESPACE>` | `scscf`'s service name, the only next hop of a client's request inside a dialog: a name inside the namespace, not `pcscf`'s own; required without a namespace |
| `PCSCF_SCSCF_PORT` | `5060` | `scscf`'s SIP port |
| `PCSCF_ICSCF_URI` | `sip:icscf.<RCS_SERVICE_NAMESPACE>;transport=tcp;lr` | the Route of a REGISTER: a `sip` URI with `transport=tcp` and `lr`, of an address or a name inside `RCS_SERVICE_NAMESPACE`; required without a namespace |
| `RCS_IMS_DOMAIN` | required | the operator's IMS domain, a host name: the `orig-ioi` of `P-Charging-Vector` |
| `PCSCF_VISITED_NETWORK_ID` | `RCS_IMS_DOMAIN` | `P-Visited-Network-ID` of REGISTERs, one network identifier (RFC 7315 §4.3) |
| `PCSCF_REGISTER_RATE`, `PCSCF_REGISTER_BURST` | `50`, `200` | REGISTERs a second per client address, and the burst |
| `PCSCF_INITIAL_RATE`, `PCSCF_INITIAL_BURST` | `50`, `200` | requests outside a dialog a second per client address, and the burst |
| `PCSCF_MAX_REGISTER_RATE`, `PCSCF_MAX_REGISTER_BURST` | `2000`, `4000` | REGISTERs a second for all clients of a task together, and the burst |
| `PCSCF_MAX_REGISTRATIONS` | `100000` | registrations kept by one task |
| `PCSCF_MAX_PENDING_REGISTERS_PER_IP` | `64` | identities one client address (IPv4 address or IPv6 /64) may have REGISTERs under way for at once, 1 to 1024 |
| `PCSCF_MAX_CONNECTIONS` | `10000` | connections the transport accepts |
| `PCSCF_MAX_CLIENT_FLOWS` | `9000` | connections the client listener holds among them, counted from accept; plus `PCSCF_CORE_CONNECTIONS` it must not exceed `PCSCF_MAX_CONNECTIONS` |
| `PCSCF_CORE_CONNECTIONS` | `256` | connections the core listener holds, kept for it |
| `PCSCF_CLIENT_IDLE_TIMEOUT` | `340s` | close a client connection silent this long, just under the NLB TLS listener's 350 s |
| `PCSCF_DRAIN_TIMEOUT` | `RCS_SHUTDOWN_TIMEOUT` less 5 s | how long a stop spreads the closing of client flows over; plus 5 s it must not exceed `RCS_SHUTDOWN_TIMEOUT` |

For production, set `RCS_SHUTDOWN_TIMEOUT` to most of the ECS stop timeout,
for example `115s`, so that the drain spreads over about 110 s.

## Shutdown

On SIGTERM `pcscf` stops accepting client connections and closes the client
flows one by one, evenly spread over `PCSCF_DRAIN_TIMEOUT`. A flow that
already ended takes no time of its own. The core listener stays open until
the end, so `scscf` can still reach the clients not yet closed. After the last
flow, `pcscf` spends up to 4 s of the 5 s margin on the requests still in
progress: up to 2 s waiting for them, then it answers what is left 500 with
`Retry-After` (`proxy.Drain`, #281), so its sender tries another task at
once, and waits up to 2 s more for those answers to be written. A stopping task's
clients then reconnect to another task and re-register over the stop
timeout, not all at once, and `hss` and `scscf` are sized for that burst
([ADR 0003](adr/0003-aws-topology.md)).
