# rcs-sim

`tools/rcs-sim` simulates an RCS client for end-to-end tests: it transfers
files over HTTP with `ft-server` and chats over MSRP through `msrp-relay`, with
delivery and display notifications. It runs in CI (`make e2e`) and is meant to
run against a deployed stack as well.

This is step 1 (#62). There is no SIP yet. So for chat the simulator also
takes the two parts SIP will later give to the network:

- **pcscf**: it allocates and completes the relay binding through the relay's
  control API, in the order pcscf follows while it rewrites SDP
  ([msrp-relay](msrp-relay.md), "How a session is anchored").
- **rcs-as**: it listens as the passive MSRP end the relay connects to, with
  the session registered as rcs-as registers one when it answers an INVITE.

The control API is internal ([ADR 0007](adr/0007-internal-transport.md)), so
the chat scenarios work against a local stack only. Against a deployed stack,
only the file transfer scenarios apply until step 2 (SIP REGISTER, INVITE and
MESSAGE through pcscf) replaces both parts.

## Scenarios

| Scenario | Steps | Checks |
|---|---|---|
| `ft` | pre-check, upload (with a thumbnail), get_download_info, download, download-range, download-resume, download-thumbnail | 401 before credentials; file-info sizes, type and links; content by SHA-256, against the server's strong ETag too; a single range gets 206, and so does rcsjta's download resume, `bytes=<received>-<total>` |
| `ft-resume` | pre-check, interrupted-upload, get_upload_info, resume (or upload-again), get_download_info, download | the server keeps whole leading parts of a broken upload; the PUT with `Content-Range` completes it; the file comes back whole by SHA-256 |
| `chat-client-originated` | listen-core, allocate (client path), answer (core path), connect, client-to-core, core-to-client, chunked-message, keep-alive, clean, release | ADR 0004's first row: messages both ways with CPIM and IMDN, delivered and displayed notifications, the success report of each message by its Message-ID, a 100 KiB message in 2 KiB chunks, keep-alives on a quiet session; after the release, the client path is refused with 481 |
| `chat-core-originated` | listen-core, allocate (core path), connect-then-answer, core-sends-first, then as above | ADR 0004's second row: the client connects as soon as it has answered, before pcscf records its path (the PATCH goes 300 ms later, so the relay must wait, `RELAY_PATH_WAIT`), and the network speaks first |
| `chat-invite` | register (both clients), invite, connect, client-to-peer, peer-to-client, bye, released, clean | 1-to-1 chat over SIP (#135 AC 4): the client's INVITE to the peer's IMPU with an MSRP offer, its own `a=path` and `a=setup:active` (RCC.07 feature tags, Accept-Contact). The 2xx's `a=path` is the relay's `client_path` and its `a=setup` passive (RFC 6135), and the client connects to it. The network opens a chat to the peer by an INVITE of its own, `actpass` or `passive` with the relay's `client_path`, which the peer answers `active` and connects for. A message each way, with CPIM and IMDN: the success report by its Message-ID, the text and sender intact, the delivered and displayed notifications; an earlier run's leftovers are skipped and counted (`skipped`). The client's BYE answered 200; then the client closes its MSRP connection and binds again until the relay answers 481, the binding released (each 403, the binding still claimed while pcscf's release is on its way, counts in `binds`). Needs `-sip-proxy` and a peer IMPI |
| `pager-message` | register (both clients), message, receive, delivery-notification, peer-offline | RCC.07 standalone messaging, pager mode (#135): a MESSAGE with CPIM and an IMDN delivery request from the client to the peer's IMPU, answered 200 and received on the peer's flow, its text and Message-ID intact; the delivery notification back to the client as a MESSAGE of its own, to the message's SIP From (RFC 5438 §7.2.1, §12.1.3.1), matched by Message-ID. Messages an earlier run left in a store-and-forward network are told by the run's Message-IDs and a token in the text, skipped and counted (`skipped`). Then the peer unregisters and the client sends it another message: a network without store-and-forward, as the unit tests' stand-in core, answers 480, which passes; one that stores it (200 or 202), as rcs-as does, passes only if it delivers it once the peer registers again (`stored`), and one that accepts it and loses it fails. Both clients unregister at the end. Needs `-sip-proxy` and a peer IMPI |
| `reg-event` | register, subscribe, re-register, unregister, network-deregister | the reg event of the client's own IMPU (RFC 3680, TS 24.229 §5.1.1.3, #135): the SUBSCRIBE is answered 2xx and the first NOTIFY is active, the full state, version 0, with the client's contact active; a refresh REGISTER brings a NOTIFY with the contact still active; the de-registration brings one with the client's contact terminated by `unregistered`. The subscription must then end (no reason, `timeout` or `deactivated`) unless another registration is still active, a binding an earlier run left say, which `others` counts. Then the client registers and subscribes again, the network deregisters it (`scenario.Config.Deregister`, as an operator's DELETE through the HSS API would), and its contact must end by `unregistered`, `deactivated` or `rejected` (TS 24.229 §5.4.1.5), with the subscription ending with no reason or one RFC 6665 §4.1.3 allows. Each step waits for the NOTIFY of its own change: one that repeats the last state with the version raised, which RFC 3680 allows, is skipped and counted (`skipped`), and re-register takes the NOTIFY whose contact gives a `cseq` of at least the refresh's CSeq, or without one says `refreshed`. After the user's own de-registration `noresource` fails: it says the registration went away without the user. In each subscription the versions start at 0 and rise by one (RFC 3680 §5.1, §5.2), an active contact must be in an active registration (§4.7.1), and AORs compare in canonical form (`user=phone` and the host's case do not matter). Errors are fixed texts. Needs `-sip-proxy`. network-deregister also needs a deregistration hook, which rcs-sim has no flag for yet: the HSS API's DELETE of a subscription has scscf deregister the user by RTR, but it also removes the subscriber, which a run against a shared stack must not do. Until there is one the step is skipped, and `-require-all` makes that a failure |
| `options` | register (both clients), tel-uri, capabilities | OPTIONS through the network to the peer, which answers both itself (#14): one to the peer's tel URI, with no feature tags, which reaches its flow because the SIP and tel URIs are one implicit registration set (#282); then a capability query (RCC.07) to its SIP URI with the client's feature tags in Contact, which the default profile sends to `rcs-as`, SESSION_CONTINUED, in both session cases. Each must reach the peer, its Call-ID the one sent and the query's tags kept, and its 200 come back; the capability query's 200 must carry the peer's tags. The client answers every OPTIONS 200 with its Contact. Needs `-sip-proxy` and a peer IMPI |

`all` runs every scenario. It leaves the SIP ones out when no SIP client is configured (no `-sip-proxy`), since a stack without pcscf cannot run them. With `-sip-proxy` they all run, and one that needs a setting not given, such as the peer, fails at its first step with a line that says which. A scenario stops at its first failed step.

### What the clients do

The FT client follows the GSMA rcsjta reference client
(HttpAuthenticationAgent, HttpUploadManager):

- It starts each upload with an empty POST and reads the challenge of the
  401.
- It answers only the last `WWW-Authenticate` field, as MD5 without an
  algorithm parameter, counting `nc` from 1 for each new nonce.
- It sends `get_upload_info` and `get_download_info` without credentials
  first, takes the fresh challenge of the 401, and signs the repeated GET for
  the path only. A second 401 is a failure.
- It sends the form as `tid`, `Thumbnail`, `File`, each part with its own
  `Content-Length`, and URL-encodes the file name.
- It resumes with `get_upload_info` and a PUT from the first byte not held.
  When `get_upload_info` holds nothing, it uploads the file again from the
  start (`upload-again`).
- It downloads the rest of a file with `Range: bytes=<received>-<total>`
  (HttpDownloadManager), one past the last byte.
- It sends the upload POSTs again where rcsjta does (HttpUploadManager), and
  at most three times per transfer between them (`RETRY_MAX`):
  - the empty POST on any answer but 401, after the `Retry-After` of a 503
    (a 204, "no authentication", is an error here: ft-server always asks);
  - the multipart POST on a 503 whose `Retry-After` is above zero only.

  The steps report these as `busy_retries`.
- It retries nothing else: a 401 to a signed request, a 503 to anything but
  the upload POSTs, a 503 without a usable `Retry-After`, or a PUT answered
  other than 200 fails the step.

One wait is the simulator's own. A device resumes once it is back on a
network, seconds after the break; the simulator asks at once, before
`ft-server` may have noticed the break. So `get_upload_info` asks again, every
100 ms. It stops once the answers have named the same bytes held for 300 ms,
counted from the answer that first named that value: the server reads what
it holds somewhere between a request and its answer, so a slow answer's wait
is no time it is known to have held them (#377). A 404 is asked again for up
to 3 s (`-upload-settle`). A request sent after the 3 s gets, once, the rest
of the 300 ms for the bytes held it names. If the bytes held are still
changing after that, the step fails ("the server is still storing the broken
upload") instead of resuming from a value that has not settled. The 3 s bound
when requests are sent, not when answers come, so one slow answer on a loaded
host does not fail the step, not even a slow 404 to the first request (#344).
Two equal answers in a row were not enough: `ft-server` may still hold the
broken upload, and about one resume in 800 got 503 (#77). Nothing in the
upload-info document says the upload is released. Its lease runs for
minutes when the process holding it has gone, so waiting for it is no
option. The 300 ms stand for the time a device takes to come back on a
network. The step reports how often it asked again (`retries`), how
many of those answers were 404 (`not_held`), and how long after the step
began it sent the last request that did not get the bytes it settled on
(`showed_ms`, 0 if the first one got them): the time the server took to
show what it keeps. The server reads what it holds somewhere between a
request and its answer, so a slow answer, a 404 among them, adds nothing.

`make e2e` asserts that `showed_ms` is reported and at most 2 s. It also asserts that
`ft-resume` resumed rather than uploading again, and that `busy_retries` is 0 on every step. So a server that is slow to keep a
broken upload, or busy on an idle stack, fails the run. The bound is on time
rather than on the number of answers, so a loaded host that answers slowly
keeps the margin, and on the time until the parts showed rather than the
step's whole time, which the answers' own slowness and the quiet time's
confirmation stretch to seconds on a loaded host (#286).

The chat client connects actively, as a device behind NAT does: over TLS for
an `msrps:` path, plain for `msrp:`. It binds the session with a bodiless SEND
(RFC 4975 §5.4) and wraps every message in CPIM (RFC 3862) with an IMDN
request (RFC 5438). It answers delivery requests at once. Display
notifications go out when the scenario reads the message, as a user would.
The rcs-as stand-in answers both at once.

### The SIP client (step 2, in progress)

Step 2 (#135) gives the simulator a SIP client, `internal/sipua`, which
`pager-message`, `reg-event`, `options` and `chat-invite` use. It is built on the
platform's own `internal/sip/transport` and `internal/sip/transaction`, and
behaves as a device behind NAT does:

- It opens one TCP or TLS connection to pcscf and never another. If that
  connection closes, the client fails rather than reconnecting, since a new
  connection is a new flow the registrar knows nothing of.
- It registers with SIP outbound (RFC 5626 §4.2): `+sip.instance` and `reg-id`
  in Contact, `Supported: path, outbound`, and a Route to pcscf alone. The
  Contact has the connection's address and no user part.
- Once the registrar's 2xx carries `Require: outbound` (RFC 5626 §4.2.1), it
  sends CRLF pings. Each interval is drawn anew between 80% and 100% of the
  registrar's `Flow-Timer`, or of 120 s without one. A pong that takes more
  than 10 s fails the flow (RFC 5626 §4.4.1), and the client closes the
  connection.
- REGISTERs go one at a time: a refresh and a de-registration never overlap
  on the one Call-ID (RFC 3261 §10.2). The registered identity is a SIP URI
  (TS 24.229 §5.1.1.2.1).
- Requests from the network arrive over that same connection.
- After registration, every request carries the route set of TS 24.229
  §5.1.2A.1.1: pcscf, then the `Service-Route` of the last 2xx to REGISTER.
  It also carries the IMPU as `P-Preferred-Identity`, for pcscf to check and
  assert (RFC 3325 §9.2).
- The REGISTER Contact names the RCS services the client registers for
  (RCC.07): the ICSIs of 1-to-1 chat and of standalone messaging, and the IARI
  of file transfer over HTTP.

It answers the registrar's challenge:

- Every unchallenged REGISTER, a de-registration too, carries an
  `Authorization` with the IMPI, the home domain as realm and an empty nonce
  and response, from which the S-CSCF learns the private identity (TS 24.229
  §5.1.1.2.2, §5.1.1.2.3).
- It answers only challenges for the S-CSCF's realm (`Config.Realm`), which is
  the home domain unless the HSS's realm (`HSS_IMS_REALM`) was set apart. An answer for
  another realm would give that hop a response computed from the home
  password to guess it from offline. Of those, it takes the topmost it can
  meet (§5.1.1.5.4): with a password, MD5 or SHA-256 with `qop=auth` (RFC
  7616, RFC 8760); with AKA keys, AKAv1-MD5 with `qop=auth` or without qop
  (§5.4.1.2.1A).
- With AKA keys it answers as a card does (RFC 3310, TS 33.102 §6.3.3). A
  fresh SQN is answered with RES. An SQN the card will not accept is answered
  with AUTS, after which the network resynchronises and challenges again. An
  AUTN that does not verify, or a nonce without RAND and AUTN, is reported in
  one more REGISTER with an empty response and no `auts` (§5.1.1.5.3). The
  answer to that is the result.
- A 407 and a 401 are answered side by side: each REGISTER after them carries
  both credentials (RFC 3261 §22.3), with the next nonce-count and a new
  cnonce.
- Credentials refused once are not tried again: a second challenge of the
  same kind is the result, unless it follows AUTS or says the nonce was
  stale. One registration answers at most three challenges.

The credentials come from the environment only: K and OPc as 32 hex digits in
`RCS_SIM_AKA_K` and `RCS_SIM_AKA_OPC`, the Digest password in
`RCS_SIM_SIP_PASSWORD`. The peer has its own, in `RCS_SIM_PEER_AKA_K`,
`RCS_SIM_PEER_AKA_OPC` and `RCS_SIM_SIP_PEER_PASSWORD`: one secret shared by
two subscribers would hide a client that answers with the other's. Only
made-up keys or the TS 35.208 test sets belong there. They print as a placeholder in every form.

It sets up 1-to-1 chats as the caller (RFC 3261 §12–15):

- The INVITE has a Contact with the chat ICSI and `ob`, so the dialog's
  requests come back over the flow (RFC 5626 §4.3). The same ICSI is in
  `Accept-Contact` and `P-Preferred-Service`, and the SDP offer is the body.
- A 2xx makes the dialog. The client ACKs it along the route set, which is the
  2xx's `Record-Route` reversed. A 2xx sent again is ACKed again, also after
  the transaction has ended. A 2xx from another branch of a fork is ACKed and
  ended with BYE.
- Other final responses (486, 480, ...) are the result, with no dialog.
- Giving up on a pending INVITE sends CANCEL, but only after a provisional
  response (RFC 3261 §9.1). A 2xx that crosses the CANCEL is ACKed and ended
  with BYE.
- In the dialog, the client sends BYE. It answers the network's BYE with 200
  and refuses a re-INVITE with 488, since a chat needs no other session. A
  request with a lower CSeq gets 500. Without `OnRequest`, a request for a
  dialog it does not know, or no longer knows, gets 481; with it, such a
  request goes to `OnRequest`.

As the called party, it hands each INVITE from the network to the scenario
(`Config.OnInvite`):

- `Ring` answers 180, and `Reject` answers 486, 480, 603 and the like. `Accept`
  answers 200 with the SDP answer and a Contact with the chat ICSI and `ob`.
  Every response that sets up the dialog, the 180 as well as the 200,
  carries a Contact, the INVITE's `Record-Route` and the same To tag (RFC
  3261 §12.1.1).
- An INVITE that requires an extension gets 420 with `Unsupported`, since the
  client supports none (§8.2.2.3). A second copy of an INVITE, the same
  Call-ID, From tag and CSeq on another branch, gets 482 (§8.2.2.2).
- The 200 is sent again at T1, doubling up to T2, until its ACK confirms the
  dialog (§13.3.1.4). Without an ACK at 64*T1, the dialog is ended with BYE.
  A BYE the scenario sends waits for that ACK, or for the 64*T1 (§15).
- The dialog's route set is the INVITE's `Record-Route` in order, and its
  remote target the INVITE's Contact.
- A CANCEL before the answer gets 200, and the INVITE 487 (§9.2). After the
  answer it gets 200 and changes nothing. A CANCEL for no INVITE gets 481.

It follows its own registration state (RFC 3680, TS 24.229 §5.1.1.3):

- `SubscribeRegEvent` sends SUBSCRIBE for the reg event of the IMPU, with
  `Accept: application/reginfo+xml` and an expiry of 600000 s. A NOTIFY that
  overtakes the 2xx sets up the subscription itself (RFC 6665 §4.1.2.4).
- Each NOTIFY is answered 200 and delivered in order, with its
  `Subscription-State`, reason, and `reginfo` body as
  `internal/sip/reginfo` reads it, the parser scscf writes with and pcscf
  reads with. The scenario checks the versions, and tells a contact's
  registration by its state (`Contact.Active`), not its event.
- The NOTIFY sets up the dialog (RFC 6665 §4.4.1): the first one's
  Record-Route is the route set, and each one's Contact the remote target.
  Before any NOTIFY, the 2xx's stand in.
- A NOTIFY without a readable `Subscription-State` or `Event` gets 400, one
  for another event package 489, one with an event id this subscription
  does not have or from another dialog (another From tag: reg event
  subscriptions do not fork, RFC 3680 §4.9) 481, a CSeq not above the last
  500, and one after the subscription ended 481. A body that is not
  `reginfo`, or that `internal/sip/reginfo` refuses (a document type
  declaration, a missing or 33-bit version, an AOR repeated or not a URI,
  anything outside RFC 3680 §5.4), is answered 200 and flagged in the
  notification.
- `Unsubscribe` sends SUBSCRIBE with `Expires: 0` in the dialog, with the
  UA's Contact. A non-2xx comes back as a `StatusError`, as for
  `SubscribeRegEvent`. A terminated NOTIFY ends the subscription, and so
  does an answer that says it no longer exists, 481 among them (§4.1.2.2).

Errors carry methods, status codes and fixed reasons, never an identity, an
address, a Call-ID, a nonce or a credential. Its tests run it against an
in-process stand-in for pcscf, the registrar, the notifier and the far end,
which also calls it. The registrar
authenticates with `internal/sip/digest`'s server side and Milenage vectors.

`-sip-proxy` turns the client's configuration on (see [Running it](#running-it)),
and `-sip-peer-impi` a second client for the far end, which `pager-message`,
`options` and `chat-invite` need.
Until then the scenario tests run it against `simtest.IMSCore`, an in-process
stand-in for the IMS core: a registrar that authenticates with SIP Digest, a
notifier for the reg event of each IMPU, and a proxy that routes each request
to the flow its Request-URI is registered on (bindings, contacts and
subscriptions keyed by scheme, user and host, without parameters), and a
request in a dialog to the flow whose registered Contact its Request-URI
names, by user, host and port (the dialog's remote target, RFC 3261
§12.2.1.1). Its
NOTIFYs say what is left of each subscription, never more than was granted
(3761 s without Expires), go out one at a time, and write a contact with the
event that last changed it. `Deregister` ends an IMPU's registration from
the network side, with `deactivated` or `rejected`. A request to an IMPU without a binding gets
480, or, as a test chooses, is stored and delivered at the next
registration (or stored with its text changed), answered 200 and lost, or
refused with 404. It answers what it cannot get to the far end as the
platform does: an INVITE the far end never answers gets 408, any other
request is left unanswered, so its sender's own transaction times out (RFC
4320 §4.2, #363); a request whose far end's flow is gone, before it was sent
or while it waited, gets 480 (the P-CSCF's 430 as an endpoint sees it, RFC
5626 §5.3.1, #414), and one it fails to pass on otherwise 500 (RFC 3261 §16.7).
The binding stays until it expires or is removed. A CANCEL that matches an
INVITE transaction still live, answered or not, is answered 200, and one
that matches none 481 (§9.2). It is passed on to the far end (§16.10) once
the far end has answered the INVITE provisionally (§9.1); a cancelled INVITE
that the far end does not end within 64×T1 of that CANCEL, or that ends
without its answer, its flow gone or its timer out, gets 487, as on the
platform.

## Running it

```bash
export RCS_SIM_FT_PASSWORD=...       # ftHTTPCSPwd
export RCS_SIM_RELAY_TOKEN=...       # pcscf's control token (local stacks only)
rcs-sim -ft-upload-url http://127.0.0.1:8081/ft \
        -ft-user 001010000000001@ims.mnc001.mcc001.3gppnetwork.org \
        -resume-size $((12 << 20)) \
        -relay-control http://127.0.0.1:8082 -core-listen 127.0.0.1:2855 \
        all
```

| Flag | Default | Meaning |
|---|---|---|
| `-ft-upload-url` | none | ft-server's upload URI (`ftHTTPCSURI`); the FT scenarios fail without it |
| `-ft-user` | `RCS_SIM_FT_USER` | FT user name (`ftHTTPCSUser`) |
| `-file-size` | 256 KiB | size of the `ft` file |
| `-upload-settle` | 3s | how long `get_upload_info` is asked again for a broken upload to show; when it ends with the bytes still changing, the step fails. Tests that run the in-process stack set an hour, so that only `-step-timeout` bounds the step |
| `-resume-size` | 12 MiB | size of the `ft-resume` file; must exceed the server's `FT_PART_SIZE`, since only whole parts survive a break; otherwise nothing is held and the scenario uploads again instead of resuming |
| `-relay-control` | none | msrp-relay control API base URL; the chat scenarios fail without it |
| `-core-listen` | `127.0.0.1:0` | where the rcs-as stand-in listens; the port must be in the relay's `RELAY_CORE_PORTS` |
| `-core-advertise` | the listener's address | host the relay is told to connect to |
| `-msrp-keepalive` | 200s | MSRP keep-alive interval of both ends (ADR 0003). It must be shorter than the relay's (`RELAY_KEEPALIVE_INTERVAL`, 240 s by default): the relay's own keep-alive resets the client's timer, so with a longer interval the client never sends one and the keep-alive step fails |
| `-idle-wait` | 0 (skip) | stay quiet this long in the chat scenarios, to see keep-alives go out; set it above `-msrp-keepalive`. If no keep-alive has gone out by then, the step waits for one until `-step-timeout`, since a loaded host can run the timer late. Only a SEND the client starts counts; the step's `bytes_while_quiet` (reported on failure too) is everything it wrote meanwhile |
| `-self`, `-peer` | `+15550100001`, `+15550100002` in the MCC 001 test domain | the CPIM addresses of the two ends |
| `-step-timeout` | 30s | bound on each step; must be longer than `-idle-wait`, which the keep-alive step spends within it |
| `-require-all` | false | fail a step that would be skipped for want of something the stack does not offer yet, such as reg-event's network-deregister; for CI once the stack offers it |
| `-sip-proxy` | none | pcscf's `host:port`; configures the SIP client. A host name is resolved at start |
| `-sip-transport` | `tcp` | `tcp` or `tls` to pcscf |
| `-sip-server-name` | `-sip-proxy`'s host | the name pcscf's certificate is verified for, and the host of the first Route; TLS to an address needs it |
| `-sip-domain` | `-self`'s host | home network domain, REGISTER's Request-URI |
| `-sip-realm` | `-sip-domain` | the S-CSCF's Digest realm, the only one whose challenges are answered; set it when the HSS's `HSS_IMS_REALM` differs from the domain |
| `-sip-impi` | `RCS_SIM_SIP_IMPI` | private user identity, the Digest username |
| `-sip-auth` | `aka` | `aka` takes K and OPc from `RCS_SIM_AKA_K` and `RCS_SIM_AKA_OPC`; `digest` takes the password from `RCS_SIM_SIP_PASSWORD` |
| `-sip-instance` | a new `urn:uuid` | `+sip.instance` (RFC 5626 §4.1) |
| `-sip-peer-impi` | `RCS_SIM_SIP_PEER_IMPI` | the far end's private user identity. The peer registers as `-peer` with the same other settings, its own credentials (`RCS_SIM_PEER_AKA_K` and `RCS_SIM_PEER_AKA_OPC`, or `RCS_SIM_SIP_PEER_PASSWORD`) and its own new instance. Without it, the scenarios with two clients fail at their first step |
| `-list`, `-version` | | print the scenarios or the version |

Secrets are read from the environment only, never from flags, because flags
are visible in process listings: `RCS_SIM_FT_PASSWORD`,
`RCS_SIM_RELAY_TOKEN`, `RCS_SIM_AKA_K`, `RCS_SIM_AKA_OPC`,
`RCS_SIM_SIP_PASSWORD`, and the peer's `RCS_SIM_PEER_AKA_K`,
`RCS_SIM_PEER_AKA_OPC` and `RCS_SIM_SIP_PEER_PASSWORD`. The FT user name may also come from
`RCS_SIM_FT_USER`, and the IMPIs from `RCS_SIM_SIP_IMPI` and `RCS_SIM_SIP_PEER_IMPI`. A usage error names
the flag or variable, never its value.

### Output

One JSON line per step on standard output:

```json
{"scenario":"ft-resume","step":"get_upload_info","ok":true,"ms":252,"detail":{"held":5242880,"not_held":1,"retries":2,"showed_ms":0}}
{"scenario":"chat-core-originated","step":"keep-alive","ok":true,"ms":1500,"detail":{"bytes_while_quiet":514}}
```

A failed step has `"ok":false` and an `error` naming the operation and the
status or cause. A step the stack cannot run yet has `"ok":true` and a
fixed `skipped` reason, such as `"skipped":"network deregistration not
configured"`; `-require-all` turns it into a failure with that reason as its
`error`. When the run ends, standard error gets a summary,
`rcs-sim: 12 steps, 0 failed, 1 skipped`. Results never carry a URL, a session id, a user name, a
password, a token or an address: download URLs and MSRP session ids are
capabilities, and the run's output goes to CI logs. Network failures are
reduced to a fixed reason ("connection refused", "host name not resolved"),
without the address, host name or resolver Go's errors name. So are
`net/http`'s own failures, which can quote what the server sent:
- "the answer is not HTTP";
- "the HTTP exchange failed", for a bad `Content-Length` or a link with another
  scheme;
- "the answer's body could not be read", for a broken chunked encoding.

The exit status is 0 when every step succeeded, 1 when one failed, and 2 for a
usage error.

## make e2e

`make e2e` (CI job "end to end (rcs-sim)") builds `ft-server`, `msrp-relay`
and `rcs-sim`. It starts the two services as processes of their own,
configured from the environment as a test stack configures them:

- `ft-server` on its memory stores, with static credentials and 5 MiB parts
  (the smallest, as on S3);
- `msrp-relay` on its memory store, with a plain public listener on loopback
  (no NLB, so no PROXY header and no TLS) and the core side limited to
  loopback and the stand-in's port.

It then runs `rcs-sim all` against them and checks every result line. The
unit tests of `tools/rcs-sim` run the same scenarios against the same service
code inside the test process (`internal/simtest`).

`make e2e-compose` runs `rcs-sim ft ft-resume` against the local compose stack
instead: the platform image on DynamoDB Local and S3Mock, with `ft-server`
checking credentials against `hss` and the FT URI taken from what `acs`
provisions. It then runs `rcs-sim reg-event options pager-message
chat-invite` over SIP through `pcscf`, `icscf`, `scscf`, `rcs-as` and
`msrp-relay`, the two test subscribers registering with IMS AKA
([local-stack.md](local-stack.md#make-e2e-compose)). The stand-in chat
scenarios are `make e2e`'s, which has no CSCFs.

The scenario tests run `chat-invite` against `simtest.IMSCore` with an
anchor of the test's own (`sipchat_test.go`): it allocates a binding for
each client at the in-process relay, as pcscf does, and stands in for
rcs-as with a core leg for each client that sends on the other what it
receives, as a B2BUA does.

## Findings

- A client that breaks an upload and at once sends another request under the
  same nonce can lose the whole upload. The transport gives up on the broken
  request as soon as its body fails, possibly before ft-server has read its
  headers. If the next request, with a higher nonce-count, is verified first,
  the broken one is refused as a replay (RFC 7616 §3.4) and stores nothing.
  `get_upload_info` then answers 404, and the client starts over. rcsjta does
  not hit this: it sends `get_upload_info` without credentials first and
  answers the fresh nonce of that 401 with `nc` 1, so the broken POST's nonce
  sees no later count. Only clients that keep the nonce across a break are
  affected, so #66 is P2 hardening.
