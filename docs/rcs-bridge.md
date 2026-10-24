# rcs-bridge

`rcs-bridge` lets an application send and receive RCS standalone messages
through the platform without speaking SIP, IMS AKA, CPIM or IMDN itself
(#658). It is a small HTTP API with a WebSocket for events. Each endpoint the
application names is a test subscriber of its own:

1. The bridge provisions the subscriber in `hss`.
2. It registers the subscriber with IMS AKA through `pcscf`, `icscf` and
   `scscf`, on a TCP flow of its own, and keeps the registration refreshed.
3. It sends and receives pager-mode MESSAGEs with CPIM (RCC.07 standalone
   messaging) through `rcs-as`, with delivery and display notifications
   (RFC 5438).

An endpoint can be set offline and online again, as a car whose ignition is
off or a phone that is off. `rcs-as` keeps what is sent to it meanwhile and
delivers it once the endpoint registers again.

It is a development tool for the [local stack](local-stack.md), like
[rcs-sim](rcs-sim.md), whose SIP client (`tools/rcs-sim/internal/sipua`) it
uses. It is not part of the platform image and is not deployed to AWS.
Chat sessions (MSRP), group chat and file transfer are out of its scope.

## Running it

```bash
make bridge-up     # make up, then rcs-bridge, and wait until it is healthy
make logs LOGS="-f rcs-bridge"
make down          # stops the bridge with the rest of the stack
```

- **Where.** The bridge listens on `127.0.0.1:8720` on the host
  (`RCS_BRIDGE_HOST_PORT` in `deploy/compose.env`). On the compose network it
  is `http://rcs-bridge:8720`.
- **Token.** `RCS_BRIDGE_TOKEN` in `deploy/compose.env`, 256 random bits that
  `make up` generates (`scripts/compose-env.sh`). So is `RCS_BRIDGE_IMPI_KEY`,
  the key of the endpoints' IMPIs ([below](#endpoints-and-their-subscribers)).
  A file written before these settings existed gets them at the next
  `make up`.
- **Loopback only.** The bridge speaks plain HTTP, with no TLS, and holds
  `hss`'s operator token. Never make it reachable beyond the host's loopback:
  compose publishes it on `127.0.0.1` only, and run by hand it listens on
  `127.0.0.1:8720` unless `RCS_BRIDGE_ADDR` says otherwise.
- **What it uses.** The bridge reaches `hss` at `http://hss:8081` with the
  operator token (`HSS_ADMIN_TOKEN`), the only caller that may create
  subscriptions and set their keys ([scopes](api/hss-scopes.md)). It reaches
  `pcscf` at `pcscf:5060` (`PCSCF_PUBLIC_HOST`), over plain TCP.
- **Image.** `deploy/rcs-bridge.Dockerfile`, built by compose as
  `<COMPOSE_PROJECT>-rcs-bridge`. The service is in the compose profile
  `bridge`, so `make up` alone does not start it.

For example, from the host:

```bash
. deploy/compose.env
B=http://127.0.0.1:${RCS_BRIDGE_HOST_PORT:-8720}
curl -s -X PUT -H "Authorization: Bearer $RCS_BRIDGE_TOKEN" -d '{"online": true}' $B/v1/endpoints/car-1
curl -s -X PUT -H "Authorization: Bearer $RCS_BRIDGE_TOKEN" -d '{"online": true}' $B/v1/endpoints/phone-1
curl -s -X POST -H "Authorization: Bearer $RCS_BRIDGE_TOKEN" \
  -d '{"to": "phone-1", "content_type": "text/plain;charset=utf-8", "body": "hello", "imdn": ["delivery", "display"]}' \
  $B/v1/endpoints/car-1/messages
```

The events come on `ws://127.0.0.1:8720/v1/events`, opened with the same
`Authorization` header.

### Settings

| Variable | Default | Meaning |
|---|---|---|
| `RCS_BRIDGE_TOKEN` | required | The bearer token every request needs, at least 32 bytes |
| `RCS_BRIDGE_ADDR` | `127.0.0.1:8720` | Listen address. The compose service sets `:8720` inside its container, published on the host's `127.0.0.1` only |
| `RCS_BRIDGE_IMPI_KEY` | required | The key of the IMPIs made from endpoint names, at least 32 bytes. Kept apart from the token and never changed: a new key gives every endpoint a new subscription |
| `RCS_BRIDGE_HSS_URL` | `http://hss:8081` | `hss`'s provisioning API |
| `RCS_BRIDGE_HSS_TOKEN` | required | An operator token of `hss` |
| `RCS_BRIDGE_PCSCF` | `pcscf:5060` | `pcscf`'s client listener, host:port, plain TCP. A name is looked up again for each registration |
| `RCS_BRIDGE_MAX_ENDPOINTS` | `64` | Endpoints online at once, registered or trying to register, 1 to 1000. Offline ones do not count |
| `RCS_IMS_DOMAIN` | required | The home network domain |
| `RCS_PII_HMAC_KEY` | none | Keys the log hints of identifiers (`internal/pii`), at least 32 bytes |
| `RCS_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` |

The compose service sets them from `deploy/compose.env`.

## Endpoints and their subscribers

The bridge has slots for 1000 subscribers in the MCC 001 / MNC 01 test
network, on `.github/allowed-test-identifiers.txt`:

| | First slot | Last slot |
|---|---|---|
| IMSI | `001010000872000` | `001010000872999` |
| MSISDN | `+15550108000` | `+15550108999` |

They are apart from `stack-seed`'s two subscribers. Each endpoint gets:

- the IMPI `rcs-bridge-<24 hex digits>@<domain>`, the first 96 bits of an
  HMAC-SHA256 of its name under `RCS_BRIDGE_IMPI_KEY`. An ISIM's IMPI is any
  NAI in the home domain (TS 23.003 §13.3). Without the key, an IMPI says
  nothing of the name, even when names are plate numbers, which could
  otherwise be tried one by one against a plain hash. Whoever holds the key
  (it is in `deploy/compose.env`) can still try names against an IMPI.
- the first free slot from one the same HMAC picks, with
  `sip:<MSISDN>@<domain>` (the default identity) and `tel:<MSISDN>` in one
  implicit registration set, as `stack-seed` provisions its subscribers.
- fresh random AKA keys, K and OPc, 128 bits each. They are sent once to
  `hss`, which never returns them, and kept only in the bridge's memory.
  They are never logged.
- a `+sip.instance` that is a version 8 UUID from a hash of the IMPI, the
  same for every flow of the endpoint (RFC 5626 §4.1).

A second `PUT` keeps the subscriber and its keys. After a restart the bridge
finds the endpoint's subscription again by its IMPI: the identities and the
SQN stay, and the subscription gets new keys. So an endpoint keeps its number
across restarts, and what `rcs-as` kept for it is still delivered to it.

The demo's scale is 64 endpoints online at once (`RCS_BRIDGE_MAX_ENDPOINTS`):
registered, or wanted online and trying to register. Offline endpoints do not
count, so a long-lived bridge serves any number of runs that each put their
endpoints offline at the end. Endpoints are never deleted. A process holds at
most 1000, one per slot, and their subscriptions stay in `hss` until
`make down`. Run one bridge per stack: two bridges with the same endpoint
names would give the subscription each other's keys.

## API

Every request needs `Authorization: Bearer <RCS_BRIDGE_TOKEN>`: the events
handshake, `/healthz` and unknown paths too. Without it, or with another
token, the answer is 401 with `WWW-Authenticate: Bearer realm="rcs-bridge"`.
The token is compared in constant time.

Answers are JSON. Errors are `{"error": "..."}`. Request bodies are JSON
objects of at most 64 KiB. Fields the bridge does not know are ignored, but
for `PUT`, where a mistyped `online` would otherwise read as `true`: there
they are refused with 400.

### Endpoint names

1 to 64 bytes of letters, digits and combining marks in any script, and
`.`, `_`, `~` and `-`, other than `.` and `..`, which a URL path resolves
away: a path with such a segment is answered 400. They are compared byte for byte, so `Car` and `car` are two
endpoints. A name has no `:`, which is how `to` tells a name from a URI.

### PUT /v1/endpoints/{name}

```json
{"online": true}
```

Creates the endpoint the first time and registers it, or with
`"online": false` removes its registration; the subscriber stays. An empty
body is `"online": true`. The answer comes once the registration (or its
removal) is done or has failed:

```json
{"name": "car-1", "impu": "sip:+15550108000@ims.mnc001.mcc001.3gppnetwork.org", "tel": "tel:+15550108000", "registered": true}
```

| Status | When |
|---|---|
| 201 | the endpoint was created |
| 200 | it existed |
| 400 | the name or the body is not valid |
| 409 | `"online": true` would put one endpoint more online than `RCS_BRIDGE_MAX_ENDPOINTS`; nothing changes, and no new endpoint is made (two such PUTs at once may leave one made and offline). Or the bridge holds an endpoint for each of its 1000 slots |
| 502 | `hss` refused the subscription or could not be reached; nothing was created |
| 503 | the bridge is shutting down |

A registration that fails is answered 200 or 201 with `"registered": false`.
The `registration` event says why. While the endpoint is wanted online, the
bridge tries again after 2 s, doubling up to a minute, so that it stays within
`scscf`'s challenge budget (ten a minute per IMPI). It also registers again
when a refresh fails or the flow to `pcscf` closes. Registrations are
refreshed as TS 24.229 §5.1.1.4.1 has a UE refresh them: 600 s before they
expire, or half way through one granted for 1200 s or less.

### POST /v1/endpoints/{name}/messages

```json
{"to": "phone-1", "content_type": "text/plain;charset=utf-8", "body": "hello", "message_id": "m-1", "imdn": ["delivery", "display"]}
```

Sends a pager-mode MESSAGE from the endpoint (RFC 3428, RCC.07 standalone
messaging). Its body is CPIM: `From` the endpoint's SIP identity, `To` the
target, `DateTime`, the IMDN `Message-ID`, and the notifications asked for
(RFC 5438 §6.3). The content is `body`, as UTF-8, with `content_type`.

| Field | Meaning |
|---|---|
| `to` | an endpoint name of this bridge (its SIP identity is the target), or a `sip:`/`sips:` URI, or a global `tel:` URI, used as it is |
| `content_type` | the content's media type, `type/subtype` with any parameters; `text/plain;charset=utf-8` when absent |
| `body` | the content |
| `message_id` | the IMDN Message-ID: a CPIM token of at most 128 characters (`rcs-as`'s bound). The bridge makes one (128 random bits) when absent |
| `imdn` | the notifications asked for: `"delivery"` (positive delivery) and `"display"`. None when absent |

The answer is the final SIP status:

```json
{"message_id": "m-1", "sip_status": 202}
```

`rcs-as` answers 202 to a message it has stored, whether the recipient is
registered or not ([rcs-as](rcs-as.md#answers)); 413 is a body over its pager
limit (`RCSAS_PAGER_LIMIT`, 1300 bytes of CPIM), and 403 a refusal such as its
sender rate. A network without store-and-forward answers 480 for a recipient
that is not registered, and the bridge reports it as `"sip_status": 480`. A
transaction that times out is 408 (RFC 3261 §8.1.3.1).

| Status | When |
|---|---|
| 200 | the MESSAGE got a final answer, in `sip_status`, whatever it is |
| 400 | a field is not valid, or `to` names no endpoint of this bridge |
| 404 | no such endpoint (create it with `PUT` first) |
| 409 | the endpoint is not registered |
| 413 | the request body is over 64 KiB |
| 502 | the MESSAGE got no final answer: the flow failed |

### POST /v1/endpoints/{name}/imdn

```json
{"to": "car-1", "message_id": "m-1", "status": "displayed"}
```

Sends a display notification about a message the endpoint received, to its
sender, as a MESSAGE of its own (RFC 5438 §12.1.3.1). `to` is the sender: its
endpoint name, or the `from` of the `message` event. The bridge sends the
delivery notifications itself, so `status` must be `displayed`.

The answer is the notification's final SIP status, with the reported
message's Message-ID:

```json
{"message_id": "m-1", "sip_status": 202}
```

| Status | When |
|---|---|
| 200 | the notification got a final answer, in `sip_status` |
| 400 | a field is not valid, or `status` is not `displayed` |
| 404 | no such endpoint; or the endpoint has received no message with that `message_id` from that sender (it remembers its last 1024, since it started) |
| 409 | the sender did not ask for a display notification (RFC 5438 §7.2.1; `rcs-as` would refuse it), or the endpoint is not registered |
| 502 | the notification got no final answer |

### GET /v1/events

A WebSocket (RFC 6455). Every event of every endpoint is a JSON text frame,
from the moment the stream opens. The bridge keeps no backlog: while no stream
is open, it refuses what it is sent (480, below), so that `rcs-as` keeps it,
and `registration` events are not kept. The bridge pings every 30 s and closes
a stream that has not answered the previous ping. A stream that falls 1024
events behind is closed with 1008, and at shutdown each is closed with 1001
once what was queued has gone. At most 16 streams are open at once; one more
is answered 503. A request that is not a WebSocket handshake is answered 426,
or 400 for a malformed one. What a client sends is read and ignored, but its
pings are answered.

**message**: an endpoint received a message.

```json
{"type": "message", "endpoint": "phone-1", "from": "tel:+15550108000", "from_endpoint": "car-1",
 "message_id": "m-1", "content_type": "text/plain;charset=utf-8", "body": "hello", "at": "2026-10-24T09:30:00Z"}
```

| Field | Meaning |
|---|---|
| `endpoint` | the endpoint that received it |
| `from` | the sender as the network names it: the SIP `From`, where notifications go back to. `rcs-as` names a sender by its tel URI |
| `from_endpoint` | the sender's endpoint name, when the sender is one of the bridge's endpoints; absent otherwise |
| `message_id` | the IMDN Message-ID; empty when the message has none |
| `content_type`, `body` | the CPIM content, the body as text (bytes that are not UTF-8 become U+FFFD) |
| `at` | the message's CPIM `DateTime`, as the sender wrote it, in RFC 3339; the time the bridge received it when there is none |

A message is answered 200 only once its event is in the queue of at least one
open stream. With no stream open it is answered 480 (Temporarily Unavailable),
and so is a notification: `rcs-as` then keeps it and sends it again when the
endpoint next registers, or when its retry timer runs (`RCSAS_RETRY_INTERVAL`,
1 minute, doubling; [rcs-as](rcs-as.md#when-a-queue-is-read-again)). To have
what was kept come at once, open a stream and put the endpoint offline and
online again. Open the stream before putting endpoints online: what `rcs-as`
kept for an endpoint comes as soon as it registers, and with no stream open it
is refused and kept again, to come only at the next registration. A message
refused so is not remembered, so a display notification about it is 404 until
it has come on a stream. Until then `rcs-as` holds that endpoint's whole
queue, so later messages to it wait too, up to the retry interval (as long as
`RCSAS_MAX_RETRY_INTERVAL`, 1 hour, after repeated refusals); opening the
stream first avoids it ([#664](https://github.com/jeonghun-app/rcs-
platform/issues/664)). A message it cannot read (not `message/cpim`, or a CPIM
or IMDN header it cannot parse) is refused with 415 or 400, so that the
network does not take it for delivered.

When the message asks for a delivery notification, the bridge sends it after
the 200, once the event is queued: the bridge is the device (RFC 5438 §5.1).
A message the bridge answered 480 gets none, so the sender hears `delivered`
only for a message a stream has taken. An event already queued for a stream
that is then closed, because it fell behind or did not answer a ping, is lost
with the queue.

**imdn**: a notification about a message an endpoint sent.

```json
{"type": "imdn", "endpoint": "car-1", "from_endpoint": "phone-1", "message_id": "m-1", "status": "delivered"}
```

`endpoint` is the original sender, `from_endpoint` the endpoint that sent the
notification (absent when it is none of the bridge's), and `message_id` the
reported message's. `status` is `delivered` or `displayed` from the bridge's
endpoints; another network may send RFC 5438's other statuses, such as
`failed`, which the event carries as they are.

**registration**: an endpoint's registration changed.

```json
{"type": "registration", "endpoint": "car-1", "state": "failed", "reason": "sipua: REGISTER answered 403"}
```

`state` is `registered`, `unregistered` (on request) or `failed` (an attempt
failed, or the registration was lost). `reason`, for `failed`, is a fixed text:
the status a REGISTER was answered, or `the flow to the P-CSCF failed`.

### GET /healthz

`{"status": "ok"}`, with the token. The compose health check runs
`rcs-bridge -healthcheck`, which asks it with `RCS_BRIDGE_TOKEN`.

## What it logs

JSON lines on standard output, as the services write them. Endpoint names
and identities go through `internal/pii` (`pii.Identity`, `pii.URI`). Bodies,
keys, the tokens and Message-IDs are never logged. A request line, at
`debug`, names the route pattern (`PUT /v1/endpoints/{name}`), never the path.

## Tests

- `tools/rcs-sim/internal/bridge`: the API, the endpoints' lifecycle (refresh,
  retry, lost flows, offline), the 480 with no stream open and the delivery
  notification only after the event is queued, and the event fan-out with the SIP and `hss`
  sides injected; the real SIP side against rcs-sim's in-process IMS core
  stand-in, with a network that stores (202) and one that refuses (480); the
  `hss` provisioning against a stub of its API.
- `tools/rcs-sim/internal/websocket`: the handshake, every frame a client may
  not send, and the fuzz targets `FuzzRead` and `FuzzMessageRoundTrip`.
- `make e2e-compose` runs `TestE2EBridgeOnTheComposeStack`
  (`tools/rcs-sim/e2e/bridge_test.go`): it builds the bridge and runs it on
  the test container. Two endpoints register through the IMS core. A message
  sent while no stream is open is refused with 480 and kept by `rcs-as`; so
  is one kept while the receiver was offline when the receiver is put online
  before a stream is open. Both come, with their delivery notifications, once
  a stream is open and the receiver registers again. A message goes from one to the other through
  `rcs-as` (202) with its delivery notification, a display notification goes
  back, and a message to the receiver offline arrives once it is online
  again. The bridge's log must hold no token, body or digit run of an
  identity.
- `make e2e-bridge` runs the same test against the compose service that
  `make bridge-up` started (`RCS_BRIDGE_E2E_URL=http://rcs-bridge:8720`), so
  that its image, its settings and its health check are tested too. It
  assumes no other client has a stream open. The CI job "end to end (compose
  stack)" runs `make bridge-up`, `make e2e-compose` and `make e2e-bridge`.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `make bridge-up`: "RCS_BRIDGE_TOKEN: not in deploy/compose.env" | The compose file was used without make. Use the make targets. |
| 401 with the token from `deploy/compose.env` | The file changed after the bridge started. `make bridge-up` recreates it. |
| `PUT` answers 502 "provisioning the subscriber failed: hss: ... answered 401" | `HSS_ADMIN_TOKEN` changed after `hss` started. `make up` recreates the services. |
| `"registered": false`, `reason` "REGISTER answered 500" after many runs | `scscf`'s challenge budget per IMPI. Wait a minute; the bridge tries again by itself. |
| A message event never comes | No event stream was open when it arrived, so the bridge answered 480 and `rcs-as` kept it. With a stream open, it comes when the receiver registers again (put it offline and online) or at `rcs-as`'s next retry, a minute or more later. The sender has not been told it was delivered. |
| `PUT` online answers 409 "as many endpoints as the bridge allows are online" | `RCS_BRIDGE_MAX_ENDPOINTS` endpoints are online. Put one offline first. |
| `"sip_status": 413` | The CPIM body is over `rcs-as`'s pager limit, 1300 bytes. Large messages need MSRP, which the bridge does not do. |
