# maap

The half of the Chatbot Platform outside the SIP trust domain
([ADR 0009](adr/0009-maap-chatbot-platform.md) §1): the chatbot registry,
the chatbot API, webhook delivery, aliases and policy limits. `rcs-as` hosts
the chatbot PSI and builds every SIP request; `maap` has no SIP, MSRP or
Diameter and reaches only `rcs-as`, over internal HTTP. Code:
`internal/maap`, wired by `cmd/maap`. It is being built under epic #668:
today it starts with checked settings, serves its health checks, and guards
its internal listener with the operator's token, where the operator
registers, changes and deletes chatbots in the [registry](#registry) (#709),
kept in [DynamoDB](#dynamodb-maap-registry-table) (#708); #710–#713 add the
operator's other routes.

## Listeners

| Listener | Setting | Who reaches it | Serves |
|---|---|---|---|
| admin | `RCS_ADMIN_ADDR` (`:8080`) | its load balancer's health checks | `/healthz`, `/readyz`, as every service's admin port (ADR 0007 §2); `/readyz` also needs `maap-registry` to answer `DescribeTable` as `ACTIVE`, which the task role needs `dynamodb:DescribeTable` for (#684) |
| internal | `MAAP_INTERNAL_ADDR` (`:8081`) | `rcs-as` and the operator path only, never the public ALB (ADR 0009 §7) | the [internal API](#internal-api): the operator's routes (#708–#713), `rcs-as`'s (#683) |
| public | (#683) | the ALB, on `MAAP_PUBLIC_HOST` | the chatbot API (#683) |

## Configuration

Environment variables prefixed `MAAP_`, plus the shared `RCS_` settings of
`internal/runtime` (`RCS_ENV`, `RCS_ADMIN_ADDR`, `RCS_PII_HMAC_KEY`, ...).
Settings marked *prod* are refused in `staging` and `prod`; every problem is
reported at once at start.

| Variable | Default | Meaning |
|---|---|---|
| `RCS_IMS_DOMAIN` | required | the home domain |
| `RCS_CHATBOT_DOMAIN` | required | host of chatbot URIs, read with `internal/chatbot`'s rules: a lower-case DNS name other than `RCS_IMS_DOMAIN` (ADR 0009 §2) |
| `MAAP_ALIAS_HOST` | required | host of aliases (ADR 0009 §10, §13): a DNS name that is neither `RCS_IMS_DOMAIN` nor `RCS_CHATBOT_DOMAIN` nor under either, compared without regard to case; stored in lower case. As for `RCS_CHATBOT_DOMAIN`, its last label starts with a letter (so no IP address), and it is at most 213 bytes, so that an alias URI stays within 255 |
| `MAAP_WEBHOOK_PORTS` | none | ports a webhook URL may name besides 443 (ADR 0009 §8); the infrastructure parameter that sets it also sets the egress rule (#684) |
| `MAAP_INTERNAL_ADDR` | `:8081` | the internal listener, `host:port` with a port from 1 to 65535 |
| `MAAP_OPERATOR_TOKEN`, `MAAP_OPERATOR_TOKEN_NEXT` | none | the operator's current and next tokens. *prod*: the first is required, and each must hold 256 bits (43 base64url characters or 64 hex digits). Everywhere: printable ASCII without white space, and a next token only with a current one and different from it |
| `MAAP_DECODES` | `8` | request bodies the internal listener decodes at once (see [Memory](#memory)); at least 1 |
| `MAAP_REGISTRY_TABLE` | `maap-registry` | DynamoDB table of chatbots and credentials (#708) |
| `MAAP_DYNAMODB_ENDPOINT` | AWS | replaces the DynamoDB endpoint, for DynamoDB Local in dev stacks. *prod*: refused |
| `MAAP_SUBSCRIBERS_TABLE` | `maap-subscribers` | aliases, conversations and blocks (#711) |
| `MAAP_REQUESTS_TABLE` | `maap-requests` | idempotency records and message statuses (#713) |
| `MAAP_COUNTERS_TABLE` | `maap-counters` | the shared limit counters (#713) |

The operator's tokens are `maap`'s own settings: `hss`'s operator token,
`HSS_ADMIN_TOKEN`, is never accepted here (ADR 0009 §7). Tokens come from
Secrets Manager through the task execution role (ADR 0007 §4). Rotate as for
`hss`: set the new token as `..._TOKEN_NEXT` and deploy; switch the operator to
it; move it to `..._TOKEN`, clear `..._TOKEN_NEXT` and deploy.

## Memory

Decoding a body costs memory in proportion to its size:
`chatbot.DecodeEnvelope` allocates about 8 bytes per input byte, and
`chatbot.ValidateContent` up to about 30 bytes per byte of content. A send
(#683), at most a 1,496 KiB envelope with 248 KiB of content, can so take about
20 MB, and so can a message from `rcs-as` (#683). Each listener has a pool of
its own, so that chatbots on the public listener cannot take the slots of
`rcs-as` and the operator: `MAAP_DECODES` is the internal listener's, and #683
adds the public listener's with a cap per chatbot. The rule is:

> The slots of all pools together × 20 MB stay under half the task's memory
> limit.

The internal default, 8, needs about 160 MB; #684 sizes the task with the
public pool added. Raise a cap only with the memory limit.

## Internal API

Specified in [api/maap.yaml](api/maap.yaml), with the callers and their
scopes in [api/maap-scopes.md](api/maap-scopes.md). Every route is checked in
this order, each before the request's body is read:

| Status | When |
|---|---|
| 404, 405 | no route serves the path, or not with that method, whatever the token; from the mux, with no audit line, as is the 307 to a cleaned path (`//`, `./`) |
| 503 | no token is configured (dev and test only: prod requires `MAAP_OPERATOR_TOKEN`); `Retry-After` does not help |
| 401 | no bearer token, more than one `Authorization` header, or a token not accepted, the operator's included in another scheme (`WWW-Authenticate: Bearer`) |
| 403 | the token's caller may not use the route |

Presented and accepted tokens are compared as SHA-256 digests, every accepted
one each time, in constant time. Each request a route serves is one audit
line (`audit: internal request`), written even if its handler panics: the
operation, the status first sent, the caller and the token slot (`current` or
`next`). Tokens, bodies and paths are never logged. Every error answer closes
the connection, so that a refusal is sent at once rather than after a body
still arriving.

A route with a body then decodes it through `chatbot.DecodeEnvelope`
(ADR 0009 §9): `application/json` only (415 otherwise, as `hss`), operator
bodies at most 16 KiB (413 above it), strict JSON (400
for unknown fields, duplicate keys or keys differing in case, trailing data,
or a string over its field's bound). A request that finds every one of the
`MAAP_DECODES` slots taken gets 503 with `Retry-After: 1` at once, before its
body is read, and counts `api.decode_busy`. A request that takes a slot has
1 s plus a second for every 64 KiB of its limit to send its body (1.25 s for
16 KiB), not the server's 15 s, so that a slow sender cannot hold a slot; the
handler keeps it until it has validated what it decoded.

`DecodeEnvelope` bounds each string but not what it holds. A string a handler
writes into a SIP, CPIM or HTTP header, or a log, such as a display name, an
out-of-service text, an idempotency key or a webhook URL, is refused first if
it holds a C0 control or DEL, tab included (400, naming the field, never the
value): CR LF would end a header block and a NUL may cut it short. C1
controls are not refused, as in `internal/chatbot`'s wire types (#717),
except in the texts the [registry](#registry) stores. The content is checked
by `chatbot.ValidateContent` instead.

Metrics have the `Service` dimension only (ADR 0009 §10):
`api.<operation>.<status>` per request and `api.decode_busy`.

A route that changes a chatbot ([Registry](#registry)) adds to its audit line the values
before and after (ADR 0009 §7) as `store.AuditChanges` writes them, a group
per changed field named by its JSON path, as the lead decided on #709: the
ID, permissions, limits, state, source networks and the webhook's verified
flag in full; the URI through `pii.URI`; the webhook URL as its host only,
without userinfo or an IPv6 zone, since the rest may hold the chatbot's
secret; and free text, the display name and out-of-service text, only as
changed with its new length in bytes (§10). A field added later is free
text until it is listed.

## Registry

The operator's routes for chatbots (ADR 0009 §7, §11), in
[api/maap.yaml](api/maap.yaml). Every one is the operator's alone; an ID in
the path that no chatbot can have is 404 before the registry is read.

| Route | Does |
|---|---|
| `POST /v1/chatbots` | registers a chatbot, `active`, with the ID the operator chose: 201 |
| `GET /v1/chatbots/{id}` | reads it: 200 |
| `PATCH /v1/chatbots/{id}` | sets the fields the body gives; a field left out keeps its value, and an object given (`permissions`, `limits`, `webhook`) replaces the whole object: 200 |
| `POST /v1/chatbots/{id}/suspend`, `.../resume` | sets the state only; a suspended chatbot keeps its record: 200 |
| `DELETE /v1/chatbots/{id}` | deletes it, and every item another table keeps of it: 204, also when it is gone already |

**Fields.** Each broken rule is 400, naming the field and never the value:

- `id`: 1–64 letters, digits, `-` and `_`, chosen by the operator. An ID is
  never registered again once its chatbot is deleted.
- `uri`: read with `internal/chatbot`'s normaliser at `RCS_CHATBOT_DOMAIN`
  and stored in its normal form (a `tk` parameter and the case of the scheme
  and host dropped). A URI at another host is refused, even in normal form
  there, which the registry alone would take. It never changes: delete the
  chatbot and register it again.
- `display_name`: at most 128 bytes, without C0 controls or DEL, tab
  included, without C1 controls and without format characters (Unicode Cf:
  every bidi control, such as U+202E, and zero-width characters), with which
  a name shows as another (T13). Only the zero-width joiner, U+200D, is
  allowed, so that emoji sequences keep working (lead decision on #709). The
  registry is the only source of the name, so it refuses them rather than
  every reader.
- `out_of_service`: what subscribers of a suspended chatbot get (ADR 0009
  §11), `text/plain` of at most 512 bytes: `chatbot.ValidateContent`'s rules
  (no C0 control but tab, CR and LF, so no NUL or ESC), then those of the
  display name for DEL, C1 and Cf (U+200D allowed).
- `webhook.url`: `https` (also `http` in `dev` and `test`), with a host and
  without userinfo, on port 443 or one on `MAAP_WEBHOOK_PORTS` (a URL without
  a port names its scheme's), at most 512 bytes, and written as Go's
  `net/url` writes it back. A URL newly set is stored unverified, and only
  its challenge (#683) marks it verified; setting the same URL keeps the
  mark. The address is checked when it is dialled (#683).
- `permissions`: `msisdn`, and `start_conversations`, which requires
  `msisdn` (ADR 0009 §9).
- `limits`: each from 0, the default, up to its default in ADR 0009 §9,
  never above.
- `sources`: at most 8 network prefixes without host bits, stored in
  canonical form (`2001:DB8::/32` as `2001:db8::/32`); none allows any
  source.

**Errors from the registry.** 409 when the ID is taken, the URI is held by
another chatbot, or the ID was a deleted chatbot's (the answer names which).
A change that meets another write is applied again to a fresh read, up to 3
times, then is 409. A record that cannot be read, damaged or written by a
newer release, is 500. A registry that fails is 503 with `Retry-After: 1`:
send the request again. A deletion runs the registry's first, which frees the
URI and keeps the ID from ever being registered again, then each table's;
each either finishes or fails, so after a 503 sending it again finishes what
is left.

**Audit.** Each request's `audit: internal request` line names the chatbot
(`chatbot`, its ID) and, for a change that was written, the values before and
after as described under [Internal API](#internal-api); a store failure adds
`store_error`, which names the operation and an AWS error code only.
`sources` is logged in full, as a structured field: a single `/32` or `/128`
may be one person's address, so treat these lines as the other audit logs.

## DynamoDB `maap-registry` table

`MAAP_REGISTRY_TABLE`, on demand with point-in-time recovery (ADR 0003),
written by `maap`'s task role only (ADR 0009 §12); the table itself comes
with the infrastructure (#684). Partition key `pk` and sort key `sk`, both
strings; no index and **no TTL attribute**: a chatbot is kept until the
operator deletes it.

| `pk` | `sk` | Holds |
|---|---|---|
| `c#<chatbot ID>` | `chatbot` | The chatbot: `version` (number), `registration` (random, per registration), `uri`, `doc` (binary, the record as `internal/maap/store` encodes it), `writer`; once deleted, a tombstone holding `deleted` only |
| `u#<chatbot URI>` | `uri` | The URI's reservation: `chatbot` (the ID), `writer` |
| `c#<chatbot ID>` | `k#<key ID>` | Reserved for the chatbot's credentials (#710) |

- **Record.** The display name (at most 128 bytes), the out-of-service text
  (512), the webhook URL (512) and whether it answered its challenge, the
  permissions (MSISDN, starting conversations) and the state, `active` or
  `suspended`, and these, as the lead fixed them on #708:
  - the **ID**: 1–64 characters of letters, digits, `-` and `_`;
  - nine **limits**, one per row of ADR 0009 §9's table that bounds a
    chatbot (sends a minute and a day; conversations started a minute and a
    day; sends to one subscriber a minute and a day; subscriber messages
    from one subscriber a minute; subscriber messages a minute; requests a
    minute), each 0 for the platform's default; the operator API keeps them
    at or under it (#709);
  - up to 8 **source networks**, in canonical prefix form (`192.0.2.0/24`,
    `2001:db8::/32`: no host bits, IPv6 in its shortest form), none for any;
  - the **URI**, which never changes: a chatbot that needs another URI is
    deleted and registered again.

  The document is strict JSON with a schema number, at most 16 KiB: a
  reader refuses a field it does not know, so a release reads a new field
  before any release writes it (ADR 0009 §6).
- **One chatbot per URI** (T13). The URI is stored only in the normal form of
  `internal/chatbot`. Registering writes the record and
  the reservation in one transaction, each on the condition that it does not
  exist yet, so a second chatbot with the same URI is refused ("taken", which
  #709 answers 409).
- **Changes** rewrite the record on the condition that its `version` and
  `registration` are the ones read and its `uri` is the chatbot's, so of two
  concurrent changes one wins and the other is refused as a conflict. A random `writer` token tells a write the SDK sent again
  after its answer was lost, which then stands, from another writer's.
- **Deleting** a chatbot first turns its record into a tombstone, on the
  condition of the registration read, together with deleting the
  reservation, which frees the URI; then it deletes the partition's other
  items, its credentials among them. A change at the same time does not
  stop it, and no credential goes from a chatbot that stays. A deletion
  that failed part way finishes its clean-up when called again; deleting a
  chatbot that is gone does nothing (ADR 0009 §10). **A deleted ID is never registered again**
  (lead decision on #708; `ErrDeleted`, which #709 answers 409), so nothing
  another table kept of it, or a change read before the deletion, reaches
  a new chatbot. Tombstones are kept, like the table, without TTL.
- **Errors.** A store failure is an error of its own, never "not found":
  callers answer it 503, not 404. Errors carry the operation and the AWS
  error code only.
