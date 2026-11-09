# maap

The half of the Chatbot Platform outside the SIP trust domain
([ADR 0009](adr/0009-maap-chatbot-platform.md) §1): the chatbot registry,
the chatbot API, webhook delivery, aliases and policy limits. `rcs-as` hosts
the chatbot PSI and builds every SIP request; `maap` has no SIP, MSRP or
Diameter and reaches only `rcs-as`, over internal HTTP. Code:
`internal/maap`, wired by `cmd/maap`. It is being built under epic #668:
today it starts with checked settings, serves its health checks, and guards
its internal listener with the operator's token, where the operator
registers, changes and deletes chatbots in the [registry](#registry) (#709)
and issues and revokes their [credentials](#credentials-and-caches) (#710),
kept in [DynamoDB](#dynamodb-maap-registry-table) (#708). The
[`maap-requests`](#dynamodb-maap-requests-table) table keeps the idempotency
records and message statuses #683's sends need, and
[`maap-counters`](#dynamodb-maap-counters-table) its shared limits (#713).
It maps subscribers to the [aliases](#aliases) chatbots see (#711); #711
and #712 add the operator's other routes and tables.

## Listeners

| Listener | Setting | Who reaches it | Serves |
|---|---|---|---|
| admin | `RCS_ADMIN_ADDR` (`:8080`) | its load balancer's health checks | `/healthz`, `/readyz`, as every service's admin port (ADR 0007 §2); `/readyz` also needs `maap-registry`, `maap-requests` and `maap-counters` to answer `DescribeTable` as `ACTIVE`, which the task role needs `dynamodb:DescribeTable` for (#684) |
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
| `MAAP_WEBHOOK_PORTS` | none | ports a webhook URL may name besides 443 (ADR 0009 §8); the infrastructure parameter that sets it also sets the egress rule (#684). An `http` webhook in dev without a port is on 80, which must then be listed |
| `MAAP_INTERNAL_ADDR` | `:8081` | the internal listener, `host:port` with a port from 1 to 65535 |
| `MAAP_OPERATOR_TOKEN`, `MAAP_OPERATOR_TOKEN_NEXT` | none | the operator's current and next tokens. *prod*: the first is required, and each must hold 256 bits (43 base64url characters or 64 hex digits). Everywhere: printable ASCII without white space, and a next token only with a current one and different from it |
| `MAAP_DECODES` | `8` | request bodies the internal listener decodes at once (see [Memory](#memory)); at least 1 |
| `MAAP_REGISTRY_TABLE` | `maap-registry` | DynamoDB table of chatbots and credentials (#708) |
| `MAAP_DYNAMODB_ENDPOINT` | AWS | replaces the DynamoDB endpoint, for DynamoDB Local in dev stacks. *prod*: refused. `maap` has no memory store, unlike `hss` and `rcs-as`: a dev run without DynamoDB Local is never ready |
| `MAAP_SUBSCRIBERS_TABLE` | `maap-subscribers` | aliases, conversations and blocks (#711) |
| `MAAP_REQUESTS_TABLE` | `maap-requests` | [idempotency records](#dynamodb-maap-requests-table) and message statuses (#713) |
| `MAAP_COUNTERS_TABLE` | `maap-counters` | the [shared limit counters](#dynamodb-maap-counters-table) (#713) |
| `MAAP_STATUS_TTL` | `192h` (8 days) | how long a message's [status](#dynamodb-maap-requests-table) is kept: by default `rcs-as`'s `RCSAS_SENT_TTL` default, the longest a notification can still come (lead decision on #713; #684 sets both from one parameter); at least 24 hours, so that the answer an idempotency record replays names a status still kept |

`RCS_PII_HMAC_KEY`, which keys log hints in every service, also keys the
request digests `maap-requests` keeps, through a subkey of their own (see
[the table](#dynamodb-maap-requests-table)).

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
| `PATCH /v1/chatbots/{id}` | sets the fields the body gives; a field left out, or null, keeps its value. `permissions` and `limits` merge field by field, as a JSON merge patch (RFC 7396): a field given replaces that one field and one left out or null keeps its value, so lowering one limit leaves the others as they are; 0 sets a limit back to its default. `webhook` is replaced whole: 200 |
| `POST /v1/chatbots/{id}/suspend`, `.../resume` | sets the state only; a suspended chatbot keeps its record: 200 |
| `DELETE /v1/chatbots/{id}` | deletes it, and every item another table keeps of it but its counters, which go by their TTL within a day, for at most 20 s a call: 204 once all is gone, also when it was gone already; 503 with `Retry-After: 1` while items are left. Call it again until it answers 204: a 503, a timeout or a connection closed without an answer is not done |

**Fields.** Each broken rule is 400, naming the field and never the value:

- `id`: 1–64 letters, digits, `-` and `_`, chosen by the operator. An ID is
  never registered again once its chatbot is deleted.
- `uri`: read with `internal/chatbot`'s normaliser at `RCS_CHATBOT_DOMAIN`
  and stored in its normal form (a `tk` parameter and the case of the scheme
  and host dropped). A URI at another host is refused, even in normal form
  there, which the registry alone would take. It never changes: delete the
  chatbot and register it again.
- `display_name`: at most 128 bytes, without C0 controls or DEL, tab
  included, and without the characters with which a name shows as another
  or as blank (T13, lead decisions on #709): C1 controls; Unicode
  Default_Ignorable_Code_Point, which holds every format character (every
  bidi control, such as U+202E, and the zero-width characters), the Hangul
  fillers (U+115F, U+1160, U+3164, U+FFA0) and the variation selectors;
  line and paragraph separators (U+2028, U+2029); U+2800, which shows blank;
  and a name of white space only. Kept, so that emoji and real names work:
  the zero-width joiner and VS16 (U+FE0F) inside an emoji sequence, the
  zero-width non-joiner between letters (Persian and Indic names), and tag
  characters in a subdivision flag. The registry is the only source of the
  name, so it refuses them rather than every reader. Look-alike letters and
  spellings that differ only in Unicode normalisation remain T13's residual
  risk.
- `out_of_service`: what subscribers of a suspended chatbot get (ADR 0009
  §11), `text/plain` of at most 512 bytes: `chatbot.ValidateContent`'s rules
  (no C0 control but tab, CR and LF, so no NUL or ESC), then no DEL, C1 or
  format character but the zero-width joiner. It is a message body, so it
  keeps line separators and the rest of the display name's wider rule does
  not apply.
- `webhook.url`: `https` (also `http` in `dev` and `test`), with a host and
  without userinfo, on port 443 or one on `MAAP_WEBHOOK_PORTS` (a URL without
  a port names its scheme's, so an `http` URL in dev on port 80 needs 80 on
  `MAAP_WEBHOOK_PORTS`), at most 512 bytes, and written as Go's `net/url`
  writes it back. A host that is an IP address must be global unicast: a
  loopback, private (RFC 1918, ULA), link-local (the metadata address
  169.254.169.254 among them), unspecified or multicast address, and an IPv4
  address inside IPv6, are refused when the URL is set, loopback and private
  ones apart in `dev`, for the compose stack. A host whose last label is a
  number (`127.1`, `2130706433`, `0x7f000001`), which some resolvers read as
  an IPv4 address, is refused unless it is one in dotted decimal, and a `%`
  (an IPv6 zone) is refused. A URL newly set is stored unverified, and only
  its challenge (#683) marks it verified; setting the same URL keeps the
  mark. What a host name resolves to is checked when it is dialled (#683).
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
is left. A chatbot that sent much has more items than one call deletes at
the paced rate below (about 180,000 at the send limits, some 36 calls), so a
call stops after 20 s, under the listener's 30 s write timeout, and answers
503 with `Retry-After: 1` (lead decision on #713); each table logs `awsstore:
chatbot deletion progress` with the chatbot's ID, how many items the call
deleted and whether it finished.

**Audit.** Each request's `audit: internal request` line names the chatbot
(`chatbot`, its ID) and, for a change that was written, the values before and
after as described under [Internal API](#internal-api); a store failure adds
`store_error`, which names the operation and an AWS error code or the
transport failure, without the endpoint's address.
`sources` is logged in full, as a structured field: a single `/32` or `/128`
may be one person's address, so treat these lines as the other audit logs.

## Credentials and caches

A chatbot authenticates with a credential (ADR 0009 §7): a key ID and a
256-bit secret from `crypto/rand`, sent as `Authorization: Bearer <key
ID>.<secret>` (#683 reads it). The operator's routes, in
[api/maap.yaml](api/maap.yaml):

| Route | Does |
|---|---|
| `POST /v1/chatbots/{id}/credentials` | issues one: 201 with `key_id` and `token`, the only time the secret is shown; 409 with two live |
| `GET /v1/chatbots/{id}/credentials` | lists the live ones by key ID, oldest first, with when each was created and last used |
| `DELETE /v1/chatbots/{id}/credentials/{key_id}` | revokes one at once in the registry, in one write: 204, also for a place a revoke cut short left; 404 when the chatbot has none with the key ID, which a repeat of a revoke whose answer was lost gets too |

- **Errors.** A stored credential this release cannot read is 500; a
  registry or table that fails is 503 with `Retry-After: 1`.
- **Stored.** Only the secret's SHA-256 digest, never the secret; neither
  is in any later answer or log line. The key ID is 26 characters of
  base32 (128 random bits), with no `.` and no control character (the
  lead's decision on #710), so the audit line names it as `key_id`.
- **Two at a time.** Rotation (the runbook, #684): issue the next, switch
  the chatbot to it, check its `last_used`, then revoke the old.
- **Deletion.** Deleting the chatbot deletes its credentials, after its
  tombstone; an issue that meets the deletion is refused (404), since the
  store checks the registration it read.

**Lookup and caches** (for #683's bearer check). A task finds a credential
by its key ID, compares the SHA-256 digest of the presented secret with the
stored one in constant time (`crypto/subtle`), then reads the chatbot: a
wrong secret, an unknown or revoked key ID, a malformed one (not read at
all), a chatbot deleted or of another registration all give one and the
same refusal. A credential that a deletion stopped part way left behind
the tombstone does not authenticate. The answer carries the chatbot as
read, whatever its state, for the caller to refuse a suspended one. A store
that fails is an error of its own, never a refusal, and is not cached.

| Cache, per task | Kept | Bound |
|---|---|---|
| credentials by key ID; chatbots by ID, or that one is gone | 30 s from the read | what the registry holds; past 10,000 the expired are dropped, at most once per 30 s |
| unknown key IDs | 30 s | 10,000; past it the oldest is forgotten |
| last use recorded | an hour | a credential's `last_used` is written at most hourly per task, off the request's path (its own context, 5 s), and a write that failed waits for the next hour; its warning is logged at most once a minute, with how many were left out |

So a revocation, a suspension, a permission change or a deletion takes
effect on every task within 30 s (T13), and a caller trying key IDs costs at
most one read each per 30 s, concurrent lookups of one key ID sharing one
read (with its own 5 s bound) and one place among the unknown; #683 adds the limits per source. The unknown
key IDs take about 1 MB at their bound.

## Aliases

By default a chatbot never learns a subscriber's number (ADR 0009 §10, U1).
It sees a **per-chatbot alias**, `sip:<alias ID>@<MAAP_ALIAS_HOST>;user=rcstk`
(RCC.07 v13.0 §2.5.4.2, *confirmed* for v13.0, *to confirm* for the target
edition), that only `maap` maps back (#683 calls it at admissions and
sends; nothing calls it yet):

| The chatbot has | Normal conversation | Anonymous (`Privacy: tk`) |
|---|---|---|
| no MSISDN permission | its alias | its anonymous alias |
| the MSISDN permission | the number, `tel:+<E.164>` | its anonymous alias |

Granting the MSISDN permission to a chatbot that had aliases lets it link
the normal alias of each subscriber who writes again to the number; the
anonymous alias stays apart. Grant it knowing that.

- **Alias ID.** 128 bits from `crypto/rand` in base32 (RFC 4648), lower
  case, without padding: 26 characters (the lead's decision on #711, the
  form `internal/pii` masks, #714), whose last character can only be one
  of `a e i m q u y 4`. An alias ID in another case, of another length or
  with another last character is refused before any read, with a message that names
  the rule and never the value (#683 and #712 answer it 400), and is never
  logged: `pii.Redact` masks an ID written in one case only (#721).
- **Nothing shared.** One subscriber has one alias per chatbot and kind of
  conversation, each drawn on its own, so two chatbots, or one chatbot's
  anonymous and normal conversations, cannot link the subscriber. An alias
  resolves only at its own chatbot: it is looked up by the chatbot and the
  alias ID together, never by the ID alone (lead decision on #711), so
  another chatbot's alias finds nothing and no index is needed. Every
  caller (#683, #712) passes the chatbot ID. It is stored by a
  conditional write, so of two tasks that store one at once, one alias
  wins and both get it.
- **Retention.** An alias the subscriber has not used for 180 days
  expires: it no longer resolves, and the subscriber's next message gets a
  new one. Only the subscriber's messages are uses; a chatbot's sends to
  the alias are not, or a chatbot alone could keep a number's alias past
  180 days (#752 review). A reply needs a message of the subscriber in the
  last 24 hours (ADR 0009 §9), so no conversation outlives its alias. A use
  written after the expiry, by a slow writer, never brings an alias back. Expiry is
  judged by comparing times at each read, never by the item's presence,
  since DynamoDB's TTL deletes late. A task writes an alias's last use at
  most hourly, off the request's path (its own context, 5 s); a write that
  failed waits for the next hour, and its warning is logged at most once a
  minute. Each alias used in the last hour takes one entry, about 100 bytes,
  in the task's memory. An absolute lifetime is not decided (held for the
  product owner, lead decision C on PR #674).
- **Logs** carry an alias only through `pii.Identity`, as `alias`.

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
| `c#<chatbot ID>` | `k#1`, `k#2` | A credential's slot: `key` (its key ID), `writer` |
| `k#<key ID>` | `key` | The credential: `chatbot` (the ID), `registration` (the chatbot's at issue), `digest` (binary, the secret's SHA-256), `created` and `last_used` (numbers, Unix seconds), `writer` |

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
  items, its credentials and their key items among them. A change at the same time does not
  stop it, and no credential goes from a chatbot that stays. A deletion
  that failed part way finishes its clean-up when called again; deleting a
  chatbot that is gone does nothing (ADR 0009 §10). **A deleted ID is never registered again**
  (lead decision on #708; `ErrDeleted`, which #709 answers 409), so nothing
  another table kept of it, or a change read before the deletion, reaches
  a new chatbot. Tombstones are kept, like the table, without TTL.
- **Credentials** (#710). A chatbot has at most two live credentials, one
  per slot. Issuing writes a free slot and the key item in one transaction
  with a check that the record's `registration` is still the one read, so
  an issue that meets a deletion either lands before the tombstone, and is
  deleted with the partition, or fails; a tombstone has no `registration`.
  A random `writer` token in the slot tells an issue the SDK sent again
  from another's. A lookup by key ID reads the key item, outside the
  partition, which is why the slot names it: deleting a slot deletes its
  key item first. Revoking deletes the key item, which ends lookups at
  once, then the slot, each on the condition that it is still that
  credential's. The key ID is 26 characters of base32 (128 random bits),
  never a `.` or a control character; only the secret's digest is stored.
- **Errors.** A store failure is an error of its own, never "not found":
  callers answer it 503, not 404. Errors carry the operation and the AWS
  error code only.

## DynamoDB `maap-requests` table

`MAAP_REQUESTS_TABLE`, on demand with point-in-time recovery, written by
`maap`'s task role only, like the registry (#684 creates it). Partition key
`pk` and sort key `sk`, both strings; **TTL on `ttl`** (number, Unix
seconds); no index. The send path that writes it is #683's.

| `pk` | `sk` | Holds | Kept |
|---|---|---|---|
| `c#<chatbot ID>` | `i#<idempotency key>` | An idempotency record: `digest` (binary, an HMAC of the request's SHA-256), `message_id`, `pending` (true until settled) or `answer` (binary, at most 8 KiB, absent when empty), `created`, `ttl`, `writer` | 24 hours from `created` (ADR 0009 §6) |
| `c#<chatbot ID>` | `m#<Message-ID>` | A message's status: `state` (`accepted`, `delivered`, `displayed` or `failed`), `accepted`, `updated` (Unix seconds), `ttl`, `writer` | `MAAP_STATUS_TTL` from `accepted` (§10) |

- **Idempotency** (ADR 0009 §4 step 2, §6). The key is 1–64 characters of
  `[A-Za-z0-9_-]`, so it holds no control character, scoped to the chatbot
  by the partition. The record is put on the condition that no live one
  exists: the first request with a key is kept, **pending**, with the
  Message-ID generated for it (32 lower-case hex digits); a repeat with the
  same digest gets that record back, one with another digest is refused
  ("key reused", which #683 answers 409). A random `writer` token tells a
  put the SDK sent again after its answer was lost, which is then this
  call's own, from another request's.
- **Settle and forget** (lead decision on #713, after the #749 security
  review). Only the call that stored a record holds its writer token, and
  only it may change the record, each by one conditional write: `Settle`
  stores the answer once `rcs-as` has answered, which repeats then get;
  `Forget` deletes the pending record of a request refused before it was
  sent (never a settled one, whose request was sent), so
  that a repeat is checked again rather than replayed. A repeat that finds
  the record pending is neither replayed nor sent: #683 answers 409, or 503
  to try again later. A call by any other writer is refused (a conflict).
- **Keyed digest.** The table keeps an HMAC-SHA256 of the request's digest,
  under a subkey of `RCS_PII_HMAC_KEY`, so that a reader of the table or of
  a backup cannot test guesses of a request (a templated one-time code, for
  instance) without the key (#749 security review). Rotating the key makes
  a repeat across the rotation another request (409) for up to 24 hours.
- **Statuses** (ADR 0009 §4). A status is put as `accepted` when `rcs-as`
  accepts a send, on the condition that no live one exists, so a resend of
  the same Message-ID leaves it as it is. Notifications move it on by a
  conditional update: `delivered` or `failed` from `accepted`, `displayed`
  from any other, since notifications come in any order and from any task
  and a status never goes back. It is read by its chatbot and Message-ID,
  so another chatbot's message is "not found" (#683 answers 404).
- **Expiry** is judged at read, by comparing `ttl` with the time: DynamoDB's
  TTL deletes late, and an expired item still there is written over.
- **Per-chatbot deletion.** A chatbot's items are its partition: deleting
  a chatbot (#709) queries it and deletes 25 items a request
  (`BatchWriteItem`), at most one request every 100 ms (250 items a second),
  so that a large deletion leaves the partitions it shares with other
  chatbots their capacity, and sends again what DynamoDB leaves
  unprocessed. It stops 2 s before the call's 20 s budget ends, unfinished
  (see the registry's errors in [Registry](#registry)). A write that races the
  deletion can leave an item behind, under an ID the registry never
  registers again (its tombstone), so no chatbot reads it; its TTL or a
  repeated deletion removes it.
- **Logs** never carry an idempotency key; errors carry the operation and
  the AWS error code only.

## DynamoDB `maap-counters` table

`MAAP_COUNTERS_TABLE`, **on demand** with point-in-time recovery, written by
`maap`'s task role only, like the other tables (#684 creates it). Partition
key `pk` and sort key `sk`, both strings; **TTL on `ttl`** (number, Unix
seconds); no index. The limits of ADR 0009 §9 live here, shared by every
task; which counters a request takes is #683's.

| `pk` | `sk` | Holds | Kept |
|---|---|---|---|
| `c#<chatbot ID>#m#<HMAC of the name>` | `c` | A chatbot's per-minute bucket: `full` and `returned` (nanoseconds), `ttl`, `writer` | until the bucket is full again |
| `c#<chatbot ID>#d#<YYYY-MM-DD>#<HMAC of the name>` | `c` | A chatbot's count of a UTC day: `n`, `ttl`, `writer` | the day and an hour |
| `n#m#<HMAC>`, `n#d#<YYYY-MM-DD>#<HMAC>` | `c` | The same, for a counter of all chatbots (a subscriber's from all chatbots) | the same |

- **Keys** (lead decision on #713, after the operations review of #751).
  Every counter has a partition key of its own, so no chatbot's counters
  share a hot key and DynamoDB spreads them by hash from the first write. A
  counter's name may name a subscriber, so the key holds only an
  HMAC-SHA256 of it (base64url) under a subkey of `RCS_PII_HMAC_KEY`, and
  no raw identifier reaches a key, CloudTrail data events or Contributor
  Insights; the chatbot ID, which is no subscriber's, stays readable for
  them. Rotating the key starts every counter again.
- **Buckets.** A per-minute bound of rate *r* is a token bucket with a burst
  of ⌈*r*/6⌉, refilled continuously at *r* (one token every 60/*r* seconds,
  rounded up to the nanosecond). The item holds the time `full` at which the
  bucket is full again, so a take is one conditional update and never a
  read followed by a write: of concurrent takes, from any task, none is lost
  and none exceeds the bucket. A take sets an idle bucket (absent, or full
  by now) to now plus an interval, or adds an interval to a busy one while
  it holds a token (`full` at most now plus burst − 1 intervals); a refused
  take writes nothing and answers the time until the next token, for
  `Retry-After`. An absent item is a full bucket, so TTL may delete it once
  it is full again.
- **Days.** A daily bound counts in an item per UTC day, which adds one on
  the condition that the count is under the limit; a refused take changes
  nothing and waits until midnight UTC, **09:00 in Korea (KST)**, when every
  daily limit starts again.
- **Give-back** (lead decisions on #713). A request takes several counters
  in turn; when a later one refuses, #683 gives back what the earlier ones
  took, once each, so that refused requests are not counted (§9). A day's
  give-back takes one from the count of the take's day while it is above
  zero. A bucket's returns only the part of the take that has not refilled
  since, at most an interval, so that a bucket never holds more than an
  exact token bucket would had the take never happened (#751 review): what
  the take left missing (its `full` less its time), less the refill since,
  less what `returned` (all ever given back to the bucket) says older
  takes were given back since, which may have refilled it in their stead;
  `full` never moves before now. It is a strongly consistent read and one
  update conditional on `full` and `returned` read. A fuzz test checks
  every run of takes, give-backs and time steps against an exact integer
  token bucket, and a seeded run checks that the DynamoDB backend answers
  as the memory one does. Given back 2 to 50 ms after their takes on a 10 ms
  bucket (6,000 a minute) at half to twice its rate, give-backs return at
  least 80 % of what a token bucket would (a simulation on #751): only
  takes from a bucket near full lose part of theirs.
- **The requests counter is never given back.** "Requests per chatbot, all
  endpoints" counts refused requests too: it is the ceiling of a chatbot's
  request rate, which give-backs would otherwise lift once a daily limit is
  reached. "Refused requests are not counted" holds for the send and
  conversation limits. #683 also keeps, per task, the refusals it has seen
  until their wait ends, so that a chatbot over a limit costs no write.
- **Retries.** A random `writer` token tells a take the SDK sent again after
  its answer was lost, so it counts once. A give-back is sent once, without
  the SDK's retries: one sent again after another writer's update would
  return a token twice, and a token per take on the item to tell it would
  grow a hot item. One lost counts the refused request, the safe side. A
  take that meets give-backs at the edge of full may find the bucket idle
  and busy in turn; each turn follows another writer's success, and it
  gives up after 64 only if others keep changing the bucket, a store
  failure. Every error is a store failure, which #683 answers 503, never
  429 (§9).
- **No per-chatbot deletion.** Counters last a day and an hour at most,
  under a chatbot ID never registered again, so deleting a chatbot leaves
  them to their TTL (lead decision on #713) and costs nothing here.
  Counter names are never logged.

**Write units and cost** (the operations review of #751, Seoul on-demand
prices of 2026-11-09: $0.68 per million write request units). A counter
item is under 1 KB, so one write is 1 WRU, a failed conditional write too.
A take costs about 1 + its bucket's load: one write when idle, two near the
rate, one for a refusal; a give-back one write and one read.

| Case | WRU | Cost |
|---|---|---|
| Hottest item: a chatbot's received messages at 6,000 a minute | about 200 a second on one key (1.99 a take at the rate) | under the 1,000 one key takes |
| One send (in the reply window, with an idempotency key, delivered and displayed): 7 counter takes (4 buckets, 3 days) and 4 request writes | 11–13; +8 when the answer is near 8 KiB | $7.5–8.8 a million |
| One received message | 2–3 | $1.4–2.0 a million |
| A chatbot at its send limit for a day (20,000 sends) | about 260,000 | about $5.3 a month |
| Abuse, refused at the first counter, no refusal cache | 1 a refusal | about $70 a month per source the WAF lets through at 40 a second |
| Abuse after a daily limit, with the requests counter never given back and #683's refusal cache | at most 20 a second per task | about $70 a month for two tasks |

On demand rather than provisioned: provisioned capacity is cheaper only
above about 29 % average use of its peak, and chatbot traffic comes in
campaigns; counters fail closed, so too little provisioned capacity would
turn into 503s for every chatbot before auto scaling reacts. To be looked
at again after a month of `ConsumedWriteCapacityUnits` (#684).
