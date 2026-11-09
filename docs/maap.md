# maap

The half of the Chatbot Platform outside the SIP trust domain
([ADR 0009](adr/0009-maap-chatbot-platform.md) §1): the chatbot registry,
the chatbot API, webhook delivery, aliases and policy limits. `rcs-as` hosts
the chatbot PSI and builds every SIP request; `maap` has no SIP, MSRP or
Diameter and reaches only `rcs-as`, over internal HTTP. Code:
`internal/maap`, wired by `cmd/maap`. It is being built under epic #668:
today it starts with checked settings, serves its health checks, and guards
its internal listener with the operator's token; no route is mounted yet
(#708–#713 add the operator's).

## Listeners

| Listener | Setting | Who reaches it | Serves |
|---|---|---|---|
| admin | `RCS_ADMIN_ADDR` (`:8080`) | its load balancer's health checks | `/healthz`, `/readyz`, as every service's admin port (ADR 0007 §2) |
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
| `MAAP_ALIAS_HOST` | required | host of aliases (ADR 0009 §10, §13): a DNS name that is neither `RCS_IMS_DOMAIN` nor `RCS_CHATBOT_DOMAIN` nor under either, compared without regard to case; stored in lower case |
| `MAAP_WEBHOOK_PORTS` | none | ports a webhook URL may name besides 443 (ADR 0009 §8); the infrastructure parameter that sets it also sets the egress rule (#684) |
| `MAAP_INTERNAL_ADDR` | `:8081` | the internal listener, `host:port` |
| `MAAP_OPERATOR_TOKEN`, `MAAP_OPERATOR_TOKEN_NEXT` | none | the operator's current and next tokens. *prod*: the first is required, and each must hold 256 bits (43 base64url characters or 64 hex digits). Printable ASCII without white space everywhere |
| `MAAP_DECODES` | `8` | request bodies decoded at once in a task, on every listener (see [Memory](#memory)); at least 1 |
| `MAAP_REGISTRY_TABLE` | `maap-registry` | DynamoDB table of chatbots and credentials (#708) |
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
20 MB. `MAAP_DECODES` bounds the bodies decoded at once, whichever listener
they come on, and the rule is:

> `MAAP_DECODES` × 20 MB stays under half the task's memory limit.

The default, 8, needs about 160 MB, so a task of 512 MB or more (#684 sizes
it). Raise the cap only with the memory limit.

## Internal API

Specified in [api/maap.yaml](api/maap.yaml), with the callers and their
scopes in [api/maap-scopes.md](api/maap-scopes.md). Every route is checked in
this order, each before the request's body is read:

| Status | When |
|---|---|
| 404 | no route serves the path, whatever the token |
| 503 | no token is configured (dev and test only: prod requires `MAAP_OPERATOR_TOKEN`); `Retry-After` does not help |
| 401 | no bearer token, more than one `Authorization` header, or a token not accepted, the operator's included in another scheme (`WWW-Authenticate: Bearer`) |
| 403 | the token's caller may not use the route |

Presented and accepted tokens are compared as SHA-256 digests, every accepted
one each time, in constant time. Each request is one audit line
(`audit: internal request`): the operation, the status, the caller and the
token slot (`current` or `next`). Tokens, bodies and paths are never logged.

A route with a body then decodes it through `chatbot.DecodeEnvelope`
(ADR 0009 §9): operator bodies at most 16 KiB (413 above it), strict JSON (400
for unknown fields, duplicate keys or keys differing in case, trailing data,
or a string over its field's bound). A request that finds every one of the
`MAAP_DECODES` slots taken gets 503 with `Retry-After: 1` at once, before its
body is read, and counts `api.decode_busy`; the handler keeps its slot until
it has validated what it decoded.

`DecodeEnvelope` bounds each string but not what it holds. A string a handler
writes into a SIP, CPIM or HTTP header, or a log, such as a display name, an
out-of-service text, an idempotency key or a webhook URL, is refused first if
it holds a C0 control or DEL, tab included (400, naming the field, never the
value): CR LF would end a header block and a NUL may cut it short. C1
controls are not refused, as in `internal/chatbot`'s wire types (#717). The
content is checked by `chatbot.ValidateContent` instead.

Metrics have the `Service` dimension only (ADR 0009 §10):
`api.<operation>.<status>` per request and `api.decode_busy`.
