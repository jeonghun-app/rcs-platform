# ADR 0009 — MaaP: chatbots reach subscribers through `rcs-as`, from a service outside the SIP core

**Status:** accepted

## Context

On 2026-10-25 the product owner decided to build a minimum Messaging as a
Platform (MaaP) as a new service, `cmd/maap` (epic #668): chatbots run by
parties outside the operator exchange RCS messages with subscribers, and an
operator registers them. Directory and search, verification and branding,
and billing are out of scope. This is the platform's first API for callers
outside the operator, its first Public Service Identities (PSIs), and the
first path on which subscriber identities leave the network. IDs such as A1
or H6 name controls of the
[security memo on #671](https://github.com/jeonghun-app/rcs-platform/issues/671#issuecomment-6393113490);
U1–U3 there are product decisions the product owner took (Decision §10, §9,
§7), and U4, the subscriber's way to refuse a chatbot, the lead took as the
memo's minimum (§11).

On `main` nothing matches a Request-URI against a wildcarded identity, `hss`
stores public user identities only, `icscf` routes to an S-CSCF only, and
`rcs-as` has no HTTP API. `rcs-as` ends every subscriber's chat, large-mode
and pager leg itself (a B2BUA), stores what it accepts and delivers through
`scscf` with `P-Served-User: <user>;sescase=term`
([rcs-as](../rcs-as.md#what-rcs-as-sends)).

Chatbot items come from **GSMA RCC.07 v13.0**
([Public sources](../spec-references.md#public-sources)), which GSMA
publishes as non-confidential: under ADR 0008 §3 an item it states is
*confirmed* for v13.0, and whether the edition matching the target profile
says the same is *to confirm* (v13.0 names no Universal Profile). Every value
taken from it is therefore operator configuration with v13.0 as the default,
never a constant. The 3GPP clauses below were checked in TS 23.003 V20.1.0,
TS 23.228 V20.1.0 and TS 29.228 V20.0.0.

## Decision

1. **Place.** `maap` is outside the SIP trust domain (ADR 0007 §7): it has
   no SIP, MSRP or Diameter, and of the platform's services reaches only
   `rcs-as`, over an internal HTTP API (ADR 0007 §3–§5). **`rcs-as` is the
   AS that hosts the chatbot PSI** and builds every SIP request toward
   subscribers, with every identity header, CPIM and IMDN body. `maap` is an
   endpoint behind it: the chatbot registry, the chatbot API, webhook
   delivery, aliases and policy limits. RCC.07 v13.0 §3.6.1 leaves the split
   inside an operator-hosted platform to the operator; `rcs-as` and `maap`
   together are the Chatbot Platform.
2. **Chatbot URIs.** A chatbot URI is what RCC.07 v13.0 §2.5.4.1.2 calls a
   chatbot service identifier: a SIP URI whose user part is the bot's
   identifier, optionally with a dot and a publisher identifier, at a
   `botplatform` host (`botplatform.mnc<MNC>.mcc<MCC>.3gppnetwork.org` for an
   operator's own platform). The host is `RCS_CHATBOT_DOMAIN` (§13), which
   must differ from `RCS_IMS_DOMAIN`. The operator issues bot identifiers in
   a strict subset of that grammar: at most two labels joined by `.`, each
   1–63 of lower-case letters, digits and `-`. One normaliser in a shared
   package, `internal/chatbot`, is used by `hss`, `icscf`, `scscf`, `rcs-as`
   and `maap` alike: `sip:` only, the host equal to `RCS_CHATBOT_DOMAIN`
   without case, no port, no URI headers, no escapes, no parameter but `tk`,
   which it drops (§2.5.4.3–§2.5.4.4). A URI at that host that is not in
   normal form is 404 wherever it is met; a tel URI is never a chatbot. The
   **chatbot range** is the set of URIs the wildcarded PSI (§3) matches.
3. **Routing in the core:** direct routing to the AS (TS 23.228
   §5.4.12.2 b).
   - **`hss`** stores one wildcarded PSI, `sip:!<ERE>!@<RCS_CHATBOT_DOMAIN>`
     (TS 23.003 §13.5), the ERE being §2's user-part grammar, with an active
     PSI activation state, the AS name `HSS_RCS_AS_URI` and no service
     profile: with direct routing no S-CSCF evaluates one. Only the operator
     scope writes it, never `acs` or `ft-server`. A pattern is compiled
     under `internal/ifc`'s ERE rules and work budget, at most 256 bytes.
     `hss` refuses every IMPU whose host is `RCS_CHATBOT_DOMAIN`, and a
     wildcard that matches an existing IMPU. Registering a chatbot writes
     nothing to `hss`.
   - **LIR** for a URI in the range: DIAMETER_SUCCESS, `Server-Name` the AS
     name, `Wildcarded-Public-Identity` the stored pattern (TS 29.228
     §6.1.4.1 step 2, Table 6.1.4.2, where a distinct identity takes
     precedence over a wildcard). **SAR and UAR** for it find no
     subscription, as today: DIAMETER_ERROR_USER_UNKNOWN, so `scscf`
     answers 404 and a REGISTER 403; a directly routed PSI has no S-CSCF.
   - **`scscf`**: after the originating iFC, it sends a request whose
     Request-URI is at `RCS_CHATBOT_DOMAIN` to `icscf`, as it does for the
     home domain; today such a request is 404. **`icscf`** normalises the
     Request-URI (§2) before the LIR, and routes to the AS the answer names
     only if it is on `ICSCF_AS_ROUTES` (§13), else 500 with Retry-After.
     Neither resolves `RCS_CHATBOT_DOMAIN` or a `Server-Name` through DNS.
     ADR 0007 §2 already admits `icscf` to `rcs-as` SIP.
   - **iFC.** The PSI has none. The subscriber's `DefaultRCSProfile` already
     sends what a client sends a chatbot to `rcs-as`, as for any peer: an
     INVITE with an RCS feature tag or MSRP stream (10) and a MESSAGE (20),
     SESSION_TERMINATED; an RCS OPTIONS (30), SESSION_CONTINUED. The chatbot
     IARIs match its RCS IARI pattern.
   - **`rcs-as` as the PSI host.** An OPTIONS reaches `rcs-as` twice: from
     iFC 30 with `P-Served-User`, which it forwards as today, then from
     `icscf` without one, which it answers from the delivery check's state
     (§4): 200 for an `active` or `suspended` chatbot, 403 for a blocked
     pair (§11), with the chatbot URI in
     `P-Asserted-Identity` (`tk` as in §10) and the chatbot IARIs, version
     and `isbot` tags in `Contact` (RCC.07 v13.0 §3.6.2, §2.5.4.1.1); 404
     otherwise. Any other method or service reaching the PSI (REFER,
     SUBSCRIBE, an INVITE that missed the originating `rcs-as`) is 403 (memo
     H5). A chatbot URI is refused as a group invitee, in a list or a REFER,
     and an originating request whose asserted identity is at
     `RCS_CHATBOT_DOMAIN` is 403.
4. **Message flows.** "Stored" names a DynamoDB table.
   - **Subscriber → chatbot** (pager MESSAGE, or messages on a chat or
     large-mode session):
     1. UE → `pcscf` → `scscf` (orig, `Service-Route`):
        `P-Asserted-Identity: <subscriber>` asserted by `pcscf`, which
        removes any client `P-Served-User`.
     2. `scscf` → `rcs-as` (iFC 10 or 20), `P-Served-User:
        <subscriber>;sescase=orig`.
     3. `rcs-as` runs its pipeline (identity, size, rate, CPIM From). A
        message or INVITE (notifications aside; a large-mode INVITE too,
        whose tags §3.6.8.3 does not give, so *to confirm*) without the
        chatbot IARI in `Accept-Contact` gets 403 with the Warning of RCC.07
        v13.0 §3.6.8.2.1 (§3.6.8.2.2 for a MESSAGE).
        Otherwise `rcs-as` asks `maap` for admission (`POST
        /v1/rcs/admissions`: chatbot, asserted subscriber, and whether
        `Privacy` holds `tk`), once per pager MESSAGE and once per session
        INVITE; its answer carries the chatbot's state and out-of-service
        text. An unknown chatbot is 404; a pair the subscriber blocked is
        403 with the Warning of §3.6.6; a suspended chatbot follows
        §3.6.8.2.3 (§11); over a subscriber limit (§9) 403, as `rcs-as`'s
        own rate limit answers; `maap` unavailable (§12) 500 with
        `Retry-After: 5`. Otherwise it stores the message in `messages`,
        queued for the conversation (chatbot, subscriber, anonymity), with a
        sent record when dispositions are asked for, and answers 202, or 200
        to the INVITE with the identity and tags of §3.
     4. `rcs-as` → `maap` `POST /v1/rcs/messages` (`rcs-as` token): the
        subscriber's asserted identity in canonical form (`messaging.UserOf`),
        never a CPIM or SIP `From`; the anonymity flag; Message-ID, DateTime,
        content type, body, dispositions asked for.
     5. `maap` maps the subscriber to the identifier the chatbot sees (§10),
        records the conversation (`maap-subscribers`) and POSTs a signed
        `message` event to the webhook (§8). Webhook 2xx: 200, and `rcs-as`
        dequeues it and sends the positive delivery notification asked for,
        from the chatbot (`Engine.Report`). Webhook failure, timeout or busy
        chatbot (§12): 503, and `rcs-as` keeps it for retry until
        `RCSAS_CHATBOT_STORE_TTL` (24 hours) ends with the negative
        notification. Unknown or suspended chatbot, or blocked pair: 404,
        undeliverable; it never reaches the webhook.
   - **Chatbot → subscriber:**
     1. Chatbot → ALB (HTTPS, `MAAP_PUBLIC_HOST`) → `maap`
        `POST /v1/messages`, the recipient named by its alias ID, or its
        MSISDN where allowed (§10).
     2. `maap` checks authentication, idempotency, the conversation or the
        right to start one, blocks and limits (§9). It generates the IMDN
        Message-ID (128 random bits, memo B3; `maap` is its only owner) and
        stores it in the idempotency record (`maap-requests`) before the
        call. A retry after `rcs-as` answered gets the stored answer; one
        after a lost answer resends the same ID, which `rcs-as` accepts
        again and the client drops as a duplicate
        ([rcs-as](../rcs-as.md#the-pipeline) step 5).
     3. `maap` → `rcs-as` `POST /v1/chatbot/messages` (`maap` token): the
        sender (the registry's chatbot URI, never chosen per request), its
        registry display name, the recipient's canonical tel URI, the
        Message-ID from step 2, the content, the dispositions, and the
        conversation's anonymity flag.
     4. `rcs-as` refuses a sender outside the chatbot range and a recipient
        inside it, applies the recipient's queue limits and its own
        backstops (§9), builds the CPIM (From with the bot tags of RCC.07
        v13.0 §3.6.8.1.2 and the name through `EscapeDisplayName`, To,
        DateTime, NS, `imdn.Message-ID`, `Disposition-Notification`),
        stores it and its sent record in `messages`, and answers 202.
     5. Before each delivery attempt `rcs-as` makes a **delivery check** (`POST
        /v1/rcs/delivery-checks`), a call of its own that reads state only (the
        chatbot's state and the pair block), counts no limit and leaves the
        reply window alone. Only a positive answer delivers. A suspended chatbot
        or blocked pair makes the message undeliverable, so suspension reaches
        what is queued within `maap`'s 30 s cache (§7); a timeout, open breaker
        or store error holds it for retry, as for an offline subscriber. The
        out-of-service text (§11) is a platform message and skips the check.
        Then `rcs-as` → `scscf`: a MESSAGE or large-mode INVITE (§5) with
        `P-Served-User: <subscriber>;sescase=term`, `P-Asserted-Identity:
        <chatbot URI;tk=on|off>` (§10), Accept-Contact with the standalone ICSI,
        and the standalone chatbot IARI (`…chatbot.sa`) with the bot version tag
        `;require;explicit`, P-Asserted-Service the standalone ICSI (RCC.07
        v13.0 §3.6.2.1, §3.6.8.1.2). `scscf` → `pcscf` → UE along `Path`. A 488
        or 606 (a client without chatbot support, §3.6.8.4.2) is undeliverable,
        not offline.
   - **Notifications.** A subscriber's delivery or display notification
     about a chatbot's message follows steps 1–2 above (MESSAGE or chat
     leg); `rcs-as` checks it against the sent record (threat model T10),
     queues it for the conversation, and sends it with
     `POST /v1/rcs/notifications`; `maap` updates the status record, which
     it wrote with its owning chatbot when it accepted the send
     (`maap-requests`, kept `RCSAS_SENT_TTL`, notifications asked for or
     not), and POSTs a signed `status` event. A chatbot's display notification is
     `POST /v1/notifications` → `POST /v1/chatbot/notifications`; `rcs-as`
     builds the IMDN, accepts it only if that message went to that chatbot
     (T10), and delivers it as step 5. Negative notifications `rcs-as`
     generates (expiry, undeliverable, queue full) reach `maap` the same
     way. A chatbot sees `delivered`, `displayed` or `failed`, without a
     reason, so unknown and offline recipients look alike (memo D5).
5. **Modes and content.** `maap` never sees the mode. `rcs-as` accepts a
   subscriber's pager MESSAGE, chat session and large-mode session to a
   chatbot (RCC.07 v13.0 §3.6.8.7 has clients send suggestion responses on a
   chat session). A chatbot's message is a Chatbot Standalone Message,
   delivered in pager mode up to `RCSAS_PAGER_LIMIT` (1300 bytes of CPIM)
   and in a large-mode session above it. §3.6.8.1.2 defines chatbot
   standalone messages as MESSAGE only, so large mode toward a chatbot's
   recipient, and the tags it carries, are *to confirm*. A client that takes
   no terminating sessions gets only what fits in pager mode, as today.
   `rcs-as` never starts a Chatbot Chat Session, and drops is-composing
   toward a chatbot.
   - **Content types**, configuration with RCC.07 v13.0 §3.6.10.2 as the
     default; anything else is 415. From chatbots: `text/plain;charset=utf-8`
     or the rich-card message type, each optionally with one suggested chip
     list, which `rcs-as` sends as the second part of a multipart CPIM
     (§3.6.10.1). From subscribers: `text/plain`, the suggestion response
     and shared client data types. The FT via HTTP file information
     document, geolocation push and every other type are refused both ways
     (memo I1).
   - **Size.** A chatbot's content, chip list included, is at most 248 KiB
     (253,952 bytes) of UTF-8, above the 250 KB RCC.07 v13.0 §3.6.10.1
     suggests for JSON payloads. It is one constant in `internal/chatbot`.
     `rcs-as` reserves 8 KiB for the CPIM it writes around it: the chatbot
     URI and To at most 256 bytes each, the display name at most 128 bytes
     before escaping (at most 896 after `EscapeDisplayName` and quoting),
     the bot tags, DateTime, NS, Message-ID (128 bytes), dispositions and the
     multipart framing come to under 4 KiB. It refuses to start with the API
     on if `RCSAS_MAX_MESSAGE_SIZE` is below 256 KiB (its default), so
     nothing `maap` accepts is refused for size by `rcs-as`. A subscriber's
     content reaches the chatbot as `rcs-as` accepted it, at most
     `RCSAS_MAX_MESSAGE_SIZE`.
   - **Validation.** Bodies are UTF-8 without C0 controls other than tab,
     CR and LF. A JSON type must be one JSON value without duplicate keys, at
     most 32 deep, with arrays of at most 1,000 elements and finite numbers.
     Its schema (§3.6.10.4) is not checked: otherwise the content is opaque
     (residual risk in threat model T16).
6. **API**, JSON under `/v1/`, specified in `docs/api/maap.yaml` by the
   implementation issue (group 5 below). Content travels as a JSON string,
   `body`, as in rcs-bridge.

   | Where | Resource | Caller |
   |---|---|---|
   | public | `POST /v1/messages`: send to one subscriber, `Idempotency-Key` required, 202 with `message_id` | chatbot |
   | public | `GET /v1/messages/{id}`: status of its own message, for `RCSAS_SENT_TTL` | chatbot |
   | public | `POST /v1/notifications`: displayed, for a message it received | chatbot |
   | public | `GET /v1/webhook-keys`: the public keys signing its deliveries | chatbot |
   | `maap` → chatbot | `message` and `status` events, POSTed to the chatbot's URL | `maap` |
   | internal | `/v1/chatbots[/{id}]` register, read, change, suspend, resume, delete; `…/credentials` issue, revoke; `…/blocks/{subscriber}` | operator |
   | internal | `DELETE /v1/subscribers/{tel}`: a recycled number; drops its aliases, conversations and blocks at every chatbot | operator |
   | internal | `POST /v1/rcs/admissions`, `/v1/rcs/delivery-checks`, `/v1/rcs/messages`, `/v1/rcs/notifications` | `rcs-as` |
   | `rcs-as` internal | `POST /v1/chatbot/messages`, `/v1/chatbot/notifications` | `maap` |

   A send has one recipient; there is no batch endpoint. **Idempotency:** a
   key is 1–64 characters of `[A-Za-z0-9_-]`, scoped to (chatbot, key) and
   kept 24 hours; the same key with the same request returns the first
   answer, with another request 409; the daily send limit bounds how many a
   chatbot holds. A webhook delivery has a new delivery ID on every attempt;
   chatbots drop duplicates by `message_id`. Pull delivery is not built:
   push suits a webhook-style client such as chatbot-framework, and pull can
   follow without changing the send side. `/v1/` contracts only grow, since
   a rolling update runs two versions at once.
7. **Who may call what.**
   - **Exposure (U3).** The chatbot API is public through the ALB on its own
     host name, `MAAP_PUBLIC_HOST`, HTTPS only in staging and prod (ADR
     0003). The operator and internal APIs are on a second listener and port
     that only the operator path and `rcs-as` reach, never on the public
     ALB. Three guards keep it so: the public listener's handler does not
     mount them; the ALB's security group reaches only the public port; and
     the internal port is in no target group. The policy test checks the
     last two (memo G1).
   - **Chatbot credentials.** A key ID and a 256-bit random secret, sent as
     `Authorization: Bearer <key-id>.<secret>`, never in a query string;
     looked up by key ID and compared as SHA-256 digests in constant time;
     only the digest is stored, and the secret is shown once at issue. Two
     credentials may be live per chatbot: issue the next, switch, revoke the
     old (runbook). Each records when it was last used, at most hourly per
     task. A chatbot may have an allow-list of source networks, checked
     against the last `X-Forwarded-For` entry, the one the ALB writes in its
     default `append` mode. Every failure is the same 401, decided before the
     body is read, and failures are limited per source (§9).
   - **Cache.** `maap` tasks cache registry entries for at most 30 s, and an
     unknown key ID for 30 s too, at most 10,000 of them per task: revocation,
     suspension, blocks and permission changes take effect on every task within
     30 s.
   - **Registration** is operator-only. The operator issues the chatbot's
     URI (§2) by a conditional write, so a URI in normal form is unique, and
     fixes its display name (at most 128 bytes), out-of-service text (§11;
     `text/plain`, at most 512 bytes),
     webhook URL, permissions and limits; a chatbot's credential changes none
     of them. Every change is an audit log line with the token name, the
     item, and the values before and after, without secrets. Look-alike
     names are a residual risk (T13); verification is out of scope.
   - **Internal tokens** follow ADR 0007 §3–§5, two each, read by the
     execution role: operator → `maap` (not `hss`'s operator token,
     `HSS_ADMIN_TOKEN`), `rcs-as` → `maap`, `maap` → `rcs-as`. rcs-bridge's
     trust model (one token, `hss`'s operator token, a UE through `pcscf`) is
     not reused.
   - **Scopes**, to be kept in `docs/api/maap-scopes.md` (group 5):

     | Caller | Allowed |
     |---|---|
     | operator | registry, credentials, webhook settings, permissions, limits, blocks, number recycling |
     | chatbot | its own sends, statuses, notifications and webhook keys; another chatbot's message ID is 404 |
     | `rcs-as` → `maap` | admissions; messages and notifications for chatbots |
     | `maap` → `rcs-as` | sends and notifications from a sender in the chatbot range, to subscribers only |

8. **Webhooks.** `maap` dials a webhook with a dialer that checks the
   resolved address when it connects and allows global unicast only: it
   refuses RFC 1918, ULA, loopback, link-local (task metadata included),
   100.64/10, 0/8, multicast, documentation ranges, IPv6 embedding IPv4
   (mapped, NAT64) and the VPC CIDR. It ignores proxy variables and follows
   no redirect. In staging and prod the URL is `https` with a verified
   certificate, on 443 or a port on `MAAP_WEBHOOK_PORTS`, without userinfo,
   at most 512 bytes, checked when set and when dialled. A new URL gets a
   signed challenge it must echo before it receives anything (memo F6). Each
   delivery has a 10 s limit in all, with connections kept alive per host;
   at most 4 KiB of the response is read, never stored, logged or
   reflected; deliveries are bounded per chatbot and per task (group 5 has
   the per-step timeouts and counts). The security group's egress follows
   `MAAP_WEBHOOK_PORTS` to `0.0.0.0/0`, which also reaches any VPC
   destination that admits by CIDR rather than by security group, so the
   dialer is the primary control (memo F5).
   **Signing:** Ed25519 (`crypto/ed25519`), one platform key pair with two
   live for rotation, in Secrets Manager read by the execution role. The
   signature covers a version label, the timestamp, the chatbot ID
   (audience), the delivery ID and the body's SHA-256, length-delimited;
   headers carry the key ID, timestamp, delivery ID and signature. Chatbots
   refuse a timestamp more than 300 s off and a delivery ID seen in the
   last 600 s; they may cache `GET /v1/webhook-keys` for an hour and fetch
   it again on an unknown key ID (`docs/api/`).
9. **Conversations and limits.** **By default a chatbot only replies (U2):** it
   may send within 24 hours of the time `rcs-as` accepted the subscriber's last
   message to it, so late delivery does not stretch the window. The operator may
   let a chatbot start conversations, with the lower limits below; that
   permission requires the MSISDN permission (§10), since the chatbot must name
   someone it has no alias for. A per-minute bound is a token bucket with a
   burst of a sixth of its rate (as `rcs-as`'s `Rate`), a daily bound a fixed
   day; both live in DynamoDB items every task shares, with TTL (as threat model
   T12). Refused requests are not counted. The answer is 429 with Retry-After,
   or 503 if the counter store fails. Subscriber limits are counted at admission
   (§4); messages within a session are bounded by `rcs-as`'s per-sender rate.
   The operator may set a chatbot's limits lower, never higher, which keeps the
   hottest counter near 100 writes a second.

   | Bound (in `maap`) | Default |
   |---|---|
   | sends per chatbot | 600 / min, 20,000 / day |
   | conversations a chatbot starts | 60 / min, 1,000 / day |
   | sends per (chatbot, subscriber) | 20 / min, 200 / day |
   | sends to one subscriber from all chatbots | 60 / min, 1,000 / day |
   | conversations started with one subscriber, all chatbots | 3 / day |
   | subscriber messages per (subscriber, chatbot) | 30 / min |
   | subscriber messages per chatbot | 6,000 / min |
   | requests per chatbot, all endpoints | 1,200 / min |
   | failed or unauthenticated requests per source (IPv4 /24, IPv6 /64), per task | 30 / min |

   **Backstops in `rcs-as`** hold whatever `maap` asks, as token buckets per
   task: chatbot senders 1,500 a minute each, burst 250 (messages and
   notifications alike, not `RCSAS_NOTIFICATION_RATE`), and 120 messages a
   minute, burst 20, to one subscriber from all chatbot senders together
   (notifications are bounded by T10's once per kind), both strictly above
   `maap`'s per-chatbot and per-subscriber buckets, so a chatbot within its
   limits never meets them; and 3,000 calls a minute, burst 500, to `rcs-as`'s
   chatbot API, a ceiling on the whole path. A refusal is 429 to `maap`, which
   answers the chatbot 503 with Retry-After; the count
   `chatbot.backstop_refused` opens the ticket alarm `RcsAsChatbotBackstopHit`,
   usually a sign to add capacity. In a subscriber's queue a chatbot is a sender
   with one share (an eighth), and all chatbots together hold at most a quarter,
   as group notifications do (T10, memo D3). Messages to a chatbot queue per
   conversation, so one subscriber's backlog does not take another's room.
   **Bodies.** A send is at most 1,496 KiB: six times the content, since JSON
   may write any character as `\uXXXX`, plus 8 KiB of envelope; other chatbot
   bodies 8 KiB, operator bodies 16 KiB. `maap`'s `/v1/rcs/*` bodies and a
   webhook body are at most six times `RCSAS_MAX_MESSAGE_SIZE` plus 8 KiB. JSON
   is strict: unknown fields, duplicate keys, keys differing only in case and
   trailing data are refused; envelopes are at most 4 deep, with arrays of at
   most 8 and strings bounded per field (`docs/api/`). The public server's idle
   timeout is 120 s, above the ALB's 60 s, so the ALB never reuses a connection
   the server is closing.
10. **What a chatbot learns (U1).** By default a **per-chatbot alias**,
    `sip:<alias-id>@<MAAP_ALIAS_HOST>;user=rcstk` (RCC.07 v13.0 §2.5.4.2): the
    alias ID is 128 random bits in base32, a row in `maap-subscribers` keyed
    both ways by (chatbot, subscriber, anonymous) and created by a conditional
    write. Aliases of one subscriber, at two chatbots or in an anonymous and a
    normal conversation, share nothing, so a reply to an alias names one
    conversation; only `maap` maps one back. The operator may let a chatbot see
    the **MSISDN** instead, as `tel:+<E.164>`. When the client asked for
    anonymity (`Privacy` holds `tk`, which triggers the anonymization function
    of §3.6.5.1), the chatbot gets the anonymous alias whatever its permission
    (§3.6.8 allows an anonymous and a normal conversation at once). Toward the
    client, `tk` on the chatbot's `P-Asserted-Identity` follows the request's
    `Privacy`: `on` when it held `tk`, `off` otherwise, in INVITE and OPTIONS
    responses (§3.6.8.6.1) and in the chatbot's requests within that
    conversation. A client that asked for nothing thus sees `tk=off` while the
    chatbot sees an alias (see Rationale). Events carry only the subscriber's
    identifier, content and type, Message-ID, time and notification kind: no SIP
    or CPIM header, IMDN XML, address, location or device data.
    - **Retention.** Aliases, conversations and blocks are keyed by the
      subscriber's canonical tel URI. An alias unused for 180 days expires.
      Recycling a number calls `DELETE /v1/subscribers/{tel}` as a required
      step of the number lifecycle procedure that deletes or moves the IMPU
      in `hss` (runbook). Conversations and idempotency records last 24
      hours, message statuses `RCSAS_SENT_TTL`. Expiry is judged by
      comparing times when an item is read, as for ADR 0005's challenges,
      since DynamoDB's TTL deletes late; "last used" is written at most
      hourly per task. Deleting a chatbot deletes all of these for it. They
      are conversation metadata, like T10's sent records.
    - **Logs** carry subscriber identifiers and aliases only through
      `pii.URI` or `pii.Identity`; the privacy check learns the alias form.
      Never logged: bodies, chatbot free text, idempotency keys, credentials,
      signatures, webhook paths or queries (the host only), webhook
      responses. **Metrics** have only the `Service` dimension (the registry
      has no fixed size); per-chatbot figures come from logs.
11. **Operator states and blocking (U4).** A chatbot is `active` or
    `suspended`. A suspended chatbot sends nothing: its API sends are 403,
    and what it queued before is undeliverable at the next attempt (§4).
    Toward subscribers it follows RCC.07 v13.0 §3.6.8.2.3 (*to confirm* for
    the target edition): a capability query gets its usual capabilities; a
    chat session is accepted, gets the chatbot's out-of-service text and a
    BYE; a standalone message gets the out-of-service text as a pager
    message. No subscriber message reaches its webhook. The operator may
    also block one (subscriber, chatbot) pair at the subscriber's request:
    the subscriber's requests get §3.6.6's 403 with its Warning, the only
    use of that answer, and the chatbot's sends to that subscriber are 404,
    as §3.6.6 has for platform requests. The subscriber-side means §3.6.6
    names (the client's local block list, the Spam Report Message, an
    operator-managed list of blocked chatbots in client configuration) are
    not in the minimum (Consequences).
12. **Calls between `rcs-as` and `maap`.** **Admission** has a 2 s timeout and
    at most 64 calls at a time per `rcs-as` task; after 5 failures in a row a
    breaker answers at once for 10 s, then lets one call through. Any of these
    is "unavailable": 500 with `Retry-After: 5`, counted in
    `chatbot.admission_unavailable` beside the timing
    `chatbot.admission_latency`. **Delivery** (`/v1/rcs/*`) has a 15 s timeout,
    above the webhook's 10 s and below `RCSAS_DELIVERY_TIMEOUT` (30 s); when a
    chatbot's deliveries are all in use, or its webhook failed 5 times in a row
    (that breaker holds 30 s), `maap` answers 503 at once. **Delivery checks**
    (2 s) and **delivery calls** each have their own cap of 64 at a time per
    task and their own breaker (5 failures, 10 s), apart from admission, so a
    queue drain never starves subscribers' admissions; over a cap the message
    stays queued. **`RCSAS_CHATBOTS=off`** turns the path off: `rcs-as` makes no
    call to `maap`; requests to `RCS_CHATBOT_DOMAIN` get 404; queued messages
    either way are held and expire under their TTL as undeliverable; `rcs-as`'s
    chatbot API answers 503, so `maap`'s `POST /v1/messages` answers 503 with
    Retry-After. ADR 0007 §2 has the ports, T4 what a compromised `maap`
    reaches; its tables are written by its task role only.
13. **New settings** (none exists on `main`):

    | Setting | Meaning |
    |---|---|
    | `RCS_CHATBOT_DOMAIN` | host of chatbot URIs (§2) |
    | `ICSCF_AS_ROUTES` | the platform's application servers `icscf` may route a PSI to (memo H6) |
    | `MAAP_PUBLIC_HOST` | ALB host name of the chatbot API |
    | `MAAP_ALIAS_HOST` | host of aliases: a name in the operator's domain that is neither `RCS_IMS_DOMAIN` nor `RCS_CHATBOT_DOMAIN`, so no IMPU or chatbot URI uses it; whether it must be routable is *to confirm* (§2.5.4.2) |
    | `MAAP_WEBHOOK_PORTS` | webhook ports besides 443; one infrastructure parameter sets it and the egress rule |
    | `RCSAS_CHATBOTS` | the switch of §12 |
    | `RCSAS_CHATBOT_STORE_TTL` | how long a message to a chatbot waits, 24 hours |
    | `RCSAS_CHATBOT_SENDER_RATE`, `RCSAS_CHATBOT_SUBSCRIBER_RATE`, `RCSAS_CHATBOT_API_RATE` | the backstops of §9 |

## Rationale

- **Outside the trust domain.** An internet-facing service that could put
  `P-Asserted-Identity` and `P-Served-User` on core requests would undo T2:
  every trigger skips `P-Served-User`, so it could reach any subscriber as
  anyone. With `rcs-as` building every request and refusing senders outside
  the range, a compromised `maap` impersonates chatbots and no one else, and
  store-and-forward, IMDN checks, MSRP and queue fairness are reused
  unchanged. The rejected alternative, `maap` as a SIP AS hosting the PSI
  (memo B4, second option), needs its own SIP stack, MSRP and store, and a
  dedicated `rcs-as` listener filtering its identities.
- **Direct routing, not a "PSI user" served by an S-CSCF** (TS 23.228
  §5.4.12.2 a): that needs SAR and User-Data for wildcards, `P-Profile-Key`
  handling and per-wildcard state in `scscf`, only to reach the same
  `rcs-as`. A PSI at all, because otherwise an OPTIONS leaving the
  originating chain toward a chatbot is 404, and the core would not know the
  range for later interconnection.
- **Admission before accepting** gives subscribers RCC.07's synchronous
  answers, at the cost of chatbots being unreachable while `maap` is down;
  its timeout, cap and breaker keep a slow `maap` from holding `rcs-as`'s
  person-to-person traffic. **The webhook as the end of `rcs-as`'s delivery
  attempt** keeps one queue, with its TTL, retries and negative
  notifications, instead of a second one in `maap`; a 24-hour TTL matches
  the reply window, so a dead webhook does not pile up a week of messages.
- **Suspension rechecked at delivery, not purged:** queues are per recipient
  with no index by sender, so a purge would scan them all. The check fails
  closed, so a compromised or absent `maap` cannot keep queued spam flowing.
- **A distinct anonymous alias:** a reply then names one conversation without
  a conversation ID in the API, and the chatbot cannot link the two, the
  stronger outcome under U1.
- **Ed25519, not per-chatbot HMAC:** HMAC keys must be stored where `maap`
  reads them back, so a registry leak would forge deliveries to every
  chatbot; Ed25519 is in the standard library. **A random alias with a
  mapping, not a keyed HMAC:** no one key, once leaked, reverses every
  alias by enumerating MSISDNs; rows delete one by one, and no key needs
  versions.
- **`tk` follows the client's request, not the alias:** RCC.07 v13.0
  §3.6.8.3.1 has a client that did not ask for privacy end a session whose
  200 carries `tk=on`, and suggestion responses need that session
  (§3.6.8.7). The client is then told less privacy than it has, which errs
  on the safe side; the mismatch is in T15.
- **Keyed by tel URI, not the HSS subscription:** `rcs-as` and `maap` see
  asserted identities only, and binding to the IMPI needs Sh or `hss`
  access, which T4 keeps from `maap`. The required recycling step and the
  expiry stand in (residual risk in T15). An absolute alias lifetime would
  change what chatbots see under U1, so it is not decided here.
- **A key-ID bearer, not OAuth 2.0:** RCC.07 v13.0 §3.6.1 puts the
  interface between a chatbot and its platform out of its scope, and whether
  another GSMA document defines it is *to confirm*. The bearer can later be
  issued from a client-credentials endpoint without changing the send side.
- **Standalone from chatbots:** pager and large mode exist; a
  platform-started chat session adds MSRP legs opened for a chatbot.
- **A 480 stays offline:** `scscf` answers 480 both for no binding and for
  no binding with the chatbot tag, so a reply to a client without chatbot
  support that answers neither 488 nor 606 is retried for `RCSAS_STORE_TTL`.
- **Blocks and suspension are decided in `maap`** (memo B5). `rcs-as`
  enforces what bounds a compromised `maap` without trusting it: the range,
  recipients that are subscribers, per-subscriber and total caps across all
  chatbot senders, and the quarter of each queue. Per-sender rates and
  shares do not bound it, since it may send as any URI in the range. Moving
  chatbot policy into `rcs-as` would not narrow what it yields.

## Consequences

- **Follow-up work for #668**, grouped for the lead to file; each group
  updates its service document and needs a security review:
  1. **`hss`**: the wildcarded PSI type, operator-only provisioning, the
     chatbot-domain and overlap checks, pattern checks, LIR with the AS
     name and `Wildcarded-Public-Identity`, SAR and UAR answers (§3).
  2. **`internal/chatbot`, `icscf`, `scscf`**: the shared normaliser and URI
     form, the chain end at `RCS_CHATBOT_DOMAIN`, the check before the LIR,
     routing to an AS on `ICSCF_AS_ROUTES` without DNS (§2, §3).
  3. **`rcs-as`**: `rcs-as`'s chatbot API listener, token and scope, with strict
     JSON, limits, `Fuzz*` targets for its `/v1/chatbot/*` request bodies and
     its spec and scope table in `docs/api/`; sender, recipient and identity
     checks; the backstops and the chatbot sender rate; CPIM and IMDN with bot
     tags and `tk`; admission, delivery checks and delivery calls, each with its
     timeout, cap and breaker; the IARI check and 488/606 handling; the OPTIONS
     answer, suspended behaviour and refusal of other PSI requests and chatbot
     invitees; per-conversation queues, the chatbot TTL and the quarter cap;
     content-type lists, dropping is-composing, the size check at start; the
     switch (§3–§5, §9, §11, §12).
  4. **`maap` core**: `cmd/maap`, tables (`maap-registry`,
     `maap-subscribers`, `maap-requests` for idempotency and statuses,
     `maap-counters`) with memory backends, on-demand with PITR as ADR 0003
     has, each with its TTL; the
     operator API, credentials, audit log and caches; aliases,
     conversations, states, blocks, recycling and expiry; the alias form in
     the privacy check (§6, §7, §10, §11).
  5. **`maap` chatbot API and webhooks**: authentication, limits, strict
     JSON and idempotency; send, status, notifications; the dialer, signing,
     challenge, breaker and webhook concurrency (8 per chatbot, 256 per
     task); the dialer's connect 3 s, TLS 3 s and response headers 5 s; the
     public server's header read 5 s, read and write 15 s, headers 8 KiB and
     512 requests at a time per task (memo J1, F3); shared counters,
     failing closed; `docs/api/maap.yaml` and `docs/api/maap-scopes.md`;
     `Fuzz*` targets for the JSON envelope, aliases, webhook URLs and the
     chatbot URI (§6–§9).
  6. **Infrastructure and operations.** Prerequisite: `rcs-as`, `scscf`,
     `icscf` and `pcscf` are not yet ECS services in `infra/platform.yaml`.
     The `maap` service and its three ports, ALB host rule and certificate,
     security groups with the ADR 0007 §2 policy test, egress from the
     `MAAP_WEBHOOK_PORTS` parameter, task role with its IAM policy test,
     secrets, and `rcs-as`'s new listener; a stable NAT egress address as a
     stack output, since chatbots allow it by address (a single NAT gateway
     stops webhooks in an AZ outage); the WAF rate rule scoped down for
     `MAAP_PUBLIC_HOST`. Alarms, `Service` dimension only, each with a
     runbook section: paging `MaapAdmissionUnavailable`,
     `MaapWebhookFailureRatio` (all chatbots), `MaapNoHealthyTargets`,
     `MaapTarget5xx`, `MaapStoreErrors`; tickets for table throttling,
     `MaapChatbotQueueAge` and the cost budget at 80 % and 100 %; memo D7
     through Contributor Insights on logs. The runbook: rotation of
     credentials, tokens and the signing key (a 32-byte Ed25519 seed; the
     next key published at least an hour, the chatbots' cache, before use,
     the old one 600 s after; withdrawn at once on compromise), suspension,
     the recycling step, the switch, deploy order (`maap` first, rollback
     the other way), RPO from PITR. Compose, with development defaults
     refused in staging and prod, and an `rcs-sim` end-to-end test. Cost
     (operations' estimate, Seoul prices on 2026-10-26): about $41 a month
     for two small tasks and about $14 per million chatbot messages in
     DynamoDB, plus secrets, WAF, NAT data and logs. A linked issue in
     auto-configuration-server sets CHATBOT MSG TECH to a value allowing
     standalone messaging (RCC.07 v13.0 §3.6.8.9).
- **To confirm**, for the RCC.07 edition matching the target profile: the
  chatbot URI form, feature-tag values and the bot version the platform may
  claim, content types, the anonymised address and `tk`, the Warning texts,
  suspended behaviour, large mode in both directions, and
  subscriber-side blocking; and whether a GSMA document defines the chatbot
  API and its authentication.
- **Not in the minimum**, for the lead to decide: the Chatbot Information
  function (§3.6.4), without which a client may not treat the contact as a
  chatbot (§3.6.2.4, *to confirm*); the `restricted` state (§3.6.8.2.4);
  platform-started Chatbot Chat Sessions; token deletion and MSISDN linking
  (§3.6.5.1.2.3, §3.6.5.1.2.4); receiving Spam Reports (§3.6.6.2); message
  revocation; the Traffic-Type CPIM header (§3.6.7); file transfer and
  geolocation with chatbots; pull delivery; coarser statuses for chatbots
  that start conversations (memo D5); rich-card schema validation;
  interconnection with other operators' chatbot platforms.
- Threat model T13–T16 record the threats and residual risks, all planned
  under #668.
- Revisit this ADR when a maintainer obtains the RCC.07 edition matching the
  target profile, or when the product owner widens MaaP.
