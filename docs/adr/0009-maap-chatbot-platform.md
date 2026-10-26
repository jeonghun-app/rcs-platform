# ADR 0009 — MaaP: chatbots reach subscribers through `rcs-as`, from a service outside the SIP core

**Status:** accepted

## Context

On 2026-10-25 the product owner decided to build a minimum Messaging as a
Platform (MaaP) as a new service, `cmd/maap` (epic #668): chatbots run by
parties outside the operator exchange RCS messages with subscribers, and an
operator registers them. Directory and search, verification and branding,
and billing are out of scope. This is the platform's first API for callers
outside the operator, its first Public Service Identities (PSIs), and the
first path on which subscriber identities leave the network. The product
owner also chose U1–U3 of the security memo on #671 (Decision §10, §9, §7).

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
   delivery, aliases and policy limits.
   RCC.07 v13.0 §3.6.1 leaves the split inside an operator-hosted platform
   to the operator; `rcs-as` and `maap` together are the Chatbot Platform.
2. **Chatbot addresses.** RCC.07 v13.0 §2.5.4.1.2 gives a chatbot service
   identifier as a SIP URI whose user part is the bot's identifier,
   optionally with a dot and a publisher identifier, at a `botplatform` host
   (`botplatform.mnc<MNC>.mcc<MCC>.3gppnetwork.org` for an operator's own
   platform). The host is `RCS_CHATBOT_DOMAIN`, which must differ from
   `RCS_IMS_DOMAIN`, so no IMPU can share it. The operator issues bot
   identifiers in a strict subset of that grammar: at most two labels joined
   by `.`, each 1–63 of lower-case letters, digits and `-`. One normaliser
   in a shared package, `internal/chatbot`, is used by `hss`, `icscf`,
   `scscf`, `rcs-as` and `maap` alike: `sip:` only, the host equal to
   `RCS_CHATBOT_DOMAIN` without case, no port, no URI headers, no escapes,
   no parameter but `tk`, which it drops (§2.5.4.3–§2.5.4.4). A URI at that
   host that is not in normal form is 404 wherever it is met, never taken
   for a subscriber's; a tel URI is never a chatbot.
3. **Routing in the core:** direct routing to the AS (TS 23.228
   §5.4.12.2 b).
   - **`hss`** stores one wildcarded PSI, `sip:!<ERE>!@<RCS_CHATBOT_DOMAIN>`
     (TS 23.003 §13.5), the ERE being §2's user-part grammar, with an active
     PSI activation state, the AS name `HSS_RCS_AS_URI` and no service
     profile: with direct routing no S-CSCF evaluates one. Only the operator
     scope writes it, never `acs` or `ft-server`. A pattern is compiled
     under `internal/ifc`'s ERE rules and work budget, at most 256 bytes.
     `hss` refuses a wildcard that matches an existing IMPU and an IMPU a
     wildcard matches. Registering a chatbot writes nothing to `hss`.
   - **LIR** for an identity in range: DIAMETER_SUCCESS, `Server-Name` the
     AS name, `Wildcarded-Public-Identity` the stored pattern (TS 29.228
     §6.1.4.1 step 2, Table 6.1.4.2, where a distinct identity takes
     precedence over a wildcard). **SAR and UAR** for it find no
     subscription, as today: DIAMETER_ERROR_USER_UNKNOWN, so `scscf`
     answers 404 and a REGISTER 403; a directly routed PSI has no S-CSCF.
   - **`scscf`** ends an originating chain for a Request-URI at
     `RCS_CHATBOT_DOMAIN` at `icscf`, as for the home domain (today 404).
     **`icscf`** normalises the Request-URI (§2) before the LIR, and routes
     to the AS the answer names only if it is on `ICSCF_AS_ROUTES`, the
     platform's own servers (memo H6), else 500 with Retry-After. ADR 0007
     §2 already admits `icscf` to `rcs-as` SIP.
   - **iFC.** The PSI has none. The subscriber's `DefaultRCSProfile` already
     sends what a client sends a chatbot to `rcs-as`, as for any peer: an
     INVITE with an RCS feature tag or MSRP stream (10) and a MESSAGE (20),
     SESSION_TERMINATED; an RCS OPTIONS (30), SESSION_CONTINUED. The chatbot
     IARIs match its RCS IARI pattern.
   - **`rcs-as` as the PSI host** answers an OPTIONS that returns through
     `icscf` with 200 for an admitted chatbot (§4), the chatbot in
     `P-Asserted-Identity` and the chatbot IARIs, version and `isbot` tags
     in `Contact` (RCC.07 v13.0 §3.6.2, §2.5.4.1.1); 404 for an unknown one.
     Any other method or service reaching the PSI (REFER, SUBSCRIBE, an
     INVITE that missed the originating `rcs-as`) is 403 (memo H5). A
     chatbot URI is refused as a group invitee, in a list or a REFER.
4. **Message flows.** "Stored" names a DynamoDB table.
   - **Subscriber → chatbot** (pager MESSAGE, or messages on a chat or
     large-mode session):
     1. UE → `pcscf` → `scscf` (orig, `Service-Route`):
        `P-Asserted-Identity: <subscriber>` asserted by `pcscf`, which
        removes any client `P-Served-User`.
     2. `scscf` → `rcs-as` (iFC 10 or 20), `P-Served-User:
        <subscriber>;sescase=orig`.
     3. `rcs-as` runs its pipeline (identity, size, rate, CPIM From), then
        asks `maap` for admission (`POST /v1/rcs/admissions`: chatbot and
        asserted subscriber). Unknown chatbot: 404. Suspended chatbot or
        block: 403 with the Warning of RCC.07 v13.0 §3.6.6. `maap`
        unreachable: 500 with Retry-After. Otherwise it stores the message in
        `messages`, queued for the conversation (chatbot, subscriber), with a
        sent record when dispositions are asked for, and answers 202 (or 200
        to the INVITE, with the identity and tags of §3).
     4. `rcs-as` → `maap` `POST /v1/rcs/messages` (`rcs-as` token): the
        subscriber's asserted identity in canonical form (`messaging.UserOf`),
        never a CPIM or SIP `From`; Message-ID, DateTime, content type, body,
        dispositions asked for.
     5. `maap` maps the subscriber to the identifier the chatbot sees (§10),
        records the conversation (`maap-subscribers`) and POSTs a signed
        `message` event to the webhook (§8). Webhook 2xx: 200, and `rcs-as`
        dequeues it and sends the positive delivery notification asked for,
        from the chatbot (`Engine.Report`). Failure or timeout: 503, and
        `rcs-as` keeps it for retry as for an offline user, until
        `RCSAS_STORE_TTL` ends with the negative notification. A chatbot
        deleted meanwhile: 404, undeliverable.
   - **Chatbot → subscriber:**
     1. Chatbot → ALB (HTTPS, `MAAP_PUBLIC_HOST`) → `maap`
        `POST /v1/messages`, the recipient named by its alias, or its MSISDN
        where allowed (§10).
     2. `maap` checks authentication, idempotency, the conversation or the
        right to start one, blocks and limits (§9). It generates the IMDN
        Message-ID (128 random bits) and stores it in the idempotency record
        (`maap-requests`) before the call. A retry after `rcs-as` answered
        gets the stored answer; one after a lost answer resends the same ID,
        which `rcs-as` accepts again and the client drops as a duplicate
        ([rcs-as](../rcs-as.md#the-pipeline) step 5).
     3. `maap` → `rcs-as` `POST /v1/chatbot/messages` (`maap` token): the
        sender (the registry's chatbot URI, never chosen per request), its
        registry display name, the recipient's canonical tel URI, the
        content, the dispositions, and whether the conversation is
        anonymised.
     4. `rcs-as` refuses a sender outside the chatbot range and a recipient
        inside it, applies the recipient's queue limits (§9), builds the CPIM
        (From with the bot tags of RCC.07 v13.0 §3.6.8.1.2 and the name
        through `EscapeDisplayName`, To, DateTime, NS, `imdn.Message-ID`,
        `Disposition-Notification`), stores it and its sent record in
        `messages`, and answers 202.
     5. `rcs-as` → `scscf`: a MESSAGE or large-mode INVITE (§5), as for any
        stored message, with `P-Served-User: <subscriber>;sescase=term`,
        `P-Asserted-Identity: <chatbot URI;tk=on|off>` (`on` when anonymised,
        §2.5.4.3, §3.6.8.5.1), Accept-Contact with the standalone ICSI and
        the chatbot IARI `;require;explicit`, P-Asserted-Service the
        standalone ICSI (§3.6.8.1.2). `scscf` → `pcscf` → UE along `Path`.
   - **Notifications.** A subscriber's delivery or display notification
     about a chatbot's message follows steps 1–2 above (MESSAGE or chat
     leg); `rcs-as` checks it against the sent record (threat model T10),
     queues it for the conversation, and sends it with
     `POST /v1/rcs/notifications`; `maap` POSTs a signed `status` event. A
     chatbot's display notification is `POST /v1/notifications` →
     `POST /v1/chatbot/notifications`; `rcs-as` builds the IMDN, accepts it
     only if that message went to that chatbot (T10), and delivers it as
     step 5. Negative notifications `rcs-as` generates (expiry,
     undeliverable, queue full) reach `maap` the same way. A chatbot sees
     `delivered`, `displayed` or `failed`, without a reason, so unknown and
     offline recipients look alike (memo D5).
5. **Modes and content.** `maap` never sees the mode. `rcs-as` accepts a
   subscriber's pager MESSAGE, chat session and large-mode session to a
   chatbot unchanged (RCC.07 v13.0 §3.6.8.7 has clients send suggestion
   responses on a chat session). A chatbot's message is a Chatbot Standalone
   Message, delivered in pager mode up to `RCSAS_PAGER_LIMIT` (1300 bytes of
   CPIM) and in a large-mode session above it; a client that takes no
   terminating sessions gets only what fits in pager mode, as today.
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
     of UTF-8, above the 250 KB RCC.07 v13.0 §3.6.10.1 suggests for JSON
     payloads. It is one constant in `internal/chatbot`; `rcs-as` reserves
     8 KiB for the CPIM headers it writes, which are all bounded, and refuses
     to start with the API on if `RCSAS_MAX_MESSAGE_SIZE` is below 256 KiB
     (its default), so nothing `maap` accepts is refused for size by
     `rcs-as`. A subscriber's content reaches the chatbot as `rcs-as`
     accepted it, at most `RCSAS_MAX_MESSAGE_SIZE`.
   - **Validation.** Bodies are UTF-8 without C0 controls other than tab,
     CR and LF; a JSON type must be one JSON value, at most 32 deep, without
     duplicate keys. Its schema (§3.6.10.4) is not checked: otherwise the
     content is opaque (residual risk in threat model T16).
6. **API**, JSON under `/v1/`, specified in `docs/api/maap.yaml` by the
   implementation issue (group 5 below). Content travels as a JSON string,
   `body`, as in rcs-bridge.

   | Listener | Resource | Caller |
   |---|---|---|
   | public | `POST /v1/messages`: send to one subscriber, `Idempotency-Key` required, 202 with `message_id` | chatbot |
   | public | `GET /v1/messages/{id}`: status of its own message | chatbot |
   | public | `POST /v1/notifications`: displayed, for a message it received | chatbot |
   | public | `GET /v1/webhook-keys`: the public keys signing its deliveries | chatbot |
   | webhook | `message` and `status` events, POSTed to the chatbot's URL | `maap` |
   | internal | `/v1/chatbots[/{id}]` register, read, change, suspend, resume, delete; `…/credentials` issue, revoke; `…/blocks/{subscriber}` | operator |
   | internal | `DELETE /v1/subscribers/{tel}`: a recycled number; drops its aliases, conversations and blocks at every chatbot | operator |
   | internal | `POST /v1/rcs/admissions`, `/v1/rcs/messages`, `/v1/rcs/notifications` | `rcs-as` |
   | `rcs-as` | `POST /v1/chatbot/messages`, `/v1/chatbot/notifications` | `maap` |

   A send has one recipient; there is no batch endpoint. **Idempotency:** a
   key is 1–64 characters of `[A-Za-z0-9_-]`, scoped to (chatbot, key) and
   kept 24 hours; the same key with the same request returns the first
   answer, with another request 409; the daily send limit bounds how many a
   chatbot holds. Pull delivery is not built: push suits a webhook-style
   client such as chatbot-framework, and pull can follow without changing
   the send side.
7. **Who may call what.**
   - **Exposure (U3).** The chatbot API is public through the ALB on its own
     host name, `MAAP_PUBLIC_HOST`, HTTPS only in staging and prod (ADR
     0003). The operator and internal APIs are on a second listener and port
     that only the operator path and `rcs-as` reach, never on the public
     ALB; the public listener's handler does not mount them, so no ALB rule
     can expose them (memo G1).
   - **Chatbot credentials.** A key ID and a 256-bit random secret, sent as
     `Authorization: Bearer <key-id>.<secret>`, never in a query string;
     looked up by key ID and compared as SHA-256 digests in constant time;
     only the digest is stored, and the secret is shown once at issue. Two
     credentials may be live per chatbot: issue the next, switch, revoke the
     old (runbook). Each records when it was last used. A chatbot may have
     an allow-list of source networks, checked against the last
     `X-Forwarded-For` entry, the one the ALB wrote. Every failure is the
     same 401, decided before the body is read, and failures are limited per
     source (§9).
   - **Revocation.** `maap` tasks cache registry entries for at most 30 s:
     revocation, suspension, blocks and permission changes take effect on
     every task within 30 s.
   - **Registration** is operator-only. The operator issues the chatbot's
     URI (§2) by a conditional write, so a URI in normal form is unique, and
     fixes its display name, webhook URL, permissions and limits; a
     chatbot's credential changes none of them. Every change is an audit
     log line with the token name, the item, and the values before and
     after, without secrets. Look-alike names are a residual risk (T13);
     verification is out of scope.
   - **Internal tokens** follow ADR 0007 §3–§5, two each, read by the
     execution role: operator → `maap` (not `hss`'s admin token), `rcs-as` →
     `maap`, `maap` → `rcs-as`. rcs-bridge's trust model (one token, the
     `hss` operator token, a UE through `pcscf`) is not reused.
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
   signed challenge it must echo before it receives anything (memo F6).
   Limits: connect 3 s, TLS 3 s, response headers 5 s, 10 s in all; at most
   4 KiB of the response is read, never stored, logged or reflected; per
   task at most 8 deliveries at a time per chatbot and 256 in all. The
   security group allows `0.0.0.0/0:443`, which also opens 443 inside the
   VPC, so the dialer is the primary control (memo F5).
   **Signing:** Ed25519 (`crypto/ed25519`), one platform key pair with two
   live for rotation, in Secrets Manager read by the execution role. The
   signature covers a version label, the timestamp, the chatbot ID
   (audience), the delivery ID and the body's SHA-256, length-delimited;
   headers carry the key ID, timestamp, delivery ID and signature. Chatbots
   refuse a timestamp more than 300 s off and a delivery ID seen in the
   last 600 s (`docs/api/`).
9. **Conversations and limits.** **By default a chatbot only replies
   (U2):** it may send within 24 hours of the subscriber's last message to
   it. The operator may let a chatbot start conversations, with the lower
   limits below; that permission requires the MSISDN permission (§10), since
   the chatbot must name someone it has no alias for. Counters are fixed
   windows shared by every task (DynamoDB atomic counters with TTL, as in
   threat model T12); a task that saw a window go over refuses the rest of
   it from memory; the answer is 429 with Retry-After. The operator may set
   a chatbot's limits lower, never higher. `rcs-as`'s per-sender rate takes
   a chatbot sender at a setting of its own, 1,200 a minute per task by
   default, a backstop above `maap`'s limits.

   | Bound | Default |
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

   In a subscriber's queue a chatbot is a sender with one share (an eighth),
   and all chatbots together hold at most a quarter, as groups do (T10, memo
   D3). Messages to a chatbot queue per conversation, so one subscriber's
   backlog does not take another's room. The public server: header read
   5 s, read and write 15 s, idle 60 s, headers 8 KiB, 512 requests at a
   time per task; a send body at most 768 KiB (three times the content, the
   most JSON escaping of UTF-8 takes, plus the envelope), other bodies
   8 KiB, operator bodies 16 KiB. JSON is strict: unknown fields, duplicate
   keys, keys differing only in case and trailing data are refused.
10. **What a chatbot learns (U1).** By default a **per-chatbot alias**,
    `sip:<token>@<MAAP_ALIAS_HOST>;user=rcstk` (RCC.07 v13.0 §2.5.4.2) with
    `tk=on`: the token is 128 random bits in base32, a row in
    `maap-subscribers` keyed both ways and created by a conditional write.
    Aliases of one subscriber at two chatbots share nothing, and only `maap`
    maps one back. The operator may let a chatbot see the **MSISDN**
    instead, as `tel:+<E.164>`, with `tk=off`; a request whose `Privacy`
    header holds `tk` is anonymised whatever the permission (§3.6.8.6.1).
    Events carry only the subscriber's identifier, content and type,
    Message-ID, time and notification kind: no SIP or CPIM header, IMDN XML,
    address, location or device data.
    - **Retention.** Aliases, conversations and blocks are keyed by the
      subscriber's canonical tel URI. A recycled number is dropped with
      `DELETE /v1/subscribers/{tel}` (runbook), and an alias unused for 180
      days expires. Conversations and idempotency records last 24 hours,
      message statuses `RCSAS_SENT_TTL`. Deleting a chatbot deletes them
      all. They are conversation metadata, like T10's sent records.
    - **Logs** carry subscriber identifiers and aliases only through
      `pii.URI` or `pii.Identity`, and the privacy check learns the alias
      form. Never logged: bodies, chatbot free text, idempotency keys,
      credentials, signatures, webhook paths or queries (the host only) and
      webhook responses. **Metrics** have no subscriber, alias or chatbot
      dimension (the registry has no fixed size); per-chatbot figures come
      from logs.
11. **Blocking (U4).** The operator may suspend a chatbot, which stops both
    directions within 30 s (a subscriber's request gets §4's 403), and block
    one (subscriber, chatbot) pair: a send to that subscriber is 404 to the
    chatbot, as RCC.07 v13.0 §3.6.6 has for platform requests. The
    subscriber-side means §3.6.6 names (the client's local block list, the
    Spam Report Message, an operator-managed list of blocked chatbots in
    client configuration) are not in the minimum (Consequences).
12. **Ports and reach.** ADR 0007 §2 has the rows: `maap` public HTTP from
    the ALB; `maap` internal HTTP from `rcs-as` and the operator path;
    `rcs-as` internal HTTP from `maap`. `maap` reaches no SIP, MSRP, Diameter
    or `hss` port; its egress is `rcs-as`'s internal port, AWS endpoints and
    443 (§8). Its tables are written by its task role only. Threat model T4
    has what a compromised `maap` reaches.

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
  `rcs-as`. A PSI at all, rather than `rcs-as` spotting chatbot recipients
  alone, because otherwise an OPTIONS and anything else leaving the
  originating chain toward a chatbot is 404, and the core would not know the
  range for later interconnection.
- **Admission before accepting** gives subscribers RCC.07's synchronous 403
  and 404, at the cost of chatbots being unreachable while `maap` is down.
  **The webhook as the end of `rcs-as`'s delivery attempt** keeps one queue,
  with its TTL, retries and negative notifications, instead of a second one
  in `maap`.
- **Ed25519, not per-chatbot HMAC:** HMAC keys must be stored where `maap`
  reads them back, so a registry leak would forge deliveries to every
  chatbot; Ed25519 is in the standard library. **A random alias with a
  mapping, not a keyed HMAC:** no one key, once leaked, reverses every
  alias by enumerating MSISDNs; rows delete one by one, and no key needs
  versions.
- **Keyed by tel URI, not the HSS subscription:** `rcs-as` and `maap` see
  asserted identities only, and binding to the IMPI needs Sh or `hss`
  access, which T4 keeps from `maap`. The recycling API and expiry stand in
  (residual risk in T15).
- **A key-ID bearer, not OAuth 2.0:** RCC.07 v13.0 §3.6.1 puts the
  interface between a chatbot and its platform out of its scope, and whether
  another GSMA document defines it is *to confirm*. The bearer can later be
  issued from a client-credentials endpoint without changing the send side.
- **Standalone from chatbots, no platform-started chat sessions:** pager and
  large mode exist and need only identity and tag changes; a platform-started
  chat session adds MSRP legs opened for a chatbot.
- **Blocks and suspension are checked in `maap`, not `rcs-as`** (memo B5):
  `rcs-as` keeps the checks that protect subscribers whatever `maap` does
  (range, queue shares, rates). A compromised `maap` can already
  impersonate any chatbot, so moving chatbot policy into `rcs-as` would not
  narrow what it yields.

## Consequences

- **Follow-up work for #668**, grouped for the lead to file; each updates
  its service document:
  1. **`hss`**: the wildcarded PSI type, operator-only provisioning, overlap
     and pattern checks, LIR with the AS name and
     `Wildcarded-Public-Identity`, SAR and UAR answers for the range (§3).
  2. **`internal/chatbot`, `icscf`, `scscf`**: the shared normaliser and URI
     form, the chain end at `RCS_CHATBOT_DOMAIN`, the check before the LIR,
     routing to an AS on `ICSCF_AS_ROUTES` (§2, §3).
  3. **`rcs-as`**: the `maap` API listener, token and scope; sender and
     recipient range checks; the chatbot sender rate; CPIM and IMDN with bot
     tags and `tk`, honouring `Privacy: tk`; admission and delivery calls to
     `maap`; the OPTIONS answer, refusal of
     other PSI requests and chatbot invitees; per-conversation queues and the
     quarter cap; content-type lists and the size check at start (§3–§5, §9).
  4. **`maap` core**: `cmd/maap`, tables (`maap-registry`,
     `maap-subscribers`, `maap-requests`, `maap-counters`) with memory
     backends, the operator API, credentials, audit log and 30 s cache,
     aliases, conversations, blocks, recycling and expiry (§6, §7, §10, §11).
  5. **`maap` chatbot API and webhooks**: authentication, limits, strict
     JSON and idempotency; send, status, notifications; the dialer, signing,
     challenge and concurrency; shared counters; `docs/api/maap.yaml` and
     `docs/api/maap-scopes.md`; `Fuzz*` targets for the JSON envelope,
     aliases, webhook URLs and the chatbot URI (§6–§9).
  6. **Infrastructure and operations**: the ALB host rule; security groups
     with the ADR 0007 §2 policy test; the task role and its IAM policy test;
     Secrets Manager entries; NAT egress; alarms on per-chatbot refusals and
     block growth from logs (memo D7); the runbook (credential, token and
     signing-key rotation, suspension, number recycling); the compose service
     with development defaults refused in staging and prod, and an `rcs-sim`
     end-to-end test. In auto-configuration-server, the client setting that
     enables chatbot standalone messaging (RCC.07 v13.0 §3.6.8.9).
- **To confirm**, for the RCC.07 edition matching the target profile: the
  chatbot URI form, feature-tag values and the bot version the platform may
  claim, content types, the anonymised address and `tk`, the Warning texts
  and subscriber-side blocking; and whether a GSMA document defines the
  chatbot API and its authentication.
- **Not in the minimum**, for the lead to decide: platform-started Chatbot
  Chat Sessions; token deletion and MSISDN linking (§3.6.5.1.2.3,
  §3.6.5.1.2.4); receiving Spam Reports (§3.6.6.2); message revocation; the
  Traffic-Type CPIM header (§3.6.7); file transfer and geolocation with
  chatbots; pull delivery; coarser statuses for chatbots that start
  conversations (memo D5); rich-card schema validation; interconnection with
  other operators' chatbot platforms.
- Threat model T13–T16 record the threats and residual risks, all planned
  under #668.
- Revisit this ADR when a maintainer obtains the RCC.07 edition matching the
  target profile, or when the product owner widens MaaP.
