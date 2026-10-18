# hss

The Home Subscriber Server of the IMS core. It keeps every subscriber's
identities, credentials, service profile and S-CSCF assignment, answers the Cx
requests of `icscf` and `scscf` over Diameter, and serves the provisioning API
that operators, `acs` and `ft-server` call. Code: `internal/hss`, wired by
`cmd/hss`.

- Cx: TS 29.228 (procedures) and TS 29.229 (Diameter), see [Cx behaviour](#cx-behaviour).
- Provisioning API: [api/hss.yaml](api/hss.yaml), with the
  caller scopes in [api/hss-scopes.md](api/hss-scopes.md).
- State: DynamoDB `subscribers` and `service-profiles` ([Tables](#tables)).

## Configuration

Environment variables, prefixed `HSS_`, plus the shared `RCS_` settings of
`internal/runtime` (`RCS_ENV`, `RCS_ADMIN_ADDR`, `RCS_PII_HMAC_KEY`, ...).
`RCS_IMS_DOMAIN` is required. Settings marked *prod* are refused in `staging` and
`prod` when unsafe, and every problem is reported at once at start.

| Variable | Default | Meaning |
|---|---|---|
| `HSS_STORE` | `dynamodb` | `dynamodb`, or `memory` (one task, lost on restart; refused in prod) |
| `HSS_SUBSCRIBERS_TABLE` | `subscribers` | DynamoDB table of subscriptions |
| `HSS_PROFILES_TABLE` | `service-profiles` | DynamoDB table of service profiles |
| `HSS_DYNAMODB_ENDPOINT` | | DynamoDB Local URL for dev stacks |
| `HSS_KMS_KEY_ID` | | KMS key (ID, ARN or alias) that wraps the data key; required in prod |
| `HSS_DATA_KEY` | | base64 of a 32-byte local data key, dev and test only; required with `dynamodb` when `HSS_KMS_KEY_ID` is unset; a random one per process with `memory` |
| `HSS_IMS_REALM` | `RCS_IMS_DOMAIN` | Digest realm of SIP Digest registration |
| `HSS_FT_REALM` | | Digest realm of `ft-server`; must differ from the IMS realm; unset means no FT credentials |
| `HSS_DIAMETER_ADDR` | `:3868` | Cx listener |
| `HSS_DIAMETER_HOST` | `hss-<random>.<namespace>` | Origin-Host; leave unset in ECS (see [Diameter identity](#diameter-identity)) |
| `HSS_NAMESPACE` | `RCS_SERVICE_NAMESPACE`, else `rcs.local` | Cloud Map namespace, for the generated Origin-Host and defaults below |
| `HSS_DIAMETER_REALM` | `RCS_IMS_DOMAIN` | Origin-Realm |
| `HSS_DIAMETER_PEER_REALM` | the Origin-Realm | realm a peer must claim in its CER |
| `HSS_DIAMETER_PEER_NETWORKS` | | CIDRs peers may connect from; required in prod (ADR 0007 §6) |
| `HSS_SCSCF_HOST_PATTERN` | `scscf-*.<namespace>` | which connected peers are S-CSCFs, for RTR and PPR |
| `HSS_SCSCF_NAMES` | | S-CSCF names offered in Server-Capabilities, e.g. `sip:scscf.rcs.local` |
| `HSS_API_ADDR` | `:8081` | provisioning API listener, separate from the admin port |
| `HSS_ADMIN_TOKEN`, `HSS_ADMIN_TOKEN_NEXT` | | operator tokens; the first is required in prod |
| `HSS_ACS_TOKEN`, `HSS_ACS_TOKEN_NEXT` | | `acs` tokens |
| `HSS_FT_TOKEN`, `HSS_FT_TOKEN_NEXT` | | `ft-server` tokens |
| `HSS_ACS_RATE`, `HSS_ACS_BURST` | `20`, `40` | requests per second and burst per `acs` token |
| `HSS_DEFAULT_PROFILE` | `rcs-default` | profile of subscriptions created without one |
| `HSS_CREATE_DEFAULT_PROFILE` | `true` | create that profile at start, as [below](#default-service-profile), unless it exists |
| `HSS_RCS_AS_URI` | `sip:rcs-as.<namespace>` | application server of the default profile |
| `HSS_MAX_AUTH_ITEMS` | `4` | AKA vectors per MAR at most (1 to 16) |
| `HSS_CX_TIMEOUT` | `3s` | store work per Cx request |
| `HSS_PUSH_TIMEOUT` | `5s` | each RTR or PPR attempt, and the pushes one provisioning request causes |

In prod every token must be at least 256 bits (43 base64url characters) and no
token may be shared between callers. Tokens come from Secrets Manager through the
task execution role, injected as environment variables (ADR 0007 §4).

## Data model

One subscription per private identity (IMPI). It holds:

- the IMSI, for SIM-based subscribers;
- 1 to 32 public identities (IMPUs), each with a barring flag, its identity type
  (only distinct public user identities are provisioned for now), its implicit
  registration set (a number; identities with the same number register together,
  TS 29.228 §6.5) and its registration state, `NOT_REGISTERED`, `REGISTERED` or
  `UNREGISTERED`;
- AKA credentials: K, OPc (OP is accepted and turned into OPc, never stored),
  AMF and SQN;
- Digest credentials: the HA1 of a password per realm, for MD5 and SHA-256;
- the ID of its service profile, shared by reference;
- charging information;
- `acs_managed`, which lets `acs` issue and read the credentials;
- the Cx state: the assigned S-CSCF name and the authentication pending flag.

IMPUs are stored and matched in one canonical form: `sip:` and `sips:` URIs as
`scheme:user@host` with the user unescaped and the host in lower case, and `tel:`
URIs as `tel:+digits` without visual separators. URI parameters in a Cx request
(`;user=phone`) are ignored.

Shared public identities and several IMPIs per subscription are not modelled;
so Associated-Identities is never sent, and the S-CSCF name is kept once per
subscription, which matches the platform's single S-CSCF service name (ADR 0005).

## Tables

`internal/hss/awsstore` describes the items. For the infrastructure:

| Table | Key | Index | Notes |
|---|---|---|---|
| `subscribers` | `pk` (S) | `profile-index`: hash `profile` (S), keys only | items `s#<IMPI>`, `u#<IMPU>`, `keyring`; on-demand; point-in-time recovery |
| `service-profiles` | `pk` (S) | | one item per profile; on-demand; point-in-time recovery |

The task role needs `dynamodb:GetItem`, `PutItem`, `UpdateItem`, `DeleteItem`,
`Query` (on the index), `TransactWriteItems`, `ConditionCheckItem` and
`DescribeTable` on both tables, and `kms:GenerateDataKey` and `kms:Decrypt` on
`HSS_KMS_KEY_ID` with the encryption context `service=hss`, `purpose=subscriber-secrets`.

Every write is conditional on the version read, so two tasks cannot both reserve
the same AKA sequence numbers or overwrite each other's S-CSCF assignment: the
loser reads again and decides afresh. A subscription and its IMPU items are
written in one transaction, so an IMPU never belongs to two subscriptions.

## Secrets

K, OPc and every HA1 are sealed with AES-256-GCM under a data key before they are
stored, each bound to its subscription and field, so a sealed value copied to
another record does not open (`internal/hss/keyring`).

- With `HSS_KMS_KEY_ID`, the data key is generated by KMS the first time any task
  starts and stored, wrapped, in the `keyring` item of `subscribers`; every task
  unwraps it once at start. **Losing that item loses every stored secret**: keep
  point-in-time recovery on the table.
- Without it (dev and test), `HSS_DATA_KEY` is the data key.

Secrets never reach a log or an API response. K and OPc are written with
`PUT .../aka` and never returned. A Digest password is generated by the HSS
(192 random bits), returned once by the request that issues it, and only its HA1
is kept. HA1 leaves the HSS only in a MAA or PPR to the S-CSCF and, for the FT
realm, to `ft-server`.

## Cx behaviour

Requests are answered as TS 29.228 describes; the clauses below are where each
rule comes from. A request the HSS cannot serve because the store or the keyring
fails is answered `DIAMETER_UNABLE_TO_COMPLY` and counted (`cx.<command>.error`).

| Request | Behaviour |
|---|---|
| UAR (§6.1.1.1) | unknown identities 5001, identities of different subscriptions 5002; a barred IMPU whose set has no unbarred identity `DIAMETER_AUTHORIZATION_REJECTED`; REGISTRATION: 2002 with the stored S-CSCF name, or 2001 with Server-Capabilities; DE_REGISTRATION: success with the name, or 5003; REGISTRATION_AND_CAPABILITIES: success with capabilities. Roaming is not restricted. |
| MAR (§6.3.1) | `Digest-AKAv1-MD5`: up to `HSS_MAX_AUTH_ITEMS` vectors, their SQNs reserved in the same write that stores the S-CSCF name and sets authentication pending. `SIP Digest` (or `Unknown` for a Digest subscriber): one item with the MD5 HA1 and the SHA-256 HA1 as alternate (Table 6.3.7). A scheme the subscriber has no credential for: 5006. Resynchronisation (RAND‖AUTS in SIP-Authorization) only from the S-CSCF holding the challenge: SQN is reset to the card's when AUTS verifies and the network's SQN is out of range (TS 33.102 §6.3.5). |
| SAR (§6.1.2.1, §8.1.2) | REGISTRATION / RE_REGISTRATION register the implicit set and return User-Data (the IMSSubscription document with the set's identities and the profile's iFC) and Charging-Information; UNREGISTERED_USER stores the name and makes the set unregistered; deregistrations clear the state, and the name once nothing is served; the `*_STORE_SERVER_NAME` types keep the name (state unregistered) when the profile has services for unregistered users, and otherwise answer 2004 SERVER_NAME_NOT_STORED. Another S-CSCF than the stored one gets 5005 with the stored name (NO_ASSIGNMENT: UNABLE_TO_COMPLY). User-Data beyond 128 KiB: 5008. |
| LIR (§6.1.4.1) | registered or unregistered: the S-CSCF name; not registered with unregistered services (or an originating request): the name if one is stored, else 2003 with capabilities; otherwise 5003. |

The I-CSCF gets Server-Capabilities with the profile's mandatory and optional
capabilities and the names in `HSS_SCSCF_NAMES`; without any it may pick any
S-CSCF. Restoration (TS 23.380), emergency registration, wildcarded identities and
PSIs are not supported.

### HSS-initiated requests

RTR and PPR go by Destination-Realm to any connected peer matching
`HSS_SCSCF_HOST_PATTERN`, with Destination-Host naming the peer chosen (ADR 0005);
a busy or failed peer is followed by the next, at most three, as a retransmission.
The stored state changes first, so an S-CSCF that cannot be reached never undoes a
provisioning change: the user picks it up at the next registration.

| Change | Request |
|---|---|
| a served implicit set gains or loses identities, or a barring changes | PPR with the set's new User-Data |
| a served set loses every identity | RTR `PERMANENT_TERMINATION` for its identities |
| a served set's default identity (first unbarred) changes | RTR `SERVER_CHANGE`, so the user registers again |
| the subscription's profile changes, or the shared profile is updated | PPR per served set; a shared profile is pushed in the background to every subscriber using it |
| charging information changes | PPR with Charging-Information |
| a new IMS Digest password while registered or authenticating | PPR with the SIP-Auth-Data-Item (§6.5.2.4) |
| the subscription is deleted while served | RTR `PERMANENT_TERMINATION` |

## Default service profile

`rcs-default` sends RCS traffic to `rcs-as` in both session cases and whether the
user is registered or not, so `rcs-as` can act as originating and terminating
participating function and store messages for users who are offline
(docs/architecture.md §5):

| Priority | Trigger | Default handling |
|---|---|---|
| 10 | INVITE with an OMA CPM ICSI or RCS IARI in `Accept-Contact`/`Contact`, or a CPM ICSI in `P-Preferred-Service`/`P-Asserted-Service` | SESSION_TERMINATED |
| 20 | MESSAGE | SESSION_TERMINATED |
| 30 | OPTIONS with the same RCS service tags (capability discovery) | SESSION_CONTINUED |
| 40 | REGISTER (third-party registration) | SESSION_CONTINUED |

Chat and messaging fail rather than bypass `rcs-as`, which anchors MSRP and keeps
IMDN and store-and-forward; capability discovery and registration continue while it
is down. Each service condition is its own trigger, with one header name and one
literal pattern (`3gpp-service\.ims\.icsi\.oma\.cpm\.` or
`3gpp-application\.ims\.iari\.rcs\.`), the ICSI and IARI text after `urn-7`,
which is the same in percent-encoded feature tags and in the plain service headers.
The profile is created at start if missing; an operator's changes to it are kept.

### Writing iFC

Criteria are JSON in the provisioning API (field names follow the TS 29.228 XML
schema). Patterns are POSIX extended regular expressions (TS 29.228 Annex F). A
header *name* pattern must match the whole header name, in any case (`Contact`
selects `Contact`, not `Accept-Contact`); every other pattern matches anywhere in
its field, so anchor it with `^`/`$` to match a whole value. Request-URI patterns
ignore case.

The S-CSCF evaluates a profile for every initial request within a work budget
(`internal/ifc`, `DefaultMaxWork`) and fails the evaluation of a request the
budget cannot pay for. Write each condition as a plain header name and a literal
pattern (escaped dots are fine, and so is an outer `.*X.*`), with one trigger per
alternative rather than one alternation: a literal is found with a substring
search at a few units a byte, any other pattern costs its compiled size times the
length of every value it is tried on, and a REGISTER `Contact` can be 2 KB. The
default profile needs well under half the budget for a REGISTER with a 2 KB
`Contact` and a chat INVITE.

A profile is refused with 400, the message naming the field or the limit, when its
criteria do not compile, when a reference REGISTER, chat INVITE or MESSAGE would
exceed an evaluation limit (for example `MaxWork`) in any session case, or when the
User-Data of a subscription at the model's limits would exceed 128 KiB
(`MaxDocumentSize`). One that needs more than half of the default budget for a
reference request is stored, and the answer carries a warning, which is also
logged (`costly service profile`) and counted (`profile.costly`): requests
somewhat larger than the reference ones would exceed the budget. At most 64
criteria per profile.

## Diameter identity

Each task has its own Origin-Host, `hss-<12 hex digits>.<namespace>`, drawn at
every start (ADR 0005). With a shared one, an S-CSCF whose HSS task died would
reconnect to another task under the same Origin-Host and hold the new connection in
the watchdog's REOPEN state for about a minute. Nothing needs to resolve the name:
the CSCFs connect to `hss.<namespace>` and requests to the HSS go by realm.

## Operations

- `/healthz` and `/readyz` are on `RCS_ADMIN_ADDR`; `/readyz` checks both tables.
- The API logs one `audit: provisioning request` line per request: operation,
  caller, token slot (`current` or `next`), status and the masked IMPI.
- Metrics: `cx.<command>.<result>` (`e` before an experimental result),
  `cx.<command>.error`, `store.conflict`, `aka.resync`, `aka.auts_invalid`,
  `aka.sqn_exhausted`, `profile.missing`, `profile.costly`, `userdata.too_large`,
  `push.rtr|ppr.sent|rejected|failed`, `push.fanout.subscriptions`,
  `api.<operation>.<status>`, `api.rate_limited`, `api.store_failure`.
- A subscription whose profile was deleted (the in-use check reads an eventually
  consistent index) is answered `DIAMETER_UNABLE_TO_COMPLY` and counted as
  `profile.missing` until it is given a profile.
- Store failures answer the API with 503 and `Retry-After`, so callers retry.
- `make test-integration` runs the DynamoDB store and two HSS tasks issuing
  AKA vectors at once against DynamoDB Local.

Not in this release: the Sh interface, SLF, geo-redundancy, IMS restoration.
