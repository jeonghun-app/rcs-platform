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
| `HSS_ACS_RATE`, `HSS_ACS_BURST` | `20`, `40` | requests per second and burst of each `acs` token, in each task: a bucket per token slot per task, so the most one caller gets is rate × tasks × 2 slots (a shared limit is a follow-up) |
| `HSS_DEFAULT_PROFILE` | `rcs-default` | profile of subscriptions created without one |
| `HSS_CREATE_DEFAULT_PROFILE` | `true` | create that profile at start, as [below](#default-service-profile), unless it exists |
| `HSS_RCS_AS_URI` | `sip:rcs-as.<namespace>` | application server of the default profile |
| `HSS_MAX_AUTH_ITEMS` | `4` | AKA vectors per MAR at most (1 to 16) |
| `HSS_CX_TIMEOUT` | `3s` | store work per Cx request, waiting for the subscriber's lock included |
| `HSS_API_TIMEOUT` | `5s` | store work per API request, lock wait included |
| `HSS_START_TIMEOUT` | `60s` | opening the store and the keyring at start; past it the task exits. At most `240s` (see Operations) |
| `HSS_KEYRING_BOOTSTRAP` | `false` | allow creating a first data key although subscriptions are stored (see [Secrets](#secrets)) |
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
  AMF (default `0000`: the separation bit of TS 33.102 Annex H is for EPS
  and 5GS, not IMS AKA) and SQN;
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
| `subscribers` | `pk` (S) | `profile-index`: hash `profile` (S), keys only | items `s#<IMPI>`, `u#<IMPU>`, `keyring`; on-demand; point-in-time recovery; deletion protection |
| `service-profiles` | `pk` (S) | | one item per profile; on-demand; point-in-time recovery; deletion protection |

The task role needs `dynamodb:GetItem`, `PutItem`, `DeleteItem`, `Query` and
`Scan` (on the index), `TransactWriteItems`, `ConditionCheckItem` and
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

- With `HSS_KMS_KEY_ID`, the data key is generated by KMS when the first task
  starts on an empty table and stored, wrapped, in the `keyring` item of
  `subscribers` (as `key_<creation time in Unix ms>`); every task unwraps it
  once at start. **Losing that item loses every stored secret**: keep
  point-in-time recovery and deletion protection on the table.
- Without it (dev and test), `HSS_DATA_KEY` is the data key.

If the `keyring` item is missing while subscriptions are stored, the HSS refuses
to start: a new key would seal new secrets under a key nothing stored opens with,
and turn a restore of the lost item into a second loss. To recover, restore the
`keyring` item from point-in-time recovery (an export of the table at a time it
existed, copied back with its `key_*` attributes) and start again. Only when the
key is truly gone, start once with `HSS_KEYRING_BOOTSTRAP=true`: a new key is
created (logged as `created the first data key...`, counted as
`keyring.created`), the old secrets stay unusable (their requests answer 500 or
`DIAMETER_UNABLE_TO_COMPLY`) and must be provisioned again; then remove the flag.
Every start that finds a key while the flag is still set logs `HSS_KEYRING_BOOTSTRAP
is set although a data key exists; remove it`.

Secrets never reach a log or an API response. K and OPc are written with
`PUT .../aka` and never returned. A Digest password is generated by the HSS
(192 random bits), returned once by the request that issues it, and only its HA1
is kept. HA1 leaves the HSS only in a MAA or PPR to the S-CSCF and, for the FT
realm, to `ft-server`.

## Cx behaviour

Requests are answered as TS 29.228 describes; the clauses below are where each
rule comes from. A request the HSS cannot serve because the store or the keyring
fails is answered `DIAMETER_UNABLE_TO_COMPLY`, as the procedures say, and counted
(`cx.<command>.error`): every task shares the store, so another task would fail
too. A request that waited past `HSS_CX_TIMEOUT` for its subscriber's lock in
this task, because another request for that subscriber (or one sharing its lock
stripe) is slow, is answered `DIAMETER_TOO_BUSY` and counted (`lock.busy`): the
condition is local to the task, and the S-CSCF may retry on another one.

| Request | Behaviour |
|---|---|
| UAR (§6.1.1.1) | unknown identities 5001, identities of different subscriptions 5002; a barred IMPU whose set has no unbarred identity `DIAMETER_AUTHORIZATION_REJECTED`; REGISTRATION: 2002 with the stored S-CSCF name, or 2001 with Server-Capabilities; DE_REGISTRATION: success with the name, or 5003; REGISTRATION_AND_CAPABILITIES: success with capabilities. Roaming is not restricted. |
| MAR (§6.3.1) | `Digest-AKAv1-MD5`: up to `HSS_MAX_AUTH_ITEMS` vectors, their SQNs reserved in the same write that stores the S-CSCF name and sets authentication pending. `SIP Digest`: one item with the MD5 HA1 and the SHA-256 HA1 as alternate (Table 6.3.7). `Unknown` takes the stored scheme only if it is SIP Digest, as step 4 says ("neither NASS-Bundled nor SIP Digest" is 5006), so an AKA-only subscriber gets 5006; an S-CSCF wanting AKA vectors names the AKA scheme. A scheme the subscriber has no credential for: 5006. Resynchronisation (RAND‖AUTS in SIP-Authorization) only from the S-CSCF holding the challenge: SQN is reset to the card's when AUTS verifies and the network's SQN is out of range (TS 33.102 §6.3.5). |
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

The HSS only answers connections, so it can push only over a connection an S-CSCF
opened to *this* task. **Every `scscf` task must therefore hold a Cx connection to
every `hss` task**: connect to every address `hss.<namespace>` resolves to, and
resolve again periodically to follow tasks that come and go (an acceptance
criterion of the S-CSCF, #14, which also handles the RTR and PPR it receives;
the I-CSCF, #15, needs no pushes). An API request served by a task no S-CSCF is
connected to stores its change but cannot push it, which is counted as
`push.<rtr|ppr>.no_peer`, apart from `failed` (a peer did not answer) and
`rejected` (it answered with an error).

A PPA failure is acted on as §6.2.2.1 asks of an HSS without restoration:
`DIAMETER_ERROR_USER_UNKNOWN` (the S-CSCF lost the user) sets every identity of
the subscription to not registered (`push.ppr.user_unknown`);
`DIAMETER_ERROR_NOT_SUPPORTED_USER_DATA` or `TOO_MUCH_DATA` sets them to not
registered and sends RTR `SERVER_CHANGE`, so the user registers again
(`push.ppr.data_refused`).

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
| 10 | INVITE with an OMA CPM ICSI, an RCS IARI or the OMA SIMPLE IM tag `+g.oma.sip-im` (rcsjta's chat) in `Accept-Contact`/`Contact`, or a CPM ICSI in `P-Preferred-Service`/`P-Asserted-Service` | SESSION_TERMINATED |
| 20 | MESSAGE | SESSION_TERMINATED |
| 30 | OPTIONS with the same RCS service tags (capability discovery) | SESSION_CONTINUED |
| 40 | REGISTER (third-party registration) | SESSION_CONTINUED |

Every trigger also requires that the request has no `P-Served-User`. `rcs-as`
sends requests of its own: stored messages it delivers later, notifications the
network generates, and the terminating legs of chat sessions. It sends them to
`scscf` as terminating requests with `P-Served-User: <user>;sescase=term`, so
that they go on to the user's contacts. Without that check they would come back
to `rcs-as`, which would store them and send them again, in a loop. A client
cannot set the header: `pcscf` removes it from every client request ([ADR
0007](adr/0007-internal-transport.md) §7), and only platform services reach the
core SIP ports.

Chat and messaging fail rather than bypass `rcs-as`, which anchors MSRP and keeps
IMDN and store-and-forward; capability discovery and registration continue while it
is down. Each service condition is its own trigger, with one header name and one
literal pattern (`3gpp-service\.ims\.icsi\.oma\.cpm\.`,
`3gpp-application\.ims\.iari\.rcs\.` or `\+g\.oma\.sip-im`), the ICSI and IARI
text after `urn-7`, which is the same in percent-encoded feature tags and in the
plain service headers, or the OMA SIMPLE IM tag, with which rcsjta asks for a chat.
The profile is created at start if missing; an operator's changes to it are kept.
So a profile created before the `P-Served-User` check or the OMA SIMPLE IM tag
(#137) keeps its old triggers until an operator updates it through the API. No
deployment had one.

### Writing iFC

Every trigger that sends requests to `rcs-as` needs the condition that the
request has no `P-Served-User`, in a group of its own, as in the default
profile. Without it, the requests `rcs-as` sends for its users come back to it:
`rcs-as` refuses them with 482 and counts `sip.loop`, and those users' messages
are not delivered.

Criteria are JSON in the provisioning API (field names follow the TS 29.228 XML
schema). Patterns are POSIX extended regular expressions (TS 29.228 Annex F). A
header *name* pattern must match the whole header name, in any case (`Contact`
selects `Contact`, not `Accept-Contact`); every other pattern matches anywhere in
its field, so anchor it with `^`/`$` to match a whole value. Request-URI patterns
ignore case.

A few constructs mean one thing to POSIX and another to the Go engine the S-CSCF
runs, so the API refuses them with 400, naming the construct:

- a backslash inside brackets (`[\.]com`; write `[.]com` or `\.com`);
- a backslash before anything but an ERE special character, one of
  `. [ ] ( ) * + ? { } | ^ $ \`: letters and digits (`\d`, `\w`, `\b`, `\x41`,
  `\n`, `\1`), which some engines read as classes or escapes, `\<`, `\>`, `` \` ``
  and `\'`, which glibc and musl read as word or value boundaries, and other
  punctuation (`\-`, `\@`, `\/`, `\:`). Write `[[:digit:]]`, `[[:space:]]` and
  so on, or the character itself;
- collating symbols and equivalence classes (`[[.a.]]`, `[[=a=]]`), and
  `[[:^alpha:]]`, which is not a class name (write `[^[:alpha:]]`);
- an interval without a lower bound (`a{,3}`; write `a{0,3}`, or `a\{,3\}` for
  the text).

A backslash before a special character, such as `\.` or `\+`, is a literal and
is fine. Named classes such as `[[:alpha:]]` hold ASCII characters only, as in
the POSIX locale: `[[:alpha:]]` does not match `ä`, and `[^[:upper:]]` does.

A pattern is at most 4 KiB (`MaxPatternBytes`); a longer one is refused with
400 naming the limit. The limit bounds the time to parse a pattern, which for
some inputs grows with the square of their length. A profile's patterns
together may cost at most `MaxSetCompileCost` (1 000 000 units) to compile,
counted in bytes and instructions processed rather than timed. A profile of
64 ordinary RCS criteria uses about 92% of it and the default RCS profile
about 2%; ten 4 KiB patterns of the costliest shape exceed it. On a 32-core
development host at load 140 to 230, a profile at the limit took 39 to 48 ms
of CPU (33 to 70 ms wall) to compile when made of 4 KiB patterns, and about
2 to 2.3 times as long when made of hundreds of short ones; other hosts and
loads differ, and the HSS compiles a profile once on each write. A profile
over it is refused with 400 naming the limit.

The API checks patterns when a profile is written. A profile stored before
this rule keeps working as it is, and needs these constructs removed when it
is next changed.

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

- `/healthz` and `/readyz` are on `RCS_ADMIN_ADDR`. Both answer 503 "starting"
  until the store, the keyring and the listeners are up (`/healthz` waits too,
  #58); then `/healthz` passes for as long as the process runs and `/readyz`
  checks both tables. No load balancer sends to `hss`, so nothing acts on
  `/readyz`: a deployment relies on the container health check (`-healthcheck`,
  which probes `/healthz`) and ECS's deployment circuit breaker, which sees a
  task that exits at `HSS_START_TIMEOUT`. ECS ignores failed checks during the
  health check's `startPeriod` and then marks a task unhealthy after `retries`
  failures `interval` apart, so `startPeriod + interval × retries` must exceed
  `HSS_START_TIMEOUT`, or ECS replaces a task that is still starting. The
  default 60 s start-up fits `startPeriod` 60, `interval` 15, `retries` 3
  (105 s). `startPeriod` is at most 300 s, so `HSS_START_TIMEOUT` is refused
  above 240 s.
- The API logs one `audit: provisioning request` line per request: operation,
  caller, token slot (`current` or `next`), status and the masked IMPI.
- Metrics: `cx.<command>` (latency), `cx.<command>.<result>` (`e` before an
  experimental result), `cx.<command>.error`, `lock.busy`, `store.conflict`,
  `aka.resync`, `aka.auts_invalid`, `aka.sqn_exhausted`, `profile.missing`,
  `profile.costly`, `userdata.too_large`, `keyring.created`,
  `push.rtr|ppr.sent|rejected|failed|no_peer`, `push.ppr.user_unknown`,
  `push.ppr.data_refused`, `push.fanout.subscriptions`, `api.<operation>` (latency),
  `api.<operation>.<status>`, `api.rate_limited`, `api.store_failure`,
  `api.data_error`.
- Alarm candidates (Phase 7): `cx.*.error`, `lock.busy`, `api.store_failure`,
  `api.data_error`, `push.*.no_peer`, `push.*.failed`, `aka.sqn_exhausted`,
  `profile.missing`, `keyring.created`, and `cx.mar`/`cx.sar` latency
  (Maximum, or the average `cx.sar.sum / cx.sar.count`) against
  `HSS_CX_TIMEOUT` (docs/architecture.md §8 has the rules for EMF alarms).
- A shared profile's fan-out that a shutdown cuts short logs `profile push cut
  short by shutdown` with how many subscriptions it reached; apply the profile
  again to reach the rest before they register again.
- A subscription whose profile was deleted (the in-use check reads an eventually
  consistent index) is answered `DIAMETER_UNABLE_TO_COMPLY` and counted as
  `profile.missing` until it is given a profile.
- API answers: a store failure (outage, throttling, timeout) or a busy subscriber
  is 503 with `Retry-After`, so callers retry; stored data that cannot be used (a
  record that does not decode, a secret that does not open) is 500 without
  `Retry-After` and counted as `api.data_error`, since retrying will not help.
- `make test-integration` runs the DynamoDB store and two HSS tasks issuing
  AKA vectors at once against DynamoDB Local.

## Sizing

DynamoDB units per Cx command for a subscription item of 1 to 2 KB (strongly
consistent reads: one read unit per 4 KB; writes: one unit per KB):

| Command | Reads | Writes |
|---|---|---|
| UAR | 1 (+1 profile when it returns capabilities) | 0 |
| MAR | 1 | 1 item (1–2 units) |
| SAR | 2 (subscription, profile) | 1 item when the state changes, none for a re-registration that changes nothing |
| LIR | 2 (IMPU index, subscription; +1 profile when not registered) | 0 |

An AKA registration (UAR, MAR, UAR, SAR) costs about 5 read and 2–4 write
units, a re-registration about 4 read and 1–2 write units. At ap-northeast-2
on-demand prices (read $0.1355 and write $0.68 per million units, 2026-10), a
million registrations cost about $3 in DynamoDB and a million re-registrations
about $1.5; a million subscribers re-registering every hour, about $1.1k a month,
and up to six times that for clients on 600 s registrations (ADR 0003). Metrics
cost almost nothing in log ingestion: the runtime aggregates them and writes one
EMF line per metric a minute, at most a few kilobytes each, however many Cx
requests a task serves. KMS sees only one
`Decrypt` per task start.

On a task, the profile work of a SAR, reading the stored profile and writing
User-Data, takes about 0.4 ms of one core for the default profile
(`BenchmarkSARProfileWork`), most of it writing the XML.

iFC cost at the S-CSCF (`internal/ifc`, default budget 1 000 000 units): a literal
pattern costs 4 units a byte of each value it is tried on, so one condition on a
2 KB `Contact` is about 8 000 units, and some 60 such conditions reach half the
budget; a header name that is a plain token costs 1 unit a byte of each header
name; any other pattern costs its compiled size times the length of every value.
The default profile needs about 370 units for the reference requests, because
each trigger stops at its method.

Not in this release: the Sh interface, SLF, geo-redundancy, IMS restoration.
