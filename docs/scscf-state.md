# S-CSCF shared state

`scscf` instances share their state in DynamoDB so that any instance serves any
user (ADR 0005). The code is `internal/scscf/state` (stores and sweeps) and
`internal/scscf/state/dynamostore` (DynamoDB); the package documentation has
the exact attributes. This page is for whoever creates the tables and runs
them.

## Tables

| Table | Key | Indexes | Holds |
|---|---|---|---|
| `registrations` | `pk` (S): `set#<IMPI>#<default IMPU>`, a canonical IMPU, or `profile#<IMPI>#<default IMPU>` | `impi-index` (`impi`), `expiry-index` (`shard`, `expires` N), both keys only, of sets only; TTL on `ttl` | per implicit registration set its bindings (or an unregistered user's record) and its User-Data, and per IMPU the set it belongs to |
| `auth-challenges` | `pk` (S): IMPI, `sk` (S): nonce, or `#count#<kind>#<window>` | none; TTL on `expires` | the vector or Digest state between the two REGISTERs, sealed; the per-IMPI counts of challenges and resynchronisations |
| `reg-subscriptions` | `pk` (S): subscription ID | `impu-index` (`impu`), `expiry-index` (`shard`, `expires` N), both keys only | reg event subscriptions and their NOTIFY counters |

Data at rest: registration items hold Contact URIs (device addresses),
`+sip.instance` (for 3GPP devices an IMEI URN), Path and the IMSSubscription,
and the keys are IMPIs, which usually embed the IMSI. The infrastructure should
therefore encrypt all three tables with a customer-managed KMS key, keep
point-in-time recovery with a stated retention, and grant the tables to the
`scscf` task role only, with no `dynamodb:Scan` for anyone else. Challenges are
additionally sealed (below).

## Rules for scscf

- **A REGISTER during a deregistration.** When the last contact of a set
  expires, a sweep claims the set's record for a lease (`Deregistering`, one
  minute) while it sends SAR TIMEOUT_DEREGISTRATION and the reg event NOTIFY,
  and deletes it afterwards. A REGISTER that finds a registration without
  contacts, leased or not, is handled as an initial registration: SAR
  REGISTRATION, and a save conditional on the version read, which makes the
  sweep's later delete fail harmlessly (#14). A record it takes over from a
  lease gets a new incarnation, which both backends require: the sweep
  deletes only the identity items naming the incarnation it claimed, so the
  ones the REGISTER points at the record stay.
- **Unregistered users.** A terminating request to an IMPU without a
  registration sends SAR UNREGISTERED_USER, then stores a record without
  contacts whose `Unregistered` is when that state ends (now plus
  `SCSCF_UNREGISTERED_TTL`, default one hour) and the set's profile, which
  later requests reuse. A sweep then claims the record like an expired
  registration and sends SAR TIMEOUT_DEREGISTRATION; a REGISTER before that
  turns it into a registration. PPR and RTR apply to it as to a registration.
- **One profile per implicit registration set.** The HSS sends User-Data per
  set: an SAA for the set of the IMPU in the request, a PPR for one set at a
  time. A set is therefore keyed by the IMPI and its default IMPU
  (`state.SetKey`), which names both its registration and its profile, and a
  PPR saves only its own set.
- **One record per set.** The bindings that every identity of a set shares
  are one item, so a REGISTER, a deregistration or a sweep is one
  conditional save, whichever identity it came for; each IMPU's item only
  names its set and the set's incarnation (`state.Identity`), written when
  the S-CSCF is assigned the set or the set changes, before the record that
  names them: the record's save is the commit point. An item naming an
  incarnation that was never saved still finds its set's record if the
  record lists the IMPU, is live and is not being deregistered: a
  terminating request uses it and repairs the item in the background
  (internal/scscf/routing), so that an interrupted REGISTER costs no call;
  with no such record the item is as good as none. A re-registration only
  keeps the items, or repairs one. A terminating request reads the IMPU's
  item and the set. An IMPU names one set: a public identity shared by several
  IMPIs (TS 23.228 §4.3.3.4) is out of scope, and the second IMPI to
  register it takes the IMPU's item.
- **Identities go before their set.** Every deregistration deletes the IMPU
  items and the profile first and the set's record last, while the record
  still holds the deregistration's lease: an instance that stops in between
  leaves the record, and the next sweep does the rest. As a safety net for an
  item no path reaches, each carries `KeepUntil` in `ttl`, kept like the
  profile's (below), and is not found from then on.
- **Profiles are ordered by arrival, per set.** `SaveProfile` takes the time
  the SAA or PPR arrived and keeps the later one, so an SAA answered slowly
  cannot undo the PPR that followed it; a refused save (`ErrConflict`) is not
  an error to report. A profile is deleted when the HSS no longer assigns its
  set to this S-CSCF, never by a sweep.
- **A profile outlives its set by a day at most.** Every deregistration path
  (user, sweep, RTR, administrative) deletes the profile; a user's own
  deregistration deletes only the one it read (`DeleteProfileIf`), so a
  registration that another instance saved meanwhile keeps its profile. As a
  safety net for one that fails to, a profile carries `KeepUntil`, stored as
  the TTL attribute `ttl`: the last contact expiry of the set, or the end of an
  unregistered user's state, plus one day (`state.ProfileGrace`). A save never
  brings it closer, not even one refused because a later profile is stored.
  A registration extends it only when the new expiry is 12 hours or more past
  what `KeepUntil` covers (`KeepDue`, `KeepProfile`): about twice a day for
  hourly re-registrations, and at every one for registrations longer than half
  a day, so the profile never runs out while a binding lives. From
  `KeepUntil` on the profile is not found, whether or not DynamoDB has removed
  it yet. Set records have no
  `ttl`: only a sweep, which sends the SAR, may remove one, so the
  infrastructure must enable TTL on `ttl`, never on `expires`.
- **Challenges are limited per IMPI and P-CSCF flow.** Before each challenge
  the registrar counts it for the flow in the REGISTER's Path and the
  current window, and over a limit answers 500 with Retry-After without
  asking the HSS. A flow a live binding of the user came over is the
  registered UE's while it stays on it: it has a budget of its own (default
  6 a minute, `RegisteredFlowChallengeLimit`) and nothing else; a UE that
  reconnects comes over a new flow. Any other flow has a
  small one (3, `FlowChallengeLimit`) and shares the IMPI's (10,
  `ChallengeLimit`, per `ChallengeWindow`). The limits count challenges, not
  MARs: a Digest subscriber's costs two MARs when the AKA one gets 5006. A
  challenge allows one resynchronisation (#196), and an IMPI three per
  challenge lifetime (`ResyncLimit`), the registered UE's flow apart; one the
  MAR never reaches the HSS gives its slot back, and its challenge counts
  as such a challenge does; a busy answer or a timeout keeps them. An AUTS
  over the flow its challenge was issued to counts in the shared budget
  only. Windows are fixed, so up to twice
  a budget passes across an edge, and an instance whose clock is off counts
  into its own idea of the window. Every instance counts into the same items,
  beside the IMPI's challenges, which the table's TTL removes; an instance
  that has seen a count over its limit refuses the rest of that window
  without writing. No nonce starts with `#`, so no client can take a count as
  a challenge (#201).
- **A permanent SAR failure ends the deregistration.** The sweep's handler
  returns an error only for failures that may pass (the HSS unreachable, a
  busy answer); for a permanent one such as `DIAMETER_ERROR_USER_UNKNOWN`
  (5001) it returns nil, or the SAR would be retried every minute.

## Metrics and alarms

`registrar.challenge_limited` and `registrar.resync_limited` count the
REGISTERs refused over a budget; neither carries an identifier. Alarm on
`registrar.challenge_limited` (Sum over 5 minutes above a few dozen, or any
sustained rate): it is how a flood against one subscriber shows, and a
first registration of that subscriber, or a registration over a new
connection, is held back while it lasts (T12). While it is raised, postpone
P-CSCF deploys and drains: each moves its clients to new connections.
`registrar.internal_errors` with a store that cannot count says the counts
are failing closed: every REGISTER that needs a challenge gets 500.

## HSS discovery

`scscf` and `icscf` find the HSS tasks with Cloud Map (`cxclient`,
`CloudMapDiscovery`), so both task roles need
`servicediscovery:DiscoverInstances` with both the namespace and its `hss`
service as resources, since the call names both. Without it no HSS peer is
found and every Cx request fails.

## Challenge keys

Challenges hold XRES, CK, IK and HA1. They are sealed with AES-256-GCM under
keys every `scscf` instance shares (Secrets Manager), each with an ID; one is
the seal key. Rotate at least quarterly, in three steps, each rolled out to
every instance before the next:

1. add the new key to the key set, still sealing with the old one;
2. make the new key the seal key;
3. after `state.MaxChallengeLifetime` (10 minutes), remove the old key.

An instance one step behind opens everything the others seal, and rolling one
step back works too. A challenge that does not open (a step skipped) costs the
client one more 401, not a failed registration.

## Capacity and cost

A re-registration is three strongly consistent reads, of the IMPU's item (under
1 KB), of its set's registration (a few KB) and of the set's profile (which
tells whether `KeepUntil` is due), and one put of the set's registration, plus
two writes to `expiry-index`, whatever the size of the set; the profile is
written only on SAR and PPR, plus about two updates of its `ttl` a day, and the
IMPU items only when the S-CSCF is assigned the set, plus as many updates of
their `ttl`. The reads are about 1 + 1
+ 2 RRU for a typical 5 KB IMSSubscription (1 + 1 + 32 for the 128 KiB
maximum). Every terminating request reads the IMPU's item, the set's
registration and its profile: about 4 RRU, $0.55 per million at the prices
below. With 1 M users of two IMPUs re-registering every 600 s that is about 4.3
G saves a month, some 15 G write request units and $10k at ap-northeast-2
on-demand prices (October 2026), half what one item per IMPU cost, plus some 17
G RRU and $2.2k for the reads; 3600 s registrations cost a sixth of that.
Authentication adds a put and a conditional delete per challenge, and one
update of the IMPI's count before each MAR. Sweeps read each expiring set once.

`expiry-index` is spread over 16 shards, which carry about 8000 saves per
second, some 4.8 M IMPUs at 600 s re-registrations. The shard of an item is
fixed when it is written, so a larger deployment raises the shard count before
its first item.
