# S-CSCF shared state

`scscf` instances share their state in DynamoDB so that any instance serves any
user (ADR 0005). The code is `internal/scscf/state` (stores and sweeps) and
`internal/scscf/state/dynamostore` (DynamoDB); the package documentation has
the exact attributes. This page is for whoever creates the tables and runs
them.

## Tables

| Table | Key | Indexes | Holds |
|---|---|---|---|
| `registrations` | `pk` (S): canonical IMPU, or `profile#<IMPI>#<default IMPU>` | `impi-index` (`impi`), `expiry-index` (`shard`, `expires` N), both keys only | the bindings of each IMPU, and the User-Data of each implicit registration set |
| `auth-challenges` | `pk` (S): IMPI, `sk` (S): nonce | none; TTL on `expires` | the vector or Digest state between the two REGISTERs, sealed |
| `reg-subscriptions` | `pk` (S): subscription ID | `impu-index` (`impu`), `expiry-index` (`shard`, `expires` N), both keys only | reg event subscriptions and their NOTIFY counters |

Data at rest: registration items hold Contact URIs (device addresses),
`+sip.instance` (for 3GPP devices an IMEI URN), Path and the IMSSubscription,
and the keys are IMPIs, which usually embed the IMSI. The infrastructure should
therefore encrypt all three tables with a customer-managed KMS key, keep
point-in-time recovery with a stated retention, and grant the tables to the
`scscf` task role only, with no `dynamodb:Scan` for anyone else. Challenges are
additionally sealed (below).

## Rules for scscf

- **A REGISTER during a deregistration.** When the last contact of an IMPU
  expires, a sweep claims the registration for a lease (`Deregistering`, one
  minute) while it sends SAR TIMEOUT_DEREGISTRATION and the reg event NOTIFY,
  and deletes it afterwards. A REGISTER that finds a registration without
  contacts, leased or not, is handled as an initial registration: SAR
  REGISTRATION, and a save conditional on the version read, which makes the
  sweep's later delete fail harmlessly (#14).
- **One profile per implicit registration set.** The HSS sends User-Data per
  set: an SAA for the set of the IMPU in the request, a PPR for one set at a
  time. A profile is therefore keyed by the IMPI and the set's default IMPU
  (`state.ProfileKey`), a PPR saves only its own set, and each registration
  records its set's default IMPU (`DefaultIMPU`), which a terminating request
  uses to find the profile.
- **Profiles are ordered by arrival, per set.** `SaveProfile` takes the time
  the SAA or PPR arrived and keeps the later one, so an SAA answered slowly
  cannot undo the PPR that followed it; a refused save (`ErrConflict`) is not
  an error to report. A profile is deleted when the HSS no longer assigns its
  set to this S-CSCF, never by a sweep.
- **A permanent SAR failure ends the deregistration.** The sweep's handler
  returns an error only for failures that may pass (the HSS unreachable, a
  busy answer); for a permanent one such as `DIAMETER_ERROR_USER_UNKNOWN`
  (5001) it returns nil, or the SAR would be retried every minute.

## HSS discovery

`scscf` and `icscf` find the HSS tasks with Cloud Map (`cxclient`,
`CloudMapDiscovery`), so both task roles need
`servicediscovery:DiscoverInstances` on the HSS namespace. Without it no HSS
peer is found and every Cx request fails.

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

A re-registration is one strongly consistent read and one put of the IMPU's
registration item (a few KB), plus two writes to `expiry-index`; the profile is
written only on SAR and PPR. Every terminating request reads the IMPU's
registration and its set's profile, two strongly consistent reads: about 1
read request unit for the registration and 1 per 4 KB of profile (2 for a
typical 5 KB IMSSubscription, 32 for the 128 KiB maximum), so 3 RRU per
terminating request, $0.4 per million at the same prices. With 1 M users of
two IMPUs re-registering every
600 s that is about 8.6 G saves and 30 G write request units a month, some
$20k at ap-northeast-2 on-demand prices (October 2026); 3600 s registrations
cost a sixth of that. Authentication adds a put and a conditional delete per
challenge. Sweeps read each expiring item once.

`expiry-index` is spread over 16 shards, which carry about 8000 saves per
second, some 4.8 M IMPUs at 600 s re-registrations. The shard of an item is
fixed when it is written, so a larger deployment raises the shard count before
its first item.
