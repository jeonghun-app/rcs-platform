# Runbook

What to do when the platform pages you, and the procedures that change a
running stack. Every alarm of `infra/platform.yaml` has a section here under
its own name. `make infra-lint` checks that each alarm links its section and
that the section exists. The deployment itself is in
[aws-deployment.md](aws-deployment.md).

This is a skeleton. The sections say what each alarm means, where to look
first and what usually helps. They come from the service documents, not
from incidents yet. After an incident, add what you learned to the section.

## Conventions

- An alarm `<stack>-<Name>` is in the section `<Name>`. Alarms and the
  security, service and cost notifications go to the stack's alarm topic
  (the `AlarmTopic` output). The `DashboardUrl` output opens the stack's
  dashboard: each service's traffic, errors, latency and saturation beside
  the load balancers and tables, the first place to look.
- Service metrics are CloudWatch EMF in the namespace `RCS/<stack>`, with
  `Service` as the only dimension. Metric names are those of the service
  documents: [ft-server](ft-server.md#metrics-and-logs), and
  `docs/msrp-relay.md` (Metrics) and `docs/hss.md` (Operations). acs writes
  to `RCS/<stack>/acs`.
- Logs are JSON lines in `/rcs/<stack>/<service>`. No log or metric holds an
  IMSI, MSISDN, token, key or message body. Do not paste values out of the
  tables or secrets into tickets or chat.
- The commands below set `STACK` and `REGION` first. The ECS cluster is
  named after the stack, and its services are `hss`, `ft-server`,
  `msrp-relay` and `acs`.
- **Commands that change something are marked "changes the stack".** Run
  them only with the approval [aws-deployment.md](aws-deployment.md#approval)
  asks for. Configuration changes go through `scripts/deploy.sh` and its
  config file, never the console. CloudFormation does not undo a console
  edit: a deployment whose template and parameters did not change does
  nothing. To find and revert one, see
  [Undoing a change made outside CloudFormation](#undoing-a-change-made-outside-cloudformation).

```sh
STACK=rcs-platform REGION=ap-northeast-2

# The service's state and its last events (deployments, failed tasks, health).
aws ecs describe-services --region "$REGION" --cluster "$STACK" --services ft-server \
  --query 'services[0].{running:runningCount,desired:desiredCount,deployments:deployments[].rolloutState,events:events[:5].message}'

# Error and warning lines of the last 30 minutes.
aws logs tail "/rcs/$STACK/ft-server" --region "$REGION" --since 30m \
  --filter-pattern '{ $.level = "ERROR" || $.level = "WARN" }'

# One metric, summed per 5 minutes over the last 3 hours.
aws cloudwatch get-metric-statistics --region "$REGION" --namespace "RCS/$STACK" \
  --metric-name auth.backend_error --dimensions Name=Service,Value=ft-server \
  --statistics Sum --period 300 \
  --start-time "$(date -u -d '-3 hours' +%FT%TZ 2>/dev/null || date -u -v-3H +%FT%TZ)" \
  --end-time "$(date -u +%FT%TZ)"     # GNU date, or BSD date on macOS
```

Scaling out means raising the service's `...DesiredCount` in the config file
and deploying it **from the commit the stack runs** (changes the stack):
check out the stack's `TemplateRevision` output first, or the deployment
ships whatever the checkout's template and image are. deploy.sh shows the
change set and asks before it runs. In prod each rolling step adds one task
first (ADR 0003), so a deployment never lowers capacity.

## ft-server

### FtAuthBackendError

**Symptom.** Credential lookups to the HSS fail (`auth.backend_error`), and
uploads get `503`.

**Check.** Is `hss` running and ready (`describe-services --services hss`)?
Do the hss alarms fire too (`HssApiStoreFailure`, `HssLockBusy`)? Does the
ft-server log show timeouts (`FT_HSS_TIMEOUT`, 2 s) or `401`/`403` from the
HSS? Those point at a token mismatch, for example a
[token rotation](#token-rotation) done out of order.

**Act.** Fix the HSS first. If the tokens disagree, finish the rotation, or
restore the previous value into the current secret, then restart ft-server.

### FtBadCredentialRecord

**Symptom.** The HSS returned an FT credential record ft-server cannot use.
That one subscriber cannot upload.

**Check.** The ft-server warning carries the masked owner. Is the
subscriber's FT credential in the HSS complete (issued by acs, realm
`FtRealm`)?

**Act.** Issue the subscriber's FT credential again through acs or the
provisioning API. Several subscribers at once point at the provisioning
path. Look at acs and at `HssApiDataError`.

### FtLookupBusy

**Symptom.** Credential lookups pile up for 15 minutes (`auth.lookup_busy`):
each task already runs `FT_MAX_CONCURRENT_LOOKUPS` (16).

**Check.** Is the HSS slow (`HssLockBusy`, hss latency `api.*`)? Or is there
a flood of unauthenticated requests: WAF `BlockedRequests` on the ALB's web
ACL, request counts on the ft-server target group?

**Act.** Slow HSS: as [FtAuthBackendError](#ftauthbackenderror). A flood
from a few addresses: see [WafRateLimited](#wafratelimited) before lowering
the limit, since one carrier-grade NAT address carries thousands of
handsets. Scale ft-server only when the traffic is real.

### FtStorageErrors

**Symptom.** S3 or DynamoDB calls fail under uploads or downloads
(`upload.failed.storage`, `download.failed.storage`).

**Check.** Is `FilesThrottled` firing too? Is there an S3 or DynamoDB event
on the AWS Health Dashboard? Does the log show `AccessDenied`? That means the
task role, the bucket policy or, with `FileEncryption=aws:kms`, the key.

**Act.** Throttling: see [FilesThrottled](#filesthrottled). Permissions:
compare the task role with `docs/ft-server.md` (IAM), and deploy the fix.
Clients resume interrupted uploads by themselves.

### FtMissingObject

**Symptom.** A file whose link is still valid has no object in S3
(`download.failed.missing_object`).

**Check.** The bucket's lifecycle rule must be 2 × `FtValidityDays` + 1
days. Both come from the one parameter, so a mismatch means someone edited
the bucket by hand. Look at CloudTrail for `PutBucketLifecycleConfiguration`
and `DeleteObject` outside ft-server's role.

**Act.** Put the template's lifecycle back by hand (see [Undoing a change
made outside CloudFormation](#undoing-a-change-made-outside-cloudformation)):
a deployment alone does not. Deleted objects come back only if they still
exist elsewhere: the bucket has no versioning.

### FtUploadsBusy

**Symptom.** The tasks' upload slots (`FT_MAX_CONCURRENT_UPLOADS`, 32) have
been full for 15 minutes (`upload.failed.busy`). Clients get `503` with
`Retry-After`.

**Check.** Upload counts and bytes against the last days. Uploads are bound
by I/O, not CPU, so low CPU does not mean spare capacity.

**Act.** Raise `FtServerDesiredCount` and deploy. A larger
`FtServerTaskSize` allows more slots, but only with a template change of
`FT_MAX_CONCURRENT_UPLOADS` (memory: docs/ft-server.md, Memory).

### FtDownloadsBusy

**Symptom.** The tasks' download slots (`FT_MAX_CONCURRENT_DOWNLOADS`, 256)
have been full for 15 minutes (`download.failed.busy`).

**Check.** Download counts and the target group's request count. A spike
from few addresses is a client loop or abuse (WAF metrics).

**Act.** Raise `FtServerDesiredCount` and deploy. A flood: lower
`WafRateLimit`.

### FtLinksBusy

**Symptom.** One link (`download.failed.file_busy`, 64 per task) or one
uploader's links (`download.failed.uploader_busy`, 128 per task) hit their
limit for 15 minutes.

**Check.** A large group chat fetching an album is the usual cause: with one
task, 63 recipients × 3 photos already exceed 128. With two or more tasks
this should clear. If it persists with several tasks and no group traffic,
one subscriber's links are being hammered. Check the WAF before raising
limits.

**Act.** Run at least two tasks. Raise the per-file and per-uploader limits
(template change) only together, keeping file ≤ uploader < task
(docs/ft-server.md, Settings).

### FtSweepFailed

**Symptom.** The expiry sweeper fails (`sweep.failed`).

**Check.** The ft-server log at the sweep. Until the expiry index exists, a
table too large to scan within `FT_STORAGE_TIMEOUT` (1 minute) makes every
sweep fail. Also check `FilesThrottled`.

**Act.** Throttling: as [FilesThrottled](#filesthrottled). A large table: raise
`FT_STORAGE_TIMEOUT` (template change) until the index ships. Expired files
stay unservable either way, because downloads check the expiry; only the
clean-up waits.

### FtSweepStalled

**Symptom.** No sweep finished for two hours (`sweep.duration.count`), with
a sweep due every hour: the sweeper is stuck, or ft-server is not running.

**Check.** Is ft-server running? Does its log show sweeps starting without
ending?

**Act.** Restart ft-server (`aws ecs update-service --region "$REGION"
--cluster "$STACK" --service ft-server --force-new-deployment`, changes the
stack). If it stalls again, open an issue with the log.

### FtTooSlowRatio

**Symptom.** Over 5% of downloads (once 20 have been served in 5 minutes) are
cut off by the rate floor (`download.failed.too_slow`), for 15 minutes.

**Check.** Is `FtDownloadsBusy` firing too? Under pressure the 16 KiB/s
floor applies on purpose, to free slots. Without pressure, the 4 KiB/s
floor is too high for some client networks.

**Act.** Under pressure: add tasks. Without: lower `FT_MIN_DOWNLOAD_RATE`
(template change), keeping it below the pressure floor.

### FtServerTarget5xx

**Symptom.** Over 5% of ft-server's requests through the ALB (once there
were 20 in 5 minutes) were answered 5xx, in 2 of 3 periods.

**Check.** Which ft-server alarms fire with it? `503` from busy slots is
counted here too. Is a deployment in progress?

**Act.** Follow the alarm that fires with it. If it started with a
deployment that the circuit breaker did not stop, [roll back](#rollback).

### FtServerUnhealthyTargets

**Symptom.** A target in the ft-server target group has failed `/readyz`
for 3 minutes.

**Check.** The service events: tasks stopping (out of memory, failed
health check)? `/readyz` checks S3 and DynamoDB, so storage problems show
up here too.

**Act.** Out of memory: a larger `FtServerTaskSize`. A deployment: [roll
back](#rollback). Otherwise as [FtStorageErrors](#ftstorageerrors).

### FtServerNoHealthyTargets

**Symptom.** The ft-server target group has had no healthy target for 2 of 3
minutes: file transfer is down for every client.

**Check.** The service events (`describe-services`): tasks failing to start
(image, secrets, `/readyz` never ready)? `ServiceImpaired` usually arrives
with it.

**Act.** A deployment: [roll back](#rollback). Tasks that cannot start: fix
what the events name (often secrets or an image that ECR no longer has),
then force a new deployment (changes the stack).

## msrp-relay

### RelayStoreErrors

**Symptom.** Calls to `msrp-bindings` fail or time out (`StoreErrors`). New
MSRP sessions are refused: the client sees a closed connection and sends a
new INVITE.

**Check.** `MsrpBindingsThrottled`, DynamoDB health, and `AccessDenied` in
the relay log (the task role).

**Act.** Throttling: as [MsrpBindingsThrottled](#msrpbindingsthrottled).
Bridges already running are not affected.

### RelayLookupPressure

**Symptom.** Binds were refused for overload (`Refused.BindOverload`, the
task's `RELAY_MAX_CONCURRENT_BINDS`) or for the per-source lookup budget
(`Refused.SourceLookupBudget`) for 15 minutes.

**Check.** Overload: are store calls slow (DynamoDB latency,
`MsrpBindingsThrottled`)? Budget: are refusals concentrated on one address?
That is usually one misbehaving client behind a shared carrier-grade NAT
address; `MsrpBindingsReadBudget` may fire too.

**Act.** Overload with healthy storage: raise `RelayDesiredCount`. One CGNAT
address with legitimate traffic: raise `RELAY_FAILED_LOOKUPS_PER_SOURCE`
(template change). A scan from one source: the harm stays with that
address. Keep the budget.

### RelayCoreUnreachable

**Symptom.** The relay could not reach `rcs-as` for 15 minutes
(`Refused.CoreUnreachable`). Sessions answer `481`.

**Check.** Is `rcs-as` running? Do `Core.Closed.*` counts rise as well?
Security group changes (`SecurityGroupChanges`) between the relay and
`rcs-as` on port 2855?

**Act.** Restore `rcs-as`. A security group rule removed by hand: put it back
as in [Undoing a change made outside CloudFormation](#undoing-a-change-made-outside-cloudformation).

### RelayAlreadyClaimedRatio

**Symptom.** Over 5% of claims were refused because another connection had
claimed the session (`Refused.AlreadyClaimed` / `BindingsClaimed`) for 15
minutes.

**Check.** During a deployment or right after a relay task stopped, this is
expected: clients come back on new connections. Outside those windows, a
sustained ratio means session ids are reused or leaked.

**Act.** Outside deployments, treat it as a security event: collect the
binding ids from the log (never the URIs) and escalate to security. See the
threat model, T3.

### RelayUnhealthyTargets

**Symptom.** A relay target behind the NLB has failed its TCP health check
for 3 minutes.

**Check.** Service events, and whether the task is at
`RELAY_MAX_CONNECTIONS`. The NLB checks the MSRP port over TCP, because AWS
sends a PROXY header on health checks too and the admin port cannot read
one yet (#230). A TCP check passes a task that accepts connections but is
not ready (its store unreachable, say), so `RelayStoreErrors` is what shows
that case.

**Act.** Out of memory or connections: a larger `RelayTaskSize`, with
`RelayMaxConnections` to match, or more tasks. A deployment: [roll
back](#rollback).

### RelayConnectionsNearLimit

**Symptom.** A relay task has held over 80% of `RelayMaxConnections` client
connections for 15 minutes. At the limit, new connections are closed at
once.

**Check.** `ClientConnections` (Maximum) per task against the last days.
Many connections from few sources point at one client opening connections
in a loop (`Refused.SourceLimit`).

**Act.** Raise `RelayDesiredCount`, or a larger `RelayTaskSize` with a
higher `RelayMaxConnections`, and deploy.

### MsrpBindingsReadBudget

**Symptom.** Reads on `msrp-bindings` exceeded `MsrpReadBudget` units a
second for 15 minutes. Each lookup of an unknown session is one strongly
consistent read.

**Check.** Is `RelayLookupPressure` firing? Do `Refused.UnknownSession` or
`LookupBudgetUntracked` rise? A scan from many sources defeats the
per-source budget.

**Act.** A scan from a few sources: deny them in the public subnets' network
ACL, see [Blocking a source](#blocking-a-source) (the WAF sits only on the
ALB, and security groups cannot deny). Legitimate growth: raise the budget
in the config and deploy.

### RelayNoHealthyTargets

**Symptom.** The relay target group behind the NLB has had no healthy target
for 2 of 3 minutes: no client can start an MSRP session (chat and file
transfer by MSRP).

**Check.** As [FtServerNoHealthyTargets](#ftservernohealthytargets), for
`msrp-relay`.

**Act.** As [FtServerNoHealthyTargets](#ftservernohealthytargets).

## pcscf

pcscf is not deployed yet. Its alarms exist once `PcscfEnabled` is `true`.

### PcscfQueueUse

**Symptom.** pcscf's queued output toward clients has been over 75% of its
256 MiB budget (`QueuedBytes`, Maximum) for 15 minutes. Clients that read
slowly or not at all hold it.

**Check.** Does `PcscfBudgetSheds` fire too? Are many connections from one
network slow (a mobile network in trouble), or is it a few clients that
stopped reading?

**Act.** A few stalled clients: the transport sheds them by itself when the
budget runs out. Broad slowness: add pcscf tasks, which spreads the
connections.

### PcscfBudgetSheds

**Symptom.** pcscf closed stalled connections to keep its output queues
within budget (`BudgetSheds`). Those clients reconnect and register again.

**Check.** As [PcscfQueueUse](#pcscfqueueuse). A few sheds under load are
the budget doing its job; many mean the tasks are short of memory for the
traffic.

**Act.** Add pcscf tasks. Do not raise the budget beyond what the task's
memory holds.

### PcscfTransactionsRejected

**Symptom.** pcscf answered requests 503 because its server-transaction cap
(`MaxServerTransactions`) was full (`ServerTransactionsRejected` in 2 of 3
minutes).

**Check.** A request flood (many transactions from few sources, the NLB's
new flows), or a slow transaction user holding transactions open (latency
toward the core, `HssCxLatency`)?

**Act.** Scale out pcscf. If tasks have memory to spare, raise
`MaxServerTransactions`. A flood from few sources: [Blocking a
source](#blocking-a-source).

### PcscfTransactionBytes

**Symptom.** pcscf's live server transactions held over 80% of
`MaxServerTransactionBytes` (256 MiB by default) in 2 of 3 minutes
(`ServerTransactionBytes`, Maximum). At the cap, requests get 503.

**Check.** As [PcscfTransactionsRejected](#pcscftransactionsrejected); large
requests (big SDP or bodies) raise bytes faster than counts.

**Act.** As [PcscfTransactionsRejected](#pcscftransactionsrejected), or raise
`MaxServerTransactionBytes` with the task's memory.

## hss

### HssCxErrors

**Symptom.** Cx requests (UAR, MAR, SAR, LIR) were answered
`DIAMETER_UNABLE_TO_COMPLY` because the store or the keyring failed.
Registrations fail.

**Check.** `SubscribersThrottled`, DynamoDB health, the hss log for KMS or
keyring errors, and `HssApiDataError`.

**Act.** Throttling: as [SubscribersThrottled](#subscribersthrottled). A
keyring error at start: see [Keyring bootstrap](#keyring-bootstrap).

### HssLockBusy

**Symptom.** Requests timed out waiting for a subscriber's lock
(`lock.busy`) for 15 minutes.

**Check.** Do many requests for the same subscribers arrive at once (a
client in a registration loop)? Is DynamoDB slow, holding locks longer?

**Act.** A looping client: find it through the masked IMPI in the pcscf or
S-CSCF log and stop it at the edge. Slow storage: as
[SubscribersThrottled](#subscribersthrottled).

### HssApiStoreFailure

**Symptom.** The provisioning API failed on the store (`api.store_failure`).
Callers got `503` with `Retry-After` and retry.

**Check.** As [HssCxErrors](#hsscxerrors).

**Act.** As [HssCxErrors](#hsscxerrors). Callers retry by themselves.

### HssApiDataError

**Symptom.** Stored HSS data could not be used: a record that does not
decode, or a secret that does not open (`api.data_error`, `500`).

**Check.** The audit line carries the masked IMPI and the operation. Was
the record written by hand, or restored from another stack (sealed values
are bound to their record and their key)?

**Act.** Provision the subscription's secrets again. Many at once after a
restore: the keyring item and the records come from different points in
time. Restore them together.

### HssPushFailed

**Symptom.** RTR or PPR pushes found no S-CSCF peer (`push.*.no_peer`) or
failed (`push.*.failed`). Changes did not reach the S-CSCF.

**Check.** Are S-CSCF peers connected (hss log, `scscf` service)? Until the
CSCFs are deployed, every push has no peer.

**Act.** Restore the S-CSCF. Then apply the change again (a profile push
reaches registered users only when it runs).

### HssSqnExhausted

**Symptom.** A subscriber's AKA sequence numbers are exhausted. That
subscriber cannot authenticate.

**Check.** The masked IMPI in the hss log.

**Act.** Provision new K and OPc for the subscription (a new SIM profile).
Many at once points at a resynchronisation loop: escalate.

### HssProfileMissing

**Symptom.** Subscriptions refer to a deleted service profile
(`profile.missing`). Their registrations are refused.

**Check.** Which profile? The hss log names it.

**Act.** Create the profile again, or move the subscriptions to another one.

### HssKeyringCreated

**Symptom.** The HSS created a new data key (`keyring.created`). This is
expected exactly once, at the first start of a new stack.

**Check.** Is this the first deployment of the stack? If not, did someone
deploy with `HssKeyringBootstrap=true`?

**Act.** On a new stack, nothing. Otherwise follow [Keyring
bootstrap](#keyring-bootstrap): the secrets sealed under the old key no
longer open, and the flag must go back to `false`.

### HssCxLatency

**Symptom.** A MAR or SAR took over 2 s (Maximum) in 3 of 5 minutes, near the
3 s `HSS_CX_TIMEOUT`. The CSCFs time out first, and registrations fail while
`cx.*.error` stays at zero.

**Check.** DynamoDB latency and `SubscribersThrottled`; `HssLockBusy`; hss CPU
on the dashboard.

**Act.** Throttling: as [SubscribersThrottled](#subscribersthrottled). CPU:
add hss tasks (at most 7, see `HssDesiredCount`).

## icscf and scscf

These alarms exist once `IcscfEnabled` or `ScscfEnabled` is `true`.

### IcscfTransactionsRejected

**Symptom.** icscf answered requests 503 at its server-transaction cap.

**Check.** As [PcscfTransactionsRejected](#pcscftransactionsrejected): a
request flood or a slow transaction user (the HSS's `HssCxLatency`).

**Act.** Scale out icscf, or raise `MaxServerTransactions`.

### IcscfTransactionBytes

**Symptom.** icscf's live server transactions held over 80% of
`MaxServerTransactionBytes`.

**Check.** As [PcscfTransactionBytes](#pcscftransactionbytes).

**Act.** As [PcscfTransactionBytes](#pcscftransactionbytes), for icscf.

### ScscfTransactionsRejected

**Symptom.** scscf answered requests 503 at its server-transaction cap.

**Check.** As [PcscfTransactionsRejected](#pcscftransactionsrejected); slow
iFC evaluation or a slow HSS holds transactions too.

**Act.** Scale out scscf, or raise `MaxServerTransactions`.

### ScscfTransactionBytes

**Symptom.** scscf's live server transactions held over 80% of
`MaxServerTransactionBytes`.

**Check.** As [PcscfTransactionBytes](#pcscftransactionbytes).

**Act.** As [PcscfTransactionBytes](#pcscftransactionbytes), for scscf.

### ScscfIfcBudgetExceeded

**Symptom.** scscf stopped evaluating a profile's iFC because it exceeded its
work budget (`ifc.budget_exceeded` in 2 of 3 five-minute periods). Those
users' sessions do not reach their application servers as the profile says.

**Check.** An operator profile is too expensive: look for the iFC cost
warnings (`profile.costly`) in the HSS log, which name the profile.

**Act.** Simplify the profile's conditions (docs/hss.md, Writing iFC) and
apply it again. Do not raise the budget to fit one profile.

## acs

### AcsTarget5xx

**Symptom.** Over 5% of acs's requests through the ALB (once there were 20 in
5 minutes) were answered 5xx, in 2 of 3 periods.

**Check.** The acs log, and `AcsThrottled`. acs's own runbook (in the
auto-configuration-server repository) has the details of each path.

**Act.** Follow acs's runbook. If it started with a deployment,
[roll back](#rollback).

### AcsUnhealthyTargets

**Symptom.** An acs target failed `/healthz` for 3 minutes.

**Check.** Service events and the acs log at start (a refused setting stops
the task).

**Act.** A deployment: [roll back](#rollback). Otherwise follow acs's
runbook.

### AcsOtpVolume

**Symptom.** acs sent more than 500 OTP SMS in 5 minutes. Every OTP is an
SMS the operator pays for, so this can be SMS pumping.

**Check.** The acs log: are the requests spread over many MSISDNs from few
client addresses? WAF metrics for the ALB.

**Act.** A pumping attack from a few addresses: switch the WAF to block (see
[WafRateLimited](#wafratelimited)) or deny the sources in the network ACL
([Blocking a source](#blocking-a-source)). Narrowing `PublicIngressCidr` is
a full stop: it shuts every client out of the NLB and the ALB, SIP and MSRP
included. Escalate to security. Real growth: raise the threshold in the
template.

### AcsNoHealthyTargets

**Symptom.** The acs target group has had no healthy target for 2 of 3
minutes: no device can be configured.

**Check.** As [FtServerNoHealthyTargets](#ftservernohealthytargets), for
`acs`.

**Act.** As [FtServerNoHealthyTargets](#ftservernohealthytargets).

## The ALB and its WAF

### AlbElb5xx

**Symptom.** Over 5% of the ALB's requests were answered 5xx by the ALB
itself (502, 503, 504), in 2 of 3 periods: it found no target to take them.

**Check.** The `*NoHealthyTargets` alarms, and target timeouts on the
dashboard.

**Act.** As the target group alarm that fires with it.

### WafRateLimited

**Symptom.** Client addresses went over `WafRateLimit` requests in 5 minutes
(the rule's `CountedRequests` with `WafRateAction=count`, or
`BlockedRequests` with `block`).

**Check.** The WAF log group (`aws-waf-logs-<stack>`) shows which addresses,
and the paths they hit (query strings are redacted). One address with many
distinct devices behind it is carrier-grade NAT; one client looping, or a
scan, is something else.

**Act.** Stay on `count` until a week of normal traffic has shown the peak
per address of the operators' NAT addresses. Then set `WafRateLimit` above
that peak with headroom, and `WafRateAction=block` (changes the stack). In
`block` mode, a legitimate NAT address over the limit means raising the
limit, not lowering it.



## Tables

The tables are on demand. They throttle when a burst exceeds what the
table can serve at once (its warm throughput) or one partition's limit.

### SubscribersThrottled

**Symptom.** Reads or writes to the subscribers table were throttled for 3
minutes. Cx requests and provisioning slow down or fail.

**Check.** Is a [re-registration burst](#re-registration-burst-sizing) in
progress, after an outage or a pcscf restart?

**Act.** Raise `SubscribersWarmReadUnits` and `SubscribersWarmWriteUnits`
and deploy. Raising warm throughput takes some minutes and is charged once.
It cannot be lowered: keep the raised values in the config file for good,
or the next deployment fails and rolls back.

### ServiceProfilesThrottled

**Symptom.** Reads of service profiles were throttled for 3 minutes.

**Check.** Every SAR reads the subscriber's profile, so a registration burst
reads one profile item very often.

**Act.** As [SubscribersThrottled](#subscribersthrottled). If one profile
is hot, open an issue (a cache of profiles in hss is a follow-up).

### FilesThrottled

**Symptom.** Reads or writes to the files table were throttled for 3
minutes.

**Check.** Upload and download volume, and sweeps (a sweep scans the
table).

**Act.** Usually a burst that clears. If it repeats at sweep times, open an
issue for the expiry index.

### MsrpBindingsThrottled

**Symptom.** Reads or writes to `msrp-bindings` were throttled for 3
minutes.

**Check.** Did relay tasks stop just before (deployment, AZ failure)? Their
clients come back at once, each with about three writes and one read. See
[Re-registration burst sizing](#re-registration-burst-sizing).

**Act.** Raise `MsrpWarmReadUnits` and `MsrpWarmWriteUnits` and deploy. Like
all warm throughput, they cannot be lowered again.

### RegistrationsThrottled

**Symptom.** Reads or writes to the S-CSCF's `registrations` table were
throttled for 3 minutes (once scscf runs). Registrations and terminating
requests slow down or fail.

**Check.** A [re-registration burst](#re-registration-burst-sizing): every
re-registration is one read and one put here, plus two index writes.

**Act.** A burst clears by itself. Repeated bursts: open an issue to give
this table warm throughput parameters like the subscribers table.

### AuthChallengesThrottled

**Symptom.** Writes to `auth-challenges` were throttled for 3 minutes.
Each authentication is a put and a conditional delete.

**Check.** As [RegistrationsThrottled](#registrationsthrottled). Many
challenges without a second REGISTER point at a client failing to
authenticate in a loop.

**Act.** As [RegistrationsThrottled](#registrationsthrottled).

### RegSubscriptionsThrottled

**Symptom.** Reads or writes to `reg-subscriptions` were throttled for 3
minutes. reg event subscriptions and NOTIFYs slow down.

**Check.** A registration burst raises NOTIFYs too.

**Act.** As [RegistrationsThrottled](#registrationsthrottled).

### MessagesThrottled

**Symptom.** Reads or writes to rcs-as's messages table were throttled for
3 minutes (once rcs-as runs). Store-and-forward slows down.

**Check.** Message volume, and whether many messages go to one recipient:
a recipient's queue is one partition.

**Act.** A burst clears by itself. One hot recipient (a bot or a group
fan-out): open an issue with the counts, never the identity.

### AcsThrottled

**Symptom.** Reads or writes to acs's table were throttled for 3 minutes.

**Check.** acs's request volume, and `AcsOtpVolume`.

**Act.** A flood: as [AcsOtpVolume](#acsotpvolume). Otherwise it is a burst
that clears.

## Metrics pipeline

One alarm per service log group; the sections below share the same steps.

### EmfErrorsHss

**Symptom.** CloudWatch could not extract metrics from hss's log lines
(`EMFValidationErrors`, `EMFParsingErrors` in `AWS/Logs`). Each such line
loses a minute of a metric, and the alarms on it go quiet.

**Check.** Did it start with a deployment? The service log has the line;
CloudWatch's error says what it refused (a name, a value array over 100
values, a unit).

**Act.** Roll back if a deployment caused it, and open an issue: every
service writes EMF through `internal/runtime`, which should never produce
such a line.

### EmfErrorsFtServer

**Symptom.** As [EmfErrorsHss](#emferrorshss), for ft-server.

**Check.** As [EmfErrorsHss](#emferrorshss).

**Act.** As [EmfErrorsHss](#emferrorshss).

### EmfErrorsRelay

**Symptom.** As [EmfErrorsHss](#emferrorshss), for msrp-relay.

**Check.** As [EmfErrorsHss](#emferrorshss).

**Act.** As [EmfErrorsHss](#emferrorshss).

### EmfErrorsAcs

**Symptom.** As [EmfErrorsHss](#emferrorshss), for acs (its own EMF, under
`RCS/<stack>/acs`).

**Check.** As [EmfErrorsHss](#emferrorshss).

**Act.** As [EmfErrorsHss](#emferrorshss); acs's fix belongs in acs's
repository.

## Security and cost notifications

These arrive on the alarm topic as events or budget messages, not as
CloudWatch alarms.

### SecurityGroupChanges

**Symptom.** A security group in the account was changed (CloudTrail
`AuthorizeSecurityGroup*`, `RevokeSecurityGroup*`, `ModifySecurityGroupRules`,
`CreateSecurityGroup`, `DeleteSecurityGroup`).

**Check.** Every deployment that changes groups sends these too. Compare
the time with deployments. Otherwise look at `userIdentity` in the event.

**Act.** An unexplained change to a platform group: revert it as in [Undoing
a change made outside CloudFormation](#undoing-a-change-made-outside-cloudformation)
(a deployment alone does not), and escalate to security.

### SecretChanges

**Symptom.** A secret was changed (`PutSecretValue`, `UpdateSecret`, ...).

**Check.** Expected during a [token rotation](#token-rotation). Otherwise
look at `userIdentity`.

**Act.** An unexplained change: rotate the token concerned, and escalate to
security.

### ServiceImpaired

**Symptom.** ECS reports that a service cannot start tasks
(`SERVICE_TASK_START_IMPAIRED`) or that a deployment failed and the circuit
breaker rolled it back (`SERVICE_DEPLOYMENT_FAILED`). hss has no load
balancer, so this is how its outage shows.

**Check.** The event names the service. Its events in `describe-services`
say why: an image ECR no longer has, a secret it cannot read, a start-up
the service refused (its log: a setting, the keyring).

**Act.** Fix the cause; for a failed deployment, the old tasks still run.
For hss's keyring refusal see [Keyring bootstrap](#keyring-bootstrap).

### KmsKeyChanges

**Symptom.** A key policy or key state changed (`PutKeyPolicy`,
`ScheduleKeyDeletion`, `DisableKey`, grants).

**Check.** Deployments that change a key policy send it too, and DynamoDB
creates grants for its tables. Otherwise look at `userIdentity`.

**Act.** An unexplained change: cancel a scheduled deletion at once (`aws
kms cancel-key-deletion`, changes the stack), revert the policy, and
escalate to security. A deleted HSS or S-CSCF key loses every secret or
item under it.

### TaskDefinitionChanges

**Symptom.** A task definition was registered or a service changed.

**Check.** Every deployment and restart sends these. Outside one, look at
`userIdentity` and what the new revision changed (image, role, commands).

**Act.** An unexplained change: deploy the stack's current revision again
from its commit (deploy.sh registers the template's definitions) and
escalate to security.

### IamPolicyChanges

**Symptom.** An IAM policy or trust relationship changed. This rule exists
only in a stack in us-east-1, where CloudTrail delivers IAM events.

**Check.** As [TaskDefinitionChanges](#taskdefinitionchanges).

**Act.** As [TaskDefinitionChanges](#taskdefinitionchanges).

### MonthlyBudget

**Symptom.** The account's cost this month passed 80% or 100% of
`MonthlyBudgetUsd`.

**Check.** Cost Explorer by service. The usual suspects are Fargate (more
tasks than planned), NAT data, CloudWatch (logs and metrics), and SMS
(`AcsOtpVolume`).

**Act.** Remove what is not needed, or raise the budget in the config if
the growth is planned. See the [cost estimate](aws-deployment.md#cost).

### DailyBudget

**Symptom.** The account's cost today passed 80% or 100% of
`DailyBudgetUsd`.

**Check.** As [MonthlyBudget](#monthlybudget). A sudden day usually means
SMS, NAT data or a scaling loop.

**Act.** As [MonthlyBudget](#monthlybudget).

## Procedures

### Rollback

Roll forward with a fix when you can. When you cannot, deploy the previous
image with the same config file. `--skip-build` builds nothing and changes
nothing else:

```sh
scripts/deploy.sh --config <your config> --stack-name "$STACK" --region "$REGION" \
  --skip-build --image-tag <previous tag>       # changes the stack
```

The previous tag is the stack's `PreviousImageTag` output, which deploy.sh
records at every deployment that changes the image, and which it prints
at the end of each run. Every image a service ran is also in its task
definition revisions (`aws ecs describe-task-definition --task-definition
"$STACK-hss:<revision>"`). The tags in ECR alone do not say which ran: some
were pushed by deployments that rolled back.

deploy.sh ships the checkout's template with any deployment, rollbacks
included, and refuses a working tree with changes. Run the rollback from
the commit the stack runs (its `TemplateRevision` output), so only the
image changes. If the template change is the fault, check out the
previous release's commit and run the same command from there. Its template
and its config file must match: a parameter added since then is refused as
unknown.

A stack left in `UPDATE_ROLLBACK_FAILED` needs `aws cloudformation
continue-update-rollback` (changes the stack) after fixing what blocked the
rollback (read the stack events).

### First deployment rolled back

A stack whose first creation failed is `ROLLBACK_COMPLETE` and cannot be
updated. `deploy.sh` refuses it. Read the events for the first
`CREATE_FAILED`, fix the cause, delete the stack with
`scripts/teardown.sh` (changes the stack; it skips load balancers the
rollback already deleted) and deploy again. Tables, the bucket, the keys or
the NLB's addresses created before the failure may have been retained: the
teardown lists them, and deploy.sh refuses a first creation while their
names are taken. Delete them by hand while they are still empty.

A stack in `REVIEW_IN_PROGRESS` is the empty shell of a first change set
that never ran (an interrupted or `--plan` run). deploy.sh creates it
afresh, and teardown.sh deletes it.

### Teardown failed

`scripts/teardown.sh` stops when the stack deletion fails, and turns the load
balancers' deletion protection back on, since a later deployment would not.
Read the events for `DELETE_FAILED`. Usual causes are a security group still
attached to an interface outside the stack, or a non-empty bucket in the
registry stack. Fix it and run teardown again.

### Undoing a change made outside CloudFormation

CloudFormation does not revert a change made in the console or the CLI: a
deployment with the same template and parameters has nothing to do. Find
the drift first (read-only):

```sh
aws cloudformation detect-stack-drift --region "$REGION" --stack-name "$STACK"
aws cloudformation describe-stack-resource-drifts --region "$REGION" --stack-name "$STACK" \
  --stack-resource-drift-status-filters MODIFIED DELETED \
  --query 'StackResourceDrifts[].[LogicalResourceId,StackResourceDriftStatus,PropertyDifferences]'
# Security group rules the matrix does not have:
aws ec2 describe-security-group-rules --region "$REGION" \
  --filters Name=group-id,Values=<group id> --query 'SecurityGroupRules[].[IsEgress,IpProtocol,FromPort,CidrIpv4,ReferencedGroupInfo.GroupId]'
```

Then revert each difference by hand to the template's value (changes the
stack): `revoke-security-group-ingress` for an added rule,
`put-bucket-lifecycle-configuration` with the template's rule, and so on.
Drift detection does not see every property, and not separate rule
resources added outside the stack: compare security groups with the
ADR 0007 matrix in `scripts/check_infra.py` as well.

### Blocking a source

Security groups cannot deny, and AWS WAF sits only on the ALB, so a source
is turned away from the NLB (SIP, MSRP) in the public subnets' network ACL.
The template keeps rules 1 to 999 free for this; rule 1000 allows the rest.

```sh
ACL=$(aws ec2 describe-network-acls --region "$REGION" \
  --filters Name=tag:Name,Values="$STACK-public" --query 'NetworkAcls[0].NetworkAclId' --output text)
# Deny one range inbound (changes the stack). Use a free number under 1000.
aws ec2 create-network-acl-entry --region "$REGION" --network-acl-id "$ACL" \
  --rule-number 100 --protocol -1 --rule-action deny --ingress --cidr-block 198.51.100.0/24
# And remove it when done.
aws ec2 delete-network-acl-entry --region "$REGION" --network-acl-id "$ACL" --rule-number 100 --ingress
```

Blast radius: the ACL covers everything in the public subnets: the NLB, the
ALB and the NAT gateways. A denied range also loses replies to the
platform's own outbound calls to it, and a carrier-grade NAT address takes
every handset behind it with it. An ACL takes at most 20 entries a
direction by default. Entries added this way are outside CloudFormation: a
deployment keeps them, and they must be removed by hand.

### Token rotation

Each internal token (ADR 0007 §4) has two secrets: `<stack>/<receiver>/<caller>-token`
and `...-token-next`. The receiver accepts both. The caller presents the
current one. Secrets reach tasks only when the tasks start, so each step
ends with a restart:

| Token | Receiver (reads both) | Caller (reads current) |
|---|---|---|
| `hss/admin-token` | hss | the operator |
| `hss/ft-server-token` | hss | ft-server |
| `hss/acs-token` | hss | acs (not wired yet) |
| `msrp-relay/pcscf-token` | msrp-relay | pcscf (not deployed yet) |

`scripts/rotate-token.sh` does it (changes the stack):

```sh
scripts/rotate-token.sh --stack-name "$STACK" --region "$REGION" --token hss/ft-server-token
```

1. A new value goes into next; the receiver restarts and accepts old and new.
2. Old goes into next, then new into current. The receiver restarts, so
   that no task that started between the two writes keeps a wrong pair, and
   then the caller restarts and presents new.
3. A fresh, unused value replaces old in next; the receiver restarts and no
   longer accepts old.

Each restart waits until the service is steady (one deployment, completed,
all tasks running), up to 45 minutes, since ft-server's deregistration
delay makes its rollouts long. Any failure stops the rotation where it is;
`--step <n>` resumes it. For a token whose caller is outside the stack (the
operator, or a service not wired yet), the script stops after step 2: give
the callers the value of the current secret, then run `--step 3`. Values
pass only through shell variables and a file only the user can read; they
never reach the screen or a command line.

For about a second in step 2, the two secrets hold the same value. A
receiver task starting in that second would see equal values; msrp-relay
refuses to start then (ECS starts another), hss accepts only that value.
The restart that follows the writes replaces any such task (#231 removes the
window). In staging and
prod, a token shorter than 43 characters stops the receiver from starting;
the generated ones have 64.

### Keyring bootstrap

The HSS seals every K, OPc and HA1 under a data key kept, wrapped by the
stack's KMS key, in the `keyring` item (`pk = keyring`) of the subscribers
table (docs/hss.md, Secrets). If the item is missing while subscriptions are
stored, hss refuses to start, and the log says `the subscribers table holds
subscriptions but no data key`.

1. **Restore the item; do not create a new key.** Restore the table to a
   point in time when the item existed, into a new table (changes the
   stack):
   `aws dynamodb restore-table-to-point-in-time --region "$REGION"
   --source-table-name "$STACK-subscribers" --target-table-name
   "$STACK-subscribers-restore" --restore-date-time <time>`.
   Copy the `keyring` item, with all its `key_*` attributes, back into
   `$STACK-subscribers`. Restart hss, then delete the restored table. The
   wrapped key opens only with the KMS key it was wrapped under: that key
   is retained even when the stack is deleted.
2. **Only when the key is truly gone** (no restorable copy, or its KMS key
   deleted): set `HssKeyringBootstrap=true` in the config and deploy. hss
   creates a new key (`HssKeyringCreated` fires) and starts. Every stored
   secret stays unusable (`500` or `DIAMETER_UNABLE_TO_COMPLY`) until it is
   provisioned again.
3. Set `HssKeyringBootstrap=false` and deploy again at once. While it stays
   `true`, hss logs `HSS_KEYRING_BOOTSTRAP is set although a data key
   exists; remove it` at every start, and a later loss would pass unnoticed.

### Re-registration burst sizing

After an outage of the edge or the core, every client registers again
within its retry window, and the tables must serve that burst. An on-demand
table serves at once up to its warm throughput: 12,000 read and 4,000 write
units a second for a new table, more after it has seen higher traffic.

From docs/hss.md (Sizing), an AKA registration costs about 5 read and up to
4 write units on the subscribers table. For `S` subscribers registering
again within `W` seconds:

| | Units per second | 1,000,000 subscribers in 10 minutes |
|---|---|---|
| Reads | 5 × S / W | 8,333 |
| Writes | 4 × S / W | 6,667: over the 4,000 default |

Set `SubscribersWarmWriteUnits` (and `SubscribersWarmReadUnits`) above
these values, with some headroom, before the subscriber count gets there.
Raising warm throughput is charged once, not per month. Under throttling,
hss answers `DIAMETER_UNABLE_TO_COMPLY` and clients retry, which makes the
burst longer.

msrp-relay: a stopping task closes its client connections over the second
half of its 100 s drain, so up to `RelayMaxConnections` / 50 clients a
second come back, each with about three writes and one strongly consistent
read on `msrp-bindings`. With 5,000 connections that is about 300 writes a
second per stopping task. A rolling update stops one task at a time; an AZ
failure stops half of them at once. Size `MsrpWarmWriteUnits` for the
second case.

The task counts are not sized by load tests yet. Watch hss's `cx.mar` and
`cx.sar` latency against `HSS_CX_TIMEOUT` (3 s) during a burst, and add hss
tasks when it approaches the limit.
