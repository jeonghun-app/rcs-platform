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
  security and cost notifications go to the stack's alarm topic (the
  `AlarmTopic` output).
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
  config file, never the console: the next deployment would undo a console
  edit.

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
  --start-time "$(date -u -d '-3 hours' +%FT%TZ)" --end-time "$(date -u +%FT%TZ)"
```

Scaling out means raising the service's `...DesiredCount` in the config file
and deploying (changes the stack). In prod each rolling step adds one task
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

**Act.** Slow HSS: as [FtAuthBackendError](#ftauthbackenderror). A flood:
lower `WafRateLimit` and deploy. Scale ft-server only when the traffic is
real.

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

**Act.** Deploy again to restore the template's lifecycle. Deleted objects
come back only if they still exist elsewhere: the bucket has no versioning.

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

**Symptom.** ft-server answered more than ten 5xx a minute through the ALB
for 3 minutes.

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

**Act.** Restore `rcs-as` or the security group rule. Deploy again to put
the template's rules back.

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
sends a PROXY header on health checks too.

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

**Act.** A scan: block the sources in the WAF or with an NLB-facing
security group change (changes the stack). Legitimate growth: raise the
budget in the config and deploy.

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

## acs

### AcsTarget5xx

**Symptom.** acs answered more than ten 5xx a minute through the ALB for 3
minutes.

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

**Act.** A pumping attack: lower `WafRateLimit`, or narrow
`PublicIngressCidr` while you investigate, and deploy. Escalate to
security. Real growth: raise the threshold in the template.

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

**Act.** Raise `MsrpWarmReadUnits` and `MsrpWarmWriteUnits` and deploy.

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

### EmfErrors

**Symptom.** CloudWatch could not extract metrics from a service's log lines
(`EMFValidationErrors`, `EMFParsingErrors` in `AWS/Logs`). Each such line
loses a minute of a metric, and the alarms on it go quiet.

**Check.** Which log group (the alarm's metrics are per group)? Did it start
with a deployment? The service log has the line; CloudWatch's error says
what it refused (a name, a value array over 100 values, a unit).

**Act.** Roll back if a deployment caused it, and open an issue: every
service writes EMF through `internal/runtime`, which should never produce
such a line.

## Security and cost notifications

These arrive on the alarm topic as events or budget messages, not as
CloudWatch alarms.

### SecurityGroupChanges

**Symptom.** A security group in the account was changed (CloudTrail
`AuthorizeSecurityGroup*`, `RevokeSecurityGroup*`, `ModifySecurityGroupRules`,
`CreateSecurityGroup`, `DeleteSecurityGroup`).

**Check.** Every deployment that changes groups sends these too. Compare
the time with deployments. Otherwise look at `userIdentity` in the event.

**Act.** An unexplained change to a platform group: deploy again to restore
the ADR 0007 matrix, and escalate to security.

### SecretChanges

**Symptom.** A secret was changed (`PutSecretValue`, `UpdateSecret`, ...).

**Check.** Expected during a [token rotation](#token-rotation). Otherwise
look at `userIdentity`.

**Act.** An unexplained change: rotate the token concerned, and escalate to
security.

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

The previous tag is in the stack's parameters history (CloudFormation
events) or in ECR (`aws ecr describe-images --repository-name "$STACK"`).
If the template change is the fault, check out the previous release's commit
and run the same command from there. Its template and its config file must
match: a parameter added since then is refused as unknown.

A stack left in `UPDATE_ROLLBACK_FAILED` needs `aws cloudformation
continue-update-rollback` (changes the stack) after fixing what blocked the
rollback (read the stack events).

### First deployment rolled back

A stack whose first creation failed is `ROLLBACK_COMPLETE` and cannot be
updated. `deploy.sh` refuses it. Read the events for the first
`CREATE_FAILED`, fix the cause, delete the stack with
`scripts/teardown.sh` (changes the stack) and deploy again. Tables, the
bucket or the key created before the failure may have been retained: the
teardown lists them. Delete them by hand while they are still empty, or the
new stack cannot create its tables under the same names.

### Teardown failed

`scripts/teardown.sh` stops when the stack deletion fails. Read the events
for `DELETE_FAILED`. Usual causes are a security group still attached to an
interface outside the stack, or a non-empty bucket in the registry stack.
Fix it and run teardown again.

### Token rotation

Each internal token (ADR 0007 §4) has two secrets: `<stack>/<receiver>/<caller>-token`
and `...-token-next`. The receiver accepts both. The caller presents the
current one. Secrets reach tasks only when the tasks start, so each step
ends with a restart. The order below never leaves a starting task without
the value its peers present:

| Token | Receiver (reads both) | Caller (reads current) |
|---|---|---|
| `hss/admin-token` | hss | the operator |
| `hss/ft-server-token` | hss | ft-server |
| `hss/acs-token` | hss | acs (not wired yet) |
| `msrp-relay/pcscf-token` | msrp-relay | pcscf (not deployed yet) |

Every command here changes the stack. Values stay in shell variables and,
for a moment, in a file only you can read; they never reach the screen or a
command line, where other users of the host could see them:

```sh
STACK=rcs-platform REGION=ap-northeast-2 TOKEN=hss/ft-server-token RECEIVER=hss CALLER=ft-server
get() { aws secretsmanager get-secret-value --region "$REGION" --secret-id "$STACK/$1" --query SecretString --output text; }
put() (
  umask 077; f="$(mktemp)"; trap 'rm -f "$f"' EXIT
  printf '%s' "$2" >"$f"
  aws secretsmanager put-secret-value --region "$REGION" --secret-id "$STACK/$1" --secret-string "file://$f" >/dev/null
)
restart() {
  aws ecs update-service --region "$REGION" --cluster "$STACK" --service "$1" --force-new-deployment >/dev/null
  aws ecs wait services-stable --region "$REGION" --cluster "$STACK" --services "$1"
}
random() { aws secretsmanager get-random-password --region "$REGION" --password-length 64 --exclude-punctuation --query RandomPassword --output text; }

# 1. The new value goes into next; the receiver accepts old and new.
put "$TOKEN-next" "$(random)"; restart "$RECEIVER"
# 2. Old into next, then new into current: a receiver task starting now
#    accepts both. The caller restarts with the new value.
old="$(get "$TOKEN")"; new="$(get "$TOKEN-next")"
put "$TOKEN-next" "$old"; put "$TOKEN" "$new"; unset old new
restart "$CALLER"
# 3. A fresh, unused value replaces old in next; the receiver drops old.
put "$TOKEN-next" "$(random)"; restart "$RECEIVER"
```

If `services-stable` gives up (it waits ten minutes; ft-server's 300 s
deregistration delay makes its deployments long), check the service with
`describe-services` and run the wait again before the next step. For the
admin token, step 2's "caller" is whoever calls the provisioning
API: give them the new value from the current secret, then do step 3. In
staging and prod, a token shorter than 43 characters stops the receiver
from starting, and the generated ones have 64.

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
