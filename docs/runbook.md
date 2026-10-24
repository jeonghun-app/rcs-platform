# Runbook

What to do when the platform pages you. Every alarm of `infra/platform.yaml`
links a section here under its own name: an alarm `<stack>-<Name>` is in the
section `<Name>`. Only some sections are written yet; the rest come with the
deployment runbook (#126).

Service metrics are CloudWatch EMF in the namespace `RCS/<stack>`, with
`Service` as the only dimension. Logs are JSON lines in
`/rcs/<stack>/<service>`. No log or metric holds an IMSI, MSISDN, token, key
or message body.

## ft-server

### FtAuthBackendError

**Symptom.** In 5 minutes, the sum of two ft-server metrics went above 0:

- `auth.backend_error`: a credential lookup at the HSS failed or took longer
  than `FT_HSS_TIMEOUT` (2 s), or an update of the nonce-count store in
  DynamoDB failed or took that long: throttling, an update that lost every
  conditional write to other requests on its nonce, or a table that did not
  answer. The upload got `503` with `Retry-After`.
- `auth.nonce_count_unusable`: a nonce-count item in the files table could
  not be decoded. The client got `401` with `stale=true` and moves to a new
  nonce. Only a bug, a hand edit, or two versions that write items
  differently leave items like that.

A client that closed its connection during either call is counted in
`auth.interrupted` and does not raise this alarm
([ft-server.md](ft-server.md#authentication)).

**Check.** First, which of the two, and how many, beside `auth.interrupted`.
The alarm adds the first two. If `auth.interrupted` rises with
`auth.backend_error`, clients are giving up on a backend that has become
slow, though still within `FT_HSS_TIMEOUT`:

```sh
STACK=rcs-platform REGION=ap-northeast-2

for m in auth.backend_error auth.nonce_count_unusable auth.interrupted; do
  echo "$m"
  aws cloudwatch get-metric-statistics --region "$REGION" --namespace "RCS/$STACK" \
    --metric-name "$m" --dimensions Name=Service,Value=ft-server \
    --statistics Sum --period 300 \
    --start-time "$(date -u -d '-3 hours' +%FT%TZ 2>/dev/null || date -u -v-3H +%FT%TZ)" \
    --end-time "$(date -u +%FT%TZ)" \
    --query 'sort_by(Datapoints, &Timestamp)[].[Timestamp, Sum]' --output text
done
```

Then the warnings, which name the cause, and the versions running:

```sh
aws logs tail "/rcs/$STACK/ft-server" --region "$REGION" --since 30m \
  --filter-pattern '{ $.level = "WARN" && ($.msg = "credential lookup failed" || $.msg = "nonce count store failed" || $.msg = "nonce count record unusable") }'

aws ecs describe-services --region "$REGION" --cluster "$STACK" --services ft-server \
  --query 'services[0].deployments[].{status:status,rollout:rolloutState,taskDefinition:taskDefinition,running:runningCount,updated:updatedAt}'
```

- "credential lookup failed": the HSS. Is the `hss` service running and
  ready, and do the hss alarms fire too (`HssApiStoreFailure`,
  `HssLockBusy`)? A timeout points at a slow HSS; an HSS that answers `401`
  or `403` points at a provisioning token that differs between the HSS and
  ft-server.
- "nonce count store failed": DynamoDB. Does `FilesThrottled` fire? An
  error ending "context deadline exceeded" is a table slower than
  `FT_HSS_TIMEOUT`. One ending "too many concurrent updates" is many
  requests on one nonce at once; `auth.nonce_contended` rises with it.
- "nonce count record unusable": does it start with a deployment or a
  rollback, and does more than one task definition run?

**Act.**

- HSS: fix the HSS first. If the tokens differ, finish the token rotation,
  or put the previous token back into the current secret. Then restart
  ft-server (changes the stack):

  ```sh
  aws ecs update-service --region "$REGION" --cluster "$STACK" --service ft-server --force-new-deployment
  ```

- DynamoDB: throttling of the on-demand files table passes as it scales.
  If it persists, or the contention does, look for one client sending the
  same Authorization in a loop (the WAF rule, `WafRateLimited`). A table
  that answers slowly without throttling is an AWS-side fault: check the
  AWS Health Dashboard for DynamoDB in the region.
- Unusable items while two versions run: let the deployment or the rollback
  finish, so that one version runs. Do not roll back again yet. For up to
  5 minutes after that (the nonce lifetime) requests still come with
  nonces from before, whose items the remaining version may not read. The
  warnings go on for that long and stop by themselves; the alarm clears
  once a 5-minute period passes without them.
- Unusable items that go on more than 5 minutes after one version alone
  runs (one deployment listed above, rollout `COMPLETED`; count from its
  `updated` time): their nonces were issued, and their items written,
  after the other version stopped. The version that runs cannot read items
  it writes itself. Roll back to the last image that ran without these
  warnings (changes the stack), with the deployment procedure (#126).

**Verify.** The alarm returns to `OK` once 5 minutes pass without either
metric.
