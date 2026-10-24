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

- `auth.backend_error`: a credential lookup at the HSS failed or timed out
  (`FT_HSS_TIMEOUT`, 2 s), or an update of the nonce-count store in DynamoDB
  failed (throttling, or an update that lost every conditional write to other
  requests on its nonce). The upload got `503` with `Retry-After`.
- `auth.nonce_count_unusable`: a nonce-count item in the files table could
  not be decoded. The client got `401` with `stale=true` and moves to a new
  nonce. Only a bug, a hand edit, or two versions that write items
  differently leave items like that.

A client that closed its connection during either call is counted in
`auth.interrupted` and does not raise this alarm
([ft-server.md](ft-server.md#authentication)).

**Check.** The warnings name the cause:

```sh
STACK=rcs-platform REGION=ap-northeast-2

aws logs tail "/rcs/$STACK/ft-server" --region "$REGION" --since 30m \
  --filter-pattern '{ $.level = "WARN" && ($.msg = "credential lookup failed" || $.msg = "nonce count store failed" || $.msg = "nonce count record unusable") }'

# Running versions and recent deployments of ft-server.
aws ecs describe-services --region "$REGION" --cluster "$STACK" --services ft-server \
  --query 'services[0].deployments[].{status:status,taskDefinition:taskDefinition,running:runningCount,updated:updatedAt}'
```

- "credential lookup failed": the HSS. Is the `hss` service running and
  ready, and do the hss alarms fire too (`HssApiStoreFailure`,
  `HssLockBusy`)? A timeout points at a slow HSS; an HSS that answers `401`
  or `403` points at a provisioning token that differs between the HSS and
  ft-server.
- "nonce count store failed": DynamoDB. Does `FilesThrottled` fire? An
  error ending "too many concurrent updates" is many requests on one nonce
  at once; `auth.nonce_contended` rises with it.
- "nonce count record unusable": does it start with a deployment or a
  rollback, and does more than one task definition run?

**Act.**

- HSS: fix the HSS first. If the tokens differ, finish the token rotation,
  or put the previous token back into the current secret, then restart
  ft-server.
- DynamoDB: throttling of the on-demand files table passes as it scales.
  If it persists, or the contention does, look for one client sending the
  same Authorization in a loop (the WAF rule, `WafRateLimited`).
- Unusable items while two versions run: finish the deployment or the
  rollback so that one version runs. With one version and every request
  affected, that version cannot read its own items: roll back to the
  previous image. Items it cannot read stop mattering when their nonces
  expire, 5 minutes after issue.

**Verify.** The alarm returns to `OK` once 5 minutes pass without either
metric.
