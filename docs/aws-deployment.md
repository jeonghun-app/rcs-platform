# Deploying to AWS

One command deploys the platform to an AWS account (ADR 0003):
`scripts/deploy.sh` builds the images, pushes them to ECR and deploys two
CloudFormation stacks. `scripts/teardown.sh` removes them again and keeps
the data. What to do once the stack runs is in the [runbook](runbook.md).

## Approval

Both scripts write to the AWS account the credentials point at, and the
platform costs money from the first hour (see [Cost](#cost)). Run them only
with the approval of the person who owns the account. That includes a
rollback and a change of the config file. `--dry-run` needs no approval: it
checks the config and prints the commands without calling AWS or Docker.

## What is deployed

| Stack | Template | Holds |
|---|---|---|
| `<stack>-ecr` | `infra/ecr.yaml` | ECR repositories of the platform image and the acs image (immutable tags, scan on push, the last 30 tagged images kept) and the bucket the platform template is uploaded to |
| `<stack>` | `infra/platform.yaml` | everything else, in one stack |

The platform stack:

- **Network.** A VPC across two AZs, with public subnets (NLB, ALB, NAT) and
  private subnets (tasks). One NAT gateway per AZ, or one in all. Gateway
  endpoints for DynamoDB and S3. VPC Flow Logs in prod.
- **Cluster.** ECS on Fargate (and Fargate Spot, unused by default) and a
  Cloud Map private namespace (`rcs.local`).
- **Security groups.** One per service, exactly the matrix of ADR 0007 §2,
  including the services not deployed yet. `make infra-lint` checks the
  matrix.
- **Load balancers.**
  - A public NLB for SIP (5060, 5061 TLS) and MSRP (2855, 2856 TLS). Proxy
    Protocol v2 is on, and TCP connections idle out after 1800 s.
  - A public ALB for acs and ft-server, behind an AWS WAF rate-based rule.
- **Data.**
  - DynamoDB tables `subscribers` and `service-profiles` (hss), `files`
    (ft-server), `msrp-bindings` (msrp-relay) and acs's table. All are on
    demand, with point-in-time recovery and deletion protection in prod.
  - Ahead of their services, with their task roles: `messages` (rcs-as),
    and `registrations`, `auth-challenges` and `reg-subscriptions` (scscf),
    the last three under a key of their own (docs/scscf-state.md).
  - The files bucket.
  - The KMS key of the HSS keyring.
  - Twelve generated secrets: the ADR 0007 tokens, current and next, and the
    shared keys.
- **Services.** hss, ft-server, msrp-relay and acs (pinned release, ADR 0006),
  each with its own execution and task role, log group and alarms.
- **Notifications.** The alarms, a daily and a monthly cost budget, and
  EventBridge rules on security group and secret changes, all to one SNS
  topic.

### What is not deployed yet

- **pcscf, icscf, scscf and rcs-as.** Their security groups exist, and so
  do the tables and task roles of rcs-as and scscf. Their task definitions come with their pull
  requests. `PcscfEnabled` adds the SIP listeners and pcscf's alarms once
  pcscf exists. Until then no client can register, and
  the HSS has no Cx peer (`HssPushFailed` fires on pushes).
- **msrp-relay without an NLB certificate.** The relay offers only `msrps:`
  paths, so without `NlbCertificateArn` the stack creates no relay service.
  A dev stack needs a certificate to run it.
- **acs's SMPP provider.** It needs an egress rule to the operator's SMSC.
  `eum` and `sns` work. The acs → hss token is generated but not given to
  acs until an acs release uses it.
- **A smoke test.** docs/ft-server.md asks for a 12 MB upload broken off and
  resumed, and a ranged download across a part boundary, against real S3.
  It is not scripted yet.
- **Load tests.** Task counts and sizes follow the service documents, not
  measurements.
- **CI-driven deployment.** Deployment runs from a workstation.
- **Interface endpoints.** Tasks reach ECR, Secrets Manager, KMS, CloudWatch
  and SMS through the NAT gateways. msrp-relay's egress is therefore
  HTTPS to the internet as well as the DynamoDB endpoint.

## Prerequisites

- **Tools.** The AWS CLI v2, Docker with buildx, make, git and bash 3.2 or
  later, and access to `ghcr.io`, where the acs release image is copied
  from. The platform image is built for `linux/amd64` (Fargate X86_64). An
  arm64 host needs Docker's emulation for that.
- **An AWS account of its own** for each stack, or at least for prod: the
  cost budgets watch the whole account.
- **Credentials** that may create the resources above, IAM roles included
  (`CAPABILITY_IAM`), in the target region (default `ap-northeast-2`).
- **A CloudTrail trail** recording management events in that region.
  Without it the security change rules see nothing.
- **In prod, GuardDuty Runtime Monitoring for Fargate** (ADR 0007 §9). It is
  configured per account, not by this template.
- **Outside dev:**
  - ACM certificates in the region: `AlbCertificateArn` covering `FtHostName`
    and `AcsHostName`, and `NlbCertificateArn` covering `RelayPublicHost` and,
    later, pcscf's name.
  - The DNS zone of those names.
  - An End User Messaging origination identity, or SNS, for acs's OTP SMS.

## One-command deployment

```sh
cp infra/platform.example.params ~/rcs-dev.params    # edit: see Parameters
scripts/deploy.sh --config ~/rcs-dev.params --dry-run
scripts/deploy.sh --config ~/rcs-dev.params          # needs approval
```

`deploy.sh` then:

1. Refuses a config that lacks a parameter, names an unknown one or quotes
   a value. Every problem is listed at once. It also refuses a working tree
   with uncommitted or untracked files: the image tag is `git describe` of
   the commit, so it must say what is in the image.
2. Checks that neither stack is in a state CloudFormation cannot update (a
   failed first creation, an operation in progress).
3. Deploys the registry stack.
4. Builds the platform image (`make image`) and pushes it, unless ECR
   already holds that tag. Tags are immutable.
5. Copies acs's release image `ACS_VERSION` from GHCR into ECR by the digest
   pinned in the script (`ACS_DIGEST`, the same as the local stack's), with
   every platform in it, unless ECR holds it. It refuses an ECR tag whose
   digest is not the pinned one, so ECR runs the bytes that were tested.
6. Uploads `infra/platform.yaml` to the registry stack's bucket (it is
   larger than CloudFormation takes inline) and deploys the platform stack.
   It passes **every** parameter explicitly: the three it sets itself
   (`EcrStackName`, `ImageTag`, `AcsImageTag`) and everything else from the
   config. Nothing silently takes a template default or the previous value.
7. Prints the stack's outputs.

Run it again after any change. An unchanged stack is left alone. The first
creation takes about 20 to 30 minutes, mostly the NAT gateways, the load
balancers and the services becoming stable.

`--stack-name` (default `rcs-platform`) names the platform stack. The
registry stack is `<name>-ecr`, and the repositories are `<name>` and
`<name>-acs`, so several stacks can share an account.

### After the first deployment

1. Point the names at the load balancers (the outputs `AlbDnsName` and
   `NlbDnsName`): `FtHostName` and `AcsHostName` at the ALB, and
   `RelayPublicHost` at the NLB.
2. Subscribe the on-call address to the `AlarmTopic` output, and confirm the
   subscription. Alarms, budgets and security events reach nobody until
   then. With your own `AlarmTopicArn`, its policy must let
   `events.amazonaws.com`, `budgets.amazonaws.com` and CloudWatch publish.
3. The HSS provisioning API is reachable only from inside the VPC (ADR 0007
   §5). Run provisioning from a task or an internal load balancer that
   carries the `OperatorSecurityGroupId` group. Its token is in the
   `HssAdminTokenSecret` secret.
4. Run the smoke test above by hand until it is scripted.

## Parameters

Each parameter's `Description` in `infra/platform.yaml` is the reference.
`infra/platform.example.params` is a working dev config. A test keeps it in
step with the template.

| Parameter | Template default | What to know |
|---|---|---|
| `Environment` | `prod` | `RCS_ENV` of every service. `staging` and `prod` refuse unsafe settings and need both certificates, the three host names, a real SMS provider and (prod) two tasks of every service |
| `VpcCidr` | `10.30.0.0/16` | A /16 of RFC 1918 space (10/8, 172.16/12 or 192.168/16); anything else is refused, because the services dial internal hosts only at private addresses. The subnets are its first four /20s |
| `NatGateways` | `per-az` | `single` saves one gateway, but makes one AZ's outage cut the other's egress |
| `ServiceNamespace` | `rcs.local` | The Cloud Map namespace. Internal plain HTTP is allowed only to names in it (ADR 0007 §5) |
| `PublicIngressCidr` | `0.0.0.0/0` | Who reaches the NLB and the ALB. Narrow it until real clients use the stack |
| `AlbCertificateArn`, `NlbCertificateArn` | empty | Empty means plain HTTP on the ALB and no TLS listeners or relay on the NLB, which only dev allows |
| `FtHostName`, `AcsHostName`, `RelayPublicHost` | empty | The names clients use, which the certificates must cover. Empty (dev only) uses the load balancers' DNS names |
| `FtDeregistrationDelay` | `300` | Seconds the ALB lets running uploads finish before an ft-server task stops |
| `PcscfEnabled` | `false` | `true` once pcscf exists |
| `WafRateLimit` | `1000` | Requests per client address per 5 minutes before the WAF blocks that address. The only limit across tasks (docs/ft-server.md) |
| `ImsDomain`, `FtRealm` | required | The home domain (and IMS realm) and the FT realm. They must differ (ADR 0007 §8) |
| `FtValidityDays` | `7` | `FT_VALIDITY`. The bucket's expiry follows from it |
| `FileEncryption` | `AES256` | `aws:kms` uses the account's `aws/s3` key and adds KMS charges |
| `HssDesiredCount`, `FtServerDesiredCount`, `RelayDesiredCount`, `AcsDesiredCount` | `2` | Tasks per service. Each rolling step adds one task before it stops one |
| `HssTaskSize`, `FtServerTaskSize`, `RelayTaskSize`, `AcsTaskSize` | `512x1024` | CPU units × MiB. `GOMEMLIMIT` is set to 85% of it |
| `HssKeyringBootstrap` | `false` | `true` only for the one deployment of [Keyring bootstrap](runbook.md#keyring-bootstrap) |
| `RelayMaxConnections` | `5000` | Client connections per relay task. Size it to the task |
| `SubscribersWarmReadUnits`, `SubscribersWarmWriteUnits`, `MsrpWarmReadUnits`, `MsrpWarmWriteUnits` | `12000`, `4000` | What the tables serve at once in a burst ([sizing](runbook.md#re-registration-burst-sizing)). Raising them is charged once |
| `MsrpReadBudget` | `1000` | Read units a second on `msrp-bindings` above which `MsrpBindingsReadBudget` fires |
| `AcsSmsProvider`, `AcsSmsOriginationIdentity` | `eum`, empty | `mock` sends nothing and is dev only |
| `AcsDefaultRcsProfile` | `UP_2.4` | The profile acs serves by default |
| `AlarmTopicArn` | empty | An SNS topic of your own; empty creates one |
| `MonthlyBudgetUsd`, `DailyBudgetUsd` | `600`, `25` | Cost budgets of the account, notified at 80% and 100%. `0` creates none |
| `ContainerInsights` | `enabled` | About $30 a month at the default size |
| `LogRetentionDays` | `30` | The VPC Flow Logs |

## Cost

Estimated monthly cost in ap-northeast-2 (Seoul). Prices are list prices
from the AWS Price List API on 2026-10-19, without tax, free tier or
discounts. Check them again before you rely on the totals.

| Item | Unit price | Default prod config | Example dev config |
|---|---|---|---|
| Fargate, 0.5 vCPU and 1 GB per task | $0.04656 per vCPU-hour, $0.00511 per GB-hour | 8 tasks: $166 | 3 tasks (no relay without a certificate): $62 |
| NAT gateways | $0.059 an hour, plus $0.059 per GB | 2: $86 | 1: $43 |
| Public IPv4 addresses | $0.005 an hour | 6: $22 | 5: $18 |
| NLB and ALB | $0.0225 an hour each, plus capacity units by traffic | $33 | $33 |
| AWS WAF | $5 per web ACL, $1 per rule, $0.60 per million requests | $6 | $6 |
| Secrets Manager | $0.40 per secret | 12: $4.80 | $4.80 |
| KMS keys (HSS keyring, S-CSCF state) | $1 each, plus $1 per rotation kept (at most $3) | 2: $2 | $2 |
| Cloud Map and its hosted zone | $0.10 per registered instance, $0.50 per zone | $1.30 | $0.80 |
| CloudWatch alarms | $0.10 per alarm metric | 69: $6.90 | 67: $6.70 |
| CloudWatch custom metrics (EMF) | $0.30 per metric | about 200 names once every path has run: $60 | fewer while idle: up to $60 |
| Container Insights | as custom metrics | about 100 metrics: $30 | disabled |
| **Fixed total** | | **about $420** | **about $180 to $240** |

Costs that grow with use:

- **DynamoDB on demand.** $0.1355 per million read units and $0.68 per
  million write units. About $3 per million registrations and $1.5 per
  million re-registrations (docs/hss.md, Sizing). Storage beyond 25 GB is
  $0.27 per GB-month, and point-in-time recovery $0.2166 per GB-month.
- **CloudWatch Logs.** $0.76 per GB ingested and $0.0314 per GB-month
  stored. The HSS writes about 2.4 KB per registration, so about $1.8 per
  million registrations. VPC Flow Logs (prod) cost the same per GB.
- **NAT data**, $0.059 per GB: image pulls at every task start and AWS API
  calls (see interface endpoints above).
- **S3** at $0.025 per GB-month for files, which expire after
  2 × `FtValidityDays` + 1 days, and **ECR** at $0.10 per GB-month for
  images.
- **SMS** sent by acs, per message at End User Messaging or SNS prices.
  `AcsOtpVolume` watches it.
- **DNS queries** to Route 53 at $0.40 per million, Cloud Map API calls at
  $1 per million, and KMS requests at $0.03 per 10,000 (the HSS makes one
  per task start).

Cheaper choices: `NatGateways=single` and one task per service outside
prod, `ContainerInsights=disabled`, and deleting dev stacks when not in use.

## Rollback

Deploy the previous image with the same config file:

```sh
scripts/deploy.sh --config ~/rcs-prod.params --skip-build --image-tag <previous tag>
```

`--skip-build` builds and pushes nothing and leaves the registry stack as
it is. The tags must already be in ECR (`--acs-image-tag` for acs, default
the pinned release). Because every parameter comes from the config, the
rollback changes the image and nothing else. A rollback of the template is
a deployment from the earlier commit. See the [runbook](runbook.md#rollback),
also for stacks CloudFormation cannot update.

## Teardown

```sh
scripts/teardown.sh --stack-name rcs-dev --dry-run
scripts/teardown.sh --stack-name rcs-dev             # needs approval; asks for the name
```

The script asks you to type the stack name, or takes `--confirm <name>`. It
then turns off the load balancers' deletion protection, deletes the platform
stack and waits. `--with-registry` also empties the template bucket and
deletes the registry stack, after the platform stack.

These are retained, still hold data and are still billed. The script lists
them with their names:

| Resource | Why it is kept | To delete it |
|---|---|---|
| The nine DynamoDB tables | Subscriptions, the keyring item, files, bindings, acs data, messages, S-CSCF state | Turn off deletion protection (prod), then delete the table |
| The files bucket | Users' files | Empty it, then delete it |
| The HSS keyring and S-CSCF state KMS keys ($1 a month each) | The keyring item and the S-CSCF tables open only with them | Schedule its deletion (7 to 30 days); everything sealed under it is lost after that |
| The VPC flow log group (prod) | Audit | Delete the log group |
| The ECR repositories | Images a stack may still start from | Delete the repository with its images |

Secrets are deleted with the stack; Secrets Manager may keep them scheduled
for deletion for a recovery window. A new stack of the same name cannot
create its tables, nor a secret still in that window, until the old ones
are gone. Reusing the old data in a new stack (CloudFormation import) is not
scripted.

## Design notes

- **NLB health checks are TCP on the traffic port**, not HTTP on the admin
  port. With Proxy Protocol v2 on, AWS sends the PROXY header on health check
  connections too, and the admin HTTP server would not parse it. A TCP check
  proves the task accepts connections; `/readyz` remains for the ALB
  targets and the container health checks.
- **The NLB has a security group, and client IP preservation is off.** The
  tasks then see the NLB's group as the source, which the ADR 0007 matrix
  needs. The client's address arrives in the PROXY header.
- **Policy checks.** `make infra-lint` runs cfn-lint on both templates,
  `scripts/check_infra.py` (the ADR 0007 matrix, PPv2, WAF, task hardening,
  point-in-time recovery, secrets only through execution roles, the bindings,
  messages and S-CSCF tables read by their own service alone, the S-CSCF
  tables' key, hss's start timeout against its health check, the alarm rules
  of docs/architecture.md §8, a runbook section per alarm), shellcheck on
  the scripts, and the tests of the scripts against stubbed `aws`, `docker`
  and `git`. CI runs the same target. Nothing in it calls AWS.
