# Deploying to AWS

One command deploys the platform to an AWS account (ADR 0003):
`scripts/deploy.sh` builds the images, pushes them to ECR and deploys two
CloudFormation stacks through change sets it shows before running.
`scripts/teardown.sh` removes them again and keeps the data. What to do
once the stack runs is in the [runbook](runbook.md).

## Approval

Both scripts write to the AWS account the credentials point at, and the
platform costs money from the first hour (see [Cost](#cost)). Run them only
with the approval of the person who owns the account. That includes a
rollback, a change of the config file and `scripts/rotate-token.sh`.
`--dry-run` needs no approval: it checks the config and prints the
commands without calling AWS or Docker. `--plan` pushes images and creates
change sets, but changes no stack; it needs approval for the pushes.

## What is deployed

| Stack | Template | Holds |
|---|---|---|
| `<stack>-ecr` | `infra/ecr.yaml` | ECR repositories of the platform image and the acs image (immutable tags, scan on push, the last 30 tagged images kept) and the bucket the platform template is uploaded to |
| `<stack>` | `infra/platform.yaml` | everything else, in one stack |

The platform stack:

- **Network.**
  - A VPC across two AZs, with public subnets (NLB, ALB, NAT) and private
    subnets (tasks). One NAT gateway per AZ, one in all, or none
    (`NatGateways`).
  - Gateway endpoints for DynamoDB and S3, and, with `InterfaceEndpoints`
    (on outside dev), interface endpoints for CloudWatch Logs, ECR, Secrets
    Manager, KMS, Cloud Map (both APIs) and acs's SMS provider. Each
    endpoint has a policy: the gateway endpoints reach only this account's
    tables and buckets (and ECR's layer bucket), the interface endpoints
    serve only this account's principals.
  - The public subnets' network ACL, with rules 1 to 999 kept free for
    [blocking a source](runbook.md#blocking-a-source).
  - VPC Flow Logs in prod.
- **Cluster.** ECS on Fargate (and Fargate Spot, unused by default) and a
  Cloud Map private namespace (`rcs.local`).
- **Security groups.** One per service, exactly the matrix of ADR 0007 §2,
  including the services not deployed yet. With the interface endpoints,
  no group sends anywhere but its matrix peers, the endpoints and the S3 and
  DynamoDB prefix lists. `make infra-lint` checks both.
- **Load balancers.**
  - A public NLB with two fixed, retained Elastic IPs (the
    `NlbPublicAddresses` output). It takes SIP over TLS (5061, to pcscf's
    5061) and MSRP over TLS (2856). The plain SIP 5060 and MSRP 2855
    listeners exist in dev only (ADR 0003). Proxy Protocol v2 is on.
  - A public ALB for acs and ft-server, behind an AWS WAF rate-based rule
    that counts (`WafRateAction=count`) until set to block. Only acs's
    client-facing paths (configuration, OMA-DM, the MSISDN flow) and
    ft-server's reach a service; acs's `/admin` API and console get a 404
    (ADR 0007 §5). WAF logs every request, with the query string and the
    identity and credential headers redacted.
- **Data.**
  - DynamoDB tables `subscribers` and `service-profiles` (hss), `files`
    (ft-server), `msrp-bindings` (msrp-relay) and acs's table. All are on
    demand, with point-in-time recovery and deletion protection in prod.
  - Ahead of their services, with their task roles: `messages` and
    `groupchats` (rcs-as), and `registrations`, `auth-challenges` and
    `reg-subscriptions` (scscf),
    the last three under a key of their own (docs/scscf-state.md).
  - The files bucket.
  - The KMS keys of the HSS keyring, the S-CSCF state and the alarm topic.
  - Twelve generated secrets: the ADR 0007 tokens, current and next, and the
    shared keys.
- **Services.** hss, ft-server, msrp-relay and acs (pinned release, ADR 0006),
  each with its own execution and task role, log group and alarms. Images
  run by digest.
- **Notifications.**
  - The alarms, a daily and a monthly cost budget, and EventBridge rules on
    security group, secret, key policy, task definition and ECS service
    events, all to one encrypted SNS topic.
  - A CloudWatch dashboard (the `DashboardUrl` output).

### What is not deployed yet

- **pcscf, icscf, scscf and rcs-as.** Their security groups exist, and so do
  the tables and task roles of rcs-as and scscf. Their task definitions
  come with their pull requests. `PcscfEnabled`, `IcscfEnabled` and
  `ScscfEnabled` add their listeners and alarms once they exist. Several of
  those alarms watch metrics no service emits yet
  ([runbook](runbook.md#conventions)). pcscf's
  task needs `PCSCF_PUBLIC_ADDRS`: the `NlbPublicAddresses` output. Until
  then no client can register.
- **acs's SMPP provider.** It needs an egress rule to the operator's SMSC.
  `eum` and `sns` work. The acs → hss token is generated but not given to
  acs until an acs release uses it.
- **ALB access logs.** They cannot redact the query string, which carries
  acs's IMSI and MSISDN and ft-server's download ids; the WAF logs, which
  redact it, record the requests instead.
- **IAM change alerts outside us-east-1.** CloudTrail delivers IAM events to
  EventBridge in us-east-1 only, so the `IamPolicyChanges` rule exists only
  in a stack there. A small us-east-1 stack for the account is #229, with
  the least-privilege deploy role of threat model T7.
- **Autoscaling.** Task counts change through the config (#228).
- **HTTP health checks on the NLB.** See [Design notes](#design-notes) (#230).
- **A smoke test.** docs/ft-server.md asks for a 12 MB upload broken off and
  resumed, and a ranged download across a part boundary, against real S3.
  It is not scripted yet.
- **Load tests.** Task counts and sizes follow the service documents, not
  measurements.
- **CI-driven deployment.** Deployment runs from a workstation.

## Prerequisites

- **Tools.** The AWS CLI v2, Docker with buildx, make, git and bash 3.2 or
  later, and access to `ghcr.io`, where the acs release image is copied
  from. The platform image is built for `linux/amd64` (Fargate X86_64). An
  arm64 host needs Docker's emulation for that.
- **One stack per AWS account.** The cost budgets watch the whole account,
  and two stacks in one account would each count the other's spending. If
  dev stacks share an account anyway, set `MonthlyBudgetUsd` and
  `DailyBudgetUsd` to 0 in all but one. deploy.sh tags every resource with
  `rcs:stack=<name>`, so cost allocation can tell them apart once that tag
  is activated.
- **Credentials** that may create the resources above, IAM roles included
  (`CAPABILITY_IAM`), in the target region (default `ap-northeast-2`). The
  deploying role or user is named in the S-CSCF key's policy (deploy.sh sets
  `DeployPrincipalArn`): it may create and restore those tables.
- **Fargate vCPU quota.** A rolling update runs one extra task of every
  service at once: Σ (task vCPU × (desired + 1)). The defaults need 6 vCPU
  in prod (4 services × 3 tasks × 0.5 vCPU), more once the CSCFs and rcs-as
  run, and the default quota of a new account may be just that.
  deploy.sh refuses a deployment above the quota. Check it (read-only), and
  request an increase in time:
  `aws service-quotas get-service-quota --service-code fargate --quota-code L-3032A538`.
- **Elastic IP quota.** A first creation allocates one address per NAT
  gateway and one per NLB subnet not given a retained allocation
  (`NlbAllocationIdA/B`): four in prod. The default quota is 5 per region,
  and addresses an earlier stack retained still count. deploy.sh refuses a
  deployment above it (`--quota-code L-0263D0A3`, service code `ec2`): a
  first creation, or an update that adds NAT gateways or gives up a reused
  NLB address. Reuse the retained NLB addresses
  ([runbook](runbook.md#keeping-the-nlb-addresses)) or release them first.
  A reused address must be free: deploy.sh refuses one attached to anything
  but this stack's NLB.
- **A CloudTrail trail** recording management events in that region.
  Without it the security change rules see nothing.
- **In prod, GuardDuty Runtime Monitoring for Fargate** (ADR 0007 §9). It is
  configured per account, not by this template. Its agent sends through the
  `guardduty-data` endpoint GuardDuty creates, which the tasks' security
  groups do not reach when the interface endpoints are on; until #278
  gives it a path, check the coverage after the first deployment
  (`aws guardduty list-coverage`, read-only) and expect it unhealthy.
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

1. Refuses a config that lacks a parameter, names an unknown one, or quotes
   a value or comments after it. Every problem is listed at once.
2. Refuses a working tree with uncommitted or untracked files, rollbacks
   included: every deployment ships the checkout's template, so it must be
   a commit. The image tag is `git describe` of that commit, and the
   template's commit is recorded as `TemplateRevision`.
3. Stops if the caller's identity cannot be read. It checks that neither
   stack is in a state CloudFormation cannot update, that the Fargate vCPU
   quota fits a rolling update, and, before a first creation, that no name
   the stack would take (tables, secrets, log groups, repositories) is
   still held by an earlier stack's retained resources. Before a first
   creation, and an update that allocates Elastic IPs, it checks that they
   fit the quota. Before an update, it warns when the stack runs the
   template of another commit (`TemplateRevision`), which this run would
   replace.
4. Deploys the registry stack through a change set (below).
5. Builds the platform image (`make image`) and pushes it, unless ECR
   already holds that tag. Tags are immutable.
6. Copies acs's release image `ACS_VERSION` from GHCR into ECR by the digest
   pinned in the script (`ACS_DIGEST`, the same as the local stack's), with
   every platform in it, unless ECR holds it. It refuses an ECR tag whose
   digest is not the pinned one, so ECR runs the bytes that were tested.
7. Uploads `infra/platform.yaml` to the registry stack's bucket (it is
   larger than CloudFormation takes inline) and deploys the platform stack
   through a change set. It passes **every** parameter explicitly: those it
   sets itself (the images by tag and digest, the S3 and DynamoDB prefix
   lists, the deploying principal, `TemplateRevision`, `PreviousImageTag`
   (the image the stack ran before), and the addresses of the NLB
   allocations the config names) and everything else from the config.
   Nothing silently takes a template default or the previous value.
8. Prints the stack's outputs and the rollback command.

The first creation takes about 20 to 30 minutes, mostly the NAT gateways,
the load balancers and the services becoming stable.

`--stack-name` (default `rcs-platform`) names the platform stack. The
registry stack is `<name>-ecr`, and the repositories are `<name>` and
`<name>-acs`.

### Change sets

Each stack changes through a change set. deploy.sh prints every resource it
adds, modifies or removes. It marks with `!!` the resources that hold data
or an address, or what operators added by hand (tables, keys, buckets,
secrets, log groups, repositories, load balancers, the VPC and its subnets,
Elastic IPs, NAT gateways, the namespace, the network ACL with its deny
entries and the alarm topic with its subscriptions) that CloudFormation
removes or **replaces**. A replaced table,
key or bucket starts empty, since the originals are retained, not moved. A
replaced load balancer or namespace gets a new address. Changing `VpcCidr`
or `ServiceNamespace` replaces almost everything. Other replacements, such
as the task definitions every image deployment registers, are listed
without a mark. deploy.sh then asks for the stack name before it runs the
change set, or for `replace <stack>` when anything is marked.

The NLB itself cannot be replaced while it holds the fixed addresses:
CloudFormation creates the new one first, and the addresses are still
taken, so such a change set fails. Change what forces the replacement
(its name, scheme or type) only with a planned address change.

- `--plan` prints the change sets and deletes them without running them.
  It builds and pushes nothing: an image tag not yet in ECR is planned with
  a placeholder digest. A first creation leaves an empty stack in
  `REVIEW_IN_PROGRESS`, which the next run creates afresh.
- `--yes` runs them without asking, for CI. Without it and without a
  terminal, deploy.sh refuses.
- A change set without changes is deleted, and the stack is left alone.

### After the first deployment

1. Point the names at the load balancers (the outputs `AlbDnsName` and
   `NlbDnsName`): `FtHostName` and `AcsHostName` at the ALB, and
   `RelayPublicHost` at the NLB. The NLB's addresses are fixed
   (`NlbPublicAddresses`).
2. Subscribe the on-call address to the `AlarmTopic` output, and confirm the
   subscription. Alarms, budgets and security events reach nobody until
   then. With your own `AlarmTopicArn`, its policy must let
   `cloudwatch.amazonaws.com`, `events.amazonaws.com` and
   `budgets.amazonaws.com` publish, and its key, if any, let them use it.
3. The HSS provisioning API is reachable only from inside the VPC (ADR 0007
   §5). Run provisioning from a task or an internal load balancer that
   carries the `OperatorSecurityGroupId` group. Its token is in the
   `HssAdminTokenSecret` secret. acs's admin API is not on the public ALB
   either.
4. Run the smoke test above by hand until it is scripted.

## Parameters

Each parameter's `Description` in `infra/platform.yaml` is the reference.
`infra/platform.example.params` is a working dev config. A test keeps it in
step with the template.

| Parameter | Template default | What to know |
|---|---|---|
| `Environment` | `prod` | `RCS_ENV` of every service. `staging` and `prod` refuse unsafe settings and need both certificates, the three host names, a real SMS provider, the interface endpoints and (prod) two tasks of every service |
| `VpcCidr` | `10.30.0.0/16` | A /16 of RFC 1918 space (10/8, 172.16/12 or 192.168/16); anything else is refused, because the services dial internal hosts only at private addresses. The subnets are its first four /20s |
| `NatGateways` | `per-az` | `single` saves one gateway, but makes one AZ's outage cut the other's egress. `none` needs the interface endpoints (a Rule refuses it otherwise): with them on, no security group sends to the internet, so the gateways carry nothing until acs's SMPP provider needs a path to an SMSC. Whether staging and prod use `none` is decided after the first verification deployment |
| `NlbAllocationIdA`, `NlbAllocationIdB` | empty | Elastic IPs to give the NLB, such as those an earlier stack retained ([runbook](runbook.md#keeping-the-nlb-addresses)). Empty allocates new ones. The two must differ |
| `InterfaceEndpoints` | `auto` | `auto` is on outside dev and off in dev. Off sends AWS API calls through NAT and gives every group HTTPS to the internet: a dev-only deviation |
| `ServiceNamespace` | `rcs.local` | The Cloud Map namespace. Internal plain HTTP is allowed only to names in it (ADR 0007 §5) |
| `PublicIngressCidr` | `0.0.0.0/0` | Who reaches the NLB and the ALB. Narrow it until real clients use the stack; narrowing it later shuts every client out |
| `AlbCertificateArn`, `NlbCertificateArn` | empty | Empty means plain HTTP on the ALB and plain MSRP on the NLB, which only dev allows |
| `FtHostName`, `AcsHostName`, `RelayPublicHost` | empty | The names clients use, which the certificates must cover. Empty (dev only) uses the load balancers' DNS names |
| `FtDeregistrationDelay` | `300` | Seconds the ALB lets running uploads finish before an ft-server task stops |
| `PcscfEnabled`, `IcscfEnabled`, `ScscfEnabled` | `false` | `true` once that service exists: its listeners (pcscf) and alarms. Set it only after that service's pull request has checked that the service emits the metric names its alarms watch |
| `WafRateLimit`, `WafRateAction` | `10000`, `count` | Requests per client address per 5 minutes, and whether the WAF counts or blocks above it. Carrier-grade NAT puts thousands of handsets behind one address: measure first ([WafRateLimited](runbook.md#wafratelimited)) |
| `ImsDomain`, `FtRealm` | required | The home domain (and IMS realm) and the FT realm. They must differ (ADR 0007 §8) |
| `FtValidityDays` | `7` | `FT_VALIDITY`. The bucket's expiry follows from it |
| `FileEncryption` | `AES256` | `aws:kms` uses the account's `aws/s3` key and adds KMS charges |
| `HssDesiredCount`, `FtServerDesiredCount`, `RelayDesiredCount`, `AcsDesiredCount` | `2` | Tasks per service. Each rolling step adds one task before it stops one. hss at most 7, so a rolling update stays within the 8 addresses a Cloud Map DNS answer lists |
| `HssTaskSize`, `FtServerTaskSize`, `RelayTaskSize`, `AcsTaskSize` | `512x1024` | CPU units × MiB. `GOMEMLIMIT` is set to 85% of it |
| `HssKeyringBootstrap` | `false` | `true` only for the one deployment of [Keyring bootstrap](runbook.md#keyring-bootstrap) |
| `RelayMaxConnections` | `5000` | Client connections per relay task. Size it to the task |
| `SubscribersWarmReadUnits`, `SubscribersWarmWriteUnits`, `MsrpWarmReadUnits`, `MsrpWarmWriteUnits` | `12000`, `4000` | What the tables serve at once in a burst ([sizing](runbook.md#re-registration-burst-sizing)). Raising them is charged once and **cannot be undone**: never lower them in the config, or the deployment fails |
| `MsrpReadBudget` | `1000` | Read units a second on `msrp-bindings` above which `MsrpBindingsReadBudget` fires |
| `AcsSmsProvider`, `AcsSmsOriginationIdentity` | `eum`, empty | `mock` sends nothing and is dev only |
| `AcsDefaultRcsProfile` | `UP_2.4` | The profile acs serves by default |
| `AlarmTopicArn` | empty | An SNS topic of your own; empty creates one, encrypted |
| `MonthlyBudgetUsd`, `DailyBudgetUsd` | `800`, `35` | Cost budgets of the account, notified at 80% and 100%. `0` creates none. One stack per account sets them |
| `ContainerInsights` | `enabled` | About $30 a month at the default size |
| `LogRetentionDays` | `30` | The VPC Flow Logs and the WAF logs |

deploy.sh sets `EcrStackName`, `ImageTag`, `ImageDigest`, `AcsImageTag`,
`AcsImageDigest`, `S3PrefixListId`, `DynamoDbPrefixListId`,
`TemplateRevision`, `PreviousImageTag`, `DeployPrincipalArn`,
`NlbReusedAddressA` and `NlbReusedAddressB`; the config may not. The
template's Rules refuse an allocation without its address or the other way
round, which only a deployment outside deploy.sh could send.

### acs's header enrichment stays off

`ACS_TRUSTED_PROXY_CIDRS` is empty, acs's default. In acs it lists the
client addresses whose identity header (`X-3GPP-Intended-Identity`) acs
believes: the operator gateways on the data path, as the ALB saw them in
`X-Forwarded-For`. It is not a list of proxies in front of acs. No address of
this VPC, the ALB's subnets included, is ever such a client, so any value
would only open a way to forge an identity later (a proxy added in front,
or the ALB's header mode changed). Enable it only with the operator's
gateway ranges, once they exist.

## Cost

Estimated monthly cost in ap-northeast-2 (Seoul). Prices are list prices
from the AWS Price List API on 2026-10-19, without tax, free tier or
discounts. Check them again before you rely on the totals.

| Item | Unit price | Default prod config | Example dev config |
|---|---|---|---|
| Fargate, 0.5 vCPU and 1 GB per task | $0.04656 per vCPU-hour, $0.00511 per GB-hour | 8 tasks: $166 | 4 tasks: $83 |
| NAT gateways | $0.059 an hour, plus $0.059 per GB | 2: $86 | 1: $43 |
| Interface endpoints | $0.013 an hour per AZ, plus $0.01 per GB | 8 in 2 AZs: $152 | off (`auto` in dev) |
| Public IPv4 addresses | $0.005 an hour | 6: $22 | 5: $18 |
| NLB and ALB | $0.0225 an hour each, plus capacity units by traffic | $33 | $33 |
| AWS WAF | $5 per web ACL, $1 per rule, $0.60 per million requests | $6 | $6 |
| Secrets Manager | $0.40 per secret | 12: $4.80 | $4.80 |
| KMS keys (HSS keyring, S-CSCF state, alarm topic) | $1 each, plus $1 per rotation kept (at most $3) | 3: $3 | $3 |
| Cloud Map and its hosted zone | $0.10 per registered instance, $0.50 per zone | $1.30 | $0.90 |
| CloudWatch alarms | $0.10 per alarm metric | 90: $9 | 90: $9 |
| CloudWatch custom metrics (EMF) | $0.30 per metric | about 200 names once every path has run: $60 | fewer while idle: up to $60 |
| Container Insights | as custom metrics, plus its performance logs | about 100 metrics: $30 | disabled |
| CloudWatch dashboard | 3 free per account, then $3 | free | free |
| **Fixed total** | | **about $575** | **about $200 to $265** |

Costs that grow with use:

- **DynamoDB on demand.** $0.1355 per million read units and $0.68 per
  million write units. About $3 per million registrations and $1.5 per
  million re-registrations (docs/hss.md, Sizing). Storage beyond 25 GB is
  $0.27 per GB-month, and point-in-time recovery $0.2166 per GB-month.
- **CloudWatch Logs.** $0.76 per GB ingested and $0.0314 per GB-month
  stored, for the services, the VPC Flow Logs (prod), the WAF logs (one line
  per request) and Container Insights' performance logs.
- **NAT data**, $0.059 per GB: with the interface endpoints, nothing, since
  no security group sends to the internet (GHCR during a deployment runs
  from the workstation, not the VPC); without them, image pulls and every
  AWS API call.
- **Data between AZs** at $0.01 per GB each way: the NLB balances across
  zones, and tasks reach peers in the other AZ.
- **S3** at $0.025 per GB-month for files, which expire after
  2 × `FtValidityDays` + 1 days, and **ECR** at $0.10 per GB-month for
  images.
- **SMS** sent by acs, per message at End User Messaging or SNS prices.
  `AcsOtpVolume` watches it.
- **DNS queries** to Route 53 at $0.40 per million, Cloud Map API calls at
  $1 per million, and KMS requests at $0.03 per 10,000 (the HSS makes one
  per task start).

With the interface endpoints on, `NatGateways=none` saves the gateways
($86 in prod) and their two addresses ($7.30). Cheaper choices outside
prod: `NatGateways=single`, one task per service,
`InterfaceEndpoints=auto` (off in dev), `ContainerInsights=disabled`, and
deleting dev stacks when not in use.

## Rollback

Deploy the previous image with the same config file, from the commit the
stack runs (its `TemplateRevision` output), so only the image changes:

```sh
git checkout <TemplateRevision>
scripts/deploy.sh --config ~/rcs-prod.params --skip-build --image-tag <PreviousImageTag>
```

`--skip-build` builds and pushes nothing and leaves the registry stack as
it is. The tags must already be in ECR (`--acs-image-tag` for acs, default
the pinned release). deploy.sh prints the rollback command with the right
tag at the end of every deployment, and refuses a working tree with
changes, so a rollback never ships an uncommitted template. To roll the
template back too, check out the earlier release's commit instead. See the
[runbook](runbook.md#rollback), also for stacks CloudFormation cannot
update.

## Teardown

```sh
scripts/teardown.sh --stack-name rcs-dev --dry-run
scripts/teardown.sh --stack-name rcs-dev             # needs approval; asks for the name
```

The script asks you to type the stack name, or takes `--confirm <name>`. It
reads the template the stack was deployed with, turns off the load
balancers' deletion protection where it is on (skipping those already
gone; one whose protection cannot be read stops the teardown before
anything changes), deletes the platform stack and waits. If the deletion fails
(`DELETE_FAILED`), it turns back on only the protection it turned off. If
the waiter gives up while the deletion still runs, it changes nothing and
says so. `--with-registry` also empties the template bucket and deletes the
registry stack, after the platform stack.

These are retained, still hold data and are still billed. The script lists
them with their names:

| Resource | Why it is kept | To delete it |
|---|---|---|
| The ten DynamoDB tables | Subscriptions, the keyring item, files, bindings, acs data, messages, group chats, S-CSCF state | Turn off deletion protection (prod), then delete the table |
| The files bucket | Users' files | Empty it, then delete it |
| The HSS keyring and S-CSCF state KMS keys ($1 a month each) | The keyring item and the S-CSCF tables open only with them | Schedule its deletion (7 to 30 days); everything sealed under it is lost after that |
| The NLB's two Elastic IPs ($3.65 a month each) | Clients cache the NLB's address | Give them to the next stack ([runbook](runbook.md#keeping-the-nlb-addresses)), or release them |
| The VPC flow log group (prod) | Audit | Delete the log group |
| The ECR repositories (registry stack) | Images a stack may still start from | Delete the repository with its images |

A new stack of the same name cannot be created while these names are taken:

- the tables (named `<stack>-<table>`);
- the flow log group `/rcs/<stack>/vpc-flow-logs`;
- after `--with-registry`, the repositories `<stack>` and `<stack>-acs`;
- the secrets (`<stack>/...`) while Secrets Manager keeps them scheduled
  for deletion.

deploy.sh checks these names before a first creation and lists those
taken. Delete them, or deploy under another stack name.

Elastic IPs the stack was given (`NlbAllocationIdA/B`) were never its own:
the teardown lists them as kept as they were, neither released nor
counted among the retained resources above.

Dev stacks leave their keys behind at every teardown. Schedule their
deletion with the shortest window when the data is not needed:
`aws kms schedule-key-deletion --key-id <id> --pending-window-in-days 7`.

Reusing retained data in a new stack (CloudFormation import) is not
scripted. If it is done by hand, the retained keys' policies still name
the old stack's roles, which no longer exist. Give each key a policy for the
new stack's roles (`aws kms put-key-policy`) before its service starts:
`HssTaskRole` for the HSS key, and `ScscfTaskRole` and the deploying
principal for the S-CSCF key.

## Design notes

- **NLB health checks are TCP on the traffic port**, not HTTP on the admin
  port. With Proxy Protocol v2 on, AWS sends the PROXY header on health check
  connections too ("After you enable proxy protocol, the proxy protocol
  header is also included in health check connections", Elastic Load
  Balancing guide), and the admin HTTP server does not parse it yet. A TCP
  check proves the task accepts connections, but passes one that is not
  ready; #230 lets the admin ports accept the header and then switches to
  `/readyz`. The ALB targets and the container health checks use `/readyz`
  and `/healthz` already.
- **The NLB has a security group, and client IP preservation is off.** The
  tasks then see the NLB's group as the source, which the ADR 0007 matrix
  needs. The client's address arrives in the PROXY header.
- **Policy checks.** `make infra-lint` runs:
  - cfn-lint on both templates;
  - `scripts/check_infra.py`, which checks:
    - the ADR 0007 matrix, egress held to the endpoints and prefix lists,
      and plain listeners in dev only;
    - the endpoint policies, and the Rules that pair each NLB allocation
      with its address;
    - load balancer ports, PPv2, and the WAF with its rate rule;
    - task hardening and images by digest;
    - table, bucket and topic encryption, and point-in-time recovery;
    - secrets through execution roles only, and only those injected;
    - the readers of the bindings, messages, group chats and S-CSCF
      tables, scans, `Resource: '*'`, wildcard ARNs and `Not*` grants, and
      it refuses an IAM statement it cannot read (a function other than
      `Ref`, `GetAtt` and `Sub`, or an `If` inside an `If`);
    - who may use each key;
    - that each task role grants exactly the actions its service's code
      calls (`infra/task-role-actions.yaml`);
    - hss's start timeout;
    - the alarm rules of docs/architecture.md §8, and a runbook section per
      alarm;
  - shellcheck on the scripts;
  - the tests of the scripts against stubbed `aws`, `docker`, `git` and
    `make`.

  CI runs the same target. Nothing in it calls AWS.
