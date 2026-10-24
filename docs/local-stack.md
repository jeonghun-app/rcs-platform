# Local stack

`deploy/docker-compose.yml` runs the platform on one host:

- the services from the one platform image (`make image`);
- DynamoDB Local and S3Mock in place of DynamoDB and S3, the same pinned images
  as `make test-integration`;
- the pinned `acs` release ([ADR 0006](adr/0006-acs-integration.md)).

Contributors and CI use it to exercise real processes, real DynamoDB and S3
APIs and the released `acs` together. `make e2e-compose` runs
[rcs-sim](rcs-sim.md) against it. The services read the same environment
contracts as in AWS (#56); [Local and AWS](#local-and-aws) lists what differs.

## Prerequisites

- Docker Engine with Compose v2. Tested with Compose v2.40. `make up` uses
  `up --wait` and the `service_completed_successfully` condition.
- GNU make and a POSIX shell. Go is not needed on the host; it runs in the
  toolchain container, as for `make check`.
- About 1 GB of free memory. The stack used about 720 MB after a run of
  `make e2e-compose`, most of it the two JVMs, DynamoDB Local and S3Mock.
- Network access to `ghcr.io` for the `acs` image and to Docker Hub for the
  stand-ins, the first time.

## Using it

```bash
make up            # build the image, start everything, wait until healthy, seed
make e2e-compose   # rcs-sim and the acs checks against the running stack
make bridge-up     # make up, then rcs-bridge (docs/rcs-bridge.md)
make e2e-bridge    # the rcs-bridge test against that compose service
make logs          # the last 200 lines of every service; make logs LOGS="-f hss"
make down          # stop and remove the containers and all data
```

`make up` can be run again on a running stack. It builds the platform and
bootstrap images again and runs the bootstrap again, which leaves existing
tables and subscribers alone. A build can give an image a new ID even when
nothing changed: BuildKit's provenance attestation records the build time. In
that case the service containers are recreated. Their data is in DynamoDB
Local and S3Mock, whose containers keep running.

The first `make up` writes `deploy/compose.env` (`scripts/compose-env.sh`) from
[`deploy/compose.env.example`](../deploy/compose.env.example). The file holds
every setting and fresh random secrets, 256 bits each
([ADR 0007](adr/0007-internal-transport.md) §4). It is readable by its owner
only. Git and docker builds ignore it.

Later runs keep its values. If a later change adds a setting to the example,
`make up` appends it to the file, with a fresh value if it is a secret, and
says which it added. It refuses a file in which a secret is empty. Run
`scripts/compose-env.sh -f` and then `make down` and `make up` for new secrets.
To change a setting, edit `deploy/compose.env`, not the example.

### A second stack on the same host

The stack is named `rcs-local` (`COMPOSE_PROJECT`). The name covers its
containers, its network `rcs-local_default` and its bootstrap image
`rcs-local-stack-init`. Two worktrees on one host that both run `make up` with
the default name share one stack: the second replaces the first's containers
and secrets. To run a second stack beside the first, give it its own name and
host ports:

1. set other `*_HOST_PORT` values in that worktree's `deploy/compose.env`;
2. pass the name to every target, for example
   `make up e2e-compose down COMPOSE_PROJECT=rcs-local-b`.

The services' data is in memory: `make down` loses it, and so does a restart of
DynamoDB Local or S3Mock.

## Services

| Service | Image | Role here | Health |
|---|---|---|---|
| `dynamodb` | `DDBLOCAL_IMAGE` (Makefile) | DynamoDB for `hss`, `scscf`, `rcs-as`, `ft-server` and `msrp-relay`, in memory, one shared database | a bare `GET` answers 400 |
| `s3` | `S3MOCK_IMAGE` (Makefile) | S3 for `ft-server`'s content | `GET /` |
| `stack-tables` | `deploy/stack-init.Dockerfile` | one-shot: creates the tables and the bucket ([Bootstrap](#bootstrap)) | exits 0 |
| `hss` | platform image | subscribers, Cx on 3868, provisioning API | `hss -healthcheck` |
| `ft-server` | platform image | FT via HTTP; credentials from `hss` | `ft-server -healthcheck` |
| `msrp-relay` | platform image | MSRP anchor; plain MSRP, no PROXY header | `msrp-relay -healthcheck` |
| `icscf` | platform image | I-CSCF; finds `hss` as `hss.rcs.local` by DNS ([icscf](icscf.md#settings)), SIP on 5060 | `icscf -healthcheck` |
| `scscf` | platform image | S-CSCF; its state in DynamoDB Local, `hss` by DNS as `icscf` finds it ([scscf](scscf.md)), SIP on 5060 | `scscf -healthcheck` |
| `pcscf` | platform image | P-CSCF; clients' SIP on plain TCP 5060, the core listener on 5070 (`RCS_PCSCF_CORE_PORT`, [pcscf](pcscf.md)) | `pcscf -healthcheck` |
| `rcs-as-a` | platform image | rcs-as, the default profile's application server: chat, pager messages, group chat (off); its queue and groups in DynamoDB Local ([rcs-as](rcs-as.md)), SIP on 5060, MSRP on 2855 | `rcs-as -healthcheck` |
| `acs` | `ACS_IMAGE` (Makefile) | auto-configuration, memory store, mock SMS | the image's own `/healthz` check |
| `stack-seed` | `deploy/stack-init.Dockerfile` | one-shot, after the services are healthy: the test subscriber ([Bootstrap](#bootstrap)) | exits 0 |
| `rcs-bridge` | `deploy/rcs-bridge.Dockerfile` | profile `bridge`, started by `make bridge-up` only: the HTTP and WebSocket bridge of [rcs-bridge](rcs-bridge.md) | `rcs-bridge -healthcheck` |

`-healthcheck` asks the process's own `/healthz` on `RCS_ADMIN_ADDR` (port
8080), as the ECS container health check does. The distroless image has no
shell or curl. `make up` waits until every service is healthy (up to 300 s). The
test of `make e2e-compose` also waits for each `/readyz`, which checks the
stores.

### rcs-as

`rcs-as` runs as one task, `rcs-as-a`, addressed as the D4 design on #121 sets
out, so that a second task can join it with the same settings:

- **Names.** Every task has two network aliases:
  - `rcs-as.rcs.local`, the host of the AS URI `hss` gives `scscf` in the
    default profile (`HSS_RCS_AS_URI`'s default);
  - `conf.rcs.local`, the conference host (`RCSAS_CONFERENCE_HOST`). It is a
    name in the namespace, which `scscf` and the resolvers look up. It is not
    `RCS_IMS_DOMAIN`, which rcs-as refuses. A deployment sets its own.

  Docker's DNS answers each name with every task that has it, as Cloud Map
  does.
- **Its own addresses.**
  - SIP: every task listens on 5060, the port the AS URI names.
    `RCSAS_SIP_HOST` is unset, so each task finds the one private IPv4 address
    of its container, as staging and prod with group chat require.
  - MSRP: each task names itself by an alias only it has, `rcs-as-a.rcs.local`
    (`RCSAS_MSRP_HOST`). `msrp-relay` has the namespace
    (`RCS_SERVICE_NAMESPACE`), so it accepts that name in a `core_path`, and it
    connects on `RELAY_CORE_PORTS` (2855).
- **What it sends** goes to `scscf.rcs.local` (`RCSAS_CORE_URI`'s default in
  the namespace).
- **Group chat** is off (`RCSAS_GROUP_CHAT_ENABLED`): the factory and
  conference URIs are answered 404.

The default profile's criteria send each REGISTER's third-party REGISTER, a
capability query's OPTIONS, a chat INVITE, a MESSAGE and a group chat's roster
SUBSCRIBE to `rcs-as` ([hss](hss.md#default-service-profile)).

### Ports

Published on `127.0.0.1` only. The defaults are in `deploy/compose.env`.

| Host port | Service | What |
|---|---|---|
| 18080 (`ACS_HOST_PORT`) | `acs` | configuration requests, admin API, operator console `/admin/ui` |
| 18081 (`FT_HOST_PORT`) | `ft-server` | upload `/ft`, download `/dl` |
| 18082 (`HSS_API_HOST_PORT`) | `hss` | provisioning API |
| 18083 (`RELAY_CONTROL_HOST_PORT`) | `msrp-relay` | control API (pcscf's) |
| 12855 (`RELAY_MSRP_HOST_PORT`) | `msrp-relay` | MSRP, plain TCP |
| 18000 (`DYNAMODB_HOST_PORT`) | `dynamodb` | DynamoDB API (any credentials) |
| 15060 (`PCSCF_SIP_HOST_PORT`) | `pcscf` | SIP for a client on the host, plain TCP |
| 19090 (`S3_HOST_PORT`) | `s3` | S3 API |
| 8720 (`RCS_BRIDGE_HOST_PORT`) | `rcs-bridge` | its API and event stream ([rcs-bridge](rcs-bridge.md)), with `make bridge-up` |

The admin ports (8080) and Diameter (3868) are reachable on the compose network
only. On the network every service has its compose name: `hss:8081`,
`ft-server:8081`, `msrp-relay:2855` and `:8082`, `icscf:5060`, `scscf:5060`,
`pcscf:5060` and `:5070`, `acs:8080`, `dynamodb:8000`, `s3:9090`. `hss`,
`icscf`, `scscf` and `msrp-relay` also have their Cloud Map names in
`rcs.local`, such as `hss.rcs.local`, which the CSCFs' defaults name.

For example, to read the test subscription with the operator token:

```bash
. deploy/compose.env
curl -s -H "Authorization: Bearer $HSS_ADMIN_TOKEN" \
  http://127.0.0.1:18082/v1/subscriptions/001010000000001@ims.mnc001.mcc001.3gppnetwork.org
```

### Names clients are given

`ft-server`'s upload and download URIs, the relay's `client_path` host and
what `acs` provisions name the compose network: `FT_PUBLIC_BASE`
(`http://ft-server:8081`), `RELAY_PUBLIC_HOST` (`msrp-relay`) and
`PCSCF_PUBLIC_HOST` (`pcscf`). `make e2e-compose` runs on that network and
follows them.

A client on the host can upload to `http://127.0.0.1:18081/ft`, but the
download links it gets back name `ft-server`. To test from the host, set
`FT_PUBLIC_BASE=http://127.0.0.1:18081` in `deploy/compose.env` and run
`make up`. `make e2e-compose` then fails: inside the network `127.0.0.1` is
the test's own container. Change the value back to run it.

## Bootstrap

The services never create their storage. In AWS, CloudFormation does (#56).
Locally, `tools/stack-init` does it, in two one-shot containers built from
`deploy/stack-init.Dockerfile`, which is not part of the service image.

- `stack-init tables` (`stack-tables`) runs before the services start. It
  creates what their documents describe for the infrastructure:
  - `subscribers` and `service-profiles` ([hss](hss.md#tables)), through
    `internal/hss/awsstore.CreateTables`;
  - `registrations`, `auth-challenges` and `reg-subscriptions`
    ([scscf state](scscf-state.md)), through
    `internal/scscf/state/dynamostore.CreateTables`;
  - `messages`, with its `expiry` index, and `groupchats`
    ([rcs-as](rcs-as.md#dynamodb-messages-table)), through
    `internal/rcsas/awsstore.CreateMessagesTable` and `CreateGroupsTable`;
  - `files` with TTL on `ttl` and the bucket `ft-content`
    ([ft-server](ft-server.md#storage));
  - `msrp-bindings` with TTL on `ttl` ([msrp-relay](msrp-relay.md#the-bindings-table)).

  The key names come from the store packages. `make test-integration` checks
  that each store accepts what this creates.
- `stack-init seed` (`stack-seed`) runs once `hss` and `acs` are healthy. It
  provisions rcs-sim's two test subscribers, the client (IMSI
  `001010000000001`, MSISDN `+15550100001`) and the peer (`001010000000002`,
  `+15550100002`), each the same way:
  - `hss`: the subscription of IMPI `<IMSI>@ims.mnc001.mcc001.3gppnetwork.org`,
    IMPUs `sip:<MSISDN>@…` (the default identity) and `tel:<MSISDN>` in one
    implicit registration set ([architecture](architecture.md#4-identities-and-the-home-domain)),
    managed by `acs`, with its own AKA keys (`PUT /aka`), which keeps the SQN
    on a re-run. A subscription that exists is put again, so a stack seeded
    before gains identities added since. The PUT resets every provisioned
    field to the seed's: the identities, the service profile (back to
    `hss`'s default, `rcs-default`), the charging information (none) and
    `acs_managed`, so edits made to the two test subscriptions through the
    provisioning API do not survive a `make up`. The Cx state, the
    credentials and the SQN stay;
  - `acs`: the subscriber, with the overrides in [acs](#acs).

  The keys are `RCS_SIM_AKA_K` and `RCS_SIM_AKA_OPC` for the client and
  `RCS_SIM_PEER_AKA_K` and `RCS_SIM_PEER_AKA_OPC` for the peer, the names
  rcs-sim reads, in `deploy/compose.env`: `make up` generates 128 random bits
  for each, so they are made up for the stack, never a SIM's, and never
  shared by the two subscribers (seed refuses a shared one, #236). The output
  says "client" and "peer", never an identity or a key. Digest passwords are
  not seeded: `hss` issues them, and whoever needs one asks for it, as `make
  e2e-compose` does for FT.

  It is in the compose profile `seed`, and `make up` runs it with
  `docker compose run`. `up --wait` would count a finished one-shot that
  nothing depends on as a failure.

Both commands are idempotent.

## acs

The image is the GHCR release `ACS_VERSION` (1.4.0), pinned by its digest
(`ACS_DIGEST`). `ACS_IMAGE` in the Makefile combines the two. To move to
another release, change both in one pull request: with a digest given, Docker
pulls by digest and ignores the tag.

Locally `acs` runs with:
- `ACS_ENV=dev`;
- the memory store: its DynamoDB table layout belongs to its own repository;
- the mock SMS provider, with `/dev/sms` enabled for the OTP flow by hand;
- `ACS_ADMIN_TOKEN` from `deploy/compose.env`.

Its configuration must point at this stack. `acs` 1.4.0 cannot do that
deployment-wide, so the stack works around it:

| Value | acs 1.4.0 | Here |
|---|---|---|
| home domain, IMPI and IMPU | from the IMSI's MCC and MNC, no setting | `RCS_IMS_DOMAIN` is fixed in the compose file to the same `ims.mnc001.mcc001.3gppnetwork.org`, so `hss` holds what `acs` hands out |
| P-CSCF address (`LBO_P-CSCF_Address`, OMA-CP and OMA-DM) | `pcscf.{ims_domain}`, no setting | per-subscriber override `PCSCF_PUBLIC_HOST` |
| `ftHTTPCSURI`, `ftHTTPDLURI` | `https://ft.{ims_domain}/…`, no setting | per-subscriber override from `FT_PUBLIC_BASE` |
| `ConfFctyURI` | `sip:conf-factory@{ims_domain}`, no setting | per-subscriber override, the same value: `rcs-as`'s own default factory (`RCSAS_CONFERENCE_FACTORY_URI`) |
| `ftHTTPCSUser`, `ftHTTPCSPwd` | not provisioned | not provisioned; `make e2e-compose` issues the FT password from `hss` itself |
| IMS credentials from `hss` | not called | `HSS_ACS_TOKEN` is set, unused |

The missing pieces are `acs` work:
- deployment-wide address settings:
  [auto-configuration-server#70](https://github.com/jeonghun-app/auto-configuration-server/issues/70);
- calling the `hss` with a scoped token:
  [#68](https://github.com/jeonghun-app/auto-configuration-server/issues/68);
- provisioning the FT credentials:
  [#69](https://github.com/jeonghun-app/auto-configuration-server/issues/69).

When a release has them, the override seeding goes and the compose file sets
the new `ACS_` variables.

`make e2e-compose` fetches the test subscriber's configuration as `acs`'s own
deployment check does: a token issued through the admin API, then an RCC.14
request. It checks:
- that the identities it hands out are the ones `hss` holds: IMPI, IMPU and
  home domain;
- the overridden values.

The `acs` admin API stores an override key it does not know without complaint
(#70), so a mistyped key shows only in this check. That holds for the FT URIs
and the OMA-CP P-CSCF address, whose overrides differ from the defaults. It
does not hold for two keys:
- `ConfFctyURI`: its override equals the default, which is also `rcs-as`'s;
- the OMA-DM P-CSCF node: the test makes no DM session.

Both keys were checked by hand against the v1.4.0 catalogue.

## make e2e-compose

The test (`tools/rcs-sim/e2e`, build tag `e2ecompose`) runs in the toolchain
container on the stack's network (`<COMPOSE_PROJECT>_default`), with
`deploy/compose.env` as its environment. It:

1. waits for the `/readyz` of `hss`, `ft-server`, `msrp-relay`, `icscf`,
   `scscf`, `pcscf`, `rcs-as-a` and `acs`;
2. checks `acs`'s configuration document, as above;
3. issues the test subscriber's FT password through the `hss` API;
4. runs `rcs-sim ft ft-resume`: the FT scenarios go to the `ftHTTPCSURI`
   `acs` provisioned. `ft-server` looks the credentials up in `hss` and keeps
   the content in S3Mock and DynamoDB Local. The chat scenarios that stand in
   for `pcscf` and `rcs-as` are `make e2e`'s; here chat goes over SIP (5).
5. runs `rcs-sim reg-event options pager-message chat-invite` over SIP, at the P-CSCF `acs`
   provisions. Both test subscribers register with IMS AKA, with the keys
   `stack-seed` gave `hss`, through `pcscf`, `icscf` and `scscf`:
   - `reg-event` subscribes to the client's own registration and follows it
     through a refresh and the de-registration. Its network-deregister step
     is skipped: rcs-sim has no way to ask for one yet.
   - `options` sends the peer an OPTIONS to its tel URI and a capability
     query to its SIP URI, through `scscf`'s originating and terminating
     iFC chains; `rcs-as` passes the capability query on.
   - `pager-message` sends the peer a MESSAGE with CPIM and an IMDN request
     through `rcs-as`, which stores it and delivers it, and the peer's
     delivery notification comes back the same way. A second MESSAGE, to the
     peer unregistered, waits in `rcs-as`'s queue until the peer registers
     again. The test checks that `rcs-as` answered both, and the
     notification's MESSAGE, 202, which the peer's client never answers, so
     none went past it.
   - `chat-invite` sends the peer an INVITE with an MSRP offer. `pcscf`
     anchors it at `msrp-relay` and `scscf` takes it to `rcs-as`, which
     answers with the relay's `client_path`. The client connects there, and
     `rcs-as` opens a chat to the peer for the client's message, which the
     peer answers and connects to the relay for. A message goes each way,
     with its success report and its delivery and display notifications,
     and one in 2 KiB chunks. The client's BYE ends the chat, and the relay
     then refuses its session with 481. Then the peer ends its chats and
     unregisters, and the client opens a chat to it: `rcs-as` answers 200
     and keeps the message, and once the peer registers again it opens a
     chat of its own to the peer and delivers the message there. The test
     checks the 200, that the message came on that new chat, and that it
     came whole.
6. runs `rcs-sim options` once more, with the client's OPTIONS in the
   originating session case sent through two more application servers:
   stubs on the test container, which act as proxies and send them back to
   `scscf` with the iFC position it signed, ahead of `rcs-as`. The test
   gives the client a service profile of its own for this, `hss`'s default
   with those criteria first, `SESSION_TERMINATED`, and puts the default
   back at the end (as `stack-seed` does at every `make up`). Each stub must
   have taken both OPTIONS, the second after the first.
7. checks the results of every run by the same rules as `make e2e`: every
   step, the resume bounds, no busy retries, nothing secret or identifying
   in the output.
8. in a test of its own, runs [rcs-bridge](rcs-bridge.md#tests) on the test
   container: two of its endpoints register through the IMS core, a message
   sent with no event stream open is kept by `rcs-as` until there is one, a
   message goes from one to the other through `rcs-as` with its delivery and
   display notifications, and one to the receiver offline arrives once it is
   online again.

The CI job "end to end (compose stack)" runs `make bridge-up` (`make up` and
[rcs-bridge](rcs-bridge.md)), `make e2e-compose`, `make e2e-bridge`, `make
logs` on failure, and `make down`.

## Local and AWS

The services read the same variables in both places, as their documents
describe them. #56 provides the AWS values. Locally:

| Setting | Local | AWS |
|---|---|---|
| `RCS_ENV` | `dev` | `staging` or `prod` |
| stop grace | `stop_grace_period: 25s`, above `RCS_SHUTDOWN_TIMEOUT` 20 s | the task definition's `stopTimeout` (at most 120 s), above `RCS_SHUTDOWN_TIMEOUT` ([msrp-relay](msrp-relay.md#settings)) |
| `RCS_IMS_DOMAIN` | fixed, `ims.mnc001.mcc001.3gppnetwork.org` (see [acs](#acs)) | the operator's IMS domain |
| `HSS_DYNAMODB_ENDPOINT`, `SCSCF_DYNAMODB_ENDPOINT`, `FT_DYNAMODB_ENDPOINT`, `FT_S3_ENDPOINT`, `RELAY_DYNAMODB_ENDPOINT` | `http://dynamodb:8000`, `http://s3:9090` | unset |
| `AWS_*` credentials | `local` | the task role |
| hss data key | `HSS_DATA_KEY` (dev keyring path) | `HSS_KMS_KEY_ID` |
| tokens, `FT_NONCE_KEY`, `RCS_PII_HMAC_KEY`, `scscf`'s keys | `deploy/compose.env` (`scscf`'s as `SCSCF_NONCE_KEY`, `SCSCF_DIALOG_KEY` and `SCSCF_CHALLENGE_KEY`) | Secrets Manager |
| `ICSCF_HSS_DISCOVERY`, `SCSCF_HSS_DISCOVERY` | `dns`, `hss.rcs.local` | `cloudmap` |
| `PCSCF_CLIENT_TRANSPORT` | `tcp`, no TLS | `nlb-tls` or `tls` |
| `RELAY_PUBLIC_TLS`, `RCS_PROXY_PROTOCOL` | `false`, `false` (no NLB) | `true`, `true` |
| `FT_UPLOAD_URI`, `FT_DOWNLOAD_URI` | `http://ft-server:8081/…` | `https://` names on the ALB |
| `FT_HSS_URL` | `http://hss:8081` | the Cloud Map name, `RCS_SERVICE_NAMESPACE` set |
| tables and bucket | `stack-init tables` | CloudFormation, with point-in-time recovery and deletion protection |
| `acs` store and SMS | memory, mock | DynamoDB, an SMS provider |

## Adding a service

1. Give the service its own document with its settings, as
   [hss](hss.md#configuration) has.
2. In `deploy/docker-compose.yml`, replace its placeholder:
   - `<<: *platform` for the image, `depends_on` on `stack-tables`, and
     `restart: "no"`;
   - `command: ["<binary>"]`;
   - `environment: { <<: *shared, ... }` with the document's variables;
   - a `healthcheck` running `/usr/local/bin/<binary> -healthcheck`.

   Publish a port on `127.0.0.1` only if a person on the host needs it, and add
   it to `deploy/compose.env.example` and [Ports](#ports).
3. Put new secrets in `deploy/compose.env.example` with an empty value. Teach
   `scripts/compose-env.sh` to fill them. It refuses to write a file with an
   empty `*TOKEN` or `*KEY`.
4. If the service needs a table or a bucket, create it in `tools/stack-init`
   from the store package's exported names, and extend its integration test.
5. Add what `make e2e-compose` should check, and update this page.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `make up` stops at "Waiting" and then fails with a service unhealthy | `make logs LOGS="<service>"`. A setting the service refuses is reported at start, every problem at once. |
| "port is already allocated" | Another process uses a host port. Change it in `deploy/compose.env`. |
| "not in deploy/compose.env; make up adds new settings to it" | The env file lacks a setting. `make up` adds it (`scripts/compose-env.sh`); running `docker compose` directly does not. |
| "run make up, which …" for an image variable | The compose file was used without make. Use the make targets, which set the image variables. |
| Another worktree's `make up` replaced this stack's containers, or `make e2e-compose` gets 401 from a stack it did not start | Both use the default `COMPOSE_PROJECT`. See [A second stack on the same host](#a-second-stack-on-the-same-host). |
| `stack-tables` fails with "only some of the hss tables exist" (or the scscf tables) | A half-made stack. Run `make down` and `make up`. |
| `make e2e-compose` fails with `REGISTER answered 500` right after several runs | `scscf`'s challenge budget per IMPI, 10 a minute (`registrar.challenge_limited` in its metrics): each run registers the client afresh five times. Wait a minute and run it again. |
| `stack-seed` answers 401 | `deploy/compose.env` changed after the services started. Run `make up` again to recreate them, or `make down` and `make up`. |
| `make e2e-compose`: "no local stack rcs-local is running: run make up first" | The stack's network does not exist, or `deploy/compose.env` is missing. Run `make up` first; the test does not start the stack. With another `COMPOSE_PROJECT`, pass the same name to both. |
| `make e2e-compose`: "… is not ready: is the stack up" | The stack exists but a service is not ready within the test's wait. `make logs LOGS="<service>"`. |
| `make e2e-compose`: wrong FT URIs from `acs` | `FT_PUBLIC_BASE` was changed after the subscriber was seeded. `make up` seeds it again. |
| The `acs` image does not pull | `ghcr.io` is unreachable, or `ACS_VERSION` and `ACS_DIGEST` do not belong together. |
| Out of memory or very slow on Docker Desktop | Give the VM more memory. DynamoDB Local and S3Mock take about 650 MB together. |
