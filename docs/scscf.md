# scscf

`scscf` is the Serving-CSCF of the IMS core (TS 24.229 §5.4): the registrar,
the notifier of the reg event package, and the service router that takes a
user's requests along the iFC of the user's service profile to the
application servers. Its state is in DynamoDB, shared by every task
([ADR 0005](adr/0005-shared-state-and-instance-addressing.md),
[docs/scscf-state.md](scscf-state.md)), so any task serves any user.

## What it does

The proxy hands each request to the part that serves it:

- **REGISTER** goes to the registrar (§5.4.1). It challenges with the HSS's
  vector (IMS AKA or SIP Digest, MAR), assigns the user (SAR), stores the
  bindings, and answers 200 with the `Service-Route`. The servers whose
  criteria take the REGISTER get a third-party REGISTER (§5.4.1.7).
- **SUBSCRIBE for the reg event**, initial or in its dialog, goes to the
  notifier (§5.4.2.1). Its NOTIFYs go only to the P-CSCF a live binding of the
  set came over.
- **Any other request outside a dialog** goes along the served user's iFC
  chain. Along a `Service-Route` (`orig`) it is originating, and when the chain
  is done it goes to the I-CSCF (`SCSCF_ICSCF_URI`). Otherwise it is
  terminating and goes to the user's contacts.
- **A request inside a dialog** goes along its route, only to a hop the dialog
  was set up through, a P-CSCF on `RCS_PCSCF_CORE_PORT`, or an application
  server in `SCSCF_APPLICATION_SERVERS`.

What `scscf` sends itself, NOTIFYs and third-party REGISTERs, goes in client
transactions over the core listener, to the first `Route` or else the
Request-URI.

Every task names itself by its service name, `sip:scscf.<namespace>`, never a
task's own:

- to the HSS, as the Server-Name of every SAR, which the HSS hands the I-CSCF;
- in the `Service-Route` it returns;
- in the `Record-Route` it adds.

So any task serves what another started. icscf routes only to Server-Names
that match its own S-CSCF list (`ICSCF_SCSCF`).

## Listener

`scscf` has one SIP listener, `SCSCF_CORE_ADDR` (TCP). `pcscf`, `icscf` and
the application servers reach it by security group
([ADR 0007](adr/0007-internal-transport.md)). No client reaches `scscf`.

## Settings

The shared `RCS_` settings are in `internal/runtime`; `RCS_IMS_DOMAIN` is
required. `RCS_PCSCF_CORE_PORT` (default `5070`) is shared with `pcscf`. It is
the port of pcscf's core listener, the only one where `scscf` sends a P-CSCF
the requests inside a dialog.

Keys come from Secrets Manager and are the same on every task. Each key list
is `id:base64` pairs, comma separated, the first the one that signs or seals.

| Variable | Default | Meaning |
|---|---|---|
| `SCSCF_NAMESPACE` | `RCS_SERVICE_NAMESPACE`, else `rcs.local` | Cloud Map namespace: `hss`, `icscf` and `rcs-as` are found in it |
| `SCSCF_CORE_ADDR` | `0.0.0.0:5060` | the SIP listener |
| `SCSCF_CORE_HOST` | the task's private IPv4 address | this task's address, in the Via of what it forwards |
| `SCSCF_DIAMETER_HOST` | `scscf-<random>.<namespace>` drawn at start | this task's Diameter identity; leave unset in ECS (refused in staging and prod) |
| `SCSCF_DIAMETER_REALM` | `RCS_IMS_DOMAIN` | this task's Diameter realm |
| `SCSCF_HSS_REALM` | `SCSCF_DIAMETER_REALM` | the HSS's realm |
| `SCSCF_HSS_DISCOVERY` | `cloudmap` | how the HSS tasks are found: `cloudmap`, or `dns` (refused in staging and prod), as icscf's |
| `SCSCF_HSS_HOST_PATTERN` | `hss-*.<namespace>` | the Origin-Host every HSS task must have; in staging and prod only `<prefix>*.<namespace>` |
| `SCSCF_CX_TIMEOUT` | `5s` | one Cx attempt |
| `SCSCF_STORE` | `dynamodb` | `dynamodb`, or `memory` for one task in development (refused in staging and prod) |
| `SCSCF_REGISTRATIONS_TABLE`, `SCSCF_CHALLENGES_TABLE`, `SCSCF_SUBSCRIPTIONS_TABLE` | `registrations`, `auth-challenges`, `reg-subscriptions` | the tables ([docs/scscf-state.md](scscf-state.md)) |
| `SCSCF_DYNAMODB_ENDPOINT` | none | DynamoDB Local's address in the compose stack; refused in staging and prod |
| `SCSCF_CHALLENGE_KEYS` | none; required with `dynamodb` | AES-256 keys the challenges are sealed with in the table |
| `SCSCF_CHALLENGE_SEAL_KEY_ID` | the only key | the key that seals, during a rotation |
| `SCSCF_NONCE_KEY` | none; required | base64 key, at least 32 bytes, that authenticates Digest nonces |
| `SCSCF_DIALOG_KEYS` | none; required | the current key and at most the previous one, at least 32 bytes each, that sign the `Record-Route` values and iFC positions (odi) |
| `SCSCF_ICSCF_URI` | `sip:icscf.<namespace>:5060;transport=tcp;lr` | where an originating request goes once its chain is done |
| `SCSCF_APPLICATION_SERVERS` | `sip:rcs-as.<namespace>:5060;transport=tcp` | the application servers' SIP listeners, comma separated: a request inside a dialog may go to their port and transport |
| `SCSCF_EDGE_PROXY_PUBLIC_HOSTS` | none | the names and addresses clients reach pcscf at, comma separated; a next hop naming one ends a dialog's route set |
| `SCSCF_AS_TIMEOUT` | `5s` | wait for an application server's answer to a request other than INVITE, after which its default handling applies |
| `SCSCF_THIRD_PARTY_TIMEOUT` | `10s` | one third-party REGISTER's transaction |
| `SCSCF_MAX_THIRD_PARTY` | `256` | third-party REGISTERs at one application server at a time |
| `SCSCF_NOTIFY_TIMEOUT` | `10s` | one NOTIFY's transaction |
| `SCSCF_SWEEP_INTERVAL`, `SCSCF_SWEEP_LIMIT` | `10s`, `100` | how often the registration and subscription sweeps run, and how many items one handles at once |
| `SCSCF_DRAIN_TIMEOUT` | `RCS_SHUTDOWN_TIMEOUT` less 5 s | how long a stop waits for the requests in progress |
| `SCSCF_MAX_SERVER_TRANSACTIONS`, `SCSCF_MAX_SERVER_TRANSACTION_BYTES` | as icscf's | the requests held at once, and their memory |

The registrar's own limits keep their package defaults: Expires,
challenge lifetime and counts, and the unregistered state's TTL
(`internal/scscf/registrar`).

## Metrics

Counters, by the names the packages' documentation lists:
`registrar.*`, `regevent.*`, `routing.*` and `ifc.*`. `cxclient.*` counts the
Cx answers by result code and their latency.

Alarm on a rise of these:

- `registrar.hss_failed`;
- `registrar.reassert_failed`;
- `routing.third_party.dropped`;
- `routing.third_party.terminated_unanswered`;
- `regevent.notify_dropped`;
- `regevent.final_abandoned`.

## Health

`/readyz` fails while no HSS task is connected, as a REGISTER would then be
answered 480.

## Stop

On `SIGTERM`, `scscf` keeps its listener open and runs these steps in order:

1. It drains the requests in progress, for at most `SCSCF_DRAIN_TIMEOUT`.
2. It stops the sweeps.
3. It stops the third-party registrations: none starts after this.
4. It waits for the NOTIFYs it queued, for no longer than the rest of the
   shutdown.

What it leaves undone is the other tasks' sweeps' to finish. Every end of a
set is saved before its NOTIFY is queued, and the lease of a deregistration
cut short is finished by the sweep after it ([docs/scscf-state.md](scscf-state.md)).

## AWS permissions

- DynamoDB on its three tables and their indexes ([docs/scscf-state.md](scscf-state.md)).
- `servicediscovery:DiscoverInstances` in its namespace, to find the HSS tasks.

## Not in place yet

- The compose stack and its end-to-end checks (#14 PR F2).
- Deregistering a user whose SESSION_TERMINATED application server does not
  answer its third-party REGISTER (§5.4.1.7), and sending a re- or
  de-registration to the application server address the initial one reached
  (§5.4.0) (#14 PR F3).
