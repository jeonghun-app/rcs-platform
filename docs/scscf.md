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

Keys come from Secrets Manager and are the same on every task. Each is a plain
secret, such as CloudFormation's `GenerateSecretString` writes, used as its
bytes; one shorter than 32 bytes is refused, by its name alone. A key is named
in what it seals or signs by the first 8 hex digits of a labelled SHA-256 of
it.

A rotation of `SCSCF_DIALOG_KEY` or `SCSCF_CHALLENGE_KEY` takes three
deploys, so that no task meets a value signed or sealed with a key it does not
hold while a rolling deploy runs old and new tasks side by side, which would
refuse a request inside a dialog 403:

1. the key stays the old one, and `_PREVIOUS` is the new one: every task
   learns the new key, and still signs and seals with the old;
2. the key is the new one, and `_PREVIOUS` the old: every task signs and seals
   with the new key, and still opens what the old one made;
3. once what the old key signed or sealed has expired, `_PREVIOUS` goes.

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
| `SCSCF_CHALLENGE_KEY` | none; required with `dynamodb` | the secret, at least 32 bytes, from which the AES-256 key that seals the challenges in the table is drawn |
| `SCSCF_CHALLENGE_KEY_PREVIOUS` | none | during a rotation, the other key: it does not seal, but opens what it sealed |
| `SCSCF_NONCE_KEY` | none; required | the secret, at least 32 bytes, that authenticates Digest nonces |
| `SCSCF_DIALOG_KEY` | none; required | the secret, at least 32 bytes, that signs the `Record-Route` values and iFC positions (odi) |
| `SCSCF_DIALOG_KEY_PREVIOUS` | none | during a rotation, the other key: it does not sign, but verifies what it signed |
| `SCSCF_ICSCF_URI` | `sip:icscf.<namespace>:5060;transport=tcp;lr` | where an originating request goes once its chain is done |
| `SCSCF_APPLICATION_SERVERS` | `sip:rcs-as.<namespace>:5060;transport=tcp` | the application servers' SIP listeners, comma separated: a request inside a dialog may go to their port and transport |
| `SCSCF_EDGE_PROXY_PUBLIC_HOSTS` | none | the names and addresses clients reach pcscf at, comma separated; a next hop naming one ends a dialog's route set; required in staging and prod |
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

`sip.overloaded` counts the requests refused as overloaded (503 with
Retry-After): at the transaction layer's caps
(`SCSCF_MAX_SERVER_TRANSACTIONS`, `SCSCF_MAX_SERVER_TRANSACTION_BYTES`), or at
the proxy's own bound, which charges headers twice. It is recorded every 15 s
and at the stop, as icscf's and pcscf's are; #56's overload alarm reads it
(#467).

Alarm on a rise of these:

- `registrar.hss_failed`;
- `registrar.reassert_failed`;
- `routing.third_party.dropped`;
- `routing.third_party.end_dropped`: an application server never heard
  that a user ended, so it keeps them registered until the last Expires;
- `routing.third_party.terminated_unanswered`;
- `regevent.notify_dropped`;
- `regevent.final_abandoned`;
- `proxy.hook_panics`, panics recovered in scscf's routing (#428), and
  `transaction.handler_panics`, in a response handler of a request scscf
  sends itself, a NOTIFY or a third-party REGISTER (#445). Each ends only
  the request or the call it was in; alarm on any.

`routing.third_party.evicted` counts refreshes an end took the place of in a
full queue: a server that does not keep up. Each is made good by the user's
next re-registration, so it needs no alarm of its own, but a steady rate says
the server's queue is too short for it.

## Health

`/readyz` fails while no HSS task is connected, as a REGISTER would then be
answered 480.

## Stop

On `SIGTERM`, `scscf` keeps its listener open and runs these steps in order:

1. It drains the requests in progress, for at most `SCSCF_DRAIN_TIMEOUT`.
2. It stops the sweeps.
3. It stops the third-party registrations: none starts after this. It waits
   for those under way and queued, and for the identity repairs, then drops
   what is left and counts it as `routing.third_party.dropped_at_stop`.
4. It waits for the NOTIFYs it queued, and for the first NOTIFY of each
   SUBSCRIBE it answered.
5. It closes the transport, disconnects from the HSS tasks (DPR), and closes
   the proxy.

The stop ends by its deadline, `SCSCF_DRAIN_TIMEOUT` plus 4.5 s from the
`SIGTERM`: half a second inside `RCS_SHUTDOWN_TIMEOUT` at the default drain,
for the proxy's Close and the return. Steps 3 and 4 end 3 s before that
deadline, and step 5 has those 3 s. That is longer than a connection to a
peer takes to open or fail (2 s), so a REGISTER or NOTIFY that began to open
one as the waits ended is done within it. In step 5, the third-party
REGISTERs given up on in step 3 are waited for once the transport has
closed, and then the Cx client says goodbye.

An application server that missed a third-party REGISTER at a stop hears of
the registration at its next refresh. What the stop leaves undone is the other
tasks' sweeps' to finish. Every end of a set is saved before its NOTIFY is
queued, and the lease of a deregistration cut short is finished by the sweep
after it ([docs/scscf-state.md](scscf-state.md)).

## AWS permissions

- DynamoDB on its three tables and their indexes ([docs/scscf-state.md](scscf-state.md)).
- `servicediscovery:DiscoverInstances` in its namespace, to find the HSS tasks.

## Not in place yet

- The compose stack and its end-to-end checks (#14 PR F2).
- Deregistering a user whose SESSION_TERMINATED application server does not
  answer its third-party REGISTER (§5.4.1.7), and sending a re- or
  de-registration to the application server address the initial one reached
  (§5.4.0) (#14 PR F3).
