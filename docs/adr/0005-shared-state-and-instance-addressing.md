# ADR 0005 — Shared state in DynamoDB, instance addressing only where a connection lives

**Status:** accepted

## Context

Every service scales to several tasks. SIP routing is address based: a response
follows `Via`, a terminating request follows `Path`, an in-dialog request follows
`Record-Route`.

## Decision

- Registration bindings, subscriber data, stored messages, group state, MSRP
  bindings and file metadata are in DynamoDB. A service instance keeps only
  transactions, connections and caches in memory.
- `scscf` advertises its **service** name in `Service-Route` and `Record-Route`
  and to the HSS as the S-CSCF name, so any instance can serve any user.
- `pcscf` advertises its **instance** address (task private IP) in `Path` and
  `Record-Route`, because the client's connection lives on that instance.
- `rcs-as` advertises its instance address in `Record-Route`/`Contact` and in
  MSRP paths, because the MSRP session lives on that instance.

## Rationale

Instance addressing exactly where a connection exists, and nowhere else, gives
horizontal scaling without sticky load balancing.

## Consequences

- A `pcscf` or `rcs-as` task that stops drops its connections and sessions;
  clients recover by re-registering and re-establishing sessions, which RCS
  clients already do.
- ECS deployments use a minimum healthy percent of 100 and connection draining so
  rolling updates do not cut every connection at once.
