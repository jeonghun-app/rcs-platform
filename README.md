# rcs-platform

[한국어](README.ko.md)

A GSMA RCS (Universal Profile) service platform written from scratch in Go: the IMS
core (P-CSCF, I-CSCF, S-CSCF, HSS), the RCS messaging application server, an MSRP
relay and an HTTP file transfer server, each a separate service, deployable to AWS
with one command. Device configuration comes from
[auto-configuration-server](https://github.com/jeonghun-app/auto-configuration-server).

> **Status: under construction.** The services are being built in the order of the
> [roadmap](#roadmap). Nothing here is production-ready yet.

## Status

Built and merged on `main` (details in [CHANGELOG.md](CHANGELOG.md)):

- **Libraries**: service runtime, identifier masking, SIP messages, SIP/HTTP
  Digest and AKA, Milenage, SDP, Diameter base, Cx and Sh, iFC, MSRP, CPIM,
  IMDN, conference-info, PROXY protocol v2.
- **Services**: the IMS core, `hss` ([docs](docs/hss.md)), `pcscf`
  ([docs](docs/pcscf.md)), `icscf` ([docs](docs/icscf.md)) and `scscf`
  ([docs](docs/scscf.md)), and `ft-server` ([docs](docs/ft-server.md)) and
  `msrp-relay` ([docs](docs/msrp-relay.md)).
- **In progress**: `rcs-as` ([docs](docs/rcs-as.md)) runs in the local stack
  as the IMS core's application server. Pager messages run end to end there;
  chat does not yet, since `rcs-sim` has no chat over SIP.
- **Tools**: the client simulator `rcs-sim` ([docs](docs/rcs-sim.md)) and the
  local stack ([docs](docs/local-stack.md)). In the local stack a client
  registers through the IMS core with IMS AKA, follows its registration (reg
  event), reaches another client with OPTIONS, and sends it pager messages
  through `rcs-as`, which stores one for a client that is not registered.
- **Decisions**: ADRs 0001–0007 and the [threat model](docs/threat-model.md).

There is no release yet.

## Services

| Service | What it does |
|---|---|
| `pcscf` | SIP entry point for clients (TCP/TLS), identity assertion, MSRP anchoring control |
| `icscf` | S-CSCF selection and location queries over Diameter Cx |
| `scscf` | Registrar, IMS AKA and SIP Digest authentication, iFC routing to application servers |
| `hss` | Subscribers, credentials, service profiles; Diameter Cx/Sh; HTTP provisioning API |
| `rcs-as` | 1-to-1 Chat, Group Chat, Standalone Messaging, IMDN, store-and-forward |
| `msrp-relay` | MSRP media anchor at the network edge |
| `ft-server` | File Transfer via HTTP content server (upload, resume, download) on S3 |
| `acs` | RCS auto configuration, from its own repository |

Every SIP, SDP, Diameter, MSRP, CPIM, IMDN and Milenage implementation lives in this
repository; runtime dependencies are the Go standard library and the AWS SDK.
See [docs/architecture.md](docs/architecture.md) and the
[architecture decision records](docs/adr/README.md).

## Building

Only Docker is needed; Go runs in a pinned container.

```bash
make check     # format, vet, tests, race detector, build, docs links, privacy
make fuzz      # every parser's fuzz target
make vuln      # go mod verify + govulncheck
```

The whole platform runs locally with docker compose: the services, DynamoDB
Local, S3Mock and the pinned `acs` release. See
[docs/local-stack.md](docs/local-stack.md).

```bash
make up            # start the local stack and wait until it is healthy
make e2e-compose   # the client simulator against it
make down          # stop it and remove its data
```

## Roadmap

1. Protocol foundations: service runtime, SIP stack, SDP, Diameter, MSRP, CPIM/IMDN, Milenage
2. HSS with Cx and the provisioning API
3. P-CSCF, I-CSCF and S-CSCF: registration, authentication, routing
4. MSRP relay and P-CSCF media anchoring
5. RCS application server: capability discovery, 1-to-1 Chat, Standalone Messaging, IMDN, store-and-forward
6. Group Chat
7. File Transfer via HTTP
8. ACS integration, full local stack, AWS infrastructure and end-to-end verification

## Specifications

Specifications are cited by document and clause, never quoted; see
[docs/spec-references.md](docs/spec-references.md).

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE).
