# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and the
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

No release has been tagged yet, so nothing below breaks an existing deployment.
The IMS core (`hss`, `pcscf`, `icscf`, `scscf`), `ft-server` and `msrp-relay`
run as services, and the local stack runs them together. `rcs-as` runs on its
own and is not in the local stack yet.

### Added

- Repository skeleton: architecture, ADRs 0001–0006, specification references,
  build in a pinned Go container (`make check`), CI with test, fuzz, vuln and
  hygiene jobs, and the privacy allow-list check. (#1)
- Shared service runtime (`internal/runtime`): configuration from the
  environment with every problem reported in one log line before anything
  listens, JSON logs, CloudWatch EMF metrics with `Service` as the only
  dimension, `/healthz` and `/readyz` on the admin port, graceful shutdown under
  `RCS_SHUTDOWN_TIMEOUT`, and the `-version` and `-healthcheck` modes.
  `RCS_ENV` is required. `internal/runtime/runtimetest` runs a service in tests
  without a process. (#18)
- Subscriber identifier masking for logs (`internal/pii`), keyed by
  `RCS_PII_HMAC_KEY` so masked values still correlate across services. (#18)
- Service image (`deploy/Dockerfile`, `make image`): every `cmd/*` binary on a
  distroless, non-root base pinned by digest. `rcs-version` is the default
  command. (#18)
- MILENAGE (`internal/milenage`, TS 35.205/35.206): authentication vectors,
  AUTN and AUTS, and sequence number handling with resynchronisation. (#19)
- SIP and HTTP Digest authentication (`internal/sip/digest`): MD5 and SHA-256
  (RFC 7616, RFC 8760) and Digest AKA (RFC 3310), with stateless nonces any
  instance can verify and replay protection on the nonce-count. (#19)
- SDP library (`internal/sdp`, RFC 8866): parser and serializer that keep
  unknown lines and attribute order, MSRP and file transfer attributes, MSRP
  offer/answer, and the all-or-nothing relay rewrite `pcscf` needs. (#20)
- Diameter base protocol (`internal/diameter`, RFC 6733): codec, dictionary,
  capabilities exchange, watchdog, disconnect, and peer acceptance rules by
  host, host pattern, realm and source network. (#21)
- CPIM, IMDN and conference-info documents (`internal/cpim`, `internal/imdn`,
  `internal/conference`; RFC 3862, RFC 5438, RFC 4575). (#22)
- SIP message layer (`internal/sip`): message model, stream and datagram
  parser, serializer that forwards unchanged header fields byte for byte, SIP,
  SIPS and tel URIs, and typed views of the header fields IMS needs. (#27)
- MSRP (`internal/msrp`, RFC 4975): codec, chunking and reassembly, success and
  failure reports, connections shared by several sessions, keep-alive, and the
  back-to-back `Bridge` the relay uses. (#28)
- Diameter Cx and Sh applications (`internal/diameter/cx`,
  `internal/diameter/sh`), and the IMS user profile with initial filter
  criteria evaluation (`internal/ifc`, TS 29.228). (#41)
- `ft-server`: the File Transfer via HTTP content server (GSMA RCC.07) on S3
  and DynamoDB. Upload with resume, file-info document, download with byte
  ranges, Digest authentication against the HSS or static development users,
  expiry after `FT_VALIDITY` (7 days), and per-user and per-task limits. See
  [docs/ft-server.md](docs/ft-server.md). (#43)
- `make test-integration`: storage backends against S3 and DynamoDB
  containers. (#43, #52)
- `ft-server`: `FT_MAX_DOWNLOADS_PER_UPLOADER` (default 128),
  `FT_MIN_DOWNLOAD_RATE_UNDER_PRESSURE` (16 KiB/s) and
  `FT_DOWNLOAD_PRESSURE_PERCENT` (75). The metrics `download.failed.uploader_busy`
  and `upload.commit_recovered` are new. (#51)
- ADR 0007: plain transport inside the VPC, with security groups as the primary
  control and a scoped bearer token per caller on every internal HTTP API. The
  threat model is in [docs/threat-model.md](docs/threat-model.md). (#45)
- `msrp-relay`: the MSRP anchor at the edge (ADR 0004). A control API for
  `pcscf` ([docs/api/msrp-relay.yaml](docs/api/msrp-relay.yaml)), bindings in
  the DynamoDB table `msrp-bindings`, a data path that clients connect to
  through the NLB and that connects onward to `rcs-as`, and per-task and
  per-source limits. See [docs/msrp-relay.md](docs/msrp-relay.md). (#52)
- PROXY protocol v2 parser (`internal/proxyproto`), shared by the services
  behind the NLB. (#52)
- `scscf`: the Serving-CSCF as a service (`cmd/scscf`). It wires the
  registrar, the reg event notifier and the iFC router to the shared state
  in DynamoDB, the Cx client and one SIP core listener. It names itself to
  the HSS by its service name, and stops in order within the shutdown. See
  [docs/scscf.md](docs/scscf.md). (#14)
- The local stack runs `pcscf` and `scscf` with the rest of the IMS core.
  `stack-init tables` creates `scscf`'s three tables, and `make up` generates
  its keys. `make e2e-compose` now has both test subscribers register with
  IMS AKA through `pcscf`, `icscf` and `scscf`, follow the reg event, and
  reach each other with OPTIONS, to the tel URI and as a capability query
  through the iFC chains. See [docs/local-stack.md](docs/local-stack.md).
  (#14)
- `rcs-sim`: the `options` scenario, and its clients answer an OPTIONS 200
  with their feature tags. See [docs/rcs-sim.md](docs/rcs-sim.md). (#14)

### Changed

- ADR 0004: the MSRP connection direction is reached through SDP answers; no
  offer carries `a=setup:passive` (RFC 6135 §4.2.2). The relay never dials a
  client. A client that answers `passive` has its session ended by `pcscf`,
  and `rcs-as` falls back to pager-mode messaging. (#24)
- Architecture §8: receivers may interpret common deviations leniently, senders
  are strict, and content a service does not own is forwarded byte for
  byte. (#24)
- ADR 0003: keep-alives are sized for the NLB TLS listener's fixed 350 s idle
  timeout. MSRP keep-alive is 240 s, kernel TCP keep-alive is off on
  client-facing listeners, and SIP over UDP is refused in staging and
  prod. (#40)
- ADR 0003: the `pcscf` idle timeout on TCP listeners for flows that negotiated
  a keep-alive is 1740 s, just under the NLB's 1800 s, instead of 1900 s. The
  client then sees a clean close rather than a later reset. ADR 0007 §5 now
  also names IPv6 unique local addresses as private hosts for plain `http`,
  which the code already accepted. (#64)
- `ft-server` defaults for group chats: `FT_MAX_DOWNLOADS_PER_FILE` is 64
  (was 4) and `FT_MIN_DOWNLOAD_RATE` is 4 KiB/s (was 1 KiB/s). The download
  limits must nest (per file ≤ per uploader < per task); staging and prod
  refuse to start otherwise. (#51)
- `ft-server` reports success when its final record update was applied but the
  answer was lost, instead of failing an upload that is complete. (#51)
- `make fuzz` no longer fails on the Go 1.26 fuzz coordinator's deadline race;
  a real failure still fails because it leaves a corpus entry. (#31)
- The MSRP loopback TCP tests wait on progress rather than fixed deadlines, so
  slow CI runners no longer fail them. (#55)
- `HSS_RCS_AS_URI` defaults to `sip:rcs-as.<namespace>;transport=tcp`, as
  rcs-as listens on TCP only, and takes at most a `transport` parameter of
  `tcp` or `tls`. `pcscf`'s core port comes from the shared
  `RCS_PCSCF_CORE_PORT` (default 5070), which `scscf` also reads. (#14)
- A reg event SUBSCRIBE whose dialog's first hop is not the P-CSCF of a live
  binding of the set is refused 403. (#14)

### Security

- No subscriber identifier reaches a log or a metric unmasked; message bodies,
  keys, nonces, RAND/AUTN and tokens are never logged. Types that hold a secret
  format as a fixed placeholder under `fmt`, `log/slog` and
  `encoding/json`. (#18, #19, #41)
- Every parser has a size limit and a fuzz target, rejects ambiguous input
  instead of repairing it, and the XML parsers refuse any `<!DOCTYPE`. (#20,
  #21, #22, #27, #28, #41)
- Initial filter criteria evaluation is bounded in compile size, input size
  and work; a request that hits a limit is refused rather than skipping an
  application server. (#41)
- Internal HTTP APIs require a bearer token per caller of at least 256 bits,
  accept a current and a next token for rotation, and allow plain `http` only
  to a private host; staging and prod refuse to start otherwise. (#43, #45, #52)
- `ft-server` downloads are always `Content-Disposition: attachment` with
  `nosniff`, a sandbox CSP and `private, no-store`. (#43)
- `msrp-relay` stores only the SHA-256 of the client-side session id, lets one
  connection claim a binding across all tasks, refuses malformed session ids
  without a store lookup, rate-limits failed lookups per source, and connects
  only to private addresses on the ports in `RELAY_CORE_PORTS`. (#52)

[Unreleased]: https://github.com/jeonghun-app/rcs-platform/commits/main
