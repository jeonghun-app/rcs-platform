# Contributing

## Getting set up

Only Docker is needed on the host. Go runs in the pinned toolchain container.

```bash
make check       # format, vet, tests, race detector, build, docs links, privacy
make fuzz        # every fuzz target for FUZZTIME (default 10s) each
make vuln        # go mod verify + govulncheck
```

`make check` must be clean before a pull request is ready for review.

## Where things go

Read [docs/architecture.md](docs/architecture.md) first. In short: protocol
libraries in `internal/<protocol>/`, service logic in `internal/<service>/`, wiring
only in `cmd/<service>/`. A service never imports another service's package.

## Conventions

- Comments, docs and commit messages are in English. Comments explain *why*; a
  comment restating the code will be removed. A comment recording a specification
  subtlety (with the clause number) or a security reason is valuable.
- Every package starts with a doc comment saying what the package is for.
- Wire-level names keep the specification's spelling exactly (`P-Asserted-Identity`,
  `Message-ID`, `Byte-Range`).
- Tests are named as sentences describing behaviour
  (`TestUnknownTransportParameterIsKept`). Table-driven tests are preferred for
  protocol rules. Every parser has a `Fuzz*` target.
- Time, randomness and the network are injected, so tests never sleep for real
  timers and never depend on the order of goroutines.
- Runtime dependencies are the standard library and `aws-sdk-go-v2`. Anything else
  needs an ADR (`docs/adr/`).

## Specifications

**Do not paste specification text into this repository.** GSMA documents are
licensed. Cite the document and clause, for example `RCC.07 §3.2.5.1`, or
`RFC 4975 §7.1.1`.

## Privacy

- No real IMSI, IMEI, MSISDN, key or credential anywhere: code, tests, logs, issues,
  pull requests. Test IMSIs use MCC 001 / MNC 01 and are listed in
  `.github/allowed-test-identifiers.txt`; `make privacy` enforces it.
- Identifiers reach a log only through `internal/pii`. Message bodies, keys,
  nonces, RAND/AUTN and tokens never reach a log.

## Commits and pull requests

Imperative subject lines under about 70 characters, no Conventional Commits prefix.
Explain the reasoning in the body. Keep a pull request to one concern and fill in
every section of the template.

## Security

Do not open a public issue for an exploitable finding. See [SECURITY.md](SECURITY.md).
