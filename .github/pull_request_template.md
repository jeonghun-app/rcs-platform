Closes #

## What this changes

<!-- One paragraph: what and why. -->

## Specification impact

- [ ] No change to wire behaviour
- [ ] New or changed wire behaviour (cite document and clause below)
- [ ] Changes an internal HTTP API or a table schema

Clauses:

## Verification

- [ ] `make check` clean (paste the summary)
- [ ] New behaviour has a test; a bug fix has a test that failed before it
- [ ] New parsers have a fuzz target, and `make fuzz` ran
- [ ] End-to-end (`tools/rcs-sim` against the compose stack), if a flow changed

## Privacy and security

- [ ] No raw IMSI, IMEI, MSISDN, key, nonce, token or message body reaches a log or metric
- [ ] Any new identifier in a test uses MCC 001 and is on the allow-list
