# Specification references

Specifications are cited by number and clause. GSMA and 3GPP text is never copied
into the repository (GSMA documents are licensed; quoting 3GPP text adds nothing a
clause number does not).

The target profile is **RCS Universal Profile 2.4**, the profile `acs` provisions by
default. An edition marked *to confirm* has not been checked against a copy held by
a maintainer; behaviour built on it is listed as unverified in
`docs/conformance.md`.

## GSMA

| Document | Title (short) | Edition | Used by |
|---|---|---|---|
| RCC.71 | RCS Universal Profile service definition | 2.4, *to confirm* | all RCS services |
| RCC.07 | RCS advanced communications services and client | edition matching UP 2.4, *to confirm* | `rcs-as`, `ft-server`, `pcscf` |
| RCC.11 | Endorsement of OMA CPM for RCS | *to confirm* | `rcs-as` |
| RCC.14 | Service provider device configuration | as in `acs` | `acs` |
| RCC.15 | IMS device configuration and supporting services | *to confirm* | `pcscf`, `scscf` |

## 3GPP

| Document | Subject | Used by |
|---|---|---|
| TS 23.228 | IMS stage 2 | all IMS services |
| TS 24.229 | IMS SIP and SDP stage 3 | `pcscf`, `icscf`, `scscf`, `rcs-as` |
| TS 29.228 / 29.229 | Cx/Dx signalling flows and Diameter protocol | `icscf`, `scscf`, `hss` |
| TS 29.328 / 29.329 | Sh interface, user data XML schema | `hss`, `rcs-as` |
| TS 33.203 | IMS access security | `pcscf`, `scscf` |
| TS 35.205 / 35.206 / 35.208 | Milenage algorithm set and test data | `hss` (`internal/milenage`) |
| TS 23.003 | Numbering, addressing and identification | `internal/sip`, `hss` |
| TS 23.334 | IMS-ALG and IMS-AGW | `pcscf`, `msrp-relay` |

## OMA

| Document | Subject | Used by |
|---|---|---|
| OMA CPM (conversation functions, interworking) | Chat, group chat, standalone messaging | `rcs-as` |

## IETF

| RFC | Subject |
|---|---|
| 3261, 3263 | SIP, locating SIP servers |
| 3325, 3327, 3608, 3455 | Asserted identity, Path, Service-Route, P-headers for 3GPP |
| 3428 | SIP MESSAGE |
| 3310, 7616, 8760 | Digest AKA, HTTP Digest (MD5, SHA-256) |
| 4028 | Session timers |
| 4566, 8866, 3264 | SDP and offer/answer |
| 4575, 6665 | Conference event package, SIP events |
| 4975, 4976, 6135 | MSRP, MSRP relays, MSRP connection model (`a=setup`) |
| 3862 | Common Presence and Instant Messaging (CPIM) message format |
| 5438 | Instant Message Disposition Notification (IMDN) |
| 5626 | SIP outbound (flow tokens) |
| 6733, 4006 | Diameter base protocol |
| 3539 | AAA transport profile: Diameter watchdog (DWR/DWA, Tw, REOPEN) |
| 4330 | Simple Network Time Protocol: era rule for Diameter `Time` after 2036 |
