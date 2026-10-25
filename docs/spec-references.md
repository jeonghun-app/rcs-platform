# Specification references

Specifications are cited by number and clause. GSMA and 3GPP text is never copied
into the repository (GSMA documents are licensed; quoting 3GPP text adds nothing a
clause number does not).

The target profile is **RCS Universal Profile 2.4**, the profile `acs` provisions by
default. An edition or item marked *to confirm* is not established by a copy held
by a maintainer or by a public source that meets the evidence rule of
[ADR 0008](adr/0008-target-profile-up-4-0-in-stages.md#decision). Behaviour built
on it carries an "unverified" note in `docs/conformance.md`; the note is not a
row state.

The next target is **RCS Universal Profile 4.0**, reached in stages (ADR 0008).
UP 2.4 stays the target named here until stage 3 of that ADR. No maintainer holds
the UP 4.0 text, so the UP 4.0 edition of every GSMA document below is
*to confirm*. An item counts as UP 4.0 behaviour only under the ADR's evidence
rule, from a row of [Public sources](#public-sources).

## GSMA

| Document | Title (short) | Edition | Used by |
|---|---|---|---|
| RCC.71 | RCS Universal Profile service definition | 2.4, *to confirm* | all RCS services |
| RCC.07 | RCS advanced communications services and client | edition matching UP 2.4, *to confirm* | `rcs-as`, `ft-server`, `pcscf` |
| RCC.11 | Endorsement of OMA CPM for RCS | *to confirm* | `rcs-as` |
| RCC.14 | Service provider device configuration | as in `acs` | `acs` |
| RCC.15 | IMS device configuration and supporting services | *to confirm* | `pcscf`, `scscf` |

## Public sources

Public pages read for the move to UP 4.0 (ADR 0008). Cite a row by the bold short
name at the start of its Source cell. A page is summarised here, never quoted; a
page that could not be opened is not listed.

| Source | Publisher | URL | Date read | Used for |
|---|---|---|---|---|
| **GSMA UP 4.0 article**: *From Rich Text to Video: RCS Universal Profile 4.0 has arrived* | GSMA newsroom (published 2026-03-26) | <https://www.gsma.com/newsroom/article/from-rich-text-to-video-rcs-universal-profile-4-0-has-arrived/> | 2026-10-25 | Announcement that UP 4.0 is finalised, and every new UP 4.0 feature the page names: video calls started from a 1-to-1 or group conversation (messaging-initiated video calls), with late joining by group members and the call log kept in the chat timeline; rich text (bold, italics, strikethrough) with a plain-text review when it falls back to SMS; discovery of the media formats a peer supports, so the sender picks the encoding; streaming video in business rich cards; business control of whether a link opens in the messaging app or another app; more efficient handling of deep links to businesses and of their verification. States no edition, clause or value. |
| **GSMA UP 4.1 article**: *RCS Universal Profile 4.1: Stronger foundations for secure messaging* | GSMA newsroom (published 2026-07-28) | <https://www.gsma.com/newsroom/article/rcs-universal-profile-4-1-stronger-foundations-for-secure-messaging/> | 2026-10-25 | That UP 4.1 followed 4.0; it is not a target (ADR 0008). |
| **Wikipedia RCS article**: *Rich Communication Services*, revision 1378528893 | Wikipedia | <https://en.wikipedia.org/w/index.php?title=Rich_Communication_Services&oldid=1378528893> | 2026-10-25 | List of UP releases with dates and RCC.07 versions. Third-party: a lead to check against GSMA, confirms nothing. |
| **rcsjta**: *android-rcs/rcsjta*, commit f9e1e610880682a6a80869c3757e79f04205bda6 | android-rcs project, GitHub | <https://github.com/android-rcs/rcsjta/tree/f9e1e610880682a6a80869c3757e79f04205bda6> | 2026-10-25 | Open-source Android RCS client stack. At this commit (2017-03-08, the latest) its README names RCS-e Blackbird and the GSMA API (TAPI 1.5.1 and 1.6.1), not a Universal Profile, so it says nothing about UP 4.0. |

## 3GPP

| Document | Subject | Used by |
|---|---|---|
| TS 23.228 | IMS stage 2 | all IMS services |
| TS 24.229 | IMS SIP and SDP stage 3 | `pcscf`, `icscf`, `scscf`, `rcs-as` |
| TS 29.228 / 29.229 | Cx/Dx signalling flows and Diameter protocol | `icscf`, `scscf`, `hss` |
| TS 29.328 / 29.329 | Sh interface, user data XML schema | `hss`, `rcs-as` |
| TS 33.102 | 3G security architecture: AKA, AUTN/AUTS, resynchronisation (§6.3), sequence number management (Annex C) | `hss`, `scscf` (`internal/milenage`) |
| TS 33.203 | IMS access security | `pcscf`, `scscf` |
| TS 35.205 / 35.206 / 35.207 / 35.208 | Milenage algorithm set, implementers' test data (35.207) and conformance test data (35.208) | `hss` (`internal/milenage`) |
| TS 23.003 | Numbering, addressing and identification | `internal/sip`, `hss` |
| TS 23.334 | IMS-ALG and IMS-AGW | `pcscf`, `msrp-relay` |
| TS 23.218 | IMS session handling: use of iFC and ServiceInfo by the S-CSCF | `scscf` (`internal/ifc`) |

## OMA

| Document | Subject | Used by |
|---|---|---|
| OMA CPM (conversation functions, interworking) | Chat, group chat, standalone messaging | `rcs-as` |

## IETF

| RFC | Subject |
|---|---|
| 3261, 3263 | SIP, locating SIP servers |
| 3966 | tel URI |
| 4475, 5118 | SIP torture test messages (IPv4, IPv6) |
| 3581 | Symmetric response routing (`rport`) |
| 3325, 3327, 3608, 7315 | Asserted identity, Path, Service-Route, P-headers for 3GPP (7315 obsoletes 3455) |
| 3840, 3841 | Callee capabilities (feature tags), caller preferences (`Accept-Contact`) |
| 3326 | `Reason` header |
| 3515, 3892 | REFER, `Referred-By` |
| 3428 | SIP MESSAGE |
| 3310, 7616, 8760 | Digest AKA, HTTP Digest (MD5, SHA-256) |
| 4028 | Session timers |
| 4566, 8866, 3264 | SDP and offer/answer |
| 4575, 6665 | Conference event package, SIP events |
| 3680 | Registration event package (reg event): `internal/sip/reginfo`, `pcscf`, `scscf` |
| 4975, 4976, 6135 | MSRP, MSRP relays, MSRP connection model (`a=setup`) |
| 3862 | Common Presence and Instant Messaging (CPIM) message format |
| 5438 | Instant Message Disposition Notification (IMDN) |
| 5626 | SIP outbound (flow tokens) |
| 6223 | Indication of support for keep-alive (Via `keep`) |
| 6733, 4006 | Diameter base protocol |
| 4740 | Diameter SIP application: the Digest-* AVPs that Cx reuses (TS 29.229 §6.3.37 to §6.3.41) |
| 3966 | tel URI: the telephone-subscriber that iFC Request-URI patterns match (TS 29.228 Annex F) |
| 7542 | Network Access Identifier: the user@realm form of a private user identity (IMPI), which `hss` checks on provisioning |
| 6050 | `P-Asserted-Service` and `P-Preferred-Service`: the ICSI the default `hss` service profile sends to `rcs-as` |
| 3539 | AAA transport profile: Diameter watchdog (DWR/DWA, Tw, REOPEN) |
| 4330 | Simple Network Time Protocol: era rule for Diameter `Time` after 2036 |
| 9110 | HTTP semantics: byte ranges, `Range`, `If-Range`, `Content-Range`, partial PUT (`ft-server`) |
| 7578, 2046 | `multipart/form-data` and the multipart boundary (`ft-server` uploads) |
| 6266 | `Content-Disposition` in HTTP (`ft-server` downloads) |
| 3986 | URI syntax: unreserved characters of the FT transaction id |
| 6750 | Bearer token usage: `Authorization: Bearer` and the b64token syntax (internal HTTP APIs, `msrp-relay` control API) |
| 6459 | IPv6 in 3GPP EPS: one /64 per bearer (`msrp-relay` per-source limits) |
| 5482 | TCP user timeout (§1): how long sent data may stay unacknowledged (`msrp-relay` client sockets) |

## Other

| Document | Subject | Used by |
|---|---|---|
| IEEE Std 1003.1-2004 Part 1 §9 | POSIX extended regular expressions, the syntax of iFC patterns (TS 29.228 Annex F) | `internal/ifc` |
| HAProxy `proxy-protocol.txt` | PROXY protocol version 2, the header the AWS NLB sends (ADR 0003) | `internal/proxyproto` |
