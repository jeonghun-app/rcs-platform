# Security policy

## Reporting a vulnerability

Report privately through GitHub's
[private vulnerability reporting](https://github.com/jeonghun-app/rcs-platform/security/advisories/new):
the repository's **Security** tab, then **Report a vulnerability**. The fix, the
advisory and any CVE request are coordinated in that draft advisory.

Do not open a public issue for anything exploitable.

Include the version or commit, reproduction steps and the impact you believe it
has. Expect an acknowledgement within a few working days.

## Scope

In scope: this repository's source, container image, CloudFormation templates and
scripts. The Auto Configuration Server has its own policy in
[auto-configuration-server](https://github.com/jeonghun-app/auto-configuration-server/security).

Out of scope: the GSMA, 3GPP, OMA and IETF specifications themselves, and
third-party dependencies (report those upstream; a note here is welcome).

## This platform handles subscriber data and credentials

The HSS stores IMSIs, MSISDNs, SIM keys (Ki, OPc) and digest credentials; the
CSCFs and the application server see every subscriber's signalling and message
content. Treat as high severity any finding that exposes those, including to an
operator's own logs, or that lets one subscriber act as, or read the messages of,
another.
