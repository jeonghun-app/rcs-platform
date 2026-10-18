// Package hss is the Home Subscriber Server of the platform's IMS core: it
// keeps the subscribers (identities, credentials, service profiles,
// S-CSCF assignment and registration state), answers the Cx requests of
// icscf and scscf, and serves the HTTP provisioning API that operators,
// acs and ft-server use (docs/architecture.md §2, ADR 0006, ADR 0007).
//
// The pieces:
//
//   - HSS holds the subscriber logic both front ends share: reads, writes
//     that retry on version conflicts (internal/hss/store), and sealing and
//     opening the secrets (internal/hss/keyring).
//   - CxServer answers UAR, MAR, SAR and LIR following the procedures of
//     TS 29.228 §6.1 and §6.3. procedures.go holds their rules as functions
//     of a subscription, so each is a table test.
//   - Pusher sends the HSS-initiated RTR and PPR (TS 29.228 §6.1.3, §6.2.2)
//     by Destination-Realm to any connected S-CSCF peer (ADR 0005).
//   - API is the provisioning API under /v1/, documented in
//     docs/api/hss.yaml, with bearer tokens scoped per caller.
//   - Configure and Run wire them for cmd/hss; docs/hss.md is the
//     operator's guide.
//
// Two tasks may serve the same subscriber at the same moment. Every write
// is conditional on the version read, so for example two MARs cannot hand
// out the same AKA sequence number and two SARs cannot overwrite each
// other's assignment: the loser reads again and decides afresh.
//
// Secrets never leave the package in clear except where a protocol carries
// them: K and OPc only into Milenage, HA1 only into a MAA, a PPR or the FT
// credential answer, and a generated password only in the response that
// issues it. Nothing logs an identity except through internal/pii.
package hss
