// Package sh implements the Diameter application of the Sh reference point
// (TS 29.329) between an application server and the HSS, and the subset of
// the Sh-Data user data document (TS 29.328 Annex D) that `rcs-as` needs.
//
// Over Sh an AS reads user data (UDR/UDA), updates its own transparent data
// in the HSS (PUR/PUA), subscribes to changes (SNR/SNA) and is told of them
// (PNR/PNA); the procedures are in TS 29.328 §6.1. Typed requests and answers
// work as in package cx, on whose envelope and AVP readers this package is
// built: TS 29.329 §5 applies the Cx conventions of TS 29.229 §5 to Sh, and
// Sh reuses several Cx AVPs. Register [ErrorAVPs] with
// [diameter.Node.SetErrorAVPs] on a node that answers Sh requests.
//
// # User data subset
//
// [ParseData] and [Data.Marshal] handle the parts of Sh-Data that `rcs-as`
// uses:
//
//   - PublicIdentifiers, with its IMSPublicIdentity and MSISDN elements: the
//     identities of a user (Data-Reference IMSPublicIdentity and MSISDN).
//     Its Extension, which carries the identity type, is skipped.
//   - RepositoryData: transparent data an AS stores in the HSS under a
//     Service-Indication, with the SequenceNumber that guards concurrent
//     updates (TS 29.328 §6.1.2). ServiceData is the AS's own XML and is
//     kept byte for byte.
//
// Every other part of Sh-Data (Sh-IMS-Data, location and user state, the
// identity sets of the extensions) is skipped when parsing and cannot be
// written. The XML defences are those of package ifc: no document type
// declaration, a size limit and a nesting limit.
//
// Left out of the messages, until a service needs them: DSAI, location
// retrieval (Requested-Domain, Current-Location, Requested-Nodes), call
// reference information and the External-Identifier of User-Identity.
package sh
