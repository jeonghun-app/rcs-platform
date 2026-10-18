// Package ifc models the IMS user profile that the HSS downloads to the
// S-CSCF in the Cx User-Data AVP (the IMSSubscription document of
// TS 29.228 Annex E) and evaluates the initial filter criteria (iFC) in it:
// the rules that decide which application servers a SIP request visits.
//
// Three services use it. `hss` builds the document from its service profiles
// and validates iFC an operator provisions; `scscf` parses the document from
// a Server-Assignment-Answer, compiles the criteria once per registration and
// evaluates them for every initial request and REGISTER; `rcs-as` is reached
// because its criteria match. The package depends on neither Diameter nor SIP:
// User-Data travels as bytes in package cx, and a request is evaluated through
// the small [Request] interface that the S-CSCF implements over its own SIP
// message type.
//
// # Documents
//
// [ParseSubscription] reads a document and [Subscription.Marshal] writes one.
// The parser refuses a document type declaration, documents larger than
// [MaxDocumentSize] and deeply nested elements, because the document comes
// from another node (docs/architecture.md §8). Elements this package does not
// model, such as later-release extensions, are skipped; the ones it models are
// checked against the cardinality and value ranges of TS 29.228 Tables E.1 and
// E.2. Values of XML Schema types that collapse white space (anyURI, integer,
// boolean) are read with the white space collapsed, as the TS 29.228 Annex C
// examples need; string values, which include every pattern, are kept exactly.
//
// # Evaluation
//
// [Compile] checks a list of criteria and orders it by priority; [Set.Match]
// and [Set.Next] evaluate the compiled set against a [Request] in a [Context]
// (session case and registration state). A trigger point is a boolean
// expression in conjunctive or disjunctive normal form over service point
// triggers (TS 29.228 Annex B.2.2, B.2.3, Annex C): in CNF the triggers sharing
// a Group value are ORed and the groups ANDed, in DNF the other way round; a
// trigger may belong to several groups, and ConditionNegated inverts one
// trigger. Criteria without a trigger point always match.
//
// Matching follows TS 29.228 Annex F. Request-URI, header and SDP patterns are
// POSIX extended regular expressions, run with Go's linear-time engine, so a
// hostile pattern cannot stall the S-CSCF. A pattern matches anywhere in its
// field, as a POSIX regexec would; anchor it with ^ and $ to match the whole
// field. Header name and Request-URI patterns ignore case, because header
// names and host names are case-insensitive in SIP (RFC 3261 §7.3.1,
// §19.1.4); header values and SDP content are matched as written.
package ifc
