package hss

import (
	"github.com/jeonghun-app/rcs-platform/internal/hss/store"
	"github.com/jeonghun-app/rcs-platform/internal/ifc"
)

// Patterns for the RCS services. An ICSI or IARI appears percent-encoded in
// feature tags (+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi...",
// TS 24.229 §7.9A) and plain in P-Preferred-Service and P-Asserted-Service
// (RFC 6050); both forms contain the part after "urn-7", which is what the
// patterns match. Each is a plain literal and each header name a plain
// token, so the S-CSCF finds them with a substring search and a comparison
// rather than the regular expression engine, at a few units of its work
// budget a byte (internal/ifc, Limits.MaxWork): a 2 KB Contact stays cheap.
const (
	// The OMA CPM ICSIs RCS uses for chat, group chat, standalone messaging
	// and file transfer (RCC.07 §2.6.1, Table 3; OMA CPM).
	cpmICSI = `3gpp-service\.ims\.icsi\.oma\.cpm\.`
	// The RCS IARIs, such as FT via HTTP and chatbots (RCC.07 Table 3).
	rcsIARI = `3gpp-application\.ims\.iari\.rcs\.`
)

// featureTagHeaders carry the caller's and callee's feature tags;
// serviceHeaders the requested or asserted service.
var (
	featureTagHeaders = []string{"Accept-Contact", "Contact"}
	serviceHeaders    = []string{"P-Preferred-Service", "P-Asserted-Service"}
)

// DefaultRCSProfile is the service profile every RCS subscriber gets unless
// provisioned otherwise (docs/hss.md, "Default service profile"). It sends
// to rcs-as, at asURI, in both session cases and for registered and
// unregistered users alike, so that rcs-as can act as the originating and
// terminating participating function and store messages for users who are
// offline (docs/architecture.md §5):
//
//	10  INVITE for an RCS service (CPM ICSI or RCS IARI)   SESSION_TERMINATED
//	20  MESSAGE                                             SESSION_TERMINATED
//	30  OPTIONS for an RCS service (capability discovery)   SESSION_CONTINUED
//	40  REGISTER (third-party registration)                 SESSION_CONTINUED
//
// Chat and messaging fail rather than bypass rcs-as when it cannot be
// reached: without it there is no MSRP anchor, IMDN or store-and-forward.
// OPTIONS and REGISTER continue, so capability discovery and registration
// work while rcs-as is down.
func DefaultRCSProfile(id, asURI string) *store.ServiceProfile {
	as := func(h ifc.DefaultHandling) ifc.ApplicationServer {
		return ifc.ApplicationServer{ServerName: asURI, DefaultHandling: h}
	}
	// (method) AND (an RCS service in a feature tag or a service header),
	// in conjunctive normal form: group 0 is the method, group 1 the ORed
	// service conditions, one header and one literal each.
	rcsRequest := func(method string) *ifc.TriggerPoint {
		spts := []ifc.SPT{{Groups: []int{0}, Condition: ifc.Method(method)}}
		for _, h := range featureTagHeaders {
			for _, tag := range []string{cpmICSI, rcsIARI} {
				spts = append(spts, ifc.SPT{Groups: []int{1}, Condition: ifc.SIPHeader{Header: h, Content: tag}})
			}
		}
		for _, h := range serviceHeaders {
			spts = append(spts, ifc.SPT{Groups: []int{1}, Condition: ifc.SIPHeader{Header: h, Content: cpmICSI}})
		}
		return &ifc.TriggerPoint{ConditionTypeCNF: true, SPTs: spts}
	}
	method := func(m string) *ifc.TriggerPoint {
		return &ifc.TriggerPoint{SPTs: []ifc.SPT{{Groups: []int{0}, Condition: ifc.Method(m)}}}
	}
	return &store.ServiceProfile{
		ID: id,
		Criteria: []ifc.FilterCriteria{
			{Priority: 10, TriggerPoint: rcsRequest("INVITE"), ApplicationServer: as(ifc.SessionTerminated)},
			{Priority: 20, TriggerPoint: method("MESSAGE"), ApplicationServer: as(ifc.SessionTerminated)},
			{Priority: 30, TriggerPoint: rcsRequest("OPTIONS"), ApplicationServer: as(ifc.SessionContinued)},
			{Priority: 40, TriggerPoint: method("REGISTER"), ApplicationServer: as(ifc.SessionContinued)},
		},
	}
}
