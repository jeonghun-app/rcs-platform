package hss

import (
	"errors"
	"fmt"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/ifc"
)

// The S-CSCF evaluates a profile's criteria for every initial request within
// a work budget (internal/ifc, Limits.MaxWork) and fails the evaluation of a
// request the budget cannot pay for. The HSS therefore evaluates a profile
// before it stores it against reference requests at the sizes RCS clients
// send, in every session case, and refuses one that does not fit the
// default budget: an operator learns it from the API instead of from failed
// sessions.

// refRequest is an ifc.Request built from literals.
type refRequest struct {
	name    string
	method  string
	uri     string
	headers []ifc.HeaderField
	sdp     []string
}

func (r *refRequest) Method() string                  { return r.method }
func (r *refRequest) RequestURI() string              { return r.uri }
func (r *refRequest) HeaderFields() []ifc.HeaderField { return r.headers }
func (r *refRequest) SDPLines() []string              { return r.sdp }

// Identities of the reference requests; example.invalid names no one.
const (
	refUser = "sip:user@example.invalid"
	refPeer = "sip:peer@example.invalid"
	// refConference is a group chat's conference URI, at a conference host
	// outside the home domain, as rcs-as gives one.
	refConference = "sip:chat-0123456789abcdef0123456789abcdef@conf.example.invalid"
)

// rcsTags are the feature tags of a client with the common RCS services.
const rcsTags = `;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session,` +
	`urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.msg,urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.largemsg,` +
	`urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.deferred"` +
	`;+g.3gpp.iari-ref="urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.fthttp,` +
	`urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.geopush,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.chatbot"` +
	`;+g.gsma.rcs.botversion="#=1,#=2";+g.gsma.rcs.isbot`

// bigContact is a REGISTER Contact of about 2 KB: an RCS client with many
// feature tags and an instance identifier.
func bigContact() string {
	c := "<" + refUser + ";transport=tcp;ob>;expires=600;+sip.instance=\"<urn:uuid:00000000-0000-4000-8000-000000000000>\"" + rcsTags
	for i := 0; len(c) < 2048; i++ {
		c += fmt.Sprintf(";+g.example.tag%d=\"value-%d\"", i, i)
	}
	return c
}

func commonHeaders(method string) []ifc.HeaderField {
	return []ifc.HeaderField{
		{Name: "Via", Value: "SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bK-a0b1c2d3e4f5"},
		{Name: "Max-Forwards", Value: "70"},
		{Name: "From", Value: "<" + refUser + ">;tag=a0b1c2d3"},
		{Name: "To", Value: "<" + refPeer + ">"},
		{Name: "Call-ID", Value: "00000000-0000-4000-8000-000000000000"},
		{Name: "CSeq", Value: "1 " + method},
		{Name: "P-Asserted-Identity", Value: "<" + refUser + ">"},
		{Name: "User-Agent", Value: "IM-client/OMA1.0 Example/1.0"},
	}
}

func referenceRequests() []*refRequest {
	register := &refRequest{name: "REGISTER with a 2 KB Contact", method: "REGISTER", uri: "sip:example.invalid"}
	register.headers = append(commonHeaders("REGISTER"),
		ifc.HeaderField{Name: "Contact", Value: bigContact()},
		ifc.HeaderField{Name: "Supported", Value: "path"},
		ifc.HeaderField{Name: "Supported", Value: "gruu"},
		ifc.HeaderField{Name: "Authorization", Value: `Digest username="user@example.invalid",realm="example.invalid",uri="sip:example.invalid",nonce="",response=""`},
	)
	invite := &refRequest{name: "chat INVITE", method: "INVITE", uri: refPeer}
	invite.headers = append(commonHeaders("INVITE"),
		ifc.HeaderField{Name: "Contact", Value: "<" + refUser + ";gr=urn:uuid:00000000-0000-4000-8000-000000000000>" + rcsTags},
		ifc.HeaderField{Name: "Accept-Contact", Value: `*;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session"`},
		ifc.HeaderField{Name: "P-Preferred-Service", Value: "urn:urn-7:3gpp-service.ims.icsi.oma.cpm.session"},
		ifc.HeaderField{Name: "Content-Type", Value: "application/sdp"},
		ifc.HeaderField{Name: "Supported", Value: "timer"},
		ifc.HeaderField{Name: "Allow", Value: "INVITE"}, ifc.HeaderField{Name: "Allow", Value: "ACK"},
		ifc.HeaderField{Name: "Allow", Value: "BYE"}, ifc.HeaderField{Name: "Allow", Value: "MESSAGE"},
		ifc.HeaderField{Name: "Allow", Value: "OPTIONS"},
	)
	invite.sdp = []string{
		"v=0", "o=- 0 0 IN IP4 192.0.2.10", "s=-", "c=IN IP4 192.0.2.10", "t=0 0",
		"m=message 9 TCP/MSRP *",
		"a=path:msrp://192.0.2.10:2855/a0b1c2d3e4f5a6b7;tcp",
		"a=accept-types:message/cpim application/im-iscomposing+xml",
		"a=accept-wrapped-types:text/plain message/imdn+xml application/vnd.gsma.rcs-ft-http+xml " + strings.Repeat("application/vnd.example+xml ", 8),
		"a=setup:active", "a=sendrecv",
	}
	message := &refRequest{name: "MESSAGE", method: "MESSAGE", uri: refPeer}
	message.headers = append(commonHeaders("MESSAGE"),
		ifc.HeaderField{Name: "Accept-Contact", Value: `*;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.msg"`},
		ifc.HeaderField{Name: "P-Preferred-Service", Value: "urn:urn-7:3gpp-service.ims.icsi.oma.cpm.msg"},
		ifc.HeaderField{Name: "Content-Type", Value: "message/cpim"},
	)
	// A group chat's roster SUBSCRIBE (RFC 4575), to its conference URI,
	// as rcsjta sends it.
	subscribe := &refRequest{name: "roster SUBSCRIBE", method: "SUBSCRIBE", uri: refConference}
	subscribe.headers = append(commonHeaders("SUBSCRIBE"),
		ifc.HeaderField{Name: "Contact", Value: "<" + refUser + ";gr=urn:uuid:00000000-0000-4000-8000-000000000000>" + rcsTags},
		ifc.HeaderField{Name: "Event", Value: "conference"},
		ifc.HeaderField{Name: "Accept", Value: "application/conference-info+xml"},
		ifc.HeaderField{Name: "Expires", Value: "3600"},
	)
	return []*refRequest{register, invite, message, subscribe}
}

// referenceContexts are the session cases a profile is evaluated in.
var referenceContexts = []ifc.Context{
	{Case: ifc.Originating},
	{Case: ifc.TerminatingRegistered},
	{Case: ifc.TerminatingUnregistered, Unregistered: true},
}

// checkWork evaluates a compiled profile within lim against every
// reference request in every session case. It returns an error naming the
// request and the limit (a *ifc.LimitError's Limit) that a request reached.
func checkWork(compiled *ifc.Set, lim ifc.Limits) error {
	set := compiled.WithLimits(lim)
	for _, req := range referenceRequests() {
		for _, ctx := range referenceContexts {
			if _, err := set.Match(req, ctx); err != nil {
				var le *ifc.LimitError
				if errors.As(err, &le) {
					return fmt.Errorf("evaluating a %s exceeds %s", req.name, le.Limit)
				}
				return err
			}
		}
	}
	return nil
}
