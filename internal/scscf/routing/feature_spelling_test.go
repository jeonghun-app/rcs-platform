package routing

import (
	"slices"
	"testing"
	"time"

	hssprofile "github.com/jeonghun-app/rcs-platform/internal/hss"
	"github.com/jeonghun-app/rcs-platform/internal/ifc"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sdp"
)

// chatSpellings are ways to write a chat's feature tag, and one that is no
// chat's, which caller preferences and iFC must read alike.
var chatSpellings = []string{
	`+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session"`,
	`+G.3GPP.ICSI-REF="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session"`,
	`+g.3gpp.icsi-ref="URN%3AURN-7%3A3GPP-SERVICE.IMS.ICSI.OMA.CPM.SESSION"`,
	`+g.3gpp.icsi-ref="urn%3aurn-7%3a3gpp-service.ims.icsi.oma.cpm.session"`,
	`+g.oma.sip-im`,
	`+G.OMA.SIP-IM`,
	`+g.oma.SIP-IM="TRUE"`,
	`+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"`,
}

// TestCallerPreferencesAndIFCAgreeOnWhatIsAChat (#359 security review): for
// every spelling, a request that its caller preferences send to the chat
// device and not to the voice one is one the default profile's rcs-as
// trigger takes, and the other way round; and a binding the preferences
// take for a chat device writes a Contact the trigger takes.
func TestCallerPreferencesAndIFCAgreeOnWhatIsAChat(t *testing.T) {
	set, err := ifc.Compile(hssprofile.DefaultRCSProfile(hssprofile.DefaultProfileID, rcsAS).Criteria)
	if err != nil {
		t.Fatal(err)
	}
	takes := func(t *testing.T, field string) bool {
		t.Helper()
		r := request(t, "INVITE", impu1, field)
		matched, err := set.Match(view{req: r.Message, hide: "P-Served-User"}, ifc.Context{Case: ifc.TerminatingRegistered})
		if err != nil {
			t.Fatal(err)
		}
		return slices.ContainsFunc(matched, func(fc ifc.FilterCriteria) bool { return fc.Priority == 10 })
	}
	chat := binding(1, 0, time.Hour, chatSpellings[0], "+g.oma.sip-im")
	voice := binding(2, 0, time.Hour, chatSpellings[len(chatSpellings)-1])
	for _, spelling := range chatSpellings {
		t.Run(spelling, func(t *testing.T) {
			r := request(t, "INVITE", impu1, "Accept-Contact: *;"+spelling+";require;explicit").Message
			got := accepted([]state.Contact{chat, voice}, r)
			byPrefs := len(got) == 1 && got[0].URI == chat.URI
			if byIFC := takes(t, "Accept-Contact: *;"+spelling); byPrefs != byIFC {
				t.Errorf("Accept-Contact: caller preferences take it for a chat %v, iFC %v", byPrefs, byIFC)
			}
			device := binding(3, 0, time.Hour, spelling)
			canonical := request(t, "INVITE", impu1, "Accept-Contact: *;"+chatSpellings[0]+";require;explicit").Message
			im := request(t, "INVITE", impu1, "Accept-Contact: *;+g.oma.sip-im;require;explicit").Message
			byPrefs = len(accepted([]state.Contact{device}, canonical)) == 1 || len(accepted([]state.Contact{device}, im)) == 1
			if byIFC := takes(t, "Contact: <sip:ue3@192.0.2.13:5060>;"+spelling); byPrefs != byIFC {
				t.Errorf("Contact: caller preferences take it for a chat device %v, iFC %v", byPrefs, byIFC)
			}
		})
	}
}

// msrpSpellings are m= lines that offer an MSRP stream in another case, over
// TLS or with a port count, and ones that come close to one without being
// one, which sdp.Media.IsMSRP and the iFC must read alike.
var msrpSpellings = []string{
	"m=message 9 TCP/MSRP *",
	"m=MESSAGE 9 TCP/MSRP *",
	"m=Message 2855 tcp/msrp *",
	"m=message 9 TCP/TLS/MSRP *",
	"m=message 9 tcp/Tls/msrp *",
	"m=message 9/2 TCP/MSRP *",
	"m=audio 49170 RTP/AVP 0\r\nm=MESSAGE 9 TCP/MSRP *",
	"m=message 9 TCP/XMSRP *",
	"m=message 9 UDP/MSRP *",
	"m=message 9 TCP/MSRP/X *",
	"m=messages 9 TCP/MSRP *",
	"m=audio 9 TCP/MSRP *",
	"m=audio 49170 RTP/AVP 0",
}

// TestSDPAndIFCAgreeOnWhatIsAnMSRPStream (#359 security review): an INVITE
// whose SDP the S-CSCF's own parser takes for an MSRP stream is one the
// default profile's rcs-as trigger takes, with no feature tag to go by,
// and the other way round.
func TestSDPAndIFCAgreeOnWhatIsAnMSRPStream(t *testing.T) {
	set, err := ifc.Compile(hssprofile.DefaultRCSProfile(hssprofile.DefaultProfileID, rcsAS).Criteria)
	if err != nil {
		t.Fatal(err)
	}
	const head = "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n"
	for _, lines := range msrpSpellings {
		t.Run(lines, func(t *testing.T) {
			body := head + lines + "\r\n"
			s, err := sdp.Parse([]byte(body))
			if err != nil {
				t.Fatal(err)
			}
			bySDP := slices.ContainsFunc(s.Media, func(m sdp.Media) bool { return m.IsMSRP() })
			r := request(t, "INVITE", impu1, "Content-Type: application/sdp").Message
			r.Body = []byte(body)
			matched, err := set.Match(view{req: r, hide: "P-Served-User"}, ifc.Context{Case: ifc.TerminatingRegistered})
			if err != nil {
				t.Fatal(err)
			}
			if byIFC := slices.ContainsFunc(matched, func(fc ifc.FilterCriteria) bool { return fc.Priority == 10 }); bySDP != byIFC {
				t.Errorf("the SDP parser takes it for MSRP %v, iFC %v", bySDP, byIFC)
			}
		})
	}
}

// TestAnMSRPOfferThatNamesAnotherServiceSkipsRCSAS (#359 code review): the
// MSRP stream takes an INVITE to rcs-as only when no feature tag names a
// service; image share, which names its IARI however spelled, or a call
// that names its ICSI, goes on as before.
func TestAnMSRPOfferThatNamesAnotherServiceSkipsRCSAS(t *testing.T) {
	set, err := ifc.Compile(hssprofile.DefaultRCSProfile(hssprofile.DefaultProfileID, rcsAS).Criteria)
	if err != nil {
		t.Fatal(err)
	}
	const body = "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\nm=message 9 TCP/MSRP *\r\na=file-selector:type:image/jpeg\r\n"
	for name, c := range map[string]struct {
		fields []string
		chat   bool
	}{
		"no service named":               {nil, true},
		"image share":                    {[]string{`Accept-Contact: *;+g.3gpp.iari-ref="urn%3Aurn-7%3A3gpp-application.ims.iari.gsma-is"`}, false},
		"image share, spelled otherwise": {[]string{`Contact: <sip:ue3@192.0.2.13:5060>;+G.3GPP.IARI-REF="URN%3aURN-7%3a3GPP-APPLICATION.IMS.IARI.GSMA-IS"`}, false},
		"a call's ICSI":                  {[]string{`Accept-Contact: *;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"`}, false},
		"the chat ICSI":                  {[]string{`Accept-Contact: *;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session"`}, true},
	} {
		t.Run(name, func(t *testing.T) {
			r := request(t, "INVITE", impu1, append(c.fields, "Content-Type: application/sdp")...).Message
			r.Body = []byte(body)
			matched, err := set.Match(view{req: r, hide: "P-Served-User"}, ifc.Context{Case: ifc.TerminatingRegistered})
			if err != nil {
				t.Fatal(err)
			}
			if got := slices.ContainsFunc(matched, func(fc ifc.FilterCriteria) bool { return fc.Priority == 10 }); got != c.chat {
				t.Errorf("to rcs-as %v, want %v", got, c.chat)
			}
		})
	}
}
