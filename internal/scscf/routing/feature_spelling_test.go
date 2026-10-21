package routing

import (
	"slices"
	"testing"
	"time"

	hssprofile "github.com/jeonghun-app/rcs-platform/internal/hss"
	"github.com/jeonghun-app/rcs-platform/internal/ifc"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
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
