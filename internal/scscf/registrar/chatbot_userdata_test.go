package registrar

import (
	"slices"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

// botURI is a chatbot URI an IMPU held before RCS_CHATBOT_DOMAIN was set
// (#679, #695).
const botURI = "sip:bot@botplatform.mnc001.mcc001.3gppnetwork.org"

// When a set registered with a chatbot-host identity is refreshed, hss
// answers the refresh's SAR, though it says the User-Data is already
// available, with the set's User-Data without that identity. The S-CSCF
// takes it: P-Associated-URI no longer lists the chatbot URI, and the URI
// no longer resolves to the set, also when it was the set's default
// identity and the set's key changes with it.
func TestARefreshsUserDataWithoutAChatbotURIDropsItFromTheSet(t *testing.T) {
	for name, set := range map[string][]string{
		"another identity is the default": {impu1, botURI, tel1},
		"the chatbot URI was the default": {botURI, impu1, tel1},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			g := e.instance(1)
			u := e.akaUser(impi1, set...)
			u.impu = impu1
			res := u.registerWith(g, 600)
			wantStatus(t, res, 200)
			if pau := res.Header.Values("P-Associated-URI"); !slices.Contains(pau, "<"+botURI+">") {
				t.Fatalf("before: P-Associated-URI %q has no chatbot URI", pau)
			}
			filtered := slices.DeleteFunc(slices.Clone(set), func(s string) bool { return s == botURI })
			e.hss.mu.Lock()
			e.hss.subs[impi1].set = filtered
			e.hss.sarHook = func(r *cx.SAR) (*cx.SAA, error) {
				if r.AssignmentType != cx.ReRegistration {
					return nil, nil
				}
				return &cx.SAA{Answer: cx.Answer{Result: cx.ResultCode(2001)}, UserName: impi1, UserData: userDataOf(impi1, nil, filtered...)}, nil
			}
			e.hss.mu.Unlock()

			res = u.registerWith(g, 600)
			wantStatus(t, res, 200)
			if r := e.hss.lastSAR(t); r.AssignmentType != cx.ReRegistration || r.UserDataAlreadyAvailable != cx.UserDataAlreadyAvailable {
				t.Fatalf("the refresh's SAR = %+v, want RE_REGISTRATION saying the User-Data is available", r)
			}
			want := []string{"<" + impu1 + ">", "<" + tel1 + ">"}
			if pau := res.Header.Values("P-Associated-URI"); !slices.Equal(pau, want) {
				t.Errorf("after: P-Associated-URI %q, want %q", pau, want)
			}
			if r, err := regOf(e, botURI); err == nil && slices.ContainsFunc(r.Identities, func(id state.SetIdentity) bool { return id.IMPU == botURI }) {
				t.Errorf("the chatbot URI still resolves to a set holding it: %+v", r)
			}
			r, err := regOf(e, impu1)
			if err != nil || r.Key.IMPU != impu1 {
				t.Fatalf("impu1's set: %+v, %v", r, err)
			}
		})
	}
}
