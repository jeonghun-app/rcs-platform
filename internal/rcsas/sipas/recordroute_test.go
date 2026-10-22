package sipas

import (
	"slices"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// recordRoute is what the core records in a request that sets up a dialog
// with rcs-as: scscf's entry and pcscf's, in the order the request carries
// them.
var recordRoute = []string{"<sip:scscf.example.org;lr>", "<sip:pcscf-core.example.org:5070;lr>"}

func recordRouteFields() []string {
	var fields []string
	for _, rr := range recordRoute {
		fields = append(fields, "Record-Route: "+rr)
	}
	return fields
}

// checkRecordRoute fails t unless res, a 2xx that sets up a dialog, carries
// the request's Record-Route in order (RFC 3261 §12.1.1, RFC 6665
// §4.1.2.1): the client's route set, without which pcscf refuses every
// request the client sends in the dialog, its BYE among them (#541).
func checkRecordRoute(t *testing.T, what string, res *sip.Response) {
	t.Helper()
	if got := res.Header.Values("Record-Route"); !slices.Equal(got, recordRoute) {
		t.Fatalf("the 2xx to %s has Record-Route %q, want the request's %q", what, got, recordRoute)
	}
}

func TestTheAnswerToAChatInviteCarriesItsRecordRoute(t *testing.T) {
	r := newChatRig(t, messaging.Config{})
	p := r.a.dial(t)
	s := answeredBy(t, p.send(r.chatInvite(offerSDP(relayPath(), "active"), recordRouteFields()...)))
	p.ack(s)
	checkRecordRoute(t, "a chat INVITE", s.res)
}

func TestTheAnswerToAGroupInviteCarriesItsRecordRoute(t *testing.T) {
	r := newChatRig(t, messaging.Config{})
	r.core.setAnswer(func(req *sip.Request) int {
		if req.Method == "INVITE" {
			return 486
		}
		return 200
	})
	p := r.a.dial(t)
	m := r.factoryInvite(relayPath(), bob)
	m.fields = append(m.fields, recordRouteFields()...)
	s := answeredBy(t, p.send(m))
	p.ack(s)
	checkRecordRoute(t, "the factory's INVITE", s.res)
}

func TestTheAnswerToASubscribeCarriesItsRecordRoute(t *testing.T) {
	g := newGroupRig(t, bob)
	res, _ := g.subscribe(t, alice, "600", recordRouteFields()...)
	if res.StatusCode != 200 {
		t.Fatalf("SUBSCRIBE answered %d", res.StatusCode)
	}
	checkRecordRoute(t, "a SUBSCRIBE to the roster", res)
}

// checkFocusContact fails t unless the Contact header contact is the group's
// conference URI over TCP, the way scscf reaches rcs-as: without a
// transport it would read UDP on 5060, where no application server
// listens, and refuse every request in the dialog 403 (code review on
// #542). It is still the conference URI: a transport on one side only
// does not count in a comparison (RFC 3261 §19.1.4), and rcs-as reads the
// group from the user part.
func checkFocusContact(t *testing.T, what, contact string) {
	t.Helper()
	a, err := sip.ParseAddress(contact)
	if err != nil {
		t.Fatalf("%s: Contact %q: %v", what, contact, err)
	}
	if v, ok := a.URI.Param("transport"); !ok || v != "tcp" || !strings.HasPrefix(a.URI.User, "chat-") || a.URI.Host != confHost {
		t.Fatalf("%s: Contact %q, want the conference URI with transport=tcp", what, contact)
	}
}

func TestAGroupsDialogsNameTheConferenceOverTCP(t *testing.T) {
	r := newChatRig(t, messaging.Config{})
	r.core.setAnswer(func(req *sip.Request) int {
		if req.Method == "INVITE" {
			return 486
		}
		return 200
	})
	p := r.a.dial(t)
	_, s := r.create(t, p, relayPath(), bob)
	checkFocusContact(t, "the 200 to the factory's INVITE", s.res.Header.Get("Contact"))
	inv := r.core.nextOf(t, "INVITE")
	checkFocusContact(t, "the focus's INVITE", inv.Header.Get("Contact"))
	// Every message of a dialog carries the same Contact, not only the
	// first: NOTIFY and SUBSCRIBE are target refreshes (RFC 6665 §3.1,
	// §3.2), so a subscriber retargets to each one's Contact (code review
	// round 2 on #542).
	g := newGroupRig(t, bob)
	res, sub := g.subscribe(t, alice, "600")
	checkFocusContact(t, "the 200 to a SUBSCRIBE to the roster", res.Header.Get("Contact"))
	checkFocusContact(t, "the first NOTIFY", g.nextNotify(t).req.Header.Get("Contact"))
	for i, expires := range []string{"600", "600", "0"} {
		what := "a refresh"
		if expires == "0" {
			what = "an unsubscribe"
		}
		res := g.again(t, &sub, expires)
		if res.StatusCode != 200 {
			t.Fatalf("%s (%d) answered %d", what, i, res.StatusCode)
		}
		checkFocusContact(t, "the 200 to "+what, res.Header.Get("Contact"))
		checkFocusContact(t, "the NOTIFY after "+what, g.nextNotify(t).req.Header.Get("Contact"))
	}
	// The NOTIFYs of a REFER's implicit subscription, in the creator's
	// session with the group.
	if res := g.inSession(t, alice, "a1", g.s, 2, "REFER", []string{"Refer-To: <" + carol + ">"}, ""); res.StatusCode != 202 {
		t.Fatalf("REFER answered %d", res.StatusCode)
	}
	for {
		n := g.core.nextOf(t, "NOTIFY")
		if strings.HasPrefix(n.Header.Get("Event"), "refer") {
			checkFocusContact(t, "a REFER's NOTIFY", n.Header.Get("Contact"))
			break
		}
	}
	// A client rejoins at the Contact it was given, transport and all, as
	// rcsjta stores it: still this group.
	g.uri += ";transport=tcp"
	checkFocusContact(t, "the 200 to a rejoin at the Contact", g.rejoin(t, bob).res.Header.Get("Contact"))
}
