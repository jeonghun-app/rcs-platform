package scenario

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/conference"
	"github.com/jeonghun-app/rcs-platform/internal/resourcelists"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/simtest"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/sipua"
)

// Test identities, on .github/allowed-test-identifiers.txt.
const (
	groupDomain     = "ims.mnc001.mcc001.3gppnetwork.org"
	groupSelfIMPI   = "001010000000001@" + groupDomain
	groupSelfIMPU   = "sip:+15550100001@" + groupDomain
	groupPeerIMPU   = "sip:+15550100002@" + groupDomain
	groupFactory    = "sip:conf-factory@" + groupDomain
	groupConference = "sip:chat-0123456789abcdef0123456789abcdef@conf.example.com"
	groupOffer      = "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\nm=message 9 TCP/MSRP *\r\na=path:msrp://192.0.2.1:9/s1;tcp\r\na=setup:active\r\n"
)

func mustParseURI(t *testing.T, s string) sip.URI {
	t.Helper()
	u, err := sip.ParseURI(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// registeredUA is a UA registered at an in-process IMS core, which builds
// requests as it would for the platform.
func registeredUA(t *testing.T) *sipua.UA {
	t.Helper()
	core := simtest.StartIMSCore(t, groupDomain, map[string]string{groupSelfIMPI: "self-password"})
	creds, err := sipua.DigestCredentials(groupSelfIMPI, []byte("self-password"))
	if err != nil {
		t.Fatal(err)
	}
	ua, err := sipua.Dial(context.Background(), sipua.Config{
		Network: transport.TCP, Proxy: core.Addr, Domain: groupDomain, IMPU: mustParseURI(t, groupSelfIMPU),
		InstanceID: "urn:uuid:00000000-0000-4000-8000-000000000001", Credentials: creds,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ua.Close() })
	if _, err := ua.Register(context.Background()); err != nil {
		t.Fatal(err)
	}
	return ua
}

// parts reads a multipart/mixed body as rcs-as does, by its boundary.
func parts(t *testing.T, contentType string, body []byte) []*multipart.Part {
	t.Helper()
	mt, params, err := mime.ParseMediaType(contentType)
	if err != nil || mt != "multipart/mixed" || params["boundary"] == "" {
		t.Fatalf("Content-Type %q: %v", contentType, err)
	}
	r := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	var out []*multipart.Part
	for {
		p, err := r.NextPart()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, p)
	}
}

func TestAGroupInviteBodyCarriesTheOfferAndTheList(t *testing.T) {
	// An invitee whose URI needs escaping in XML, as a display-less URI
	// with & would.
	odd := mustParseURI(t, "sip:+15550100003@"+groupDomain+";x=a&b")
	ct, body, err := groupInviteBody([]byte(groupOffer), []sip.URI{mustParseURI(t, groupPeerIMPU), odd})
	if err != nil {
		t.Fatal(err)
	}
	mt, params, _ := mime.ParseMediaType(ct)
	r := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	if mt != "multipart/mixed" {
		t.Fatalf("Content-Type %q", ct)
	}
	sdpPart, err := r.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := io.ReadAll(sdpPart); sdpPart.Header.Get("Content-Type") != "application/sdp" || string(got) != groupOffer {
		t.Fatalf("first part %v: %q", sdpPart.Header, got)
	}
	listPart, err := r.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if listPart.Header.Get("Content-Type") != resourcelists.ContentType || listPart.Header.Get("Content-Disposition") != "recipient-list" {
		t.Fatalf("second part %v", listPart.Header)
	}
	list, _ := io.ReadAll(listPart)
	// Read by the reader rcs-as reads it with.
	entries, skipped, err := resourcelists.Parse(list, 10)
	if err != nil || skipped != 0 || len(entries) != 2 || entries[0].URI != groupPeerIMPU || entries[1].URI != odd.String() {
		t.Fatalf("entries %+v, skipped %d: %v", entries, skipped, err)
	}
	if _, err := r.NextPart(); !errors.Is(err, io.EOF) {
		t.Fatalf("a third part: %v", err)
	}
	if _, _, err := groupInviteBody([]byte(groupOffer), nil); err == nil {
		t.Fatal("a list of nobody was taken")
	}
}

func TestAFactoryInviteIsRcsjtas(t *testing.T) {
	ua := registeredUA(t)
	req, err := factoryInvite(ua, mustParseURI(t, groupFactory), []byte(groupOffer), []sip.URI{mustParseURI(t, groupPeerIMPU)}, "gch-d4-1", "Lunch")
	if err != nil {
		t.Fatal(err)
	}
	cs, err := req.Header.Contact()
	switch {
	case req.URI.String() != groupFactory:
		t.Errorf("Request-URI %s", req.URI)
	case req.Header.Get("Require") != "recipient-list-invite" || req.Header.Get("Subject") != "Lunch" || req.Header.Get("Contribution-ID") != "gch-d4-1":
		t.Errorf("Require %q Subject %q Contribution-ID %q", req.Header.Get("Require"), req.Header.Get("Subject"), req.Header.Get("Contribution-ID"))
	case err != nil || len(cs) != 1 || !cs[0].Params.Has(omaIMTag) || !cs[0].URI.Params.Has("ob"):
		t.Errorf("Contact %q", req.Header.Get("Contact"))
	case !strings.Contains(strings.Join(req.Header.Values("Accept-Contact"), "\n"), "*;"+omaIMTag):
		t.Errorf("Accept-Contact %q", req.Header.Values("Accept-Contact"))
	}
	ps := parts(t, req.Header.Get("Content-Type"), req.Body)
	if len(ps) != 2 {
		t.Fatalf("%d parts", len(ps))
	}
	// No Contribution-ID, no group (rcs-as answers 400).
	if _, err := factoryInvite(ua, mustParseURI(t, groupFactory), []byte(groupOffer), []sip.URI{mustParseURI(t, groupPeerIMPU)}, "", "Lunch"); err == nil {
		t.Fatal("a factory INVITE without a Contribution-ID was built")
	}
}

func TestARejoinInviteCarriesOnlyTheOffer(t *testing.T) {
	ua := registeredUA(t)
	req, err := rejoinInvite(ua, mustParseURI(t, groupConference), []byte(groupOffer), "gch-d4-1")
	if err != nil {
		t.Fatal(err)
	}
	cs, _ := req.Header.Contact()
	if req.URI.String() != groupConference || req.Header.Get("Content-Type") != "application/sdp" || string(req.Body) != groupOffer ||
		req.Header.Get("Contribution-ID") != "gch-d4-1" || req.Header.Get("Require") != "" || len(cs) != 1 || !cs[0].Params.Has(omaIMTag) {
		t.Fatalf("rejoin %s Content-Type %q Contribution-ID %q Require %q Contact %q", req.URI, req.Header.Get("Content-Type"),
			req.Header.Get("Contribution-ID"), req.Header.Get("Require"), req.Header.Get("Contact"))
	}
}

func TestTheConferenceURIIsTheFocusContact(t *testing.T) {
	answer := func(contact string) *sip.Response {
		res := &sip.Response{StatusCode: 200}
		if contact != "" {
			if err := res.Header.Add("Contact", contact); err != nil {
				t.Fatal(err)
			}
		}
		return res
	}
	if u, err := conferenceOf(answer("<" + groupConference + ">;isfocus;+g.oma.sip-im")); err != nil || u.String() != groupConference {
		t.Fatalf("conferenceOf = %s, %v", u, err)
	}
	// rcs-as's Contact has a transport (#542): requests go there, and the
	// group is the bare URI.
	u, err := conferenceOf(answer("<" + groupConference + ";transport=tcp>;isfocus"))
	if err != nil || u.String() != groupConference+";transport=tcp" || groupIdentity(u).String() != groupConference {
		t.Fatalf("conferenceOf = %s (group %s), %v", u, groupIdentity(u), err)
	}
	for name, contact := range map[string]string{
		"no isfocus": "<" + groupConference + ">;+g.oma.sip-im",
		"none":       "",
		"two":        "<" + groupConference + ">;isfocus, <sip:other@conf.example.com>;isfocus",
	} {
		if _, err := conferenceOf(answer(contact)); err == nil {
			t.Errorf("%s: taken as a conference", name)
		}
	}
}

// rosterDoc is a conference-info document for groupConference at version,
// in state, with users as entity to endpoint status.
func rosterDoc(t *testing.T, state conference.State, version uint32, users map[string]conference.EndpointStatus) []byte {
	t.Helper()
	info := &conference.Info{Entity: groupConference, State: state, Version: version, Users: &conference.Users{State: state}}
	if state == conference.Full {
		info.Description = &conference.Description{Subject: "Lunch"}
	}
	for _, e := range []string{"tel:+15550100001", "tel:+15550100002"} {
		if s, ok := users[e]; ok {
			info.Users.List = append(info.Users.List, conference.User{Entity: e, State: conference.Full,
				Endpoints: []conference.Endpoint{{Entity: e, State: conference.Full, Status: s}}})
		}
	}
	b, err := info.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTheRosterMergesItsNotifies(t *testing.T) {
	var r roster
	full := sipua.Notification{State: "active", ContentType: conference.ContentType,
		Body: rosterDoc(t, conference.Full, 1, map[string]conference.EndpointStatus{"tel:+15550100001": conference.Connected, "tel:+15550100002": conference.DialingOut})}
	if err := r.apply(full); err != nil {
		t.Fatal(err)
	}
	if s, ok := r.status(groupSelfIMPU, "tel:+15550100001"); !ok || s != conference.Connected {
		t.Fatalf("self %q %v", s, ok)
	}
	// The peer joins: a partial document one version up.
	partial := sipua.Notification{State: "active", ContentType: conference.ContentType,
		Body: rosterDoc(t, conference.Partial, 2, map[string]conference.EndpointStatus{"tel:+15550100002": conference.Connected})}
	if err := r.apply(partial); err != nil {
		t.Fatal(err)
	}
	if s, ok := r.status("TEL:+15550100002"); !ok || s != conference.Connected || r.version() != 2 {
		t.Fatalf("peer %q %v, version %d", s, ok, r.version())
	}
	if _, ok := r.status("tel:+15550100003"); ok {
		t.Fatal("someone not in the group is listed")
	}
	// A NOTIFY without a body, as the final one of a subscription, changes
	// nothing.
	if err := r.apply(sipua.Notification{State: "terminated", Reason: "deactivated"}); err != nil || r.version() != 2 {
		t.Fatalf("an empty NOTIFY: %v, version %d", err, r.version())
	}
	// A gap in the versions is the subscriber's to refresh for (RFC 4575
	// §4.6), not something to merge.
	gap := sipua.Notification{ContentType: conference.ContentType,
		Body: rosterDoc(t, conference.Partial, 4, map[string]conference.EndpointStatus{"tel:+15550100002": conference.Disconnected})}
	if err := r.apply(gap); !errors.Is(err, conference.ErrVersionGap) {
		t.Fatalf("a gap: %v", err)
	}
	for name, n := range map[string]sipua.Notification{
		"another type": {ContentType: "text/plain", Body: []byte("x")},
		"no document":  {ContentType: conference.ContentType, Body: []byte("<x/>")},
		"a read error": {Err: errors.New("bad")},
	} {
		if err := r.apply(n); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
}
