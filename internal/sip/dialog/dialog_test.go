package dialog

import (
	"encoding/json"
	"errors"
	"math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

const (
	alice = "sip:+15550100001@ims.mnc001.mcc001.3gppnetwork.org"
	bob   = "sip:+15550100002@ims.mnc001.mcc001.3gppnetwork.org"
)

func ids() sip.IDGenerator { return sip.IDGenerator{Rand: rand.NewChaCha8([32]byte{3})} }

func parse(t *testing.T, text string) sip.Message {
	t.Helper()
	m, err := sip.ParseMessage([]byte(strings.ReplaceAll(text, "\n", "\r\n")))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func request(t *testing.T, text string) *sip.Request   { return parse(t, text).(*sip.Request) }
func response(t *testing.T, text string) *sip.Response { return parse(t, text).(*sip.Response) }

const invite = `INVITE ` + bob + ` SIP/2.0
Via: SIP/2.0/TCP 192.0.2.10:40000;branch=z9hG4bK-1
Max-Forwards: 70
From: <` + alice + `>;tag=a1
To: <` + bob + `>
Call-ID: call-1
CSeq: 7 INVITE
Contact: <sip:alice@192.0.2.10:40000;transport=tcp>
Content-Length: 0

`

const ok200 = `SIP/2.0 200 OK
Via: SIP/2.0/TCP 192.0.2.10:40000;branch=z9hG4bK-1
Record-Route: <sip:p1.example.net;lr>
Record-Route: <sip:p2.example.net;lr>
From: <` + alice + `>;tag=a1
To: <` + bob + `>;tag=b1
Call-ID: call-1
CSeq: 7 INVITE
Contact: <sip:bob@198.51.100.20:5060;transport=tcp>
Content-Length: 0

`

// The 2xx to this side's INVITE sets up its dialog: the Record-Route
// reversed is the route set, the Contact the remote target, and requests in
// it take the next CSeq (RFC 3261 §12.1.2, §12.2.1.1).
func TestA2xxSetsUpTheCallersDialog(t *testing.T) {
	d, err := UAC(request(t, invite), response(t, ok200))
	if err != nil {
		t.Fatal(err)
	}
	if d.CallID != "call-1" || d.LocalTag() != "a1" || d.RemoteTag() != "b1" || d.LocalSeq != 7 || d.HasRemoteSeq ||
		d.RemoteTarget.String() != "sip:bob@198.51.100.20:5060;transport=tcp" || d.LocalTarget.String() != "sip:alice@192.0.2.10:40000;transport=tcp" {
		t.Fatalf("%+v", d)
	}
	if d.ID() != "call-1\x00a1\x00b1" || d.NextHop().String() != "sip:p2.example.net;lr" {
		t.Errorf("ID %q, next hop %v", d.ID(), d.NextHop())
	}
	bye, err := d.Request("BYE", ids())
	if err != nil {
		t.Fatal(err)
	}
	if bye.URI.String() != "sip:bob@198.51.100.20:5060;transport=tcp" ||
		!slices.Equal(bye.Header.Values("Route"), []string{"<sip:p2.example.net;lr>", "<sip:p1.example.net;lr>"}) ||
		bye.Header.Get("CSeq") != "8 BYE" || bye.Header.Get("From") != "<"+alice+">;tag=a1" || bye.Header.Get("To") != "<"+bob+">;tag=b1" ||
		bye.Header.Get("Call-ID") != "call-1" || bye.Header.Has("Contact") || d.LocalSeq != 8 {
		t.Errorf("BYE:\n%s", text(bye))
	}
	if vias, err := bye.Header.Via(); err != nil || len(vias) != 1 || !strings.HasPrefix(vias[0].Branch(), sip.MagicCookie) {
		t.Errorf("Via %q", bye.Header.Get("Via"))
	}
	// A request the transport and the transaction layer take.
	if err := bye.Validate(); err != nil {
		t.Error(err)
	}
	reinvite, err := d.Request("INVITE", ids())
	if err != nil || reinvite.Header.Get("Contact") != "<sip:alice@192.0.2.10:40000;transport=tcp>" || reinvite.Header.Get("CSeq") != "9 INVITE" {
		t.Errorf("re-INVITE %v:\n%s", err, text(reinvite))
	}
}

// A strict router first in the route set takes the Request-URI, and the
// remote target goes to the end of the Route (RFC 3261 §12.2.1.1).
func TestAStrictRouterTakesTheRequestURI(t *testing.T) {
	d := &Dialog{CallID: "c", RemoteTarget: mustURI(t, "sip:bob@198.51.100.20"),
		Local: mustAddr(t, "<"+alice+">;tag=a"), Remote: mustAddr(t, "<"+bob+">;tag=b"),
		RouteSet: []sip.Address{mustAddr(t, "<sip:strict.example.net>"), mustAddr(t, "<sip:p.example.net;lr>")}}
	req, err := d.Request("BYE", ids())
	if err != nil {
		t.Fatal(err)
	}
	if req.URI.String() != "sip:strict.example.net" || !slices.Equal(req.Header.Values("Route"), []string{"<sip:p.example.net;lr>", "<sip:bob@198.51.100.20>"}) {
		t.Errorf("%s", text(req))
	}
	if len(d.RouteSet) != 2 || d.RouteSet[0].URI.String() != "sip:strict.example.net" {
		t.Error("the route set was changed")
	}
}

const subscribe = `SUBSCRIBE ` + alice + ` SIP/2.0
Via: SIP/2.0/TCP 10.0.2.9:5070;branch=z9hG4bK-s1
Max-Forwards: 69
Record-Route: <sip:scscf.rcs.internal;transport=tcp;lr>
From: <sip:pcscf.rcs.internal>;tag=p1
To: <` + alice + `>
Call-ID: sub-1
CSeq: 1 SUBSCRIBE
Event: reg
Expires: 1200
Contact: <sip:SUB@10.0.2.9:5070;transport=tcp>
Content-Length: 0

`

// The notifier's dialog is set up by its answer to the SUBSCRIBE: the
// request's Record-Route in order is its route set, and its NOTIFYs carry
// the event, the subscription's state, a body and its own Contact (RFC 3261
// §12.1.1, RFC 6665 §4.2.2).
func TestTheNotifiersDialogNotifies(t *testing.T) {
	sub := request(t, subscribe)
	d, err := UAS(sub, "n1", mustURI(t, "sip:scscf.rcs.internal;transport=tcp"))
	if err != nil {
		t.Fatal(err)
	}
	if d.LocalTag() != "n1" || d.RemoteTag() != "p1" || d.RemoteSeq != 1 || !d.HasRemoteSeq || d.LocalSeq != 0 ||
		d.Local.String() != "<"+alice+">;tag=n1" || d.RemoteTarget.String() != "sip:SUB@10.0.2.9:5070;transport=tcp" ||
		len(d.RouteSet) != 1 || d.RouteSet[0].String() != "<sip:scscf.rcs.internal;transport=tcp;lr>" {
		t.Fatalf("%+v", d)
	}
	ev, _ := sub.Header.Event()
	notify, err := d.Notify(ev, sip.SubscriptionState{State: "active", Params: sip.Params{{Name: "expires", Value: "1200"}}}, "application/reginfo+xml", []byte("<reginfo/>"), ids())
	if err != nil {
		t.Fatal(err)
	}
	if notify.Method != "NOTIFY" || notify.Header.Get("CSeq") != "1 NOTIFY" || notify.Header.Get("Event") != "reg" ||
		notify.Header.Get("Subscription-State") != "active;expires=1200" || notify.Header.Get("Content-Type") != "application/reginfo+xml" ||
		string(notify.Body) != "<reginfo/>" || notify.Header.Get("Contact") != "<sip:scscf.rcs.internal;transport=tcp>" ||
		notify.Header.Get("From") != "<"+alice+">;tag=n1" || notify.Header.Get("To") != "<sip:pcscf.rcs.internal>;tag=p1" ||
		notify.URI.String() != "sip:SUB@10.0.2.9:5070;transport=tcp" {
		t.Errorf("NOTIFY:\n%s", text(notify))
	}
	if err := notify.Validate(); err != nil {
		t.Error(err)
	}
	if _, err := d.Notify(ev, sip.SubscriptionState{State: "active"}, "", []byte("x"), ids()); err == nil {
		t.Error("a body without a content type")
	}
	if _, err := UAS(sub, "", sip.URI{}); !errors.Is(err, ErrNoDialog) {
		t.Errorf("no local tag: %v", err)
	}
}

const firstNotify = `NOTIFY sip:SUB@10.0.2.9:5070;transport=tcp SIP/2.0
Via: SIP/2.0/TCP 10.0.4.4:5060;branch=z9hG4bK-n1
Max-Forwards: 69
Record-Route: <sip:scscf.rcs.internal;transport=tcp;lr>
From: <` + alice + `>;tag=n1
To: <sip:pcscf.rcs.internal>;tag=p1
Call-ID: sub-1
CSeq: 4 NOTIFY
Event: reg
Subscription-State: active;expires=1200
Contact: <sip:scscf.rcs.internal;transport=tcp>
Content-Length: 0

`

// The subscriber's dialog is set up by the first NOTIFY, with its route
// set, whatever the 2xx said (RFC 6665 §4.4.1); refreshes and the end of
// the subscription go in it.
func TestTheFirstNotifySetsUpTheSubscribersDialog(t *testing.T) {
	d, err := FromNotify(request(t, subscribe), request(t, firstNotify))
	if err != nil {
		t.Fatal(err)
	}
	if d.LocalTag() != "p1" || d.RemoteTag() != "n1" || d.LocalSeq != 1 || d.RemoteSeq != 4 ||
		d.RemoteTarget.String() != "sip:scscf.rcs.internal;transport=tcp" || len(d.RouteSet) != 1 {
		t.Fatalf("%+v", d)
	}
	ev := sip.Event{Type: "reg"}
	refresh, err := d.Subscribe(ev, 1200, ids())
	if err != nil || refresh.Header.Get("CSeq") != "2 SUBSCRIBE" || refresh.Header.Get("Expires") != "1200" || refresh.Header.Get("Event") != "reg" ||
		refresh.Header.Get("Contact") != "<sip:SUB@10.0.2.9:5070;transport=tcp>" || refresh.Header.Get("Route") != "<sip:scscf.rcs.internal;transport=tcp;lr>" {
		t.Errorf("refresh %v:\n%s", err, text(refresh))
	}
	end, err := d.Subscribe(ev, 0, ids())
	if err != nil || end.Header.Get("Expires") != "0" || end.Header.Get("CSeq") != "3 SUBSCRIBE" {
		t.Errorf("end %v:\n%s", err, text(end))
	}
}

// A request is taken only in this dialog and in order; a target refresh
// moves the remote target, and on an error nothing changes (RFC 3261
// §12.2.2).
func TestAcceptChecksTheDialogAndTheOrder(t *testing.T) {
	d, err := FromNotify(request(t, subscribe), request(t, firstNotify))
	if err != nil {
		t.Fatal(err)
	}
	next := func(cseq string, edits ...string) *sip.Request {
		text := strings.Replace(firstNotify, "CSeq: 4 NOTIFY", "CSeq: "+cseq+" NOTIFY", 1)
		for i := 0; i+1 < len(edits); i += 2 {
			text = strings.Replace(text, edits[i], edits[i+1], 1)
		}
		return request(t, text)
	}
	before := *d
	for name, tt := range map[string]struct {
		req  *sip.Request
		want error
	}{
		"a lower CSeq":     {next("3"), ErrOutOfOrder},
		"another Call-ID":  {next("5", "Call-ID: sub-1", "Call-ID: sub-2"), ErrNotInDialog},
		"another From tag": {next("5", "tag=n1", "tag=n2"), ErrNotInDialog},
		"another To tag":   {next("5", "tag=p1", "tag=p2"), ErrNotInDialog},
		"two Contacts":     {next("5", "Contact: <sip:scscf.rcs.internal;transport=tcp>", "Contact: <sip:a@10.0.4.4>, <sip:b@10.0.4.4>"), ErrNoDialog},
		"a malformed CSeq": {next("x"), nil},
	} {
		err := d.Accept(tt.req)
		if tt.want == nil {
			if err == nil {
				t.Errorf("%s: accepted", name)
			}
		} else if !errors.Is(err, tt.want) {
			t.Errorf("%s: %v, want %v", name, err, tt.want)
		}
		if !reflect.DeepEqual(*d, before) {
			t.Fatalf("%s changed the dialog: %+v", name, d)
		}
	}
	moved := next("9", "Contact: <sip:scscf.rcs.internal;transport=tcp>", "Contact: <sip:scscf-2.rcs.internal;transport=tcp>")
	if err := d.Accept(moved); err != nil || d.RemoteSeq != 9 || d.RemoteTarget.String() != "sip:scscf-2.rcs.internal;transport=tcp" {
		t.Fatalf("target refresh: %v, %+v", err, d)
	}
	// A request that is no target refresh leaves the target.
	info := request(t, strings.NewReplacer("NOTIFY sip:", "INFO sip:", "CSeq: 4 NOTIFY", "CSeq: 10 INFO", "Contact: <sip:scscf.rcs.internal;transport=tcp>", "Contact: <sip:elsewhere@10.0.4.9>").Replace(firstNotify))
	if err := d.Accept(info); err != nil || d.RemoteSeq != 10 || d.RemoteTarget.String() != "sip:scscf-2.rcs.internal;transport=tcp" {
		t.Fatalf("INFO: %v, %+v", err, d)
	}
}

func TestAMessageWithoutWhatADialogNeedsSetsUpNone(t *testing.T) {
	for name, res := range map[string]string{
		"no To tag":  strings.Replace(ok200, ";tag=b1", "", 1),
		"no Contact": strings.Replace(ok200, "Contact: <sip:bob@198.51.100.20:5060;transport=tcp>\n", "", 1),
		"a star":     strings.Replace(ok200, "Contact: <sip:bob@198.51.100.20:5060;transport=tcp>", "Contact: *", 1),
		"bad RR":     strings.Replace(ok200, "Record-Route: <sip:p1.example.net;lr>", "Record-Route: sip:p1", 1),
	} {
		if _, err := UAC(request(t, invite), response(t, res)); !errors.Is(err, ErrNoDialog) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := UAC(request(t, strings.Replace(invite, ";tag=a1", "", 1)), response(t, ok200)); !errors.Is(err, ErrNoDialog) {
		t.Errorf("no From tag: %v", err)
	}
	if _, err := FromNotify(request(t, subscribe), request(t, strings.Replace(firstNotify, ";tag=n1", "", 1))); !errors.Is(err, ErrNoDialog) {
		t.Errorf("NOTIFY without a From tag: %v", err)
	}
	if _, err := UAS(request(t, strings.Replace(subscribe, ";tag=p1", "", 1)), "n1", sip.URI{}); !errors.Is(err, ErrNoDialog) {
		t.Errorf("SUBSCRIBE without a From tag: %v", err)
	}
}

func TestTheCSeqDoesNotWrap(t *testing.T) {
	d := &Dialog{CallID: "c", LocalSeq: 1<<32 - 1, Local: mustAddr(t, "<"+alice+">;tag=a"), Remote: mustAddr(t, "<"+bob+">;tag=b"), RemoteTarget: mustURI(t, bob)}
	if _, err := d.Request("BYE", ids()); err == nil || d.LocalSeq != 1<<32-1 {
		t.Fatalf("%v, %d", err, d.LocalSeq)
	}
}

// Initial builds the request that may set up a dialog: a new From tag and
// Call-ID, CSeq 1, no To tag, the routes and the Contact (RFC 3261 §8.1.1).
func TestInitialBuildsARequestOutsideADialog(t *testing.T) {
	from, to := mustAddr(t, "<sip:pcscf.rcs.internal>;tag=old"), mustAddr(t, "<"+alice+">;tag=stale")
	req, err := Initial("SUBSCRIBE", mustURI(t, alice), from, to, []sip.Address{mustAddr(t, "<sip:orig@scscf.rcs.internal;transport=tcp;lr;orig>")},
		mustURI(t, "sip:SUB@10.0.2.9:5070;transport=tcp"), "pcscf.rcs.internal", ids())
	if err != nil {
		t.Fatal(err)
	}
	f, _ := req.Header.From()
	got, _ := req.Header.To()
	if f.Tag() == "" || f.Tag() == "old" || got.Tag() != "" || req.Header.Get("CSeq") != "1 SUBSCRIBE" ||
		!strings.HasSuffix(req.Header.Get("Call-ID"), "@pcscf.rcs.internal") || req.URI.String() != alice ||
		req.Header.Get("Route") != "<sip:orig@scscf.rcs.internal;transport=tcp;lr;orig>" || req.Header.Get("Contact") != "<sip:SUB@10.0.2.9:5070;transport=tcp>" {
		t.Errorf("%s", text(req))
	}
	if from.Tag() != "old" || to.Tag() != "stale" {
		t.Error("Initial changed its arguments")
	}
	if err := req.Validate(); err != nil {
		t.Error(err)
	}
}

func mustURI(t *testing.T, s string) sip.URI {
	t.Helper()
	u, err := sip.ParseURI(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func mustAddr(t *testing.T, s string) sip.Address {
	t.Helper()
	a, err := sip.ParseAddress(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// text writes req for a failure message.
func text(req *sip.Request) string {
	b, err := req.Bytes()
	if err != nil {
		return err.Error()
	}
	return string(b)
}

// Tags are tokens, compared without case (RFC 3261 §7.3.1), and so are they
// in the dialog's ID; the Call-ID is compared exactly (§8.1.1.4).
func TestTagsCompareWithoutCase(t *testing.T) {
	d, err := FromNotify(request(t, subscribe), request(t, firstNotify))
	if err != nil {
		t.Fatal(err)
	}
	notify := request(t, strings.NewReplacer("tag=n1", "tag=N1", "tag=p1", "tag=P1", "CSeq: 4 NOTIFY", "CSeq: 5 NOTIFY").Replace(firstNotify))
	if err := d.Accept(notify); err != nil {
		t.Errorf("tags in another case: %v", err)
	}
	other, err := FromNotify(request(t, strings.Replace(subscribe, "tag=p1", "tag=P1", 1)), request(t, strings.Replace(firstNotify, "tag=n1", "tag=N1", 1)))
	if err != nil || other.ID() != d.ID() {
		t.Errorf("IDs %q and %q, %v", d.ID(), other.ID(), err)
	}
	callID := request(t, strings.NewReplacer("Call-ID: sub-1", "Call-ID: SUB-1", "CSeq: 4 NOTIFY", "CSeq: 6 NOTIFY").Replace(firstNotify))
	if err := d.Accept(callID); !errors.Is(err, ErrNotInDialog) {
		t.Errorf("a Call-ID in another case: %v", err)
	}
}

// Only a lower CSeq is out of order (RFC 3261 §12.2.2): the ACK of an
// INVITE has the INVITE's, and a target refresh without a Contact keeps
// the target.
func TestAnEqualCSeqIsInOrder(t *testing.T) {
	d, err := UAC(request(t, invite), response(t, ok200))
	if err != nil {
		t.Fatal(err)
	}
	reinvite := strings.NewReplacer("INVITE "+bob, "INVITE sip:alice@192.0.2.10:40000;transport=tcp", "From: <"+alice+">;tag=a1", "From: <"+bob+">;tag=b1",
		"To: <"+bob+">", "To: <"+alice+">;tag=a1", "CSeq: 7 INVITE", "CSeq: 3 INVITE").Replace(invite)
	if err := d.Accept(request(t, reinvite)); err != nil {
		t.Fatal(err)
	}
	ack := strings.NewReplacer("INVITE sip:", "ACK sip:", "CSeq: 3 INVITE", "CSeq: 3 ACK").Replace(reinvite)
	if err := d.Accept(request(t, ack)); err != nil || d.RemoteSeq != 3 {
		t.Errorf("the ACK of the re-INVITE: %v, %d", err, d.RemoteSeq)
	}
	target := d.RemoteTarget
	noContact := request(t, strings.NewReplacer("CSeq: 3 INVITE", "CSeq: 4 INVITE", "Contact: <sip:alice@192.0.2.10:40000;transport=tcp>\n", "").Replace(reinvite))
	if noContact.Header.Has("Contact") {
		t.Fatal("the test request has a Contact")
	}
	if err := d.Accept(noContact); err != nil || d.RemoteTarget.String() != target.String() {
		t.Errorf("a refresh without a Contact: %v, target %s", err, d.RemoteTarget)
	}
}

// An ACK takes the CSeq of the INVITE it acknowledges and leaves the next
// request's alone (RFC 3261 §13.2.2.4).
func TestAnACKTakesItsINVITEsCSeq(t *testing.T) {
	d, err := UAC(request(t, invite), response(t, ok200))
	if err != nil {
		t.Fatal(err)
	}
	reinvite, _ := d.Request("INVITE", ids())
	ack, err := d.Request("ACK", ids())
	if err != nil || reinvite.Header.Get("CSeq") != "8 INVITE" || ack.Header.Get("CSeq") != "8 ACK" {
		t.Fatalf("%q, %q, %v", reinvite.Header.Get("CSeq"), ack.Header.Get("CSeq"), err)
	}
	if bye, _ := d.Request("BYE", ids()); bye.Header.Get("CSeq") != "9 BYE" {
		t.Errorf("after the ACK: %q", bye.Header.Get("CSeq"))
	}
	fresh := &Dialog{CallID: "c", Local: mustAddr(t, "<"+alice+">;tag=a"), Remote: mustAddr(t, "<"+bob+">;tag=b"), RemoteTarget: mustURI(t, bob)}
	if _, err := fresh.Request("ACK", ids()); err == nil {
		t.Error("an ACK without an INVITE")
	}
}

// The first NOTIFY sets up a dialog only for the SUBSCRIBE it answers:
// the same Call-ID, exactly, and the SUBSCRIBE's From tag as its To tag,
// in any case.
func TestTheFirstNotifyMustAnswerTheSubscribe(t *testing.T) {
	for name, n := range map[string]string{
		"another Call-ID":           strings.Replace(firstNotify, "Call-ID: sub-1", "Call-ID: someone-else", 1),
		"the Call-ID in upper case": strings.Replace(firstNotify, "Call-ID: sub-1", "Call-ID: SUB-1", 1),
		"another To tag":            strings.Replace(firstNotify, "To: <sip:pcscf.rcs.internal>;tag=p1", "To: <sip:pcscf.rcs.internal>;tag=zz", 1),
		"no To tag":                 strings.Replace(firstNotify, "To: <sip:pcscf.rcs.internal>;tag=p1", "To: <sip:pcscf.rcs.internal>", 1),
	} {
		if _, err := FromNotify(request(t, subscribe), request(t, n)); !errors.Is(err, ErrNotInDialog) {
			t.Errorf("%s: %v", name, err)
		}
	}
	upper := strings.Replace(firstNotify, "To: <sip:pcscf.rcs.internal>;tag=p1", "To: <sip:pcscf.rcs.internal>;tag=P1", 1)
	if _, err := FromNotify(request(t, subscribe), request(t, upper)); err != nil {
		t.Errorf("the To tag in upper case: %v", err)
	}
}

// CSeq stays below 2^31, as RFC 3261 §8.1.1.5 and the platform's parser
// have it.
func TestCSeqStaysBelowTwoToThe31(t *testing.T) {
	d := &Dialog{CallID: "c", LocalSeq: 1<<31 - 2, Local: mustAddr(t, "<"+alice+">;tag=a"), Remote: mustAddr(t, "<"+bob+">;tag=b"), RemoteTarget: mustURI(t, bob)}
	req, err := d.Request("BYE", ids())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := req.Header.CSeq(); err != nil || req.Header.Get("CSeq") != "2147483647 BYE" {
		t.Fatalf("%q: %v", req.Header.Get("CSeq"), err)
	}
	if _, err := d.Request("BYE", ids()); err == nil {
		t.Error("a CSeq of 2^31")
	}
}

// A remote target's URI headers and method parameter, which a Request-URI
// may not carry (RFC 3261 §19.1.1), are left out of it, a strict router's
// too.
func TestTheRequestURIHasNoHeadersOrMethod(t *testing.T) {
	d := &Dialog{CallID: "c", Local: mustAddr(t, "<"+alice+">;tag=a"), Remote: mustAddr(t, "<"+bob+">;tag=b"),
		RemoteTarget: mustURI(t, "sip:scscf.rcs.internal;transport=tcp;method=INVITE?Route=%3Csip:x%3E"), LocalTarget: mustURI(t, "sip:p@10.0.2.9")}
	req, err := d.Request("SUBSCRIBE", ids())
	if err != nil {
		t.Fatal(err)
	}
	if req.URI.String() != "sip:scscf.rcs.internal;transport=tcp" || req.Validate() != nil {
		t.Fatalf("%s, %v", req.URI, req.Validate())
	}
	if d.RemoteTarget.String() != "sip:scscf.rcs.internal;transport=tcp;method=INVITE?Route=%3Csip:x%3E" {
		t.Errorf("the dialog's target changed: %s", d.RemoteTarget)
	}
	d.RouteSet = []sip.Address{mustAddr(t, "<sip:strict.rcs.internal;method=BYE?X=1>")}
	if req, _ := d.Request("BYE", ids()); req.URI.String() != "sip:strict.rcs.internal" {
		t.Errorf("a strict router's Request-URI %s", req.URI)
	}
}

// A Dialog is no storage format: its sip types write themselves redacted,
// so a JSON round trip fails rather than restoring another dialog.
func TestADialogIsNoJSONStorageFormat(t *testing.T) {
	d, err := FromNotify(request(t, subscribe), request(t, firstNotify))
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var back Dialog
	if err := json.Unmarshal(b, &back); err == nil {
		t.Errorf("a JSON round trip worked:\n%s", b)
	}
}
