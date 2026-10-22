package sipua

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

const (
	// testConference is a group's conference URI, as rcs-as gives one.
	testConference  = "sip:chat-0123456789abcdef0123456789abcdef@conf.example.com"
	conferenceType  = "application/conference-info+xml"
	conferenceEvent = "conference"
)

// conferenceSubscribed is subscribed with a UA subscribed to testConference's
// conference event package (RFC 4575) for expires seconds.
func conferenceSubscribed(t *testing.T, expires int) (*standIn, *notifier, *UA, *Subscription) {
	t.Helper()
	s := newStandIn(t, transport.TCP)
	n := newNotifier(t, s)
	ua := dial(t, s.config())
	register(t, ua)
	sub, res, err := ua.Subscribe(context.Background(), mustURI(t, testConference), conferenceEvent, conferenceType, expires)
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("Subscribe = %v, %v", res, err)
	}
	return s, n, ua, sub
}

func TestSubscribeAsksForTheEventAtTheTarget(t *testing.T) {
	s, _, _, _ := conferenceSubscribed(t, 3600)
	req := s.nextMethod(t, "SUBSCRIBE").req
	to, _ := req.Header.To()
	contacts, _ := req.Header.Contact()
	switch {
	case req.URI.String() != testConference || to.URI.String() != testConference:
		t.Errorf("Request-URI %s, To %s: want the conference URI", req.URI, to)
	case req.Header.Get("Event") != conferenceEvent || req.Header.Get("Accept") != conferenceType:
		t.Errorf("Event %q, Accept %q", req.Header.Get("Event"), req.Header.Get("Accept"))
	case req.Header.Get("Expires") != "3600":
		t.Errorf("Expires %q", req.Header.Get("Expires"))
	case len(contacts) != 1 || !contacts[0].URI.Params.Has("ob"):
		t.Errorf("Contact %v", contacts)
	}
}

func TestAConferenceNotifyCarriesItsBodyAsItCame(t *testing.T) {
	s, n, _, sub := conferenceSubscribed(t, 3600)
	s.nextMethod(t, "SUBSCRIBE")
	body := []byte(`<conference-info xmlns="urn:ietf:params:xml:ns:conference-info" entity="` + testConference + `" state="full" version="1"/>`)
	req := n.request(t, "active;expires=3600", "", conferenceEvent)
	req.Header.Add("Content-Type", conferenceType)
	req.Body = body
	if res := s.sendRequest(t, req, n.flow); res.StatusCode != 200 {
		t.Fatalf("NOTIFY answered %d", res.StatusCode)
	}
	got := nextNotification(t, sub)
	if got.Err != nil || got.Info != nil || got.ContentType != conferenceType || !bytes.Equal(got.Body, body) || got.State != "active" {
		t.Fatalf("notification = %+v", got)
	}
	// The package is the subscription's: a reg NOTIFY in its dialog is
	// another event (RFC 6665 §4.1.3).
	if res := s.sendRequest(t, n.request(t, "active", "", "reg"), n.flow); res.StatusCode != 489 {
		t.Errorf("a reg NOTIFY in a conference subscription answered %d, want 489", res.StatusCode)
	}
	if res, err := sub.Unsubscribe(context.Background()); err != nil || res.StatusCode != 200 {
		t.Fatalf("Unsubscribe = %v, %v", res, err)
	}
	un := s.nextMethod(t, "SUBSCRIBE")
	if un.req.Header.Get("Event") != conferenceEvent || un.req.Header.Get("Expires") != "0" {
		t.Errorf("unsubscribe Event %q Expires %q", un.req.Header.Get("Event"), un.req.Header.Get("Expires"))
	}
}

func TestAFetchEndsWithItsOneNotify(t *testing.T) {
	// RFC 6665 §4.1.2.1: Expires 0 fetches the state once, in a NOTIFY
	// that ends the subscription.
	s, n, _, sub := conferenceSubscribed(t, 0)
	if req := s.nextMethod(t, "SUBSCRIBE").req; req.Header.Get("Expires") != "0" {
		t.Fatalf("Expires %q", req.Header.Get("Expires"))
	}
	if res := s.sendRequest(t, n.request(t, "terminated;reason=timeout", "", conferenceEvent), n.flow); res.StatusCode != 200 {
		t.Fatalf("NOTIFY answered %d", res.StatusCode)
	}
	if got := nextNotification(t, sub); got.State != "terminated" || got.Reason != "timeout" {
		t.Fatalf("notification = %+v", got)
	}
	select {
	case <-sub.Done():
	case <-time.After(waitFor):
		t.Fatal("the fetch did not end")
	}
}

func TestSubscribeNeedsAnEventABodyTypeAndAnExpiry(t *testing.T) {
	s := newStandIn(t, transport.TCP)
	ua := dial(t, s.config())
	register(t, ua)
	target := mustURI(t, testConference)
	for name, tc := range map[string]struct {
		event, accept string
		expires       int
	}{
		"no event":  {"", conferenceType, 60},
		"no accept": {conferenceEvent, "", 60},
		"negative":  {conferenceEvent, conferenceType, -1},
	} {
		if sub, res, err := ua.Subscribe(context.Background(), target, tc.event, tc.accept, tc.expires); err == nil || sub != nil || res != nil {
			t.Errorf("%s: Subscribe = %v, %v, %v", name, sub, res, err)
		}
	}
}
