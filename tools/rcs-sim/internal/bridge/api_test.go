package bridge

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/websocket/wstest"
)

func TestRequestsWithoutTheTokenAreRefusedWith401(t *testing.T) {
	h := newHarness(t)
	h.online("car")
	for _, auth := range []string{"", "Bearer", "Bearer ", "Bearer wrong-token-0123456789abcdef0123456789", "Basic " + testToken, "Bearer " + testToken + "x", "Bearer " + testToken[:len(testToken)-1]} {
		for _, r := range []struct{ method, path string }{
			{http.MethodPut, "/v1/endpoints/car"},
			{http.MethodPost, "/v1/endpoints/car/messages"},
			{http.MethodPost, "/v1/endpoints/car/imdn"},
			{http.MethodGet, "/v1/events"},
			{http.MethodGet, "/healthz"},
			{http.MethodGet, "/v1/unknown"},
		} {
			status, out := h.callWith(r.method, r.path, auth, map[string]bool{"online": false})
			if status != http.StatusUnauthorized || out["error"] == nil {
				t.Errorf("%s %s with %q answered %d %v, want 401", r.method, r.path, auth, status, out)
			}
		}
	}
	// None of them did anything: the endpoint is still registered.
	if !h.net.registered(msisdnPrefix + "000") {
		t.Fatal("a request without the token unregistered the endpoint")
	}
}

func TestTheEventStreamWithoutTheTokenIsRefused(t *testing.T) {
	h := newHarness(t)
	for _, header := range []http.Header{nil, {"Authorization": {"Bearer nope-nope-nope-nope-nope-nope-nope-nope"}}} {
		c, res, err := wstest.Dial(h.srv.URL+"/v1/events", header)
		if err == nil {
			c.Close(1000)
			t.Fatal("the event stream opened without the token")
		}
		if res == nil || res.StatusCode != http.StatusUnauthorized || !strings.HasPrefix(res.Header.Get("WWW-Authenticate"), "Bearer") {
			t.Fatalf("answered %v, want 401 with WWW-Authenticate: Bearer", res)
		}
	}
}

func TestTwoAuthorizationFieldsAreRefused(t *testing.T) {
	h := newHarness(t)
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/healthz", nil)
	req.Header.Add("Authorization", "Bearer "+testToken)
	req.Header.Add("Authorization", "Bearer "+testToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("answered %d", res.StatusCode)
	}
}

func TestPutCreatesAnEndpointRegistersItAndAnswersItsIdentities(t *testing.T) {
	h := newHarness(t)
	ev := h.events()
	status, out := h.call(http.MethodPut, "/v1/endpoints/car-1", map[string]bool{"online": true})
	if status != http.StatusCreated {
		t.Fatalf("answered %d %v", status, out)
	}
	want := map[string]any{
		"name": "car-1", "registered": true,
		"impu": "sip:" + msisdnPrefix + "000@" + testDomain, "tel": "tel:" + msisdnPrefix + "000",
	}
	for k, v := range want {
		if out[k] != v {
			t.Errorf("%s = %v, want %v", k, out[k], v)
		}
	}
	if got := ev.await("registration", "car-1"); got["state"] != "registered" || got["reason"] != nil {
		t.Fatalf("registration event %v", got)
	}
}

func TestASecondPutKeepsTheSubscriberAndItsKeys(t *testing.T) {
	h := newHarness(t)
	first := h.online("car")
	e, _ := h.b.lookup("car")
	creds := e.sub.Credentials
	status, again := h.call(http.MethodPut, "/v1/endpoints/car", map[string]bool{"online": true})
	if status != http.StatusOK || again["impu"] != first["impu"] || again["tel"] != first["tel"] || again["registered"] != true {
		t.Fatalf("the second PUT answered %d %v, want 200 and %v", status, again, first)
	}
	if h.hss.calls["car"] != 1 {
		t.Fatalf("provisioned %d times, want once", h.hss.calls["car"])
	}
	e2, _ := h.b.lookup("car")
	if e2 != e || e2.sub.Credentials != creds {
		t.Fatal("the second PUT changed the subscriber's credentials")
	}
	// Online already: no second REGISTER.
	if registers, _ := h.net.counts(); registers != 1 {
		t.Fatalf("%d REGISTERs, want 1", registers)
	}
}

func TestAPutWithoutABodyIsOnline(t *testing.T) {
	h := newHarness(t)
	if status, out := h.call(http.MethodPut, "/v1/endpoints/car", nil); status != http.StatusCreated || out["registered"] != true {
		t.Fatalf("answered %d %v", status, out)
	}
}

func TestOfflineUnregistersAndKeepsTheSubscriberAndOnlineRegistersAgain(t *testing.T) {
	h := newHarness(t)
	ev := h.events()
	h.online("car")
	ev.await("registration", "car")
	status, out := h.call(http.MethodPut, "/v1/endpoints/car", map[string]bool{"online": false})
	if status != http.StatusOK || out["registered"] != false || out["impu"] == nil {
		t.Fatalf("offline answered %d %v", status, out)
	}
	if got := ev.await("registration", "car"); got["state"] != "unregistered" {
		t.Fatalf("event %v, want unregistered", got)
	}
	if h.net.registered(msisdnPrefix + "000") {
		t.Fatal("still registered in the network")
	}
	// Offline again changes nothing.
	if status, out := h.call(http.MethodPut, "/v1/endpoints/car", map[string]bool{"online": false}); status != http.StatusOK || out["registered"] != false {
		t.Fatalf("offline twice answered %d %v", status, out)
	}
	h.online("car")
	if got := ev.await("registration", "car"); got["state"] != "registered" {
		t.Fatalf("event %v, want registered", got)
	}
	if h.hss.calls["car"] != 1 {
		t.Fatalf("provisioned %d times, want once", h.hss.calls["car"])
	}
}

func TestDotNamesAreNotNames(t *testing.T) {
	for _, n := range []string{".", ".."} {
		if validName(n) {
			t.Errorf("%q is a valid name", n)
		}
	}
	for _, n := range []string{"...", ".a", "a.", "가\u0301"} {
		if !validName(n) {
			t.Errorf("%q is not a valid name", n)
		}
	}
}

func TestEndpointNamesAreChecked(t *testing.T) {
	h := newHarness(t)
	for _, name := range []string{"a%3Ab", "sip%3Aa", "a%2Fb", "a%20b", strings.Repeat("a", 65), "%E2%80%8B", "a%00"} {
		if status, _ := h.call(http.MethodPut, "/v1/endpoints/"+name, nil); status != http.StatusBadRequest {
			t.Errorf("PUT %q answered %d, want 400", name, status)
		}
	}
	for _, name := range []string{"car_01.A~b-c", "12%EA%B0%803456", strings.Repeat("a", 64)} {
		if status, out := h.call(http.MethodPut, "/v1/endpoints/"+name, nil); status != http.StatusCreated {
			t.Errorf("PUT %q answered %d %v, want 201", name, status, out)
		}
	}
}

func TestTheEndpointBoundCountsTheOnesOnline(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.MaxEndpoints = 2 })
	h.online("a")
	h.online("b")
	if status, _ := h.call(http.MethodPut, "/v1/endpoints/c", nil); status != http.StatusConflict {
		t.Fatalf("a third endpoint online answered %d, want 409", status)
	}
	if h.net.registered(msisdnPrefix + "002") {
		t.Fatal("the endpoint refused registered")
	}
	// Offline ones do not count: c may exist offline, and goes online
	// once another has gone offline.
	if status, out := h.call(http.MethodPut, "/v1/endpoints/c", map[string]bool{"online": false}); status != http.StatusOK || out["registered"] != false {
		t.Fatalf("c offline answered %d %v", status, out)
	}
	if status, _ := h.call(http.MethodPut, "/v1/endpoints/d", map[string]bool{"online": false}); status != http.StatusCreated {
		t.Fatalf("a new endpoint offline answered %d, want 201", status)
	}
	// Online again is no second count.
	if status, _ := h.call(http.MethodPut, "/v1/endpoints/a", nil); status != http.StatusOK {
		t.Fatalf("an endpoint online already answered %d", status)
	}
	h.call(http.MethodPut, "/v1/endpoints/a", map[string]bool{"online": false})
	if status, out := h.call(http.MethodPut, "/v1/endpoints/c", nil); status != http.StatusOK || out["registered"] != true {
		t.Fatalf("c online after a went offline answered %d %v", status, out)
	}
	if status, _ := h.call(http.MethodPut, "/v1/endpoints/a", nil); status != http.StatusConflict {
		t.Fatalf("a online again past the bound answered %d, want 409", status)
	}
}

// With no event stream open the bridge cannot hand a message on, so it
// answers 480: rcs-as keeps it for the endpoint's next registration
// instead of taking it for delivered, and the sender hears nothing yet
// (code review on #661).
func TestAMessageWithNoStreamOpenIs480AndComesWithItsNotificationLater(t *testing.T) {
	h := newHarness(t)
	h.online("car")
	h.online("phone")
	phone, _ := h.b.lookup("phone")
	car, _ := h.b.lookup("car")
	body, err := car.cpimMessage(outgoing{target: phone.sub.IMPU, contentType: "text/plain", body: "x", messageID: "direct", asked: imdn.PositiveDelivery})
	if err != nil {
		t.Fatal(err)
	}
	if code := phone.receive(Incoming{From: car.sub.Tel, ContentType: cpim.ContentType, Body: body}); code != 480 {
		t.Fatalf("a message with no stream open answered %d, want 480", code)
	}
	status, out := h.call(http.MethodPost, "/v1/endpoints/car/messages", map[string]any{"to": "phone", "body": "later", "message_id": "later-1", "imdn": []string{"delivery"}})
	if status != http.StatusOK || out["sip_status"] != float64(202) {
		t.Fatalf("send answered %d %v", status, out)
	}
	if n := len(h.net.sentBy(msisdnPrefix + "001")); n != 0 {
		t.Fatalf("the phone sent %d notifications for messages nobody has", n)
	}
	// Nobody saw it, so nobody can have displayed it (QA on #661).
	ev := h.events()
	if status, _ := h.call(http.MethodPost, "/v1/endpoints/phone/imdn", map[string]any{"to": "car", "message_id": "direct", "status": "displayed"}); status != http.StatusNotFound {
		t.Fatalf("a display notification for a message never shown answered %d, want 404", status)
	}
	h.call(http.MethodPut, "/v1/endpoints/phone", map[string]bool{"online": false})
	h.online("phone")
	if m := ev.await("message", "phone"); m["message_id"] != "later-1" || m["body"] != "later" {
		t.Fatalf("message event %v", m)
	}
	if d := ev.await("imdn", "car"); d["message_id"] != "later-1" || d["status"] != "delivered" {
		t.Fatalf("imdn event %v", d)
	}
}

// An application that puts its endpoint online before it opens its event
// stream, as a gateway starting up would: what rcs-as kept while the
// endpoint was offline comes at once, with no stream to take it, and must
// still not be lost (QA on #661, reproduction B).
func TestAMessageKeptWhileOfflineSurvivesOnlineBeforeTheStream(t *testing.T) {
	h := newHarness(t)
	h.online("car")
	h.online("phone")
	h.call(http.MethodPut, "/v1/endpoints/phone", map[string]bool{"online": false})
	if status, out := h.call(http.MethodPost, "/v1/endpoints/car/messages", map[string]any{"to": "phone", "body": "kept", "message_id": "kept-B", "imdn": []string{"delivery", "display"}}); status != http.StatusOK || out["sip_status"] != float64(202) {
		t.Fatalf("send answered %d %v", status, out)
	}
	h.net.mu.Lock()
	h.net.deliverFirst = true
	h.net.mu.Unlock()
	// Online first: the kept message comes before PUT returns, and is
	// refused, so the network keeps it.
	h.online("phone")
	if n := h.net.storedFor(msisdnPrefix + "001"); n != 1 {
		t.Fatalf("%d messages kept for the phone, want the one refused", n)
	}
	if n := len(h.net.sentBy(msisdnPrefix + "001")); n != 0 {
		t.Fatalf("the phone sent %d notifications for a message nobody has", n)
	}
	if status, _ := h.call(http.MethodPost, "/v1/endpoints/phone/imdn", map[string]any{"to": "car", "message_id": "kept-B", "status": "displayed"}); status != http.StatusNotFound {
		t.Fatalf("a display notification for a message never shown answered %d, want 404", status)
	}
	// Then the stream, and a registration: it comes, and is delivered.
	ev := h.events()
	h.call(http.MethodPut, "/v1/endpoints/phone", map[string]bool{"online": false})
	h.online("phone")
	if m := ev.await("message", "phone"); m["message_id"] != "kept-B" || m["body"] != "kept" {
		t.Fatalf("message event %v", m)
	}
	if d := ev.await("imdn", "car"); d["message_id"] != "kept-B" || d["status"] != "delivered" {
		t.Fatalf("imdn event %v", d)
	}
	if status, _ := h.call(http.MethodPost, "/v1/endpoints/phone/imdn", map[string]any{"to": "car", "message_id": "kept-B", "status": "displayed"}); status != http.StatusOK {
		t.Fatalf("a display notification for the message shown answered %d", status)
	}
}

// A message id the endpoint showed once stays displayable when a later
// message with the same id is refused.
func TestARefusedRepeatKeepsTheMessageShownBefore(t *testing.T) {
	r := newRecent(4)
	first := received{request: imdn.Request{MessageID: "m", Dispositions: imdn.Display}}
	r.put("m", first)
	undo := r.put("m", received{})
	undo()
	if got, ok := r.get("m"); !ok || got.request.Dispositions != imdn.Display {
		t.Fatalf("got %v %v, want the first message back", got, ok)
	}
	undo = r.put("n", received{})
	undo()
	if _, ok := r.get("n"); ok || len(r.order) != 1 {
		t.Fatalf("a refused message is still remembered (%d in order)", len(r.order))
	}
}

// The delivery notification goes only once the message's event is in a
// stream's queue.
func TestTheDeliveryNotificationGoesAfterTheEventIsQueued(t *testing.T) {
	h := newHarness(t)
	h.online("car")
	h.online("phone")
	sub, _ := h.b.hub.subscribe()
	queued := make(chan bool, 1)
	h.net.mu.Lock()
	h.net.onSend = func(from string, body []byte) {
		if from != msisdnPrefix+"001" {
			return
		}
		ok := false
		select {
		case ev := <-sub.events:
			ok = strings.Contains(string(ev), `"type":"message"`) && strings.Contains(string(ev), `"message_id":"order-1"`)
		default:
		}
		queued <- ok
	}
	h.net.mu.Unlock()
	// The hub held while the message comes in: no notification may go
	// before its event can be queued. The hold can only fail a bridge
	// that sends too early; one that waits passes however long it is.
	h.b.hub.mu.Lock()
	sent := make(chan struct{})
	go func() {
		defer close(sent)
		h.call(http.MethodPost, "/v1/endpoints/car/messages", map[string]any{"to": "phone", "body": "x", "message_id": "order-1", "imdn": []string{"delivery"}})
	}()
	eventually(t, "the message is on its way", func() bool { return len(h.net.sentBy(msisdnPrefix+"000")) == 1 })
	time.Sleep(200 * time.Millisecond)
	early := len(h.net.sentBy(msisdnPrefix + "001"))
	h.b.hub.mu.Unlock()
	<-sent
	if early != 0 {
		t.Fatal("the delivery notification went while the event could not be queued")
	}
	select {
	case ok := <-queued:
		if !ok {
			t.Fatal("the delivery notification went before the message's event was queued")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no delivery notification")
	}
}

// A stream that leaves the hub between two messages: the second, with no
// stream left, is refused, and nothing tells its sender it was delivered.
func TestAMessageAfterTheLastStreamClosedIsRefused(t *testing.T) {
	h := newHarness(t)
	h.online("car")
	h.online("phone")
	s := h.events()
	h.call(http.MethodPost, "/v1/endpoints/car/messages", map[string]any{"to": "phone", "body": "x", "message_id": "before", "imdn": []string{"delivery"}})
	s.await("imdn", "car")
	s.c.Close(1000)
	eventually(t, "the stream is gone", func() bool {
		h.b.hub.mu.Lock()
		defer h.b.hub.mu.Unlock()
		return len(h.b.hub.subs) == 0
	})
	before := len(h.net.sentBy(msisdnPrefix + "001"))
	phone, _ := h.b.lookup("phone")
	car, _ := h.b.lookup("car")
	body, _ := car.cpimMessage(outgoing{target: phone.sub.IMPU, contentType: "text/plain", body: "x", messageID: "after", asked: imdn.PositiveDelivery})
	if code := phone.receive(Incoming{From: car.sub.Tel, ContentType: cpim.ContentType, Body: body}); code != 480 {
		t.Fatalf("answered %d, want 480", code)
	}
	if after := len(h.net.sentBy(msisdnPrefix + "001")); after != before {
		t.Fatal("a notification went for a message nobody has")
	}
}

func TestAProvisioningFailureIs502AndCreatesNothing(t *testing.T) {
	h := newHarness(t)
	h.hss.fail = errors.New("hss: create subscription answered 503")
	status, out := h.call(http.MethodPut, "/v1/endpoints/car", nil)
	if status != http.StatusBadGateway || !strings.Contains(out["error"].(string), "answered 503") {
		t.Fatalf("answered %d %v", status, out)
	}
	if status, _ := h.call(http.MethodPost, "/v1/endpoints/car/messages", map[string]string{"to": "tel:+15550100001"}); status != http.StatusNotFound {
		t.Fatalf("a send from the endpoint that failed answered %d, want 404", status)
	}
	h.hss.fail = nil
	h.online("car")
}

func TestBadRequestBodiesAre400(t *testing.T) {
	h := newHarness(t)
	h.online("car")
	h.online("phone")
	for _, tc := range []struct {
		path string
		body any
	}{
		{"/v1/endpoints/car", "{"},
		{"/v1/endpoints/car", `{"online": "yes"}`},
		{"/v1/endpoints/car", `{} {}`},
		// Mistyped, which would otherwise be online.
		{"/v1/endpoints/car", `{"onlin": false}`},
		{"/v1/endpoints/car/messages", map[string]any{"to": "phone", "content_type": "text", "body": "x"}},
		{"/v1/endpoints/car/messages", map[string]any{"body": "x"}},
		{"/v1/endpoints/car/messages", map[string]any{"to": "nobody", "body": "x"}},
		{"/v1/endpoints/car/messages", map[string]any{"to": "mailto:x@example.test", "body": "x"}},
		{"/v1/endpoints/car/messages", map[string]any{"to": "tel:5550100", "body": "x"}},
		{"/v1/endpoints/car/messages", map[string]any{"to": "phone", "content_type": "not a type", "body": "x"}},
		{"/v1/endpoints/car/messages", map[string]any{"to": "phone", "content_type": "text/plain\r\nX: y", "body": "x"}},
		{"/v1/endpoints/car/messages", map[string]any{"to": "phone", "message_id": "has space", "body": "x"}},
		{"/v1/endpoints/car/messages", map[string]any{"to": "phone", "message_id": strings.Repeat("a", 129), "body": "x"}},
		{"/v1/endpoints/car/messages", map[string]any{"to": "phone", "imdn": []string{"read"}, "body": "x"}},
		{"/v1/endpoints/car/imdn", map[string]any{"to": "phone", "message_id": "m", "status": "delivered"}},
		{"/v1/endpoints/car/imdn", map[string]any{"to": "nobody", "message_id": "m", "status": "displayed"}},
	} {
		method := http.MethodPost
		if !strings.Contains(tc.path, "/messages") && !strings.Contains(tc.path, "/imdn") {
			method = http.MethodPut
		}
		if status, out := h.call(method, tc.path, tc.body); status != http.StatusBadRequest || out["error"] == nil {
			t.Errorf("%s %v answered %d %v, want 400", tc.path, tc.body, status, out)
		}
	}
	big := map[string]string{"to": "phone", "body": strings.Repeat("x", maxRequestBody)}
	if status, _ := h.call(http.MethodPost, "/v1/endpoints/car/messages", big); status != http.StatusRequestEntityTooLarge {
		t.Errorf("a body over 64 KiB answered %d, want 413", status)
	}
	// Nothing went out.
	if n := len(h.net.sentBy(msisdnPrefix + "000")); n != 0 {
		t.Fatalf("%d MESSAGEs sent", n)
	}
}

func TestASendFromAnUnknownEndpointIs404AndFromAnOfflineOne409(t *testing.T) {
	h := newHarness(t)
	if status, _ := h.call(http.MethodPost, "/v1/endpoints/ghost/messages", map[string]string{"to": "tel:+15550100001"}); status != http.StatusNotFound {
		t.Fatalf("answered %d, want 404", status)
	}
	h.online("car")
	h.call(http.MethodPut, "/v1/endpoints/car", map[string]bool{"online": false})
	if status, _ := h.call(http.MethodPost, "/v1/endpoints/car/messages", map[string]string{"to": "tel:+15550100001"}); status != http.StatusConflict {
		t.Fatalf("a send while offline answered %d, want 409", status)
	}
}

func TestAMessageArrivesAsAnEventWithItsBodyAndContentTypeAndTheSenderHearsItWasDelivered(t *testing.T) {
	h := newHarness(t)
	ev := h.events()
	h.online("car")
	h.online("phone")
	body := "{\"lat\": 37.5, \"text\": \"주차했어요 \\u2014 ok\"}"
	status, out := h.call(http.MethodPost, "/v1/endpoints/car/messages", map[string]any{
		"to": "phone", "content_type": "application/json", "body": body, "message_id": "msg-1", "imdn": []string{"delivery", "display"},
	})
	if status != http.StatusOK || out["message_id"] != "msg-1" || out["sip_status"] != float64(202) {
		t.Fatalf("send answered %d %v", status, out)
	}
	m := ev.await("message", "phone")
	want := map[string]any{
		"from": "tel:" + msisdnPrefix + "000", "from_endpoint": "car", "message_id": "msg-1",
		"content_type": "application/json", "body": body, "at": "2026-10-24T09:30:00Z",
	}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("message event %s = %v, want %v", k, m[k], v)
		}
	}
	d := ev.await("imdn", "car")
	if d["from_endpoint"] != "phone" || d["message_id"] != "msg-1" || d["status"] != "delivered" {
		t.Fatalf("imdn event %v", d)
	}
	// What went to the network is CPIM from the car's SIP identity to the
	// phone's, with both notifications asked for (RFC 5438 §6.3).
	sent := h.net.sentBy(msisdnPrefix + "000")
	if len(sent) != 1 {
		t.Fatalf("%d MESSAGEs sent", len(sent))
	}
	c, err := cpim.Parse(sent[0])
	if err != nil {
		t.Fatal(err)
	}
	req, err := imdn.ParseRequest(c)
	from, _ := c.From()
	to, _ := c.To()
	if err != nil || req.MessageID != "msg-1" || !req.Dispositions.Wants(imdn.DeliveryNotification, imdn.Delivered) ||
		!req.Dispositions.Wants(imdn.DisplayNotification, imdn.Displayed) || from.URI != "sip:"+msisdnPrefix+"000@"+testDomain ||
		len(to) != 1 || to[0].URI != "sip:"+msisdnPrefix+"001@"+testDomain || c.ContentType() != "application/json" {
		t.Fatalf("sent %q", sent[0])
	}
}

func TestAMessageWithoutAnIMDNRequestGetsNoNotificationAndAGeneratedID(t *testing.T) {
	h := newHarness(t)
	ev := h.events()
	h.online("car")
	h.online("phone")
	status, out := h.call(http.MethodPost, "/v1/endpoints/car/messages", map[string]any{"to": "phone", "body": "hi"})
	id, _ := out["message_id"].(string)
	if status != http.StatusOK || !validMessageID(id) {
		t.Fatalf("send answered %d %v", status, out)
	}
	m := ev.await("message", "phone")
	if m["message_id"] != id || m["content_type"] != defaultContentType || m["body"] != "hi" {
		t.Fatalf("message event %v", m)
	}
	// The phone sent nothing back.
	if n := len(h.net.sentBy(msisdnPrefix + "001")); n != 0 {
		t.Fatalf("the receiver sent %d MESSAGEs", n)
	}
}

func TestAMessageToAURISendsToItAsItIs(t *testing.T) {
	h := newHarness(t)
	ev := h.events()
	h.online("car")
	h.online("phone")
	// The phone's tel URI, as an application outside the bridge knows it.
	if status, out := h.call(http.MethodPost, "/v1/endpoints/car/messages", map[string]any{"to": "tel:" + msisdnPrefix + "001", "body": "hi"}); status != http.StatusOK || out["sip_status"] != float64(202) {
		t.Fatalf("send answered %d %v", status, out)
	}
	if m := ev.await("message", "phone"); m["from_endpoint"] != "car" {
		t.Fatalf("message event %v", m)
	}
	// A number no endpoint has: the network's answer is the answer.
	if status, out := h.call(http.MethodPost, "/v1/endpoints/car/messages", map[string]any{"to": "sip:alice@example.test", "body": "hi"}); status != http.StatusOK || out["sip_status"] != float64(404) {
		t.Fatalf("send answered %d %v", status, out)
	}
}

func TestAMessageToAnOfflineEndpointIsStoredAndArrivesOnceItIsOnlineAgain(t *testing.T) {
	h := newHarness(t)
	ev := h.events()
	h.online("car")
	h.online("phone")
	h.call(http.MethodPut, "/v1/endpoints/phone", map[string]bool{"online": false})
	status, out := h.call(http.MethodPost, "/v1/endpoints/car/messages", map[string]any{"to": "phone", "body": "parked", "message_id": "stored-1", "imdn": []string{"delivery"}})
	if status != http.StatusOK || out["sip_status"] != float64(202) {
		t.Fatalf("send answered %d %v", status, out)
	}
	h.online("phone")
	m := ev.await("message", "phone")
	if m["message_id"] != "stored-1" || m["body"] != "parked" || m["from_endpoint"] != "car" {
		t.Fatalf("message event %v", m)
	}
	if d := ev.await("imdn", "car"); d["message_id"] != "stored-1" || d["status"] != "delivered" {
		t.Fatalf("imdn event %v", d)
	}
}

// The network may deliver what it kept before the endpoint has its new
// line back from Register: the delivery notification goes on the line the
// message came on all the same.
func TestAStoredMessageDeliveredBeforeTheRegisterReturnsIsStillNotified(t *testing.T) {
	h := newHarness(t)
	ev := h.events()
	h.online("car")
	h.online("phone")
	h.call(http.MethodPut, "/v1/endpoints/phone", map[string]bool{"online": false})
	h.call(http.MethodPost, "/v1/endpoints/car/messages", map[string]any{"to": "phone", "body": "early", "message_id": "early-1", "imdn": []string{"delivery"}})
	h.net.mu.Lock()
	h.net.deliverFirst = true
	h.net.mu.Unlock()
	h.online("phone")
	ev.await("message", "phone")
	if d := ev.await("imdn", "car"); d["message_id"] != "early-1" || d["status"] != "delivered" {
		t.Fatalf("imdn event %v", d)
	}
}

func TestANetworkWithoutStoreAndForwardIsReportedAs480(t *testing.T) {
	h := newHarness(t)
	h.net.offline = 480
	h.online("car")
	h.online("phone")
	h.call(http.MethodPut, "/v1/endpoints/phone", map[string]bool{"online": false})
	status, out := h.call(http.MethodPost, "/v1/endpoints/car/messages", map[string]any{"to": "phone", "body": "x", "message_id": "m-480"})
	if status != http.StatusOK || out["sip_status"] != float64(480) || out["message_id"] != "m-480" {
		t.Fatalf("send answered %d %v, want sip_status 480", status, out)
	}
}

func TestADisplayNotificationThroughTheAPIReachesTheSender(t *testing.T) {
	h := newHarness(t)
	ev := h.events()
	h.online("car")
	h.online("phone")
	h.call(http.MethodPost, "/v1/endpoints/car/messages", map[string]any{"to": "phone", "body": "x", "message_id": "seen-1", "imdn": []string{"delivery", "display"}})
	m := ev.await("message", "phone")
	ev.await("imdn", "car")
	// "to" may be the sender's endpoint name, or its URI as the message
	// event gave it.
	for _, to := range []any{"car", m["from"], "sip:" + msisdnPrefix + "000@" + testDomain} {
		status, out := h.call(http.MethodPost, "/v1/endpoints/phone/imdn", map[string]any{"to": to, "message_id": "seen-1", "status": "displayed"})
		if status != http.StatusOK || out["sip_status"] != float64(202) || out["message_id"] != "seen-1" {
			t.Fatalf("imdn to %v answered %d %v", to, status, out)
		}
		d := ev.await("imdn", "car")
		if d["from_endpoint"] != "phone" || d["message_id"] != "seen-1" || d["status"] != "displayed" {
			t.Fatalf("imdn event %v", d)
		}
	}
}

func TestADisplayNotificationNobodyAskedForIsRefused(t *testing.T) {
	h := newHarness(t)
	ev := h.events()
	h.online("car")
	h.online("phone")
	h.online("van")
	h.call(http.MethodPost, "/v1/endpoints/car/messages", map[string]any{"to": "phone", "body": "x", "message_id": "only-delivery", "imdn": []string{"delivery"}})
	ev.await("message", "phone")
	ev.await("imdn", "car")
	before := len(h.net.sentBy(msisdnPrefix + "001"))
	for _, tc := range []struct {
		to, id string
		status int
	}{
		// RFC 5438 §7.2.1: not asked for.
		{"car", "only-delivery", http.StatusConflict},
		// Never received, or not from that sender.
		{"car", "never-sent", http.StatusNotFound},
		{"van", "only-delivery", http.StatusNotFound},
		{"tel:+15550100001", "only-delivery", http.StatusNotFound},
	} {
		if status, out := h.call(http.MethodPost, "/v1/endpoints/phone/imdn", map[string]any{"to": tc.to, "message_id": tc.id, "status": "displayed"}); status != tc.status {
			t.Errorf("imdn %v answered %d %v, want %d", tc, status, out, tc.status)
		}
	}
	if after := len(h.net.sentBy(msisdnPrefix + "001")); after != before {
		t.Fatalf("%d notifications went out", after-before)
	}
}

func TestAMessageTheEndpointCannotReadIsRefusedNotTakenForDelivered(t *testing.T) {
	h := newHarness(t)
	h.online("phone")
	e, _ := h.b.lookup("phone")
	for _, tc := range []struct {
		in   Incoming
		code int
	}{
		{Incoming{ContentType: "text/plain", Body: []byte("x")}, 415},
		{Incoming{ContentType: cpim.ContentType, Body: []byte("not cpim")}, 400},
	} {
		if code := e.receive(tc.in); code != tc.code {
			t.Errorf("receive(%s) = %d, want %d", tc.in.ContentType, code, tc.code)
		}
	}
}

func TestAFullInboxAnswers486SoThatTheNetworkTriesAgain(t *testing.T) {
	h := newHarness(t)
	h.events()
	h.online("car")
	h.online("phone")
	e, _ := h.b.lookup("phone")
	// The worker is held on its first message: its delivery
	// notification's MESSAGE does not return.
	h.net.mu.Lock()
	h.net.hold = make(chan struct{})
	h.net.mu.Unlock()
	defer close(h.net.hold)
	car, _ := h.b.lookup("car")
	body, err := car.cpimMessage(outgoing{target: e.sub.IMPU, contentType: "text/plain", body: "x", messageID: "first", asked: imdn.PositiveDelivery})
	if err != nil {
		t.Fatal(err)
	}
	in := Incoming{From: car.sub.Tel, ContentType: cpim.ContentType, Body: body}
	if code := e.receive(in); code != 200 {
		t.Fatalf("the first answered %d", code)
	}
	eventually(t, "the worker holds the first message", func() bool { return len(h.net.sentBy(msisdnPrefix+"001")) == 1 })
	for i := range inboxLength {
		if code := e.receive(in); code != 200 {
			t.Fatalf("message %d answered %d", i, code)
		}
	}
	if code := e.receive(in); code != 486 {
		t.Fatalf("the message past the inbox answered %d, want 486", code)
	}
}

// lockedLog is a log the bridge's goroutines write and the test reads.
type lockedLog struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func TestTheLogShowsNoBodyTokenOrIdentity(t *testing.T) {
	var log lockedLog
	h := newHarness(t, func(c *Config) {
		c.Logger = slog.New(slog.NewJSONHandler(&log, &slog.HandlerOptions{Level: slog.LevelDebug}))
	})
	ev := h.events()
	h.online("plate-12가3456")
	h.online("phone")
	h.call(http.MethodPost, "/v1/endpoints/plate-12가3456/messages", map[string]any{"to": "phone", "body": "secret body text", "message_id": "log-1", "imdn": []string{"delivery", "display"}})
	ev.await("imdn", "plate-12가3456")
	h.call(http.MethodPost, "/v1/endpoints/phone/imdn", map[string]any{"to": "plate-12가3456", "message_id": "log-1", "status": "displayed"})
	h.net.drop(msisdnPrefix + "000")
	ev.await("registration", "plate-12가3456")
	h.call(http.MethodPut, "/v1/endpoints/phone", map[string]bool{"online": false})
	out := log.String()
	for _, leak := range []string{"secret body text", testToken, "log-1", "12가3456", "phone\"", msisdnPrefix, impiPrefix} {
		if strings.Contains(out, leak) {
			t.Errorf("the log shows %q:\n%s", leak, out)
		}
	}
	for _, want := range []string{`"msg":"registered"`, `"msg":"message sent"`, `"msg":"flow lost"`, `"route":"POST /v1/endpoints/{name}/messages"`} {
		if !strings.Contains(out, want) {
			t.Errorf("the log has no %s:\n%s", want, out)
		}
	}
}
