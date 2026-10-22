package chat_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/chat"
)

var (
	alice = cpim.Address{URI: "sip:+15550100001@ims.mnc001.mcc001.3gppnetwork.org"}
	bob   = cpim.Address{URI: "sip:+15550100002@ims.mnc001.mcc001.3gppnetwork.org"}
)

func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}

// pair connects a client straight to the rcs-as stand-in, without a relay:
// what the relay does in between is msrp-relay's to test.
// setup, when given, adjusts both endpoints before any traffic, so that no
// field is written while a handler goroutine reads it.
func pair(t *testing.T, setup ...func(client, core *chat.Endpoint)) (client *chat.Endpoint, cs *msrp.Session, core *chat.Endpoint, ss *msrp.Session) {
	t.Helper()
	c, err := chat.ListenCore("127.0.0.1:0", "", msrp.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	coreURI, err := c.NewURI(nil)
	if err != nil {
		t.Fatal(err)
	}
	clientURI, err := chat.LocalURI(nil)
	if err != nil {
		t.Fatal(err)
	}
	client, core = chat.NewEndpoint(alice), chat.NewEndpoint(bob)
	for _, f := range setup {
		f(client, core)
	}
	if ss, err = c.Expect(coreURI, clientURI, core); err != nil {
		t.Fatal(err)
	}
	cl, err := chat.Dial(ctx(t), coreURI, clientURI, client, msrp.Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cl.Close() })
	return client, cl.Session, core, ss
}

func received(t *testing.T, e *chat.Endpoint) chat.Received {
	t.Helper()
	select {
	case r := <-e.Messages:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("no message")
		return chat.Received{}
	}
}

func notification(t *testing.T, e *chat.Endpoint) imdn.Notification {
	t.Helper()
	select {
	case n := <-e.Notifications:
		return n
	case <-time.After(5 * time.Second):
		t.Fatal("no notification")
		return imdn.Notification{}
	}
}

func TestMessagesAreCPIMWithTheirIMDNRequest(t *testing.T) {
	client, cs, core, _ := pair(t)
	id, err := client.Send(ctx(t), cs, bob, "text/plain", []byte("hi"), imdn.PositiveDelivery|imdn.Display)
	if err != nil {
		t.Fatal(err)
	}
	got := received(t, core)
	if string(got.Body) != "hi" || got.From.URI != alice.URI || got.ContentType != "text/plain" || got.Request.MessageID != id.IMDN ||
		!got.Request.Dispositions.Wants(imdn.DisplayNotification, imdn.Displayed) {
		t.Fatalf("received %+v", got)
	}
	// The recipient confirms delivery at once and display only when told.
	if n := notification(t, client); n.MessageID != id.IMDN || n.Status != imdn.Delivered || n.RecipientURI != bob.URI {
		t.Fatalf("notification %+v", n)
	}
	select {
	case n := <-client.Notifications:
		t.Fatalf("a display notification nobody sent: %+v", n)
	case <-time.After(50 * time.Millisecond):
	}
	if rep := <-client.Reports; rep.Code != msrp.StatusOK {
		t.Fatalf("report %+v", rep)
	}
}

func TestDisplayIsSentWhenTheUserReads(t *testing.T) {
	client, cs, core, ss := pair(t)
	id, err := client.Send(ctx(t), cs, bob, "text/plain", []byte("read me"), imdn.Display)
	if err != nil {
		t.Fatal(err)
	}
	if err := core.Display(ctx(t), ss, received(t, core)); err != nil {
		t.Fatal(err)
	}
	if n := notification(t, client); n.MessageID != id.IMDN || n.Status != imdn.Displayed {
		t.Fatalf("notification %+v", n)
	}
	core.Wait()
}

func TestAutoDisplayAnswersBothRequestsAndNothingUnasked(t *testing.T) {
	client, cs, core, ss := pair(t, func(_, core *chat.Endpoint) { core.AutoDisplay = true })
	id, err := client.Send(ctx(t), cs, bob, "text/plain", []byte("x"), imdn.PositiveDelivery|imdn.Display)
	if err != nil {
		t.Fatal(err)
	}
	received(t, core)
	statuses := map[imdn.Status]bool{}
	for range 2 {
		n := notification(t, client)
		if n.MessageID != id.IMDN {
			t.Fatal("notification for another message")
		}
		statuses[n.Status] = true
	}
	if !statuses[imdn.Delivered] || !statuses[imdn.Displayed] {
		t.Fatalf("statuses %v", statuses)
	}
	// A message asking for nothing gets nothing, and Display refuses to
	// invent a request.
	if _, err := client.Send(ctx(t), cs, bob, "text/plain", []byte("y"), 0); err != nil {
		t.Fatal(err)
	}
	if err := core.Display(ctx(t), ss, received(t, core)); err == nil {
		t.Fatal("displayed a message that asked for no notification")
	}
	core.Wait()
	select {
	case n := <-client.Notifications:
		t.Fatalf("unasked notification %+v", n)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestLargeMessagesTravelChunkedAndWhole(t *testing.T) {
	client, cs, core, _ := pair(t)
	body := bytes.Repeat([]byte("0123456789"), 20000)
	if _, err := client.Send(ctx(t), cs, bob, "application/octet-stream", body, 0); err != nil {
		t.Fatal(err)
	}
	if got := received(t, core); !bytes.Equal(got.Body, body) {
		t.Fatalf("received %d bytes", len(got.Body))
	}
}

func TestContentThatIsNotChatIsCountedAndRefused(t *testing.T) {
	_, cs, core, _ := pair(t)
	for _, out := range []msrp.Outgoing{
		{ContentType: "text/plain", Body: msrp.BodyOf([]byte("not cpim"))},
		{ContentType: cpim.ContentType, Body: msrp.BodyOf([]byte("no headers at all"))},
	} {
		if _, err := cs.Send(ctx(t), out); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for core.Malformed.Load() != 2 {
		if time.Now().After(deadline) {
			t.Fatalf("Malformed = %d", core.Malformed.Load())
		}
		time.Sleep(time.Millisecond)
	}
}

func TestLocalURIsCarryFreshSessionIDsAndNoRealHost(t *testing.T) {
	a, _ := chat.LocalURI(nil)
	b, _ := chat.LocalURI(nil)
	if a.SessionID == b.SessionID || !strings.HasSuffix(a.Host, ".invalid") || a.Port == 0 {
		t.Fatalf("%v %v", a, b)
	}
}

func TestDialFailuresDoNotNameTheAddress(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	_ = ln.Close()
	u, _ := msrp.ParseURI("msrp://" + addr + "/s3ss10n;tcp")
	local, _ := chat.LocalURI(nil)
	_, err := chat.Dial(ctx(t), u, local, chat.NewEndpoint(alice), msrp.Config{}, nil, nil)
	if err == nil || strings.Contains(err.Error(), "s3ss10n") {
		t.Fatalf("Dial = %v", err)
	}
	if _, err := chat.Dial(ctx(t), msrp.URI{Host: "x", Transport: "tcp"}, local, chat.NewEndpoint(alice), msrp.Config{}, nil, nil); err == nil {
		t.Fatal("dialled a URI without a port")
	}
}

func TestMSRPSPathsAreDialledOverTLS(t *testing.T) {
	// A listener that speaks plain TCP: the TLS handshake must fail, which
	// shows the client attempted one.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if nc, err := ln.Accept(); err == nil {
			_, _ = nc.Write([]byte("MSRP not tls\r\n"))
			_ = nc.Close()
		}
	}()
	u, _ := msrp.ParseURI("msrps://" + ln.Addr().String() + "/s;tcp")
	local, _ := chat.LocalURI(nil)
	_, err = chat.Dial(ctx(t), u, local, chat.NewEndpoint(alice), msrp.Config{}, &tls.Config{InsecureSkipVerify: true}, nil)
	if err == nil || !strings.Contains(err.Error(), "TLS") {
		t.Fatalf("Dial = %v, want a TLS failure", err)
	}
}

func TestCoreNamesItselfWithoutSessions(t *testing.T) {
	c, err := chat.ListenCore("127.0.0.1:0", "rcs-as.test", msrp.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	u, _ := c.NewURI(nil)
	if u.Host != "rcs-as.test" || u.Port != c.Port() || !strings.Contains(c.String(), "port") {
		t.Fatalf("%v %s", u, c)
	}
	if _, err := chat.ListenCore("256.0.0.1:0", "", msrp.Config{}); err == nil {
		t.Fatal("listened on an impossible address")
	}
}

func TestWhatNobodyReadsIsCountedAsDropped(t *testing.T) {
	client, cs, core, _ := pair(t, func(client, core *chat.Endpoint) {
		core.Messages = make(chan chat.Received)
		client.Reports = make(chan msrp.Report)
		client.Now = func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }
	})
	if _, err := client.Send(ctx(t), cs, bob, "text/plain", []byte("unread"), 0); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for core.Dropped.Load() != 1 || client.Dropped.Load() != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("Dropped: core %d, client %d", core.Dropped.Load(), client.Dropped.Load())
		}
		time.Sleep(time.Millisecond)
	}
}

func TestASessionIsExpectedOnce(t *testing.T) {
	c, err := chat.ListenCore("127.0.0.1:0", "", msrp.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	u, _ := c.NewURI(nil)
	peer, _ := chat.LocalURI(nil)
	if _, err := c.Expect(u, peer, chat.NewEndpoint(bob)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Expect(u, peer, chat.NewEndpoint(bob)); err == nil {
		t.Fatal("the same session was expected twice")
	}
	if _, err := c.Expect(msrp.URI{}, peer, chat.NewEndpoint(bob)); err == nil {
		t.Fatal("a session without a URI was expected")
	}
}
