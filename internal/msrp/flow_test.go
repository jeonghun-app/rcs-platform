package msrp

// The flows below follow the shape of the examples in RFC 4975 §5.1 and
// §11 (basic session, chunked message, chunked CPIM payload, system
// message, positive report), with addresses, identifiers and content of
// our own. Our side's answers are compared octet for octet.

import (
	"context"
	"net"
	"strconv"
	"testing"
)

const (
	aliceURI = "msrp://alice.example.com:7777/al1ce3zz;tcp"
	bobURI   = "msrp://bob.example.org:8888/b0bses5x;tcp"
)

// bobListens registers bob's session and returns the raw peer standing in
// for alice's client, connected to bob's passive side.
func bobListens(t *testing.T) (*recorder, *Session, *wirePeer) {
	t.Helper()
	h := newRecorder()
	bob := newTestSession(t, bobURI, aliceURI, h)
	reg := &Registry{}
	if err := reg.Add(bob); err != nil {
		t.Fatal(err)
	}
	ours, theirs := net.Pipe()
	c, err := NewPassiveConn(ours, reg, Config{Clock: newFakeClock()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return h, bob, newWirePeer(t, theirs)
}

func ok200(tid string) string {
	return wire("MSRP "+tid+" 200 OK", "To-Path: "+aliceURI, "From-Path: "+bobURI, "-------"+tid+"$")
}

func expectWire(t *testing.T, p *wirePeer, want string) *Message {
	t.Helper()
	m := p.next(t)
	got, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("on the wire:\n%q\nwant:\n%q", got, want)
	}
	return m
}

func TestFlowBasicSession(t *testing.T) {
	h, bob, alice := bobListens(t)
	alice.send(t,
		"MSRP a7k2p9q1 SEND",
		"To-Path: "+bobURI,
		"From-Path: "+aliceURI,
		"Message-ID: m4ss4ge01",
		"Byte-Range: 1-14/14",
		"Content-Type: text/plain",
		"",
		"Hello from us!",
		"-------a7k2p9q1$")
	expectWire(t, alice, ok200("a7k2p9q1"))
	if m := h.message(t); string(m.Body) != "Hello from us!" {
		t.Fatalf("bob got %q", m.Body)
	}

	if _, err := bob.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: []byte("And hello back.")}); err != nil {
		t.Fatal(err)
	}
	m := alice.next(t)
	if m.Method != MethodSend || m.ToPath[0].String() != aliceURI || m.FromPath[0].String() != bobURI ||
		*m.ByteRange != (ByteRange{1, 15, 15}) || m.ContentType != "text/plain" || string(m.Body) != "And hello back." {
		t.Fatalf("bob sent %+v", m)
	}
	resp, _ := NewResponse(m, StatusOK, "OK")
	alice.sendMessage(t, resp)
}

func TestFlowChunkedMessage(t *testing.T) {
	h, _, alice := bobListens(t)
	alice.send(t,
		"MSRP ch0nk001 SEND",
		"To-Path: "+bobURI,
		"From-Path: "+aliceURI,
		"Message-ID: ch0nkmsg",
		"Byte-Range: 1-*/8",
		"Content-Type: text/plain",
		"",
		"wxyz",
		"-------ch0nk001+")
	expectWire(t, alice, ok200("ch0nk001"))
	alice.send(t,
		"MSRP ch0nk002 SEND",
		"To-Path: "+bobURI,
		"From-Path: "+aliceURI,
		"Message-ID: ch0nkmsg",
		"Byte-Range: 5-8/8",
		"Content-Type: text/plain",
		"",
		"WXYZ",
		"-------ch0nk002$")
	expectWire(t, alice, ok200("ch0nk002"))
	if m := h.message(t); string(m.Body) != "wxyzWXYZ" || m.MessageID != "ch0nkmsg" {
		t.Fatalf("bob got %q", m.Body)
	}
}

func TestFlowChunkedCPIMPayload(t *testing.T) {
	h, _, alice := bobListens(t)
	cpim := "From: <sip:alice@example.com>\r\nTo: <sip:bob@example.org>\r\nDateTime: 2026-01-02T03:04:05Z\r\n\r\n" +
		"Content-Type: text/plain\r\n\r\n"
	text := "chunked through MSRP"
	total := len(cpim) + len(text)
	split := len(cpim) + 4
	first, second := (cpim + text)[:split], (cpim + text)[split:]
	alice.send(t,
		"MSRP cp1m0001 SEND",
		"To-Path: "+bobURI,
		"From-Path: "+aliceURI,
		"Message-ID: cp1mmsg",
		"Byte-Range: 1-"+strconv.Itoa(split)+"/"+strconv.Itoa(total),
		"Content-Type: message/cpim",
		"",
		first,
		"-------cp1m0001+")
	expectWire(t, alice, ok200("cp1m0001"))
	alice.send(t,
		"MSRP cp1m0002 SEND",
		"To-Path: "+bobURI,
		"From-Path: "+aliceURI,
		"Message-ID: cp1mmsg",
		"Byte-Range: "+strconv.Itoa(split+1)+"-"+strconv.Itoa(total)+"/"+strconv.Itoa(total),
		"Content-Type: message/cpim",
		"",
		second,
		"-------cp1m0002$")
	expectWire(t, alice, ok200("cp1m0002"))
	if m := h.message(t); string(m.Body) != cpim+text || m.MediaType() != "message/cpim" {
		t.Fatalf("bob got %q", m.Body)
	}
}

func TestFlowSystemMessageWantsNoResponse(t *testing.T) {
	h, _, alice := bobListens(t)
	alice.send(t,
		"MSRP sysm5g01 SEND",
		"To-Path: "+bobURI,
		"From-Path: "+aliceURI,
		"Message-ID: sysmsg01",
		"Byte-Range: 1-28/28",
		"Failure-Report: no",
		"Success-Report: no",
		"Content-Type: text/plain",
		"",
		"The chat closes in a minute.",
		"-------sysm5g01$")
	h.message(t)
	alice.send(t, "MSRP n3xtn3xt SEND", "To-Path: "+bobURI, "From-Path: "+aliceURI, "Message-ID: n3xtn3xt", "-------n3xtn3xt$")
	expectWire(t, alice, ok200("n3xtn3xt"))
}

func TestFlowPositiveReport(t *testing.T) {
	h, _, alice := bobListens(t)
	alice.send(t,
		"MSRP p0s1t1v3 SEND",
		"To-Path: "+bobURI,
		"From-Path: "+aliceURI,
		"Message-ID: p0smsg01",
		"Byte-Range: 1-24/24",
		"Success-Report: yes",
		"Failure-Report: no",
		"Content-Type: text/html",
		"",
		"<p>an important link</p>",
		"-------p0s1t1v3$")
	h.message(t)
	rep := alice.next(t)
	want := wire(
		"MSRP "+rep.TransactionID+" REPORT",
		"To-Path: "+aliceURI,
		"From-Path: "+bobURI,
		"Message-ID: p0smsg01",
		"Byte-Range: 1-24/24",
		"Status: 000 200 OK",
		"-------"+rep.TransactionID+"$")
	if got, _ := rep.Marshal(); string(got) != want {
		t.Fatalf("report:\n%q\nwant:\n%q", got, want)
	}
}
