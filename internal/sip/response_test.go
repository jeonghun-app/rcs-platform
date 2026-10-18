package sip

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"testing/iotest"
)

func TestNewResponseCopiesTheFieldsRFC3261Section8_2_6Requires(t *testing.T) {
	req := mustParse(t, lines(
		"INVITE sip:bob@example.com SIP/2.0",
		"Via: SIP/2.0/UDP proxy.example.com;branch=z9hG4bK2",
		"v:  SIP/2.0/UDP  client.example.com ;branch=z9hG4bK1;received=192.0.2.1",
		"Max-Forwards: 69",
		"f: Alice <sip:alice@example.com>;tag=1",
		"To: Bob <sip:bob@example.com>",
		"Call-ID: a84b4c76e66710@client.example.com",
		"CSeq: 314159 INVITE",
		"Contact: <sip:alice@client.example.com>",
		"Timestamp: 54",
		"Content-Type: text/plain",
		"Content-Length: 2",
	)+"hi").(*Request)

	res, err := NewResponse(req, 180, "", "b7c1")
	if err != nil {
		t.Fatal(err)
	}
	want := "SIP/2.0 180 Ringing\r\n" +
		"Via: SIP/2.0/UDP proxy.example.com;branch=z9hG4bK2\r\n" +
		"v:  SIP/2.0/UDP  client.example.com ;branch=z9hG4bK1;received=192.0.2.1\r\n" +
		"f: Alice <sip:alice@example.com>;tag=1\r\n" +
		"To: \"Bob\" <sip:bob@example.com>;tag=b7c1\r\n" +
		"Call-ID: a84b4c76e66710@client.example.com\r\n" +
		"CSeq: 314159 INVITE\r\n" +
		"Content-Length: 0\r\n\r\n"
	if got := string(mustBytes(t, res)); got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
	if err := res.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}

	// 100 Trying gets no tag but copies Timestamp (RFC 3261 §8.2.6.1).
	trying, err := NewResponse(req, 100, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if trying.Reason != "Trying" || trying.Header.Get("To") != "Bob <sip:bob@example.com>" || trying.Header.Get("Timestamp") != "54" {
		t.Errorf("100: %q %q", trying.Reason, trying.Header.Fields())
	}

	// A To that already has a tag is copied untouched.
	inDialog := req.Clone()
	if err := inDialog.Header.Set("To", "Bob <sip:bob@example.com>;tag=xyz"); err != nil {
		t.Fatal(err)
	}
	ok, err := NewResponse(inDialog, 200, "Fine", "ignored")
	if err != nil || ok.Reason != "Fine" || ok.Header.Get("To") != "Bob <sip:bob@example.com>;tag=xyz" || ok.Header.Has("Timestamp") {
		t.Errorf("200: %v %q", err, ok.Header.Fields())
	}
}

func TestNewResponseRefusesWhatItCannotBuild(t *testing.T) {
	req := mustParse(t, basicInvite).(*Request)
	if _, err := NewResponse(req, 99, "", "t"); err == nil {
		t.Error("code 99 accepted")
	}
	if _, err := NewResponse(req, 700, "", "t"); err == nil {
		t.Error("code 700 accepted")
	}
	if _, err := NewResponse(req, 200, "", ""); err == nil {
		t.Error("missing To tag accepted")
	}
	if _, err := NewResponse(req, 200, "", "bad tag"); err == nil {
		t.Error("To tag that is not a token accepted")
	}
	noTo := req.Clone()
	noTo.Header.Del("To")
	if _, err := NewResponse(noTo, 486, "", "t"); !errors.Is(err, ErrMissingHeader) {
		t.Errorf("request without To: %v", err)
	}
	badTo := req.Clone()
	if err := badTo.Header.Set("To", "<sip:bob@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := NewResponse(badTo, 486, "", "t"); !errors.Is(err, ErrMalformed) {
		t.Errorf("request with a malformed To: %v", err)
	}
	// Without a To, a 100 can still be sent: it needs no tag.
	if _, err := NewResponse(noTo, 100, "", ""); err != nil {
		t.Errorf("100 without To: %v", err)
	}
}

func TestDefaultReasonNamesRegisteredCodesAndClasses(t *testing.T) {
	for code, want := range map[int]string{
		100: "Trying", 200: "OK", 202: "Accepted", 401: "Unauthorized", 422: "Session Interval Too Small",
		430: "Flow Failed", 481: "Call/Transaction Does Not Exist", 489: "Bad Event", 504: "Server Time-out",
		603: "Decline", 199: "Early Dialog Terminated",
		150: "Provisional", 299: "Success", 399: "Redirection", 499: "Client Error", 599: "Server Error",
		699: "Global Failure", 99: "", 700: "",
	} {
		if got := DefaultReason(code); got != want {
			t.Errorf("DefaultReason(%d) = %q, want %q", code, got, want)
		}
	}
}

func TestIDGeneratorUsesTheInjectedRandomness(t *testing.T) {
	g := IDGenerator{Rand: bytes.NewReader(bytes.Repeat([]byte{0xab}, 64))}
	branch, err := g.Branch()
	if err != nil || branch != MagicCookie+strings.Repeat("ab", 16) {
		t.Errorf("Branch() = %q, %v", branch, err)
	}
	tag, err := g.Tag()
	if err != nil || tag != strings.Repeat("ab", 8) {
		t.Errorf("Tag() = %q, %v", tag, err)
	}
	id, err := g.CallID("client.example.com")
	if err != nil || id != strings.Repeat("ab", 16)+"@client.example.com" {
		t.Errorf("CallID() = %q, %v", id, err)
	}
	// 64 - 16 - 8 - 16 = 24 bytes left: one more Call-ID fits, the next does not.
	if id, err := g.CallID(""); err != nil || id != strings.Repeat("ab", 16) {
		t.Errorf("CallID(\"\") = %q, %v", id, err)
	}
	if _, err := g.Branch(); err == nil {
		t.Error("Branch() succeeded on exhausted randomness")
	}
}

func TestIDGeneratorReportsFailures(t *testing.T) {
	boom := errors.New("entropy unavailable")
	g := IDGenerator{Rand: iotest.ErrReader(boom)}
	if _, err := g.Branch(); !errors.Is(err, boom) {
		t.Errorf("Branch() error = %v", err)
	}
	if _, err := g.Tag(); !errors.Is(err, boom) {
		t.Errorf("Tag() error = %v", err)
	}
	if _, err := g.CallID(""); !errors.Is(err, boom) {
		t.Errorf("CallID() error = %v", err)
	}
	if _, err := (IDGenerator{}).CallID("bad host"); err == nil {
		t.Error("CallID accepted a host that is not a word")
	}
}

func TestDefaultIDGeneratorProducesDistinctValidIDs(t *testing.T) {
	var g IDGenerator
	a, errA := g.Branch()
	b, errB := g.Branch()
	if errA != nil || errB != nil || a == b || len(a) != len(MagicCookie)+32 {
		t.Errorf("Branch() = %q, %q", a, b)
	}
	vs, err := ParseVia("SIP/2.0/UDP h.example.com;branch=" + a)
	if err != nil || !vs[0].HasMagicCookie() {
		t.Errorf("generated branch does not parse: %v", err)
	}
	id, err := g.CallID("h.example.com")
	if err != nil || !isCallID(id) {
		t.Errorf("CallID() = %q, %v", id, err)
	}
}
