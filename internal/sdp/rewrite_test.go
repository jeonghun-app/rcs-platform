package sdp

import (
	"errors"
	"strings"
	"testing"
)

// relayToCore is how pcscf anchors a client offer toward the core: the relay
// connects to rcs-as over plain TCP inside the VPC.
var relayToCore = MSRPRewrite{
	Connection: Connection{"IN", "IP4", "10.0.0.5"},
	Port:       9,
	Path:       []string{"msrp://10.0.0.5:9/rl7a1;tcp"},
	Setup:      SetupActive,
}

func TestClientChatOfferIsAnchoredOnTheRelay(t *testing.T) {
	s := mustParse(t, chatOffer)
	if err := s.RewriteMSRP(0, relayToCore); err != nil {
		t.Fatalf("RewriteMSRP: %v", err)
	}
	want := crlf(
		"v=0",
		"o=- 3913000001 3913000001 IN IP4 192.0.2.10",
		"s=-",
		"c=IN IP4 10.0.0.5",
		"t=0 0",
		"m=message 9 TCP/MSRP *",
		"a=accept-types:message/cpim application/im-iscomposing+xml",
		"a=accept-wrapped-types:text/plain message/imdn+xml application/vnd.gsma.rcs-ft-http+xml",
		"a=setup:active",
		"a=path:msrp://10.0.0.5:9/rl7a1;tcp",
		"a=sendrecv",
		"a=msrp-cema",
	)
	if got := mustMarshal(t, s); got != want {
		t.Errorf("rewritten offer:\n got %q\nwant %q", got, want)
	}
}

func TestAnswerTowardTheClientGetsThePassiveTLSRelay(t *testing.T) {
	s := mustParse(t, chatAnswer)
	err := s.RewriteMSRP(0, MSRPRewrite{
		Connection: Connection{"IN", "IP4", "203.0.113.7"},
		Port:       2855,
		Path:       []string{"msrps://203.0.113.7:2855/c4x9q;tcp"},
		Setup:      SetupPassive,
	})
	if err != nil {
		t.Fatalf("RewriteMSRP: %v", err)
	}
	got := mustMarshal(t, s)
	for _, line := range []string{
		"c=IN IP4 203.0.113.7\r\n",
		"m=message 2855 TCP/TLS/MSRP *\r\n",
		"a=path:msrps://203.0.113.7:2855/c4x9q;tcp\r\n",
		"a=setup:passive\r\n",
	} {
		if !strings.Contains(got, line) {
			t.Errorf("rewritten answer lacks %q:\n%s", line, got)
		}
	}
	if strings.Contains(got, "c=IN IP4 10.0.1.20") {
		t.Errorf("the core address is still visible to the client:\n%s", got)
	}
}

func TestRewriteLeavesOtherMediaLinesAlone(t *testing.T) {
	s := mustParse(t, everyField)
	audioBefore := mustParse(t, everyField).Media[0]
	if err := s.RewriteMSRP(1, relayToCore); err != nil {
		t.Fatalf("RewriteMSRP: %v", err)
	}
	if got := s.Media[0]; got.Port != audioBefore.Port || len(got.Connections) != 2 || got.Connections[0] != audioBefore.Connections[0] {
		t.Errorf("audio line changed: %+v", got)
	}
	// The audio line has its own c= lines, so the session-level one is
	// inherited only by the MSRP line and can be replaced.
	if *s.Connection != relayToCore.Connection || len(s.Media[1].Connections) != 0 {
		t.Errorf("session c=%v, media c=%v", s.Connection, s.Media[1].Connections)
	}
}

func TestMediaGetsItsOwnConnectionWhenAnotherLineSharesTheSessionOne(t *testing.T) {
	sdp := head +
		"m=audio 49170 RTP/AVP 0\r\n" +
		"m=message 9 TCP/MSRP *\r\na=accept-types:*\r\na=path:msrp://192.0.2.1:9/x;tcp\r\n"
	s := mustParse(t, sdp)
	if err := s.RewriteMSRP(1, relayToCore); err != nil {
		t.Fatalf("RewriteMSRP: %v", err)
	}
	if s.Connection.Address != "192.0.2.1" {
		t.Errorf("session c= changed to %v though the audio line still uses it", s.Connection)
	}
	if len(s.Media[1].Connections) != 1 || s.Media[1].Connections[0] != relayToCore.Connection {
		t.Errorf("MSRP line c= = %v", s.Media[1].Connections)
	}
}

func TestMediaLevelConnectionsAreReplacedByOne(t *testing.T) {
	sdp := head + "m=message 9 TCP/MSRP *\r\nc=IN IP4 192.0.2.2\r\nc=IN IP4 192.0.2.3\r\n"
	s := mustParse(t, sdp)
	if err := s.SetMediaConnection(0, relayToCore.Connection); err != nil {
		t.Fatal(err)
	}
	if len(s.Media[0].Connections) != 1 || s.Media[0].Connections[0] != relayToCore.Connection || s.Connection.Address != "192.0.2.1" {
		t.Errorf("session c=%v, media c=%v", s.Connection, s.Media[0].Connections)
	}
}

func TestRewriteAddsSetupWhenTheOfferHadNone(t *testing.T) {
	s := mustParse(t, head+"m=message 9 TCP/MSRP *\r\na=accept-types:*\r\na=path:msrp://192.0.2.1:9/x;tcp\r\na=sendrecv\r\n")
	if err := s.RewriteMSRP(0, relayToCore); err != nil {
		t.Fatal(err)
	}
	as := s.Media[0].Attributes
	if as[len(as)-1] != (Attribute{Name: "setup", Value: "active"}) || as[2] != (Attribute{Name: "sendrecv"}) {
		t.Errorf("attributes = %+v", as)
	}
}

func TestRejectedRewriteLeavesTheSessionUntouched(t *testing.T) {
	tests := []struct {
		name    string
		sdp     string
		index   int
		rw      func(rw *MSRPRewrite)
		wantIs  error
		wantErr string
	}{
		{"index out of range", chatOffer, 1, nil, nil, "no media description 1"},
		{"not MSRP", everyField, 0, nil, ErrNotMSRP, ""},
		{"port 0", strings.Replace(chatOffer, "m=message 9 ", "m=message 0 ", 1), 0, nil, ErrMediaDisabled, ""},
		{"offer without a=path", strings.Replace(chatOffer, "a=path:msrps://192.0.2.10:9/s7d2k8f;tcp\r\n", "", 1), 0, nil, ErrNoAttribute, ""},
		{"connection with a line break", chatOffer, 0, func(rw *MSRPRewrite) { rw.Connection.Address = "10.0.0.5\r\na=x" }, nil, "rewrite: c=: address"},
		{"port 0 in the rewrite", chatOffer, 0, func(rw *MSRPRewrite) { rw.Port = 0 }, nil, "port must be from 1 to 65535"},
		{"port above 65535", chatOffer, 0, func(rw *MSRPRewrite) { rw.Port = 65536 }, nil, "port must be from 1 to 65535"},
		{"no path", chatOffer, 0, func(rw *MSRPRewrite) { rw.Path = nil }, nil, "at least one URI"},
		{"path that is not MSRP", chatOffer, 0, func(rw *MSRPRewrite) { rw.Path = []string{"sip:relay.example.com"} }, nil, "not an msrp"},
		{"no setup", chatOffer, 0, func(rw *MSRPRewrite) { rw.Setup = "" }, nil, "unknown role"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := mustParse(t, tt.sdp)
			before := mustMarshal(t, s)
			rw := relayToCore
			rw.Path = append([]string(nil), relayToCore.Path...)
			if tt.rw != nil {
				tt.rw(&rw)
			}
			err := s.RewriteMSRP(tt.index, rw)
			if err == nil {
				t.Fatal("RewriteMSRP succeeded")
			}
			if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
				t.Errorf("got %v, want %v", err, tt.wantIs)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("got %v, want an error containing %q", err, tt.wantErr)
			}
			if after := mustMarshal(t, s); after != before {
				t.Errorf("session changed:\n%q\n%q", before, after)
			}
		})
	}
}

func TestSetMediaConnectionRejectsBadInput(t *testing.T) {
	s := mustParse(t, chatOffer)
	if err := s.SetMediaConnection(1, relayToCore.Connection); err == nil {
		t.Error("index out of range: no error")
	}
	if err := s.SetMediaConnection(0, Connection{"IN", "IP4", "a b"}); err == nil {
		t.Error("address with a space: no error")
	}
	if s.Connection.Address != "192.0.2.10" {
		t.Errorf("session c= changed to %v", s.Connection)
	}
}
