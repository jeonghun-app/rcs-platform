package sdp

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestIsMSRPRecognisesBothMSRPTransportsOnly(t *testing.T) {
	tests := []struct {
		typ, proto string
		want       bool
	}{
		{"message", "TCP/MSRP", true},
		{"message", "TCP/TLS/MSRP", true},
		{"MESSAGE", "tcp/tls/msrp", true},
		{"message", "TCP/MSRPS", false},
		{"message", "UDP/MSRP", false},
		{"audio", "TCP/MSRP", false},
	}
	for _, tt := range tests {
		m := Media{Type: tt.typ, Proto: tt.proto}
		if got := m.IsMSRP(); got != tt.want {
			t.Errorf("IsMSRP(%s %s) = %v, want %v", tt.typ, tt.proto, got, tt.want)
		}
	}
}

func TestChatOfferExposesItsMSRPAttributes(t *testing.T) {
	s := mustParse(t, chatOffer)
	m := &s.Media[0]
	path, err := m.Path()
	if err != nil || !reflect.DeepEqual(path, []string{"msrps://192.0.2.10:9/s7d2k8f;tcp"}) {
		t.Errorf("Path = %q, %v", path, err)
	}
	types, err := m.AcceptTypes()
	if err != nil || !reflect.DeepEqual(types, []string{"message/cpim", "application/im-iscomposing+xml"}) {
		t.Errorf("AcceptTypes = %q, %v", types, err)
	}
	wrapped, err := m.AcceptWrappedTypes()
	if err != nil || len(wrapped) != 3 || wrapped[1] != "message/imdn+xml" {
		t.Errorf("AcceptWrappedTypes = %q, %v", wrapped, err)
	}
	if r, err := m.Setup(); err != nil || r != SetupActPass {
		t.Errorf("Setup = %q, %v", r, err)
	}
	if d, err := m.Direction(); err != nil || d != SendRecv {
		t.Errorf("Direction = %q, %v", d, err)
	}
	if _, err := m.MaxSize(); !errors.Is(err, ErrNoAttribute) {
		t.Errorf("MaxSize = %v, want ErrNoAttribute", err)
	}
	if _, err := m.TCPConnection(); !errors.Is(err, ErrNoAttribute) {
		t.Errorf("TCPConnection = %v, want ErrNoAttribute", err)
	}
}

func TestMultiHopPathKeepsEveryURIInOrder(t *testing.T) {
	m := Media{Attributes: attrs("path", "msrps://relay.example.com:2855/r1;tcp msrp://192.0.2.5:9/c1;tcp")}
	got, err := m.Path()
	if want := []string{"msrps://relay.example.com:2855/r1;tcp", "msrp://192.0.2.5:9/c1;tcp"}; err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("Path = %q, %v; want %q", got, err, want)
	}
}

func TestMSRPGettersRejectMalformedValues(t *testing.T) {
	get := map[string]func(m *Media) error{
		"path":                 func(m *Media) error { _, err := m.Path(); return err },
		"accept-types":         func(m *Media) error { _, err := m.AcceptTypes(); return err },
		"accept-wrapped-types": func(m *Media) error { _, err := m.AcceptWrappedTypes(); return err },
		"max-size":             func(m *Media) error { _, err := m.MaxSize(); return err },
		"setup":                func(m *Media) error { _, err := m.Setup(); return err },
		"connection":           func(m *Media) error { _, err := m.TCPConnection(); return err },
		"direction":            func(m *Media) error { _, err := m.Direction(); return err },
	}
	tests := []struct {
		name    string
		getter  string
		as      Attributes
		wantErr string
	}{
		{"path with a non-MSRP URI", "path", attrs("path", "sip:alice@example.com"), "not an msrp: or msrps: URI"},
		{"path with an empty authority", "path", attrs("path", "msrp://"), "not an msrp: or msrps: URI"},
		{"path with two spaces", "path", attrs("path", "msrp://a.example.com/1;tcp  msrp://b.example.com/2;tcp"), `"" is not an msrp`},
		{"path twice", "path", attrs("path", "msrp://a.example.com/1;tcp", "path", "msrp://b.example.com/2;tcp"), "more than one line"},
		{"path with no value", "path", attrs("path", ""), "value missing"},
		{"accept-types with parameters", "accept-types", attrs("accept-types", "text/plain;charset=utf-8"), "is not a media type"},
		{"accept-types without subtype", "accept-types", attrs("accept-types", "text"), "is not a media type"},
		{"accept-wrapped-types with an empty entry", "accept-wrapped-types", attrs("accept-wrapped-types", "text/plain "), "is not a media type"},
		{"max-size with a sign", "max-size", attrs("max-size", "+10"), "is not a size in bytes"},
		{"max-size beyond int64", "max-size", attrs("max-size", "9223372036854775808"), "is not a size in bytes"},
		{"unknown setup role", "setup", attrs("setup", "both"), "unknown role"},
		{"unknown connection value", "connection", attrs("connection", "reuse"), "unknown value"},
		{"direction with a value", "direction", attrs("sendonly", "x"), "takes no value"},
		{"two directions", "direction", attrs("sendonly", "", "recvonly", ""), "more than one direction attribute (sendonly, recvonly)"},
		{"no direction", "direction", nil, "attribute not present: direction"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Media{Attributes: tt.as}
			if err := get[tt.getter](m); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("got %v, want an error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestKeywordValuesAreReadCaseInsensitively(t *testing.T) {
	m := Media{Attributes: attrs("SETUP", "ActPass", "connection", "EXISTING", "SendOnly", "")}
	if r, err := m.Setup(); err != nil || r != SetupActPass {
		t.Errorf("Setup = %q, %v", r, err)
	}
	if c, err := m.TCPConnection(); err != nil || c != ConnectionExisting {
		t.Errorf("TCPConnection = %q, %v", c, err)
	}
	if d, err := m.Direction(); err != nil || d != SendOnly {
		t.Errorf("Direction = %q, %v", d, err)
	}
	if c, err := (&Media{Attributes: attrs("connection", "new")}).TCPConnection(); err != nil || c != ConnectionNew {
		t.Errorf("TCPConnection = %q, %v", c, err)
	}
}

func TestSettersChangeOnlyTheirOwnLineAndKeepItsPosition(t *testing.T) {
	s := mustParse(t, chatOffer)
	m := &s.Media[0]
	if err := m.SetPath([]string{"msrps://relay.example.com:2855/r1;tcp"}); err != nil {
		t.Fatal(err)
	}
	if err := m.SetSetup("PASSIVE"); err != nil {
		t.Fatal(err)
	}
	if err := m.SetDirection(RecvOnly); err != nil {
		t.Fatal(err)
	}
	if err := m.SetAcceptTypes([]string{"message/cpim"}); err != nil {
		t.Fatal(err)
	}
	if err := m.SetAcceptWrappedTypes(nil); err != nil {
		t.Fatal(err)
	}
	if err := m.SetMaxSize(4096); err != nil {
		t.Fatal(err)
	}
	want := attrs(
		"accept-types", "message/cpim",
		"setup", "passive",
		"path", "msrps://relay.example.com:2855/r1;tcp",
		"recvonly", "",
		"msrp-cema", "",
		"max-size", "4096",
	)
	if !reflect.DeepEqual(m.Attributes, want) {
		t.Errorf("got %+v\nwant %+v", m.Attributes, want)
	}
	if err := m.SetAcceptWrappedTypes([]string{"*"}); err != nil {
		t.Fatal(err)
	}
	if got, err := m.AcceptWrappedTypes(); err != nil || !reflect.DeepEqual(got, []string{"*"}) {
		t.Errorf("AcceptWrappedTypes = %q, %v", got, err)
	}
	if n, err := m.MaxSize(); err != nil || n != 4096 {
		t.Errorf("MaxSize = %d, %v", n, err)
	}
}

func TestSettersRejectValuesThatWouldBreakTheLine(t *testing.T) {
	var m Media
	tests := []struct {
		name string
		err  error
	}{
		{"no path URI", m.SetPath(nil)},
		{"path URI with a line break", m.SetPath([]string{"msrp://a.example.com/1;tcp\r\na=evil"})},
		{"path URI that is not MSRP", m.SetPath([]string{"https://example.com/"})},
		{"no accept type", m.SetAcceptTypes(nil)},
		{"accept type with a line break", m.SetAcceptTypes([]string{"text/plain\r\n"})},
		{"accept-wrapped type that is not a type", m.SetAcceptWrappedTypes([]string{"plain"})},
		{"negative max size", m.SetMaxSize(-1)},
		{"unknown setup role", m.SetSetup("both")},
		{"unknown direction", m.SetDirection("sideways")},
	}
	for _, tt := range tests {
		if tt.err == nil {
			t.Errorf("%s: no error", tt.name)
		}
	}
	if len(m.Attributes) != 0 {
		t.Errorf("rejected values were stored: %+v", m.Attributes)
	}
}

func TestMediaSetupFallsBackToTheSessionLevel(t *testing.T) {
	s := mustParse(t, head+"a=setup:active\r\nm=message 9 TCP/MSRP *\r\nm=message 9 TCP/MSRP *\r\na=setup:passive\r\n")
	if r, err := s.MediaSetup(0); err != nil || r != SetupActive {
		t.Errorf("MediaSetup(0) = %q, %v; want the session-level active", r, err)
	}
	if r, err := s.MediaSetup(1); err != nil || r != SetupPassive {
		t.Errorf("MediaSetup(1) = %q, %v; want the media-level passive", r, err)
	}
	if _, err := mustParse(t, head+"m=message 9 TCP/MSRP *\r\n").MediaSetup(0); !errors.Is(err, ErrNoAttribute) {
		t.Errorf("MediaSetup with no a=setup = %v, want ErrNoAttribute", err)
	}
	if _, err := s.MediaSetup(2); err == nil {
		t.Error("MediaSetup(2) on two media lines: no error")
	}
}

func TestMediaDirectionFallsBackToTheSessionLevelThenSendrecv(t *testing.T) {
	tests := []struct {
		name    string
		session string
		media   string
		want    Direction
		wantErr bool
	}{
		{"media level wins", "a=sendonly\r\n", "a=inactive\r\n", Inactive, false},
		{"session level applies", "a=recvonly\r\n", "", RecvOnly, false},
		{"default is sendrecv", "", "", SendRecv, false},
		{"conflicting media level", "", "a=sendonly\r\na=recvonly\r\n", "", true},
		{"conflicting session level", "a=sendonly\r\na=recvonly\r\n", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := mustParse(t, head+tt.session+"m=message 9 TCP/MSRP *\r\n"+tt.media)
			got, err := s.MediaDirection(0)
			if (err != nil) != tt.wantErr || got != tt.want {
				t.Errorf("MediaDirection = %q, %v; want %q, error %v", got, err, tt.want, tt.wantErr)
			}
		})
	}
	if _, err := mustParse(t, head).MediaDirection(0); err == nil {
		t.Error("MediaDirection(0) with no media: no error")
	}
}
