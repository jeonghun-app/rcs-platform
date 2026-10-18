package sdp

import (
	"strings"
	"testing"
)

func TestHandBuiltSessionIsWrittenWithOnlyTheLinesThatAreSet(t *testing.T) {
	s := &Session{
		Origin:     Origin{"-", "7", "8", "IN", "IP4", "192.0.2.1"},
		Name:       "-",
		Connection: &Connection{"IN", "IP4", "192.0.2.1"},
		Times:      []Time{{}},
		Media: []Media{{
			Type: "message", Port: 2855, Proto: ProtoMSRP, Formats: []string{"*"},
			Attributes: Attributes{{Name: "accept-types", Value: "message/cpim"}},
		}},
	}
	want := crlf(
		"v=0",
		"o=- 7 8 IN IP4 192.0.2.1",
		"s=-",
		"c=IN IP4 192.0.2.1",
		"t=0 0",
		"m=message 2855 TCP/MSRP *",
		"a=accept-types:message/cpim",
	)
	if got := mustMarshal(t, s); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestMarshalRefusesValuesThatWouldBreakTheDescription(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(s *Session)
		wantErr string
	}{
		{"line break in the origin address", func(s *Session) { s.Origin.Address = "a\r\nm=audio" }, "o=: address"},
		{"empty session id", func(s *Session) { s.Origin.SessionID = "" }, "o=: session id"},
		{"empty session name", func(s *Session) { s.Name = "" }, "s=: the session name must be non-empty"},
		{"line break in the session name", func(s *Session) { s.Name = "x\r\na=evil" }, "s=:"},
		{"line break in the information", func(s *Session) { s.Information = "a\nb" }, "i=:"},
		{"space in the URI", func(s *Session) { s.URI = "https://example.com/a b" }, "u=:"},
		{"empty e-mail", func(s *Session) { s.Emails[0] = "" }, "e=:"},
		{"line break in a phone", func(s *Session) { s.Phones[0] = "a\r" }, "p=:"},
		{"empty connection address", func(s *Session) { s.Connection.Address = "" }, "c=: address"},
		{"bandwidth type with a space", func(s *Session) { s.Bandwidths[0].Type = "A S" }, "b=: bandwidth type"},
		{"no time", func(s *Session) { s.Times = nil }, `at least one "t=" line`},
		{"malformed repeat", func(s *Session) { s.Times[0].Repeats[0] = "1d" }, "r=:"},
		{"malformed time zones", func(s *Session) { s.TimeZones = "1" }, "z=:"},
		{"line break in the key", func(s *Session) { s.Key = "prompt\n" }, "k=:"},
		{"session attribute name with a space", func(s *Session) { s.Attributes.Add("a b", "") }, `a="a b": attribute name`},
		{"line break in a session attribute", func(s *Session) { s.Attributes.Add("x", "1\r\nm=audio 9 RTP/AVP 0") }, "a=\"x\": attribute value"},
		{"empty media type", func(s *Session) { s.Media[0].Type = "" }, "media 0: m=: media type"},
		{"port above 65535", func(s *Session) { s.Media[0].Port = 65536 }, "media 0: m=: port"},
		{"negative port", func(s *Session) { s.Media[0].Port = -1 }, "media 0: m=: port"},
		{"negative port count", func(s *Session) { s.Media[0].PortCount = -1 }, "media 0: m=: number of ports"},
		{"empty protocol", func(s *Session) { s.Media[0].Proto = "" }, "media 0: m=: protocol"},
		{"no formats", func(s *Session) { s.Media[0].Formats = nil }, "media 0: m=: at least one format"},
		{"format with a space", func(s *Session) { s.Media[0].Formats = []string{"0 1"} }, "media 0: m=: formats"},
		{"line break in the media information", func(s *Session) { s.Media[0].Information = "\n" }, "media 0: i=:"},
		{"malformed media connection", func(s *Session) { s.Media[0].Connections[0].NetType = "" }, "media 0: c=: network type"},
		{"malformed media bandwidth", func(s *Session) { s.Media[0].Bandwidths[0].Type = "" }, "media 0: b=:"},
		{"line break in the media key", func(s *Session) { s.Media[0].Key = "\r" }, "media 0: k=:"},
		{"line break in a media attribute", func(s *Session) { s.Media[1].Attributes[0].Value = "*\r\n" }, `media 1: a="accept-types": attribute value`},
		{"media with no connection anywhere", func(s *Session) { s.Connection = nil }, `media 1: no "c=" line here or at session level`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := mustParse(t, everyField)
			tt.mutate(s)
			b, err := s.Marshal()
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Marshal = %q, %v; want an error containing %q", b, err, tt.wantErr)
			}
		})
	}
}
