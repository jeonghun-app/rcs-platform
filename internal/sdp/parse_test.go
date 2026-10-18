package sdp

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// head is the shortest valid session section; it occupies lines 1 to 5.
var head = crlf(
	"v=0",
	"o=- 1 1 IN IP4 192.0.2.1",
	"s=-",
	"c=IN IP4 192.0.2.1",
	"t=0 0",
)

func mustParse(t *testing.T, sdp string) *Session {
	t.Helper()
	s, err := Parse([]byte(sdp))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return s
}

func mustMarshal(t *testing.T, s *Session) string {
	t.Helper()
	b, err := s.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return string(b)
}

func TestRCSSamplesSurviveParseAndMarshalByteForByte(t *testing.T) {
	for name, sample := range map[string]string{
		"chat offer":  chatOffer,
		"chat answer": chatAnswer,
		"file offer":  fileOffer,
		"every field": everyField,
	} {
		t.Run(name, func(t *testing.T) {
			if got := mustMarshal(t, mustParse(t, sample)); got != sample {
				t.Errorf("round trip changed the description:\n got: %q\nwant: %q", got, sample)
			}
		})
	}
}

func TestEveryLineTypeIsParsedIntoItsField(t *testing.T) {
	want := &Session{
		Origin:      Origin{"alice", "2890844526", "2890842807", "IN", "IP6", "2001:db8::10"},
		Name:        "RCS conference",
		Information: "weekly sync",
		URI:         "https://example.com/conf/42",
		Emails:      []string{"alice@example.com (Alice)"},
		Phones:      []string{"+15550100001"},
		Connection:  &Connection{"IN", "IP6", "2001:db8::10"},
		Bandwidths:  []Bandwidth{{"CT", 384}},
		Times: []Time{
			{Start: 3913000000, Stop: 3913003600, Repeats: []string{"7d 1h 0 25h"}},
			{Start: 0, Stop: 0},
		},
		TimeZones:  "3913000000 -1h 3920000000 0",
		Key:        "prompt",
		Attributes: Attributes{{Name: "recvonly"}, {Name: "tool", Value: "example-client 1.0"}},
		Media: []Media{
			{
				Type: "audio", Port: 49170, PortCount: 2, Proto: "RTP/AVP", Formats: []string{"0", "96"},
				Information: "voice",
				Connections: []Connection{{"IN", "IP6", "2001:db8::11"}, {"IN", "IP6", "2001:db8::12"}},
				Bandwidths:  []Bandwidth{{"AS", 64}},
				Key:         "uri:https://example.com/keys/1",
				Attributes:  Attributes{{Name: "rtpmap", Value: "96 opus/48000/2"}},
			},
			{
				Type: "message", Port: 7394, Proto: "TCP/MSRP", Formats: []string{"*"},
				Attributes: Attributes{
					{Name: "accept-types", Value: "*"},
					{Name: "path", Value: "msrp://example.com:7394/ab12;tcp"},
				},
			},
		},
	}
	if got := mustParse(t, everyField); !reflect.DeepEqual(got, want) {
		t.Errorf("Parse:\n got %+v\nwant %+v", got, want)
	}
}

func TestUnknownAttributesKeepTheirPositionAndText(t *testing.T) {
	s := mustParse(t, chatOffer)
	got := s.Media[0].Attributes
	if n := len(got); n != 6 {
		t.Fatalf("got %d attributes, want 6", n)
	}
	if got[5] != (Attribute{Name: "msrp-cema"}) {
		t.Errorf("last attribute = %+v, want a=msrp-cema", got[5])
	}
	if got[2] != (Attribute{Name: "setup", Value: "actpass"}) {
		t.Errorf("third attribute = %+v, want a=setup:actpass", got[2])
	}
}

func TestAttributeValueKeepsColonsAndSpacesVerbatim(t *testing.T) {
	s := mustParse(t, head+"a=x-vendor: spaced : value::\r\n")
	if want := (Attribute{Name: "x-vendor", Value: " spaced : value::"}); s.Attributes[0] != want {
		t.Errorf("got %+v, want %+v", s.Attributes[0], want)
	}
}

func TestLFOnlyLineEndingsAreAcceptedAndWrittenAsCRLF(t *testing.T) {
	lf := strings.ReplaceAll(chatOffer, "\r\n", "\n")
	if got := mustMarshal(t, mustParse(t, lf)); got != chatOffer {
		t.Errorf("got %q, want %q", got, chatOffer)
	}
}

func TestMixedLineEndingsAreAccepted(t *testing.T) {
	mixed := strings.Replace(chatOffer, "\r\n", "\n", 3)
	if got := mustMarshal(t, mustParse(t, mixed)); got != chatOffer {
		t.Errorf("got %q, want %q", got, chatOffer)
	}
}

func TestMissingFinalLineEndingIsTolerated(t *testing.T) {
	trimmed := strings.TrimSuffix(chatOffer, "\r\n")
	if got := mustMarshal(t, mustParse(t, trimmed)); got != chatOffer {
		t.Errorf("got %q, want %q", got, chatOffer)
	}
}

func TestSessionWithoutMediaIsValid(t *testing.T) {
	s := mustParse(t, head)
	if len(s.Media) != 0 {
		t.Errorf("got %d media descriptions, want 0", len(s.Media))
	}
}

func TestMediaLevelConnectionsReplaceTheSessionLevelOne(t *testing.T) {
	sdp := crlf(
		"v=0",
		"o=- 1 1 IN IP4 192.0.2.1",
		"s=-",
		"t=0 0",
		"m=message 9 TCP/MSRP *",
		"c=IN IP4 192.0.2.2",
		"m=message 9 TCP/MSRP *",
		"c=IN IP4 192.0.2.3",
	)
	s := mustParse(t, sdp)
	if s.Connection != nil || len(s.Media[1].Connections) != 1 {
		t.Errorf("got session c=%v, media %+v", s.Connection, s.Media)
	}
}

func TestMalformedDescriptionsAreRejectedWithTheLine(t *testing.T) {
	msrp := "m=message 9 TCP/MSRP *\r\n"
	tests := []struct {
		name     string
		in       string
		wantLine int
		wantMsg  string
	}{
		{"empty input", "", 0, "empty description"},
		{"first line is not v=", "o=- 1 1 IN IP4 x\r\n", 1, `must start with a "v=" line`},
		{"version other than 0", "v=1\r\n", 1, "unsupported protocol version"},
		{"empty line", "v=0\r\n\r\n", 2, "empty line"},
		{"trailing empty line", head + "\r\n", 6, "empty line"},
		{"NUL byte", "v=0\r\ns=a\x00b\r\n", 2, "NUL byte"},
		{"bare CR inside a line", "v=0\r\ns=a\rb\r\n", 2, "CR not followed by LF"},
		{"bare CR at the end", "v=0\r", 1, "CR not followed by LF"},
		{"upper-case type", "V=0\r\n", 1, "lower-case type letter"},
		{"space before =", "v =0\r\n", 1, "no space before '='"},
		{"type letter alone", "v\r\n", 1, "want <type>=<value>"},
		{"unknown type letter", "v=0\r\nx=1\r\n", 2, `unknown line type 'x'`},
		{"o= after s=", "v=0\r\ns=-\r\no=- 1 1 IN IP4 x\r\n", 3, `"o=" line must come before the "s=" line`},
		{"u= after e=", "v=0\r\no=- 1 1 IN IP4 x\r\ns=-\r\ne=a@example.com\r\nu=https://example.com\r\n", 5, `"u=" line must come before the "e=" line`},
		{"second v=", "v=0\r\nv=0\r\n", 2, `more than one "v=" line`},
		{"second session c=", head + "c=IN IP4 192.0.2.2\r\n", 6, `"c=" line must come before the "t=" line`},
		{"two session c= lines", "v=0\r\no=- 1 1 IN IP4 x\r\ns=-\r\nc=IN IP4 x\r\nc=IN IP4 y\r\n", 5, `more than one "c=" line`},
		{"second s=", "v=0\r\no=- 1 1 IN IP4 x\r\ns=-\r\ns=-\r\n", 4, `more than one "s=" line`},
		{"second z=", head + "z=0 0\r\nz=0 0\r\n", 7, `more than one "z=" line`},
		{"r= without t=", "v=0\r\no=- 1 1 IN IP4 x\r\ns=-\r\nr=1d 1h 0\r\n", 4, `"r=" line must follow a "t=" or "r=" line`},
		{"r= after z=", head + "z=0 0\r\nr=1d 1h 0\r\n", 7, `"r=" line must follow`},
		{"t= after a=", head + "a=x\r\nt=0 0\r\n", 7, `"t=" line must come before the "a=" line`},
		{"missing t= before media", "v=0\r\no=- 1 1 IN IP4 x\r\ns=-\r\nc=IN IP4 x\r\n" + msrp, 5, `missing "t=" line`},
		{"missing t= at the end", "v=0\r\no=- 1 1 IN IP4 x\r\ns=-\r\n", 4, `missing "t=" line`},
		{"missing s=", "v=0\r\no=- 1 1 IN IP4 x\r\nt=0 0\r\n", 4, `missing "s=" line`},
		{"missing o=", "v=0\r\ns=-\r\nt=0 0\r\n", 4, `missing "o=" line`},
		{"session line inside media", head + msrp + "s=-\r\n", 7, `"s=" line is not allowed in a media description`},
		{"media c= after a=", head + msrp + "a=x\r\nc=IN IP4 x\r\n", 8, `"c=" line must come before the "a=" line`},
		{"second media i=", head + msrp + "i=a\r\ni=b\r\n", 8, `more than one "i=" line`},
		{"second media k=", head + msrp + "k=prompt\r\nk=prompt\r\n", 8, `more than one "k=" line`},
		{"media without any c=", "v=0\r\no=- 1 1 IN IP4 x\r\ns=-\r\nt=0 0\r\n" + msrp + "c=IN IP4 x\r\n" + msrp, 7, `no "c=" line`},
		{"o= with five fields", "v=0\r\no=- 1 1 IN IP4\r\n", 2, "o=: want <username>"},
		{"o= with two spaces", "v=0\r\no=- 1 1 IN  IP4 x\r\n", 2, "o=: want <username>"},
		{"o= session id not digits", "v=0\r\no=- 1a 1 IN IP4 x\r\n", 2, "session id must be decimal digits"},
		{"o= version not digits", "v=0\r\no=- 1 -1 IN IP4 x\r\n", 2, "session version must be decimal digits"},
		{"o= network type not a token", "v=0\r\no=- 1 1 I/N IP4 x\r\n", 2, "network type must be a token"},
		{"o= address type not a token", "v=0\r\no=- 1 1 IN IP:4 x\r\n", 2, "address type must be a token"},
		{"o= username with control byte", "v=0\r\no=\x01 1 1 IN IP4 x\r\n", 2, "username must be"},
		{"o= address with DEL", "v=0\r\no=- 1 1 IN IP4 a\x7f\r\n", 2, "address must be"},
		{"empty s=", "v=0\r\no=- 1 1 IN IP4 x\r\ns=\r\n", 3, "s=: value must not be empty"},
		{"empty session i=", "v=0\r\no=- 1 1 IN IP4 x\r\ns=-\r\ni=\r\n", 4, "i=: value must not be empty"},
		{"u= with a space", "v=0\r\no=- 1 1 IN IP4 x\r\ns=-\r\nu=https://example.com/a b\r\n", 4, "u=: value must be non-empty"},
		{"empty e=", "v=0\r\no=- 1 1 IN IP4 x\r\ns=-\r\ne=\r\n", 4, "e=: value must not be empty"},
		{"empty p=", "v=0\r\no=- 1 1 IN IP4 x\r\ns=-\r\np=\r\n", 4, "p=: value must not be empty"},
		{"c= with two fields", "v=0\r\no=- 1 1 IN IP4 x\r\ns=-\r\nc=IN IP4\r\n", 4, "c=: want <nettype>"},
		{"c= network type not a token", "v=0\r\no=- 1 1 IN IP4 x\r\ns=-\r\nc=I:N IP4 x\r\n", 4, "c=: network type"},
		{"c= address type not a token", "v=0\r\no=- 1 1 IN IP4 x\r\ns=-\r\nc=IN I@P4 x\r\n", 4, "c=: address type"},
		{"c= address with a control byte", "v=0\r\no=- 1 1 IN IP4 x\r\ns=-\r\nc=IN IP4 \x01\r\n", 4, "c=: address must be"},
		{"b= without colon", "v=0\r\no=- 1 1 IN IP4 x\r\ns=-\r\nb=AS64\r\n", 4, "b=: want <bwtype>:<bandwidth>"},
		{"b= value not digits", "v=0\r\no=- 1 1 IN IP4 x\r\ns=-\r\nb=AS:+64\r\n", 4, "b=: bandwidth must be decimal digits"},
		{"b= type not a token", "v=0\r\no=- 1 1 IN IP4 x\r\ns=-\r\nb=A/S:64\r\n", 4, "b=: bandwidth type must be a token"},
		{"t= with one field", "v=0\r\no=- 1 1 IN IP4 x\r\ns=-\r\nt=0\r\n", 4, "t=: want <start-time> <stop-time>"},
		{"t= overflows", "v=0\r\no=- 1 1 IN IP4 x\r\ns=-\r\nt=0 99999999999999999999999\r\n", 4, "t=: start and stop time"},
		{"r= with two fields", head + "r=1d 1h\r\n", 6, "r=: want <repeat-interval>"},
		{"r= with zero interval", head + "r=0 1h 0\r\n", 6, "r=: repeat interval must be positive"},
		{"r= with an unknown unit", head + "r=1w 1h 0\r\n", 6, "r=: times must be digits"},
		{"z= with an odd field count", head + "z=0\r\n", 6, "z=: want pairs"},
		{"z= offset not a time", head + "z=0 -x\r\n", 6, "z=: want pairs"},
		{"empty session k=", head + "k=\r\n", 6, "k=: value must not be empty"},
		{"a= with empty value", head + "a=path:\r\n", 6, "a=: attribute value after ':' must not be empty"},
		{"a= with empty name", head + "a=:x\r\n", 6, "a=: attribute name must be a token"},
		{"a= name with a space", head + "a=a b\r\n", 6, "a=: attribute name must be a token"},
		{"m= with three fields", head + "m=message 9 TCP/MSRP\r\n", 6, "m=: want <media>"},
		{"m= port above 65535", head + "m=message 65536 TCP/MSRP *\r\n", 6, "m=: port must be"},
		{"m= port with a sign", head + "m=message +9 TCP/MSRP *\r\n", 6, "m=: port must be"},
		{"m= port count zero", head + "m=audio 9/0 RTP/AVP 0\r\n", 6, "m=: number of ports"},
		{"m= port count not digits", head + "m=audio 9/x RTP/AVP 0\r\n", 6, "m=: number of ports"},
		{"m= media type not a token", head + "m=mes:sage 9 TCP/MSRP *\r\n", 6, "m=: media type must be a token"},
		{"m= empty protocol part", head + "m=message 9 TCP//MSRP *\r\n", 6, "m=: protocol must be"},
		{"m= format not a token", head + "m=message 9 TCP/MSRP a:b\r\n", 6, "m=: formats must be tokens"},
		{"m= trailing space", head + "m=message 9 TCP/MSRP * \r\n", 6, "m=: formats must be tokens"},
		{"empty media i=", head + msrp + "i=\r\n", 7, "i=: value must not be empty"},
		{"malformed media c=", head + msrp + "c=IN\r\n", 7, "c=: want <nettype>"},
		{"malformed media b=", head + msrp + "b=AS\r\n", 7, "b=: want <bwtype>"},
		{"empty media k=", head + msrp + "k=\r\n", 7, "k=: value must not be empty"},
		{"malformed media a=", head + msrp + "a=x y\r\n", 7, "a=: attribute name must be a token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := Parse([]byte(tt.in))
			var se *SyntaxError
			if !errors.As(err, &se) {
				t.Fatalf("Parse = %v, %v; want a *SyntaxError", s, err)
			}
			if se.Line != tt.wantLine || !strings.Contains(se.Msg, tt.wantMsg) {
				t.Errorf("got line %d %q, want line %d containing %q", se.Line, se.Msg, tt.wantLine, tt.wantMsg)
			}
		})
	}
}

func TestSyntaxErrorNamesTheLineWhenItHasOne(t *testing.T) {
	if got := (&SyntaxError{Line: 3, Msg: "bad"}).Error(); got != "sdp: line 3: bad" {
		t.Errorf("got %q", got)
	}
	if got := (&SyntaxError{Msg: "bad"}).Error(); got != "sdp: bad" {
		t.Errorf("got %q", got)
	}
}

func TestDescriptionAboveTheDefaultLimitIsRefused(t *testing.T) {
	padding := strings.Repeat("a=x-pad:"+strings.Repeat("z", 100)+"\r\n", DefaultMaxSize/110+1)
	if _, err := Parse([]byte(head + padding)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("Parse = %v, want ErrTooLarge", err)
	}
}

func TestDescriptionExactlyAtTheLimitIsAccepted(t *testing.T) {
	p := Parser{MaxSize: len(head)}
	if _, err := p.Parse([]byte(head)); err != nil {
		t.Errorf("Parse at the limit: %v", err)
	}
	p.MaxSize--
	if _, err := p.Parse([]byte(head)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("Parse one byte over = %v, want ErrTooLarge", err)
	}
}

func TestNegativeLimitMeansTheDefault(t *testing.T) {
	if _, err := (Parser{MaxSize: -1}).Parse([]byte(head)); err != nil {
		t.Errorf("Parse: %v", err)
	}
}
