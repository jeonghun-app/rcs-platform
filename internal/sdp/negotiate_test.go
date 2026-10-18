package sdp

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

var (
	asOrigin     = Origin{"rcs-as", "3913000002", "3913000002", "IN", "IP4", "10.0.1.20"}
	asConnection = Connection{"IN", "IP4", "10.0.1.20"}
)

// asEndpoint is rcs-as receiving a chat over plain TCP from msrp-relay.
func asEndpoint() MSRPEndpoint {
	return MSRPEndpoint{
		Port:               2855,
		Path:               []string{"msrp://10.0.1.20:2855/as9f2c1;tcp"},
		AcceptTypes:        []string{"message/cpim", "application/im-iscomposing+xml"},
		AcceptWrappedTypes: []string{"text/plain", "message/imdn+xml"},
	}
}

// coreChatOffer is chatOffer as pcscf forwards it toward the core: the relay
// is the active party over plain TCP.
var coreChatOffer = strings.NewReplacer(
	"TCP/TLS/MSRP", "TCP/MSRP",
	"msrps://192.0.2.10:9/s7d2k8f;tcp", "msrp://10.0.0.5:9/rl7a1;tcp",
	"setup:actpass", "setup:active",
).Replace(chatOffer)

func TestChatOfferFromTheRelayGetsTheTypicalRCSAnswer(t *testing.T) {
	offer := mustParse(t, coreChatOffer)
	ans := NewAnswer(offer, asOrigin, asConnection)
	m, err := NegotiateMSRP(offer, 0, asEndpoint())
	if err != nil {
		t.Fatalf("NegotiateMSRP: %v", err)
	}
	ans.Media[0] = m
	if got := mustMarshal(t, ans); got != chatAnswer {
		t.Errorf("answer:\n got %q\nwant %q", got, chatAnswer)
	}
}

func TestAnswerKeepsOneLinePerOfferedLineAndRejectsTheRest(t *testing.T) {
	offer := mustParse(t, everyField)
	ans := NewAnswer(offer, asOrigin, asConnection)
	if len(ans.Media) != 2 {
		t.Fatalf("answer has %d media lines, want 2", len(ans.Media))
	}
	audio := ans.Media[0]
	want := Media{Type: "audio", Port: 0, Proto: "RTP/AVP", Formats: []string{"0", "96"}}
	if !reflect.DeepEqual(audio, want) {
		t.Errorf("rejected audio line = %+v, want %+v", audio, want)
	}
	if !reflect.DeepEqual(ans.Times, offer.Times) {
		t.Errorf("answer times = %+v, want the offer's %+v", ans.Times, offer.Times)
	}
	ans.Times[0].Repeats[0] = "1d 1h 0"
	if offer.Times[0].Repeats[0] != "7d 1h 0 25h" {
		t.Error("changing the answer changed the offer's repeat times")
	}
	if _, err := NegotiateMSRP(offer, 0, asEndpoint()); !errors.Is(err, ErrNotMSRP) {
		t.Errorf("NegotiateMSRP on audio = %v, want ErrNotMSRP", err)
	}
	mustMarshal(t, ans)
}

func TestAnswerSetupComplementsTheOfferedRole(t *testing.T) {
	tests := []struct {
		name      string
		offered   string // the a=setup line, or "" for none
		session   bool   // put it at session level instead
		preferred Setup
		want      Setup
	}{
		{"active offer", "active", false, "", SetupPassive},
		{"passive offer", "passive", false, "", SetupActive},
		{"actpass offer, no preference", "actpass", false, "", SetupPassive},
		{"actpass offer, prefer active", "actpass", false, SetupActive, SetupActive},
		{"actpass offer, prefer passive", "actpass", false, SetupPassive, SetupPassive},
		{"holdconn is ignored, so the offerer connects", "holdconn", false, SetupActive, SetupPassive},
		{"session-level holdconn is ignored too", "holdconn", true, SetupActive, SetupPassive},
		{"no a=setup means the offerer connects", "", false, SetupActive, SetupPassive},
		{"session-level a=setup applies", "passive", true, "", SetupActive},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var session, media string
			if tt.offered != "" && tt.session {
				session = "a=setup:" + tt.offered + "\r\n"
			} else if tt.offered != "" {
				media = "a=setup:" + tt.offered + "\r\n"
			}
			offer := mustParse(t, head+session+"m=message 9 TCP/MSRP *\r\na=accept-types:*\r\na=path:msrp://192.0.2.1:9/x;tcp\r\n"+media)
			local := asEndpoint()
			local.PreferredSetup = tt.preferred
			m, err := NegotiateMSRP(offer, 0, local)
			if err != nil {
				t.Fatalf("NegotiateMSRP: %v", err)
			}
			if got, _ := m.Setup(); got != tt.want {
				t.Errorf("answer setup = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAnswerDirectionMirrorsTheOffer(t *testing.T) {
	tests := []struct {
		offered string
		want    Direction
	}{
		{"", SendRecv},
		{"a=sendrecv\r\n", SendRecv},
		{"a=sendonly\r\n", RecvOnly},
		{"a=recvonly\r\n", SendOnly},
		{"a=inactive\r\n", Inactive},
	}
	for _, tt := range tests {
		offer := mustParse(t, head+"m=message 9 TCP/MSRP *\r\na=accept-types:*\r\na=path:msrp://192.0.2.1:9/x;tcp\r\n"+tt.offered)
		m, err := NegotiateMSRP(offer, 0, asEndpoint())
		if err != nil {
			t.Fatalf("NegotiateMSRP(%q): %v", tt.offered, err)
		}
		if got, _ := m.Direction(); got != tt.want {
			t.Errorf("offer %q: answer direction = %q, want %q", tt.offered, got, tt.want)
		}
	}
}

func TestAnswerAcceptsTheTypesBothEndsAccept(t *testing.T) {
	tests := []struct {
		name           string
		offered, local []string
		want           []string
	}{
		{"exact matches in offer order", []string{"b/b", "a/a", "c/c"}, []string{"a/a", "b/b"}, []string{"b/b", "a/a"}},
		{"case-insensitive", []string{"Message/CPIM"}, []string{"message/cpim"}, []string{"Message/CPIM"}},
		{"offered * takes the local list", []string{"*"}, []string{"a/a", "b/b"}, []string{"a/a", "b/b"}},
		{"local * takes the offered list", []string{"a/a", "b/b"}, []string{"*"}, []string{"a/a", "b/b"}},
		{"both * stay *", []string{"*"}, []string{"*"}, []string{"*"}},
		{"type/* narrows to the subtype", []string{"text/*"}, []string{"text/plain", "image/png"}, []string{"text/plain"}},
		{"subtype matches local type/*", []string{"text/plain", "image/png"}, []string{"text/*"}, []string{"text/plain"}},
		{"duplicates collapse", []string{"*", "a/a"}, []string{"a/a"}, []string{"a/a"}},
		{"nothing in common", []string{"a/a"}, []string{"b/b", "a/*x"}, nil},
		{"offered parameters are ignored for matching and kept", []string{"text/plain;charset=UTF-8"}, []string{"text/plain"}, []string{"text/plain;charset=UTF-8"}},
		{"local parameters are ignored for matching", []string{"text/plain"}, []string{"text/plain;charset=UTF-8"}, []string{"text/plain"}},
		{"wildcard with parameters narrows to the local entry", []string{"text/*;q=1"}, []string{"text/plain;charset=UTF-8"}, []string{"text/plain;charset=UTF-8"}},
		{"offered * keeps local parameters", []string{"*"}, []string{"text/plain;charset=UTF-8"}, []string{"text/plain;charset=UTF-8"}},
		{"same entry twice collapses", []string{"text/plain", "TEXT/PLAIN"}, []string{"*"}, []string{"text/plain"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := intersectTypes(tt.offered, tt.local); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("intersectTypes(%q, %q) = %q, want %q", tt.offered, tt.local, got, tt.want)
			}
		})
	}
}

func TestAnswerLeavesOutWrappedTypesWhenNoneAreShared(t *testing.T) {
	sdp := head + "m=message 9 TCP/MSRP *\r\na=accept-types:message/cpim\r\na=accept-wrapped-types:image/png\r\na=path:msrp://192.0.2.1:9/x;tcp\r\n"
	m, err := NegotiateMSRP(mustParse(t, sdp), 0, asEndpoint())
	if err != nil {
		t.Fatal(err)
	}
	if m.Attributes.Has("accept-wrapped-types") {
		t.Errorf("answer has accept-wrapped-types: %+v", m.Attributes)
	}
	noWrapped := strings.Replace(sdp, "a=accept-wrapped-types:image/png\r\n", "", 1)
	if m, err = NegotiateMSRP(mustParse(t, noWrapped), 0, asEndpoint()); err != nil || m.Attributes.Has("accept-wrapped-types") {
		t.Errorf("offer without wrapped types: %+v, %v", m.Attributes, err)
	}
}

func TestFileTransferAnswerEchoesTheSelectorAndAdvertisesMaxSize(t *testing.T) {
	offer := mustParse(t, fileOffer)
	local := asEndpoint()
	local.AcceptWrappedTypes = []string{"*"}
	local.MaxSize = 52428800
	m, err := NegotiateMSRP(offer, 0, local)
	if err != nil {
		t.Fatalf("NegotiateMSRP: %v", err)
	}
	want := attrs(
		"accept-types", "message/cpim",
		"accept-wrapped-types", "image/jpeg",
		"max-size", "52428800",
		"path", "msrp://10.0.1.20:2855/as9f2c1;tcp",
		"setup", "passive",
		"recvonly", "",
		"file-selector", offer.Media[0].Attributes.Values("file-selector")[0],
		"file-transfer-id", "vBnG916bdberum2fFEABR4f",
		"file-range", "1-48213",
	)
	if !reflect.DeepEqual(m.Attributes, want) {
		t.Errorf("answer attributes:\n got %+v\nwant %+v", m.Attributes, want)
	}
}

func TestOffersThatCannotBeAcceptedAreDeclinedWithAReason(t *testing.T) {
	msrpLine := "m=message 9 TCP/MSRP *\r\n"
	path := "a=path:msrp://192.0.2.1:9/x;tcp\r\n"
	types := "a=accept-types:message/cpim\r\n"
	tests := []struct {
		name    string
		offer   string
		local   func(e *MSRPEndpoint)
		index   int
		wantIs  error
		wantErr string
	}{
		{"port 0", head + "m=message 0 TCP/MSRP *\r\n" + types + path, nil, 0, ErrMediaDisabled, ""},
		{"no type in common", head + msrpLine + "a=accept-types:image/png\r\n" + path, nil, 0, ErrNoCommonType, ""},
		{"TLS offer, plain local path", head + "m=message 9 TCP/TLS/MSRP *\r\n" + types + "a=path:msrps://192.0.2.1:9/x;tcp\r\n", nil, 0, ErrTransportMismatch, ""},
		{"plain offer, TLS local path", head + msrpLine + types + path, func(e *MSRPEndpoint) { e.Path = []string{"msrps://10.0.1.20:2855/a;tcp"} }, 0, ErrTransportMismatch, ""},
		{"index out of range", head + msrpLine + types + path, nil, 1, nil, "no media description 1"},
		{"offer without a=path", head + msrpLine + types, nil, 0, ErrNoAttribute, ""},
		{"offer without accept-types", head + msrpLine + path, nil, 0, ErrNoAttribute, ""},
		{"malformed accept-wrapped-types", head + msrpLine + types + "a=accept-wrapped-types:x\r\n" + path, nil, 0, nil, "is not a media type"},
		{"unknown offered setup", head + msrpLine + types + path + "a=setup:both\r\n", nil, 0, nil, "unknown role"},
		{"conflicting offered direction", head + msrpLine + types + path + "a=sendonly\r\na=recvonly\r\n", nil, 0, nil, "more than one direction"},
		{"malformed file selector", head + msrpLine + types + path + "a=file-selector:colour:blue\r\n", nil, 0, nil, "unknown selector"},
		{"malformed file transfer id", head + msrpLine + types + path + "a=file-transfer-id:a/b\r\n", nil, 0, nil, "is not a token"},
		{"malformed file range", head + msrpLine + types + path + "a=file-range:0-10\r\n", nil, 0, nil, "is not <start>-<stop>"},
		{"local port 0", head + msrpLine + types + path, func(e *MSRPEndpoint) { e.Port = 0 }, 0, nil, "port must be from 1 to 65535"},
		{"local path missing", head + msrpLine + types + path, func(e *MSRPEndpoint) { e.Path = nil }, 0, nil, "at least one URI"},
		{"local accept types missing", head + msrpLine + types + path, func(e *MSRPEndpoint) { e.AcceptTypes = nil }, 0, nil, "at least one accept type"},
		{"local accept type malformed", head + msrpLine + types + path, func(e *MSRPEndpoint) { e.AcceptTypes = []string{"cpim"} }, 0, nil, "is not a media type"},
		{"local wrapped type malformed", head + msrpLine + types + path, func(e *MSRPEndpoint) { e.AcceptWrappedTypes = []string{"\r\n"} }, 0, nil, "is not a media type"},
		{"local max size negative", head + msrpLine + types + path, func(e *MSRPEndpoint) { e.MaxSize = -1 }, 0, nil, "max size must not be negative"},
		{"local preference actpass", head + msrpLine + types + path, func(e *MSRPEndpoint) { e.PreferredSetup = SetupActPass }, 0, nil, "preferred setup must be active or passive"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			local := asEndpoint()
			if tt.local != nil {
				tt.local(&local)
			}
			_, err := NegotiateMSRP(mustParse(t, tt.offer), tt.index, local)
			if err == nil {
				t.Fatal("NegotiateMSRP accepted the offer")
			}
			if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
				t.Errorf("got %v, want %v", err, tt.wantIs)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("got %v, want an error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestNegotiateDoesNotModifyTheOffer(t *testing.T) {
	offer := mustParse(t, fileOffer)
	before := mustMarshal(t, offer)
	m, err := NegotiateMSRP(offer, 0, asEndpoint())
	if err != nil {
		t.Fatal(err)
	}
	m.Formats[0] = "changed"
	if after := mustMarshal(t, offer); after != before {
		t.Errorf("offer changed:\n%q\n%q", before, after)
	}
}

func TestOfferWithTypeParametersIsAccepted(t *testing.T) {
	offer := mustParse(t, head+"m=message 9 TCP/MSRP *\r\n"+
		"a=accept-types:message/cpim;charset=UTF-8 application/im-iscomposing+xml\r\n"+
		"a=accept-wrapped-types:text/plain;charset=UTF-8 message/imdn+xml\r\n"+
		"a=path:msrp://192.0.2.1:9/x;tcp\r\n")
	m, err := NegotiateMSRP(offer, 0, asEndpoint())
	if err != nil {
		t.Fatalf("NegotiateMSRP: %v", err)
	}
	types, _ := m.AcceptTypes()
	wrapped, _ := m.AcceptWrappedTypes()
	if !reflect.DeepEqual(types, []string{"message/cpim;charset=UTF-8", "application/im-iscomposing+xml"}) ||
		!reflect.DeepEqual(wrapped, []string{"text/plain;charset=UTF-8", "message/imdn+xml"}) {
		t.Errorf("answer accept-types %q, accept-wrapped-types %q", types, wrapped)
	}
}

func TestResumedFileTransferAnswerKeepsTheOfferedRange(t *testing.T) {
	offer := mustParse(t, strings.Replace(fileOffer, "a=file-range:1-48213", "a=file-range:1001-*", 1))
	m, err := NegotiateMSRP(offer, 0, asEndpoint())
	if err != nil {
		t.Fatalf("NegotiateMSRP: %v", err)
	}
	if r, err := m.FileRange(); err != nil || r != (FileRange{Start: 1001, Stop: -1}) {
		t.Errorf("answer file-range = %+v, %v", r, err)
	}
}

func TestDeclinedFileTransferStillNamesTheTransfer(t *testing.T) {
	offer := mustParse(t, fileOffer)
	local := asEndpoint()
	local.AcceptTypes = []string{"text/plain"}
	if _, err := NegotiateMSRP(offer, 0, local); !errors.Is(err, ErrNoCommonType) {
		t.Fatalf("NegotiateMSRP = %v, want ErrNoCommonType", err)
	}
	got := NewAnswer(offer, asOrigin, asConnection).Media[0]
	want := Media{
		Type: "message", Proto: "TCP/MSRP", Formats: []string{"*"},
		Attributes: attrs(
			"file-selector", offer.Media[0].Attributes.Values("file-selector")[0],
			"file-transfer-id", "vBnG916bdberum2fFEABR4f",
		),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("rejected line = %+v\nwant %+v", got, want)
	}
}
