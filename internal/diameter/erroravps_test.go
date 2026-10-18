package diameter

import (
	"context"
	"testing"
)

// Cx answers must carry Vendor-Specific-Application-Id and
// Auth-Session-State (TS 29.229 §6.1) even when the node builds them.
func cxErrorAVPs(req *Message) []*AVP {
	return []*AVP{cxVSA(), NewAVP(AVPAuthSessionState, FlagMandatory, 0, Enumerated(1))}
}

func TestNodeBuiltAnswersCarryTheApplicationsRequiredAVPs(t *testing.T) {
	tests := []struct {
		name    string
		code    uint32
		edit    func(b []byte) []byte
		handler HandlerFunc
		want    uint32
		extra   bool
	}{
		{"handler error", cmdTest, nil, func(ctx context.Context, p *Peer, r *Message) (*Message, error) {
			return nil, &Error{ResultCode: ResultMissingAVP}
		}, ResultMissingAVP, true},
		{"handler panic", cmdTest, nil, func(ctx context.Context, p *Peer, r *Message) (*Message, error) {
			panic("bug")
		}, ResultUnableToComply, true},
		{"malformed request", cmdTest, func(b []byte) []byte {
			return append(b, rawAVP(AVPOriginStateID, FlagMandatory, 9, 1, 0, 0, 0)...)
		}, nil, ResultInvalidAVPLength, true},
		{"protocol error keeps the generic answer-message", cmdTest + 1, nil, nil, ResultCommandUnsupported, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hss, ln, _ := startResponder(t, nil)
			var seen string
			hss.SetErrorAVPs(appCx, func(req *Message) []*AVP {
				seen, _ = req.SessionID()
				return cxErrorAVPs(req)
			})
			h := tt.handler
			if h == nil {
				h = echoHandler(hss)
			}
			hss.Handle(appCx, cmdTest, h)
			s := openScript(t, ln, scscfHost)
			req := &Message{Flags: FlagRequest, Code: tt.code, ApplicationID: appCx, HopByHop: 9, EndToEnd: 9,
				AVPs: append([]*AVP{NewAVP(AVPSessionID, FlagMandatory, 0, []byte(scscfHost+";1;9"))}, s.origin()...)}
			b, _ := req.Encode()
			if tt.edit != nil {
				b = tt.edit(b)
				b[1], b[2], b[3] = byte(len(b)>>16), byte(len(b)>>8), byte(len(b))
			}
			s.writeRaw(b)
			ans := s.read()
			if rc, _ := ans.ResultCode(); rc != tt.want {
				t.Fatalf("result %d, want %d", rc, tt.want)
			}
			hasVSA := ans.Find(AVPVendorSpecificApplicationID, 0) != nil
			hasState := ans.Find(AVPAuthSessionState, 0) != nil
			if hasVSA != tt.extra || hasState != tt.extra {
				t.Fatalf("application AVPs present: %v/%v, want %v", hasVSA, hasState, tt.extra)
			}
			if tt.extra && seen != scscfHost+";1;9" {
				t.Fatalf("hook saw Session-Id %q", seen)
			}
		})
	}
}

func TestErrorAVPsCannotBeSetForTheBaseProtocol(t *testing.T) {
	n := newTestNode(t, testConfig(newFakeClock(), hssHost))
	defer func() {
		if recover() == nil {
			t.Fatal("no panic")
		}
	}()
	n.SetErrorAVPs(AppCommon, cxErrorAVPs)
}
