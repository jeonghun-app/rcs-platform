package cxclient

import (
	"slices"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
)

func TestSchemes(t *testing.T) {
	tests := []struct {
		algorithm  string
		preference []string
		want       []string
		ok         bool
	}{
		{"", nil, []string{cx.SchemeDigestAKAv1MD5, cx.SchemeSIPDigest}, true},
		{"", []string{cx.SchemeSIPDigest, cx.SchemeDigestAKAv1MD5}, []string{cx.SchemeSIPDigest, cx.SchemeDigestAKAv1MD5}, true},
		{"AKAv1-MD5", []string{cx.SchemeSIPDigest}, []string{cx.SchemeDigestAKAv1MD5}, true},
		{"akav2-md5", nil, []string{cx.SchemeDigestAKAv1MD5}, true},
		{"MD5", nil, []string{cx.SchemeSIPDigest}, true},
		{"SHA-256", nil, []string{cx.SchemeSIPDigest}, true},
		{"MD5-sess", nil, []string{cx.SchemeSIPDigest}, true},
		{"ROT13", nil, nil, false},
	}
	for _, tt := range tests {
		got, ok := Schemes(tt.algorithm, tt.preference)
		if ok != tt.ok || !slices.Equal(got, tt.want) {
			t.Errorf("Schemes(%q, %q) = %q, %v; want %q, %v", tt.algorithm, tt.preference, got, ok, tt.want, tt.ok)
		}
	}
	got, _ := Schemes("", nil)
	got[0] = "changed"
	if DefaultSchemes[0] == "changed" {
		t.Error("Schemes returned DefaultSchemes itself")
	}
}

// TestAuthenticateFallsBackToSIPDigestOn5006 is the #14 policy: AKA first,
// SIP Digest when the user has no AKA keys (TS 29.228 §6.3.1).
func TestAuthenticateFallsBackToSIPDigestOn5006(t *testing.T) {
	e := newEnv(t, nil)
	h := startHSS(t, e.net, "192.0.2.1", "hss-a.rcs.local")
	e.refresh("192.0.2.1")
	h.setAnswer(func(code uint32, req *diameter.Message) (*diameter.Message, error) {
		mar, err := cx.ParseMAR(req)
		if err != nil {
			return nil, err
		}
		if mar.AuthDataItem.Scheme == cx.SchemeDigestAKAv1MD5 {
			return h.result(code, req, cx.ExperimentalResult(cx.ErrorAuthSchemeNotSupported))
		}
		return h.success(code, req)
	})
	mar := &cx.MAR{UserName: impi1, PublicIdentity: impu1, NumberAuthItems: 1}
	schemes, _ := Schemes("", nil)
	maa, err := e.client.Authenticate(ctx(t), mar, schemes)
	if err != nil || Classify(maa.Result) != Success || maa.AuthDataItems[0].Scheme != cx.SchemeSIPDigest {
		t.Fatalf("Authenticate = %+v, %v", maa, err)
	}
	got := h.requests()
	if len(got) != 2 || got[0].sessionID == got[1].sessionID {
		t.Fatalf("%d MARs; each scheme must be its own request", len(got))
	}
	if mar.AuthDataItem.Scheme != "" {
		t.Error("Authenticate changed the caller's MAR")
	}

	// The client named AKA: no fallback, the 5006 is the answer.
	schemes, _ = Schemes("AKAv1-MD5", nil)
	maa, err = e.client.Authenticate(ctx(t), mar, schemes)
	if err != nil || Classify(maa.Result) != SchemeNotSupported {
		t.Fatalf("with the client's algorithm: %+v, %v", maa, err)
	}
	if _, err := e.client.Authenticate(ctx(t), mar, nil); err == nil {
		t.Error("Authenticate without schemes")
	}
}
