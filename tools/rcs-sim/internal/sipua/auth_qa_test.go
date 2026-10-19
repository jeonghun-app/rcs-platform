package sipua

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
)

// QA's tests from the second review of #187.

func TestA200ToTheAUTNFailureReportIsNotARegistration(t *testing.T) {
	a := newAuthRegistrar(t, digest.AKAv1MD5)
	other := testK
	other[0] ^= 1
	creds, err := AKACredentials(testIMPI, other, testOPc)
	if err != nil {
		t.Fatal(err)
	}
	s, cfg := authStandIn(t, a, creds)
	s.auth = nil
	s.hook = func(req *sip.Request, tag string) *sip.Response {
		c, err := digest.ParseCredentials(req.Header.Get("Authorization"))
		if err != nil || c.Nonce == "" {
			a.mu.Lock()
			defer a.mu.Unlock()
			return a.challenge(t, req, tag, false)
		}
		return nil // the stand-in's 200
	}
	reg, err := dial(t, cfg).Register(context.Background())
	var se *StatusError
	if reg != nil || !errors.Is(err, ErrNetworkNotAuthenticated) || !errors.As(err, &se) || se.Code != 200 {
		t.Fatalf("Register = %+v, %v; a 200 to the report is not a registration", reg, err)
	}
}

func TestAnAKAChallengeWithOnlyAuthIntIsPassedOver(t *testing.T) {
	a := newAuthRegistrar(t, digest.AKAv1MD5)
	a.before = []string{`Digest realm="` + testDomain + `", nonce="bm9uY2U=", algorithm=AKAv1-MD5, qop="auth-int"`}
	_, cfg := authStandIn(t, a, akaCreds(t))
	register(t, dial(t, cfg))
}

func TestABrokenAKANonceIsReportedWithItsNonceAndOpaque(t *testing.T) {
	// A nonce without RAND and AUTN takes the AUTN failure path: one more
	// REGISTER with the nonce and the opaque echoed, and an empty response.
	const nonce, opaque = "not-base64-rand-autn", "opaque-value"
	a := newAuthRegistrar(t, digest.AKAv1MD5)
	s, cfg := authStandIn(t, a, akaCreds(t))
	s.auth = nil
	var report string
	s.hook = func(req *sip.Request, tag string) *sip.Response {
		if c, err := digest.ParseCredentials(req.Header.Get("Authorization")); err == nil && c.Nonce != "" {
			report = req.Header.Get("Authorization")
			return mustResponse(t, req, 403, tag)
		}
		res := mustResponse(t, req, 401, tag)
		res.Header.Add("WWW-Authenticate", `Digest realm="`+testDomain+`", nonce="`+nonce+`", opaque="`+opaque+`", algorithm=AKAv1-MD5, qop="auth"`)
		return res
	}
	_, err := dial(t, cfg).Register(context.Background())
	if !errors.Is(err, ErrNetworkNotAuthenticated) || s.registerCount() != 2 {
		t.Fatalf("Register = %v after %d REGISTERs", err, s.registerCount())
	}
	c, err := digest.ParseCredentials(report)
	if err != nil || c.Nonce != nonce || c.Opaque != opaque || c.Response != "" || len(c.AUTS) != 0 {
		t.Fatalf("report = %q, %v", report, err)
	}
}

func TestChallengesMustMatchTheConfiguredRealm(t *testing.T) {
	// Config.Realm apart from the domain, as HSS_IMS_REALM can be: a
	// challenge for the domain is then not answered, one for the realm is.
	const realm = "realm.example.net"
	a := newAuthRegistrar(t, digest.SHA256)
	s, cfg := authStandIn(t, a, digestCreds(t, testPassword))
	cfg.Realm = realm
	if _, err := dial(t, cfg).Register(context.Background()); !errors.Is(err, ErrNoUsableChallenge) {
		t.Fatalf("Register = %v; the domain's realm is not Config.Realm", err)
	}
	first, _, _ := a.seen()
	if c, err := digest.ParseCredentials(first[0]); err != nil || c.Realm != realm {
		t.Fatalf("unchallenged Authorization %q, %v; want the configured realm", first[0], err)
	}
	_ = s
	ds, err := digest.NewServer(digest.ServerConfig{
		Realm: realm, NonceKey: []byte(strings.Repeat("r", digest.MinNonceKeySize)), NonceCounts: digest.NewMemoryNonceCounts(nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	b := newAuthRegistrar(t, digest.SHA256)
	b.ds = ds
	_, cfg = authStandIn(t, b, digestCreds(t, testPassword))
	cfg.Realm = realm
	register(t, dial(t, cfg))
}
