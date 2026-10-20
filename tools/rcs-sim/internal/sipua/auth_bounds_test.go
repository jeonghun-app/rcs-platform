package sipua

import (
	"context"
	"errors"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
)

// QA's tests from the review of #187.

func TestARegistrarThatAlwaysSaysStaleIsAnsweredAtMostThreeTimes(t *testing.T) {
	// The cap on challenges: without it this loops until ctx; at 2 or 4 the
	// count of REGISTERs changes.
	a := newAuthRegistrar(t, digest.SHA256)
	s, cfg := authStandIn(t, a, digestCreds(t, testPassword))
	s.auth = nil
	s.hook = func(req *sip.Request, tag string) *sip.Response {
		res := mustResponse(t, req, 401, tag)
		ch, _ := a.ds.Challenge(digest.SHA256, true)
		res.Header.Add("WWW-Authenticate", ch.Header())
		return res
	}
	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	defer cancel()
	_, err := dial(t, cfg).Register(ctx)
	var se *StatusError
	if !errors.As(err, &se) || se.Code != 401 || s.registerCount() != 1+maxChallenges || maxChallenges != 3 {
		t.Fatalf("Register = %v after %d REGISTERs, want 401 after 4", err, s.registerCount())
	}
}

func TestAKAResyncThenStaleStillRegisters(t *testing.T) {
	// AUTS, then a stale nonce on the fresh vector: the third answer is
	// still sent, which a cap of 2 would refuse.
	a := newAuthRegistrar(t, digest.AKAv1MD5)
	s, cfg := authStandIn(t, a, akaCreds(t))
	ua := dial(t, cfg)
	register(t, ua)
	register(t, ua)
	a.mu.Lock()
	a.sqn = 0
	a.mu.Unlock()
	s.auth = nil
	staleDone := false
	s.hook = func(req *sip.Request, tag string) *sip.Response {
		c, err := digest.ParseCredentials(req.Header.Get("Authorization"))
		if err == nil && c.Nonce != "" && len(c.AUTS) == 0 && !staleDone {
			staleDone = true
			a.mu.Lock()
			defer a.mu.Unlock()
			return a.challenge(t, req, tag, true)
		}
		return a.check(t, req, tag)
	}
	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	defer cancel()
	reg, err := ua.Register(ctx)
	if err != nil || reg.Challenges != 3 || !reg.Resynchronised {
		t.Fatalf("Register = %+v, %v; want 3 challenges with a resync", reg, err)
	}
}

func TestUnregisterNamesTheIMPIToo(t *testing.T) {
	a := newAuthRegistrar(t, digest.AKAv1MD5)
	_, cfg := authStandIn(t, a, akaCreds(t))
	ua := dial(t, cfg)
	register(t, ua)
	if _, err := ua.Unregister(context.Background()); err != nil {
		t.Fatal(err)
	}
	first, _, _ := a.seen()
	if len(first) != 2 {
		t.Fatalf("%d unchallenged REGISTERs", len(first))
	}
	if c, err := digest.ParseCredentials(first[1]); err != nil || c.Username != testIMPI {
		t.Fatalf("de-registration's first Authorization = %q, %v", first[1], err)
	}
}

func TestA401WithoutAChallengeIsTheStatus(t *testing.T) {
	// Not ErrNoUsableChallenge alone: a scenario reports the status.
	a := newAuthRegistrar(t, digest.SHA256)
	s, cfg := authStandIn(t, a, digestCreds(t, testPassword))
	s.auth = nil
	s.hook = func(req *sip.Request, tag string) *sip.Response { return mustResponse(t, req, 401, tag) }
	_, err := dial(t, cfg).Register(context.Background())
	var se *StatusError
	if !errors.As(err, &se) || se.Code != 401 || errors.Is(err, ErrNoUsableChallenge) || s.registerCount() != 1 {
		t.Fatalf("Register = %v after %d REGISTERs", err, s.registerCount())
	}
}

func TestAStaleProxyChallengeIsAnsweredOnceMore(t *testing.T) {
	a := newAuthRegistrar(t, digest.SHA256)
	a.proxy, a.staleOnce = true, true
	_, cfg := authStandIn(t, a, digestCreds(t, testPassword))
	if reg := register(t, dial(t, cfg)); reg.Challenges != 2 {
		t.Fatalf("registration = %+v", reg)
	}
}

func TestDigestCredentialsKeepTheirOwnCopyOfThePassword(t *testing.T) {
	pw := []byte(testPassword)
	creds, err := DigestCredentials(testIMPI, pw)
	if err != nil {
		t.Fatal(err)
	}
	pw[0] ^= 1
	a := newAuthRegistrar(t, digest.SHA256)
	_, cfg := authStandIn(t, a, creds)
	register(t, dial(t, cfg))
}

func TestCarriedCredentialsTakeTheNextNonceCountAndANewCNonce(t *testing.T) {
	// The proxy's credentials go in two REGISTERs (RFC 3261 §22.3); the
	// second must not repeat the first's nc and cnonce (RFC 7616 §3.4).
	reg := newAuthRegistrar(t, digest.SHA256)
	proxy := newAuthRegistrar(t, digest.SHA256)
	proxy.proxy = true
	s, cfg := authStandIn(t, reg, digestCreds(t, testPassword))
	s.proxyAuth = proxy
	register(t, dial(t, cfg))
	_, answered, _ := proxy.seen()
	if len(answered) != 2 || answered[0].NC != 1 || answered[1].NC != 2 || answered[0].CNonce == answered[1].CNonce || answered[0].Nonce != answered[1].Nonce {
		t.Fatalf("the proxy saw %v", answered)
	}
}
