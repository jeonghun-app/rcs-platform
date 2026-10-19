package sipua

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/milenage"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
)

// Test credentials. K and OPc are TS 35.208 test set 1, not a SIM's; the
// IMPI's IMSI is on .github/allowed-test-identifiers.txt.
const (
	testIMPI     = "001010000000001@ims.example.com"
	testPassword = "sim-test-sip-password"
	testKHex     = "465b5ce8b199b49faa5f0a2ee238a6bc"
	testOPcHex   = "cd63cb71954a9f4e48a5994e37a02baf"
)

var (
	testK   = mustKey(testKHex)
	testOPc = mustKey(testOPcHex)
)

func mustKey(h string) [milenage.KeySize]byte {
	k, err := hexKey(func(string) string { return h }, "test")
	if err != nil {
		panic(err)
	}
	return k
}

// authRegistrar authenticates REGISTERs as the S-CSCF does, with Digest
// (RFC 7616, RFC 8760) or Digest AKA (RFC 3310) on internal/sip/digest's
// server side and internal/milenage's vectors.
type authRegistrar struct {
	ds *digest.Server

	// algorithms are the challenges offered, in order; AKAv1-MD5 alone
	// makes this an AKA registrar.
	algorithms []digest.Algorithm
	password   string
	// m is the subscriber's keys as the HSS holds them, and sqn the
	// network's counter.
	m   milenage.Milenage
	sqn milenage.SQN
	// staleOnce answers the first credentials with a stale challenge;
	// refuseWith answers wrong ones with this status instead of 403;
	// wrongXRES verifies AKA against another RES.
	staleOnce  bool
	refuseWith int
	wrongXRES  bool
	// proxy challenges with 407 and Proxy-Authenticate, as a proxy does.
	proxy bool
	// foreign, when set, challenges first for another realm, with a valid
	// challenge of each algorithm from its own server; foreignOnly leaves
	// the home realm's out.
	foreign     *digest.Server
	foreignOnly bool
	// before are raw challenge values sent ahead of the registrar's own.
	before []string
	// noQOP sends AKA challenges without qop and checks the answer in the
	// form without it (RFC 3310 §3.3, RFC 2617 §3.2.2.1).
	noQOP bool

	mu        sync.Mutex
	vectors   map[string][]byte // nonce to XRES
	firstAuth []string          // the Authorization of each unchallenged REGISTER
	answered  []digest.Credentials
	resyncs   int
	// cardSQN is the SQN_MS each verified AUTS carried.
	cardSQN []milenage.SQN
}

func newAuthRegistrar(t *testing.T, algorithms ...digest.Algorithm) *authRegistrar {
	t.Helper()
	ds, err := digest.NewServer(digest.ServerConfig{
		Realm: testDomain, NonceKey: []byte(strings.Repeat("k", digest.MinNonceKeySize)),
		NonceCounts: digest.NewMemoryNonceCounts(nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &authRegistrar{ds: ds, algorithms: algorithms, password: testPassword, m: milenage.New(testK, testOPc), vectors: map[string][]byte{}}
}

// seen returns, under the lock, what the registrar has received: network
// I/O is no synchronisation the race detector sees.
func (a *authRegistrar) seen() (first []string, answered []digest.Credentials, resyncs int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.firstAuth...), append([]digest.Credentials(nil), a.answered...), a.resyncs
}

func (a *authRegistrar) aka() bool {
	return len(a.algorithms) == 1 && a.algorithms[0] == digest.AKAv1MD5
}

// check returns the answer to a REGISTER that is not authenticated, or nil
// for one that is.
func (a *authRegistrar) check(t *testing.T, req *sip.Request, tag string) *sip.Response {
	a.mu.Lock()
	defer a.mu.Unlock()
	field := "Authorization"
	if a.proxy {
		field = "Proxy-Authorization"
	}
	v := req.Header.Get(field)
	c, err := digest.ParseCredentials(v)
	if v == "" || err != nil || c.Nonce == "" {
		a.firstAuth = append(a.firstAuth, v)
		return a.challenge(t, req, tag, false)
	}
	a.answered = append(a.answered, c)
	if a.staleOnce {
		a.staleOnce = false
		return a.challenge(t, req, tag, true)
	}
	if a.aka() {
		xres, ok := a.vectors[c.Nonce]
		if !ok {
			return a.refuse(t, req, tag)
		}
		if a.wrongXRES {
			xres = []byte("not-the-xres")
		}
		if a.noQOP {
			// digest.Server verifies qop=auth only; this is the form
			// without qop, computed here from RFC 2617 §3.2.2.1.
			ha1 := md5hex(c.Username + ":" + c.Realm + ":" + string(xres))
			if c.QOP != "" || c.Response != md5hex(ha1+":"+c.Nonce+":"+md5hex("REGISTER:"+c.URI)) {
				return a.refuse(t, req, tag)
			}
			delete(a.vectors, c.Nonce)
			return nil
		}
		err := a.ds.VerifyAKA(context.Background(), "REGISTER", c, xres, time.Now().Add(time.Minute))
		var sf *digest.SyncFailure
		switch {
		case err == nil:
			delete(a.vectors, c.Nonce)
			return nil
		case errors.As(err, &sf):
			ms, err := a.m.VerifyAUTS(sf.RAND, sf.AUTS)
			if err != nil {
				t.Errorf("registrar: AUTS did not verify: %v", err)
				return a.refuse(t, req, tag)
			}
			a.resyncs++
			a.cardSQN = append(a.cardSQN, ms)
			a.sqn = milenage.Resynchronise(a.sqn, ms)
			return a.challenge(t, req, tag, false)
		}
		return a.refuse(t, req, tag)
	}
	if err := a.ds.Verify(context.Background(), "REGISTER", c, digest.Password([]byte(a.password))); err != nil {
		return a.refuse(t, req, tag)
	}
	return nil
}

func (a *authRegistrar) challenge(t *testing.T, req *sip.Request, tag string, stale bool) *sip.Response {
	code, field := 401, "WWW-Authenticate"
	if a.proxy {
		code, field = 407, "Proxy-Authenticate"
	}
	res := mustResponse(t, req, code, tag)
	for _, v := range a.before {
		res.Header.Add(field, v)
	}
	servers := []*digest.Server{a.ds}
	switch {
	case a.foreignOnly:
		servers = []*digest.Server{a.foreign}
	case a.foreign != nil:
		servers = []*digest.Server{a.foreign, a.ds}
	}
	for _, ds := range servers {
		for _, h := range a.challenges(t, ds, stale) {
			res.Header.Add(field, h)
		}
	}
	return res
}

// challenges are ds's challenges, one per algorithm.
func (a *authRegistrar) challenges(t *testing.T, ds *digest.Server, stale bool) []string {
	var out []string
	for _, alg := range a.algorithms {
		var ch digest.Challenge
		var err error
		if alg == digest.AKAv1MD5 {
			next, e := a.sqn.Next()
			if e != nil {
				t.Errorf("registrar: %v", e)
			}
			a.sqn = next
			var r [milenage.RANDSize]byte
			rand.Read(r[:])
			vec := a.m.Vector(r, a.sqn, [milenage.AMFSize]byte{0x80, 0x00})
			rnd, autn := vec.RAND(), vec.AUTN()
			ch, err = ds.AKAChallenge(rnd[:], autn[:], stale)
			xres := vec.XRES()
			a.vectors[ch.Nonce] = xres[:]
			if a.noQOP {
				ch.QOP = nil
			}
		} else {
			ch, err = ds.Challenge(alg, stale)
		}
		if err != nil {
			t.Errorf("registrar: %v", err)
		}
		out = append(out, ch.Header())
	}
	return out
}

func (a *authRegistrar) refuse(t *testing.T, req *sip.Request, tag string) *sip.Response {
	code := 403
	if a.refuseWith != 0 {
		code = a.refuseWith
		if code == 401 || code == 407 {
			return a.challenge(t, req, tag, false)
		}
	}
	return mustResponse(t, req, code, tag)
}

func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func mustResponse(t *testing.T, req *sip.Request, code int, tag string) *sip.Response {
	res, err := sip.NewResponse(req, code, "", tag)
	if err != nil {
		t.Errorf("registrar: %v", err)
	}
	return res
}
