package registrar

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/ifc"
	"github.com/jeonghun-app/rcs-platform/internal/ims/cxclient"
	"github.com/jeonghun-app/rcs-platform/internal/milenage"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// Test identities: MCC 001 / MNC 01 and the fictional +1 555 0100 range, as
// .github/allowed-test-identifiers.txt requires.
const (
	realm = "ims.mnc001.mcc001.3gppnetwork.org"
	impi1 = "001010000000001@" + realm
	impi2 = "001010000000002@" + realm
	impu1 = "sip:+15550100001@" + realm
	tel1  = "tel:+15550100001"
	impu2 = "sip:+15550100002@" + realm
	impu3 = "sip:+15550100003@" + realm
)

var t0 = time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)

// clock is a time the test moves.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// lockedRand is a seeded source safe for concurrent use.
type lockedRand struct {
	mu sync.Mutex
	r  *rand.ChaCha8
}

func newRand(seed byte) *lockedRand {
	var s [32]byte
	s[0] = seed
	return &lockedRand{r: rand.NewChaCha8(s)}
}

func (l *lockedRand) Read(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.r.Read(p)
}

// subscriber is what the fake HSS holds for one IMPI.
type subscriber struct {
	impi string
	// set is the implicit registration set, default identity first unless
	// barred says otherwise.
	set    []string
	barred map[string]bool
	aka    *milenage.Milenage
	sqn    milenage.SQN
	// password is the SIP Digest password; nil for an AKA-only user.
	password []byte
}

// fakeHSS answers MAR and SAR as the HSS of TS 29.228 does for the cases the
// registrar meets. It is not internal/hss: these tests are about the S-CSCF,
// and the HSS's own tests cover it.
type fakeHSS struct {
	mu    sync.Mutex
	subs  map[string]*subscriber
	rands uint64
	// unavailable answers every request with a transport failure.
	unavailable bool
	// sarResult, if set, is the result of every SAR.
	sarResult *cx.Result
	// sarHook, if set, answers a SAR in place of the HSS, unless it returns
	// nil and no error.
	sarHook func(*cx.SAR) (*cx.SAA, error)
	mars    []*cx.MAR
	sars    []*cx.SAR
}

func newFakeHSS() *fakeHSS { return &fakeHSS{subs: map[string]*subscriber{}} }

var errUnreachable = fmt.Errorf("fake HSS: %w", cxclient.ErrNoPeer)

func (f *fakeHSS) add(s *subscriber) { f.mu.Lock(); f.subs[s.impi] = s; f.mu.Unlock() }

func (f *fakeHSS) Authenticate(ctx context.Context, r *cx.MAR, schemes []string) (*cx.MAA, error) {
	var maa *cx.MAA
	for _, s := range schemes {
		m := *r
		m.AuthDataItem.Scheme = s
		var err error
		if maa, err = f.MAR(ctx, &m); err != nil || maa.Result != cx.ExperimentalResult(cx.ErrorAuthSchemeNotSupported) {
			return maa, err
		}
	}
	return maa, nil
}

func (f *fakeHSS) MAR(_ context.Context, r *cx.MAR) (*cx.MAA, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := *r
	f.mars = append(f.mars, &cp)
	if f.unavailable {
		return nil, errUnreachable
	}
	s := f.subs[r.UserName]
	if s == nil || !slicesContains(s.set, r.PublicIdentity) {
		return &cx.MAA{Answer: cx.Answer{Result: cx.ExperimentalResult(cx.ErrorUserUnknown)}}, nil
	}
	switch {
	case r.AuthDataItem.Scheme == cx.SchemeDigestAKAv1MD5 && s.aka != nil:
		if auth := r.AuthDataItem.Authorization; len(auth) > 0 {
			ms, err := s.aka.VerifyAUTS([16]byte(auth[:16]), [14]byte(auth[16:]))
			if err == nil {
				s.sqn = milenage.Resynchronise(s.sqn, ms)
			}
		}
		f.rands++
		var rnd [16]byte
		binary.BigEndian.PutUint64(rnd[8:], f.rands)
		var err error
		if s.sqn, err = s.sqn.Next(); err != nil {
			return nil, err
		}
		v := s.aka.Vector(rnd, s.sqn, [2]byte{0x80, 0})
		autn := v.AUTN()
		xres, ck, ik := v.XRES(), v.CK(), v.IK()
		return &cx.MAA{Answer: cx.Answer{Result: cx.ResultCode(2001)}, AuthDataItems: []cx.AuthDataItem{{
			Scheme: cx.SchemeDigestAKAv1MD5, Authenticate: append(rnd[:], autn[:]...),
			Authorization: xres[:], ConfidentialityKey: ck[:], IntegrityKey: ik[:],
		}}}, nil
	case r.AuthDataItem.Scheme == cx.SchemeSIPDigest && s.password != nil:
		md5, _ := digest.ComputeHA1(digest.MD5, s.impi, realm, s.password)
		sha, _ := digest.ComputeHA1(digest.SHA256, s.impi, realm, s.password)
		return &cx.MAA{Answer: cx.Answer{Result: cx.ResultCode(2001)}, AuthDataItems: []cx.AuthDataItem{{
			Scheme: cx.SchemeSIPDigest, Digest: &cx.DigestAuthenticate{
				Realm: realm, Algorithm: "MD5", QoP: "auth", HA1: md5, AlternateAlgorithm: "SHA-256", AlternateHA1: sha,
			},
		}}}, nil
	}
	return &cx.MAA{Answer: cx.Answer{Result: cx.ExperimentalResult(cx.ErrorAuthSchemeNotSupported)}}, nil
}

func (f *fakeHSS) SAR(_ context.Context, r *cx.SAR) (*cx.SAA, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := *r
	f.sars = append(f.sars, &cp)
	if f.unavailable {
		return nil, errUnreachable
	}
	if f.sarResult != nil {
		return &cx.SAA{Answer: cx.Answer{Result: *f.sarResult}}, nil
	}
	if f.sarHook != nil {
		if saa, err := f.sarHook(&cp); saa != nil || err != nil {
			return saa, err
		}
	}
	s := f.subs[r.UserName]
	if s == nil {
		return &cx.SAA{Answer: cx.Answer{Result: cx.ExperimentalResult(cx.ErrorUserUnknown)}}, nil
	}
	saa := &cx.SAA{Answer: cx.Answer{Result: cx.ResultCode(2001)}}
	if r.UserDataAlreadyAvailable != cx.UserDataAlreadyAvailable && (r.AssignmentType == cx.Registration || r.AssignmentType == cx.ReRegistration) {
		saa.UserData = userDataOf(s.impi, s.barred, s.set...)
	}
	return saa, nil
}

func (f *fakeHSS) lastSAR(t *testing.T) *cx.SAR {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sars) == 0 {
		t.Fatal("no SAR was sent")
	}
	return f.sars[len(f.sars)-1]
}

func (f *fakeHSS) counts() (mars, sars int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.mars), len(f.sars)
}

func slicesContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

var testKey = bytes.Repeat([]byte{0x5a}, 32)

// env is one or more registrar instances over one store and HSS.
type env struct {
	t     *testing.T
	clock *clock
	store *state.Memory
	hss   *fakeHSS
	logs  *bytes.Buffer
}

func newEnv(t *testing.T) *env {
	return &env{t: t, clock: &clock{now: t0}, store: state.NewMemory(), hss: newFakeHSS(), logs: &bytes.Buffer{}}
}

// instance returns a registrar, which tweak may configure further.
func (e *env) instance(seed byte, tweak ...func(*Config)) *Registrar {
	e.t.Helper()
	u, err := sip.ParseURI("sip:scscf." + realm)
	if err != nil {
		e.t.Fatal(err)
	}
	cfg := Config{
		Store: e.store, HSS: e.hss, Realm: realm, ServiceRoute: u, NonceKey: testKey,
		Now: e.clock.Now, Rand: newRand(seed), Logger: newTestLogger(e.logs),
	}
	for _, f := range tweak {
		f(&cfg)
	}
	g, err := New(cfg)
	if err != nil {
		e.t.Fatal(err)
	}
	return g
}

// akaUser adds an AKA-only subscriber with set as its implicit registration
// set, and returns its UE.
func (e *env) akaUser(impi string, set ...string) *ue {
	var k, opc [16]byte
	k[0], opc[0] = 0x11, 0x22
	m := milenage.New(k, opc)
	sqn, _ := milenage.NewSQN(32, 0)
	e.hss.add(&subscriber{impi: impi, set: set, aka: &m, sqn: sqn})
	return &ue{t: e.t, impi: impi, impu: set[0], m: &m, callID: "call-" + impi[:15], contact: "sip:ue1@192.0.2.10:5060;transport=tcp"}
}

// digestUser adds a SIP Digest subscriber.
func (e *env) digestUser(impi string, set ...string) *ue {
	pw := []byte("not-a-real-password")
	e.hss.add(&subscriber{impi: impi, set: set, password: pw})
	return &ue{t: e.t, impi: impi, impu: set[0], password: pw, callID: "call-" + impi[:15], contact: "sip:ue1@192.0.2.10:5060;transport=tcp"}
}

// ue is a client that registers the way an IMS UE does (TS 24.229 §5.1.1).
type ue struct {
	t        *testing.T
	impi     string
	impu     string
	m        *milenage.Milenage
	password []byte
	callID   string
	cseq     uint32
	contact  string
	// instance and regID, when set, make the contact an outbound one.
	instance string
	regID    int
	// noAuth leaves out the Authorization field.
	noAuth bool
	// algorithm, if set, is named in the first Authorization.
	algorithm string
}

var upstream = transport.Source{Flow: "pcscf", Network: transport.TCP, Listener: "core"}

// request builds a REGISTER with the given Contact expiry (-1 for none) and
// Authorization value ("" for the empty one of a first REGISTER).
func (u *ue) request(expires int, auth string, extra ...string) *sip.Request {
	u.t.Helper()
	m, err := sip.ParseMessage([]byte(requestText(u, expires, auth, extra...)))
	if err != nil {
		u.t.Fatal(err)
	}
	return m.(*sip.Request)
}

// requestText writes the REGISTER request builds.
func requestText(u *ue, expires int, auth string, extra ...string) string {
	u.cseq++
	var b strings.Builder
	fmt.Fprintf(&b, "REGISTER sip:%s SIP/2.0\r\n", realm)
	fmt.Fprintf(&b, "Via: SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bK-%d\r\n", u.cseq)
	b.WriteString("Max-Forwards: 70\r\n")
	fmt.Fprintf(&b, "From: <%s>;tag=ue%d\r\nTo: <%s>\r\n", u.impu, u.cseq, u.impu)
	fmt.Fprintf(&b, "Call-ID: %s\r\nCSeq: %d REGISTER\r\n", u.callID, u.cseq)
	if u.contact != "" {
		c := "<" + u.contact + ">"
		if expires >= 0 {
			c += fmt.Sprintf(";expires=%d", expires)
		}
		if u.instance != "" {
			c += `;+sip.instance="` + u.instance + `"`
		}
		if u.regID != 0 {
			c += fmt.Sprintf(";reg-id=%d", u.regID)
		}
		c += `;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session"`
		fmt.Fprintf(&b, "Contact: %s\r\n", c)
	}
	b.WriteString("Path: <sip:flow-token@pcscf." + realm + ";lr;ob>\r\n")
	if !u.noAuth {
		if auth == "" {
			auth = fmt.Sprintf(`Digest username="%s", realm="%s", nonce="", uri="sip:%s", response=""`, u.impi, realm, realm)
			if u.algorithm != "" {
				auth += ", algorithm=" + u.algorithm
			}
		}
		fmt.Fprintf(&b, "Authorization: %s\r\n", auth)
	}
	for _, x := range extra {
		b.WriteString(x + "\r\n")
	}
	b.WriteString("Content-Length: 0\r\n\r\n")
	return b.String()
}

// answer returns the Authorization that answers the challenge of res, the
// i-th WWW-Authenticate.
func (u *ue) answer(res *sip.Response, i int) string {
	u.t.Helper()
	return u.respond(u.challengeOf(res, i), nil)
}

func (u *ue) challengeOf(res *sip.Response, i int) digest.Challenge {
	u.t.Helper()
	if res.StatusCode != 401 {
		u.t.Fatalf("got %d %s, want a 401", res.StatusCode, res.Reason)
	}
	vs := res.Header.Values("WWW-Authenticate")
	if i >= len(vs) {
		u.t.Fatalf("401 with %d challenges", len(vs))
	}
	ch, err := digest.ParseChallenge(vs[i])
	if err != nil {
		u.t.Fatal(err)
	}
	return ch
}

// respond computes credentials for ch; with auts set it reports a
// synchronisation failure instead (RFC 3310 §3.4).
func (u *ue) respond(ch digest.Challenge, auts []byte) string {
	u.t.Helper()
	p := digest.ClientParams{Username: u.impi, Method: "REGISTER", URI: "sip:" + realm, CNonce: "0a4f113b", NC: 1, AUTS: auts}
	if ch.Algorithm == digest.AKAv1MD5 {
		rnd, autn, err := digest.ParseAKANonce(ch.Nonce)
		if err != nil {
			u.t.Fatal(err)
		}
		if _, err := u.m.CheckAUTN(rnd, autn); err != nil && auts == nil {
			u.t.Fatalf("the network failed authentication: %v", err)
		}
		res := u.m.F2(rnd)
		p.Password = res[:]
	} else {
		p.Password = u.password
	}
	c, err := digest.Respond(ch, p)
	if err != nil {
		u.t.Fatal(err)
	}
	return c.Header()
}

// registerWith runs the two REGISTERs of an authenticated registration on g
// and returns the final response.
func (u *ue) registerWith(g *Registrar, expires int) *sip.Response {
	u.t.Helper()
	res := g.Register(context.Background(), u.request(expires, ""), upstream)
	if res.StatusCode != 401 {
		return res
	}
	return g.Register(context.Background(), u.request(expires, u.answer(res, 0)), upstream)
}

func wantStatus(t *testing.T, res *sip.Response, code int) {
	t.Helper()
	if res.StatusCode != code {
		t.Fatalf("got %d %s, want %d", res.StatusCode, res.Reason, code)
	}
}

func newTestLogger(w *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(&syncWriter{w: w}, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

type syncWriter struct {
	mu sync.Mutex
	w  *bytes.Buffer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// userDataOf is the IMSSubscription of one implicit registration set.
func userDataOf(impi string, barred map[string]bool, set ...string) []byte {
	sp := ifc.ServiceProfile{}
	for _, id := range set {
		sp.PublicIdentities = append(sp.PublicIdentities, ifc.PublicIdentity{Identity: id, BarringIndication: barred[id]})
	}
	doc, err := (&ifc.Subscription{PrivateID: impi, ServiceProfiles: []ifc.ServiceProfile{sp}}).Marshal()
	if err != nil {
		panic(err)
	}
	return doc
}

// sarsOf returns the assignment types of the SARs sent so far.
func (f *fakeHSS) sarsOf() []cx.ServerAssignmentType {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []cx.ServerAssignmentType
	for _, s := range f.sars {
		out = append(out, s.AssignmentType)
	}
	return out
}
