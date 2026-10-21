package routing

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/registrar"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
)

// Test identities: MCC 001 / MNC 01 and the fictional +1 555 0100 range
// (.github/allowed-test-identifiers.txt).
const (
	realm = "ims.mnc001.mcc001.3gppnetwork.org"
	impi1 = "001010000000001@" + realm
	impu1 = "sip:+15550100001@" + realm
	tel1  = "tel:+15550100001"
	impu2 = "sip:+15550100002@" + realm
)

var (
	bg   = context.Background()
	t0   = time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	set1 = state.SetKey{IMPI: impi1, IMPU: impu1}
)

// flow is the flow token of P-CSCF flow n: 16 bytes in URL-safe base64, as
// transport.FlowID writes them.
func flow(n int) string {
	var b [16]byte
	b[0] = byte(n)
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// pathOf is the Path pcscf writes for flow n.
func pathOf(n int) string {
	return fmt.Sprintf("<sip:%s@198.51.100.5:5070;transport=tcp;lr;ob>", flow(n))
}

// binding is binding n, of instance inst (none if 0), over flow n, expiring
// exp after t0.
func binding(n, inst int, exp time.Duration, tags ...string) state.Contact {
	c := state.Contact{
		URI: fmt.Sprintf("sip:ue%d@192.0.2.%d:5060;transport=tcp", n, 10+n), Q: 1000,
		Path: []string{pathOf(n)}, Expires: t0.Add(exp), CallID: fmt.Sprintf("call-%d", n), CSeq: 1,
		FeatureTags: tags,
	}
	if inst != 0 {
		c.InstanceID = fmt.Sprintf("<urn:uuid:00000000-0000-0000-0000-00000000000%d>", inst)
		c.RegID = uint32(n)
		c.FlowToken = flow(n)
	}
	return c
}

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
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// counts records the router's counters.
type counts struct {
	mu sync.Mutex
	m  map[string]int64
}

func (c *counts) Count(name string, n int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]int64{}
	}
	c.m[name] += n
}

func (c *counts) get(name string) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m[name]
}

type env struct {
	t       testing.TB
	store   *state.Memory
	clock   *clock
	metrics *counts
	hss     *fakeRegistrar
}

func newEnv(t *testing.T) *env {
	return &env{t: t, store: state.NewMemory(), clock: &clock{now: t0}, metrics: &counts{}, hss: &fakeRegistrar{}}
}

// fakeRegistrar stands in for the registrar's SAR UNREGISTERED_USER: the
// HSS knows no one unless serve says otherwise.
type fakeRegistrar struct {
	mu    sync.Mutex
	serve func(impu string) (*state.Registration, error)
	asked []string
}

func (f *fakeRegistrar) Unregistered(_ context.Context, impu string) (*state.Registration, error) {
	f.mu.Lock()
	f.asked = append(f.asked, impu)
	serve := f.serve
	f.mu.Unlock()
	if serve == nil {
		return nil, registrar.ErrUnknownUser
	}
	return serve(impu)
}

func (f *fakeRegistrar) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.asked)
}

// dialogKey signs the routers' Record-Route values; asURI is rcs-as's
// listener.
var (
	dialogKey = bytes.Repeat([]byte{0x5d}, MinDialogKeyBytes)
	asURI     = mustURI("sip:rcs-as.rcs.local:5060;transport=tcp")
)

func mustURI(s string) sip.URI {
	u, err := sip.ParseURI(s)
	if err != nil {
		panic(err)
	}
	return u
}

func (e *env) router(st state.Store, tweak ...func(*Config)) *Router {
	e.t.Helper()
	if st == nil {
		st = e.store
	}
	self, _ := sip.ParseURI("sip:scscf.rcs.local")
	rr, _ := sip.ParseAddress("<sip:scscf.rcs.local;transport=tcp;lr>")
	icscf, _ := sip.ParseURI("sip:icscf.rcs.local;lr")
	cfg := Config{
		Store: st, RecordRoute: rr, Self: []sip.URI{self}, Now: e.clock.Now, Metrics: e.metrics,
		Registrar: e.hss, ICSCF: icscf, HomeDomain: realm,
		DialogKeys:           []DialogKey{{ID: "k2", Key: dialogKey}},
		ApplicationServers:   []sip.URI{asURI},
		EdgeProxyPublicHosts: []string{"pcscf.example.net", "203.0.113.5"},
	}
	for _, f := range tweak {
		f(&cfg)
	}
	rt, err := New(cfg)
	if err != nil {
		e.t.Fatal(err)
	}
	return rt
}

// registered stores impi1's set {impu1, tel1, impu2 barred} with contacts,
// every identity pointing at incarnation 7.
func (e *env) registered(contacts ...state.Contact) *state.Registration {
	e.t.Helper()
	r := &state.Registration{
		Key: set1, Incarnation: 7, Contacts: contacts,
		Identities: []state.SetIdentity{{IMPU: impu1}, {IMPU: tel1}, {IMPU: impu2, Barred: true}},
	}
	saved, err := e.store.SaveRegistration(bg, r)
	if err != nil {
		e.t.Fatal(err)
	}
	for _, id := range r.Identities {
		if _, err := e.store.SaveIdentity(bg, &state.Identity{IMPU: id.IMPU, Set: set1, Incarnation: 7, Barred: id.Barred, KeepUntil: t0.Add(48 * time.Hour)}, t0); err != nil {
			e.t.Fatal(err)
		}
	}
	return saved
}

// request is an initial request for target, with extra header fields.
func request(t *testing.T, method, target string, extra ...string) *proxy.Request {
	t.Helper()
	fields := []string{
		method + " " + target + " SIP/2.0",
		"Via: SIP/2.0/TCP icscf.rcs.local;branch=z9hG4bK-term",
		"Max-Forwards: 69",
		"From: <sip:+15550100003@" + realm + ">;tag=caller",
		"To: <" + target + ">",
		"Call-ID: term-call-1",
		"CSeq: 1 " + method,
	}
	fields = append(fields, extra...)
	return &proxy.Request{Message: parse(t, strings.Join(fields, "\r\n")+"\r\nContent-Length: 0\r\n\r\n")}
}

// tryRequest is request for impu1 with extra header fields, if it parses.
func tryRequest(extra []string) (*sip.Request, bool) {
	fields := append([]string{
		"INVITE " + impu1 + " SIP/2.0",
		"Via: SIP/2.0/TCP icscf.rcs.local;branch=z9hG4bK-term",
		"Max-Forwards: 69",
		"From: <sip:+15550100003@" + realm + ">;tag=caller",
		"To: <" + impu1 + ">",
		"Call-ID: term-call-1",
		"CSeq: 1 INVITE",
	}, extra...)
	m, err := sip.ParseMessage([]byte(strings.Join(fields, "\r\n") + "\r\nContent-Length: 0\r\n\r\n"))
	if err != nil {
		return nil, false
	}
	r, ok := m.(*sip.Request)
	return r, ok
}

func parse(t *testing.T, text string) *sip.Request {
	t.Helper()
	m, err := sip.ParseMessage([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return m.(*sip.Request)
}

// uris are the Request-URIs of ts.
func uris(ts []proxy.Target) []string {
	var out []string
	for _, t := range ts {
		out = append(out, t.URI.String())
	}
	return out
}
