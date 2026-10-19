package hss

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/hss/keyring"
	"github.com/jeonghun-app/rcs-platform/internal/hss/store"
	"github.com/jeonghun-app/rcs-platform/internal/milenage"
	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
)

// Test identities: MCC 001 / MNC 01 and the fictional +1 555 0100 range
// (.github/allowed-test-identifiers.txt).
const (
	domain    = "ims.mnc001.mcc001.3gppnetwork.org"
	ftRealm   = "ft." + domain
	imsi1     = "001010000000001"
	impi1     = imsi1 + "@" + domain
	impu1     = "sip:+15550100001@" + domain
	tel1      = "tel:+15550100001"
	impi2     = "001010000000002@" + domain
	impu2     = "sip:+15550100002@" + domain
	impi3     = "001010000000003@" + domain
	impu3     = "sip:+15550100003@" + domain
	scscfName = "sip:scscf.rcs.local"
	otherName = "sip:scscf.other.example.org"
	asURI     = "sip:rcs-as.rcs.local"
	password  = "correct horse battery staple"
)

// Milenage test set 1 (TS 35.208 §4.3.1): published keys of no card.
var (
	testK   = mustHex("465b5ce8b199b49faa5f0a2ee238a6bc")
	testOPc = mustHex("cd63cb71954a9f4e48a5994e37a02baf")
	testAMF = [2]byte{0xb9, 0xb9}
)

func mustHex(s string) [16]byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return [16]byte(b)
}

// syncBuffer is a log destination that tests read while handlers write.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func newLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// countingMetrics records counts by name.
type countingMetrics struct {
	mu     sync.Mutex
	counts map[string]int64
}

func (m *countingMetrics) Count(name string, n int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.counts == nil {
		m.counts = map[string]int64{}
	}
	m.counts[name] += n
}

func (m *countingMetrics) Timing(string, time.Duration) {}

func (m *countingMetrics) get(name string) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.counts[name]
}

// env is an HSS over a memory store with the default profile.
type env struct {
	t       *testing.T
	store   store.Store
	keys    *keyring.Keyring
	h       *HSS
	logs    *syncBuffer
	metrics *countingMetrics
}

func newEnv(t *testing.T) *env {
	t.Helper()
	return newEnvWith(t, store.NewMemory())
}

func newEnvWith(t *testing.T, st store.Store) *env {
	t.Helper()
	keys, err := keyring.NewLocal(bytes.Repeat([]byte{0x42}, keyring.DataKeySize), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, store: st, keys: keys, logs: &syncBuffer{}, metrics: &countingMetrics{}}
	e.h = e.newHSS(nil)
	if err := ensureProfile(context.Background(), st, DefaultRCSProfile(DefaultProfileID, asURI)); err != nil {
		t.Fatal(err)
	}
	return e
}

// newHSS returns another HSS over the same store and keys: a second task.
func (e *env) newHSS(mutate func(*Options)) *HSS {
	o := Options{
		Store: e.store, Keys: e.keys, IMSRealm: domain, FTRealm: ftRealm, ServerNames: []string{scscfName},
		Rand: rand.Reader, Logger: newLogger(e.logs), Metrics: e.metrics,
	}
	if mutate != nil {
		mutate(&o)
	}
	h, err := New(o)
	if err != nil {
		e.t.Fatal(err)
	}
	return h
}

// provision creates a subscription of impi with the IMPUs in implicit set 0,
// AKA keys and an IMS Digest credential.
func (e *env) provision(impi string, impus ...string) *store.Subscription {
	e.t.Helper()
	s := &store.Subscription{IMPI: impi, Profile: DefaultProfileID}
	for _, impu := range impus {
		s.PublicIdentities = append(s.PublicIdentities, store.PublicIdentity{IMPU: impu})
	}
	aka, err := e.h.sealAKA(impi, testK, testOPc, testAMF, 0)
	if err != nil {
		e.t.Fatal(err)
	}
	s.AKA = aka
	d, err := e.h.sealDigest(impi, domain, []byte(password))
	if err != nil {
		e.t.Fatal(err)
	}
	s.Digest = []store.DigestCredential{d}
	saved, err := e.store.CreateSubscription(context.Background(), s)
	if err != nil {
		e.t.Fatal(err)
	}
	return saved
}

func (e *env) sub(impi string) *store.Subscription {
	e.t.Helper()
	s, err := e.store.Subscription(context.Background(), impi)
	if err != nil {
		e.t.Fatal(err)
	}
	return s
}

// modify changes a stored subscription directly, for test setup.
func (e *env) modify(impi string, fn func(*store.Subscription)) {
	e.t.Helper()
	cur := e.sub(impi)
	next := clone(cur)
	fn(next)
	if _, err := e.store.UpdateSubscription(context.Background(), cur, next); err != nil {
		e.t.Fatal(err)
	}
}

// pipeListener hands one end of a net.Pipe to Node.Serve per dial.
type pipeListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newPipeListener() *pipeListener {
	return &pipeListener{conns: make(chan net.Conn), closed: make(chan struct{})}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *pipeListener) Addr() net.Addr { return &net.TCPAddr{} }

func (l *pipeListener) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	client, server := net.Pipe()
	select {
	case l.conns <- server:
		return client, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// realWait guards against hangs; no protocol timer depends on it.
const realWait = 10 * time.Second

func nodeConfig(t *testing.T, host string, dial func(context.Context, string, string) (net.Conn, error)) diameter.Config {
	dict, err := diameter.NewDictionary(cx.AVPs...)
	if err != nil {
		t.Fatal(err)
	}
	return diameter.Config{
		OriginHost:         host,
		OriginRealm:        domain,
		HostIPAddresses:    []netip.Addr{netip.MustParseAddr("192.0.2.1")},
		Applications:       []diameter.Application{cx.Application},
		SupportedVendorIDs: []uint32{cx.Vendor3GPP, cx.VendorETSI},
		Dictionary:         dict,
		Accept:             []diameter.PeerRule{{Realm: domain}},
		Dial:               dial,
		Logger:             slog.New(slog.DiscardHandler),
	}
}

// hssNode is an HSS task serving Cx on an in-process listener.
type hssNode struct {
	node *diameter.Node
	ln   *pipeListener
}

func serveHSS(t *testing.T, h *HSS, host string) *hssNode {
	t.Helper()
	return serveHSSWith(t, h, host, 0)
}

// serveHSSWith is serveHSS with a Cx timeout.
func serveHSSWith(t *testing.T, h *HSS, host string, timeout time.Duration) *hssNode {
	t.Helper()
	ln := newPipeListener()
	n, err := diameter.NewNode(nodeConfig(t, host, nil))
	if err != nil {
		t.Fatal(err)
	}
	h.ServeCx(n, timeout)
	go func() { _ = n.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), realWait)
		defer cancel()
		_ = n.Shutdown(ctx)
		_ = ln.Close()
	})
	return &hssNode{node: n, ln: ln}
}

// cscf is a Diameter client of an HSS task: an icscf or scscf. It records
// the RTRs and PPRs it receives.
type cscf struct {
	t    *testing.T
	node *diameter.Node
	peer *diameter.Peer

	mu    sync.Mutex
	rtrs  []*cx.RTR
	pprs  []*cx.PPR
	flags []diameter.CommandFlags
	// answer is the result the cscf answers RTR and PPR with; busy makes it
	// answer DIAMETER_TOO_BUSY instead.
	answer cx.Result
	busy   bool
}

func (c *cscf) setAnswer(r cx.Result) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.answer = r
}

func (c *cscf) setBusy(b bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.busy = b
}

func connectCSCF(t *testing.T, to *hssNode, host string) *cscf {
	t.Helper()
	c := &cscf{t: t, answer: success()}
	n, err := diameter.NewNode(nodeConfig(t, host, to.ln.dial))
	if err != nil {
		t.Fatal(err)
	}
	c.node = n
	n.HandleFunc(cx.ApplicationID, cx.CodeRegistrationTermination, func(_ context.Context, _ *diameter.Peer, req *diameter.Message) (*diameter.Message, error) {
		r, err := cx.ParseRTR(req)
		if err != nil {
			return nil, err
		}
		c.mu.Lock()
		c.rtrs = append(c.rtrs, r)
		c.flags = append(c.flags, req.Flags)
		res, busy := c.answer, c.busy
		c.mu.Unlock()
		if busy {
			return nil, &diameter.Error{ResultCode: diameter.ResultTooBusy}
		}
		return (&cx.RTA{Answer: cx.Answer{Result: res}}).Message(n, req)
	})
	n.HandleFunc(cx.ApplicationID, cx.CodePushProfile, func(_ context.Context, _ *diameter.Peer, req *diameter.Message) (*diameter.Message, error) {
		r, err := cx.ParsePPR(req)
		if err != nil {
			return nil, err
		}
		c.mu.Lock()
		c.pprs = append(c.pprs, r)
		c.flags = append(c.flags, req.Flags)
		res, busy := c.answer, c.busy
		c.mu.Unlock()
		if busy {
			return nil, &diameter.Error{ResultCode: diameter.ResultTooBusy}
		}
		return (&cx.PPA{Answer: cx.Answer{Result: res}}).Message(n, req)
	})
	peer, err := n.Connect(diameter.PeerConfig{Address: "hss:3868"})
	if err != nil {
		t.Fatal(err)
	}
	c.peer = peer
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), realWait)
		defer cancel()
		_ = n.Shutdown(ctx)
	})
	deadline := time.Now().Add(realWait)
	for !peer.Available() {
		if time.Now().After(deadline) {
			t.Fatal("capabilities exchange did not complete")
		}
		time.Sleep(time.Millisecond)
	}
	// The HSS side must see the peer too before it can push to it.
	for len(to.node.Peers()) == 0 || !to.node.Peers()[0].Available() {
		if time.Now().After(deadline) {
			t.Fatal("the HSS does not see the peer")
		}
		time.Sleep(time.Millisecond)
	}
	return c
}

func (c *cscf) received() ([]*cx.RTR, []*cx.PPR) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*cx.RTR(nil), c.rtrs...), append([]*cx.PPR(nil), c.pprs...)
}

func (c *cscf) send(m *diameter.Message, err error) *diameter.Message {
	c.t.Helper()
	if err != nil {
		c.t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), realWait)
	defer cancel()
	ans, err := c.peer.Send(ctx, m)
	if err != nil {
		c.t.Fatal(err)
	}
	return ans
}

func (c *cscf) uar(impi, impu string, typ cx.UserAuthorizationType) *cx.UAA {
	c.t.Helper()
	r := &cx.UAR{Request: cx.Request{DestinationRealm: domain}, UserName: impi, PublicIdentity: impu,
		VisitedNetworkIdentifier: []byte(domain), AuthorizationType: typ}
	a, err := cx.ParseUAA(c.send(r.Message(c.node)))
	if err != nil {
		c.t.Fatal(err)
	}
	return a
}

func (c *cscf) mar(impi, impu, scheme string, n uint32, server string, authorization []byte) *cx.MAA {
	c.t.Helper()
	r := &cx.MAR{Request: cx.Request{DestinationRealm: domain}, UserName: impi, PublicIdentity: impu,
		AuthDataItem: cx.AuthDataItem{Scheme: scheme, Authorization: authorization}, NumberAuthItems: n, ServerName: server}
	a, err := cx.ParseMAA(c.send(r.Message(c.node)))
	if err != nil {
		c.t.Fatal(err)
	}
	return a
}

func (c *cscf) sar(impi string, impus []string, typ cx.ServerAssignmentType, server string) *cx.SAA {
	c.t.Helper()
	r := &cx.SAR{Request: cx.Request{DestinationRealm: domain}, UserName: impi, PublicIdentities: impus,
		ServerName: server, AssignmentType: typ}
	a, err := cx.ParseSAA(c.send(r.Message(c.node)))
	if err != nil {
		c.t.Fatal(err)
	}
	return a
}

func (c *cscf) lir(impu string, originating bool) *cx.LIA {
	c.t.Helper()
	r := &cx.LIR{Request: cx.Request{DestinationRealm: domain}, PublicIdentity: impu, OriginatingRequest: originating}
	a, err := cx.ParseLIA(c.send(r.Message(c.node)))
	if err != nil {
		c.t.Fatal(err)
	}
	return a
}

// sqnOf recovers the SQN from the AUTN of an AKA item, as the card does.
func sqnOf(t *testing.T, item cx.AuthDataItem) milenage.SQN {
	t.Helper()
	sqn, err := sqnFrom(item)
	if err != nil {
		t.Fatal(err)
	}
	return sqn
}

// sqnFrom is sqnOf for goroutines, which must not call t.Fatal.
func sqnFrom(item cx.AuthDataItem) (milenage.SQN, error) {
	if len(item.Authenticate) != 32 {
		return 0, fmt.Errorf("SIP-Authenticate is %d bytes", len(item.Authenticate))
	}
	m := milenage.New(testK, testOPc)
	sqn, err := m.CheckAUTN([16]byte(item.Authenticate[:16]), [16]byte(item.Authenticate[16:]))
	if err != nil {
		return 0, fmt.Errorf("AUTN does not verify with the subscriber's keys: %w", err)
	}
	return sqn, nil
}

func ha1(t *testing.T, alg digest.Algorithm, user, realm string) string {
	t.Helper()
	v, err := digest.ComputeHA1(alg, user, realm, []byte(password))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// secretsIn lists what must never appear in a log line or an API response
// other than the one that carries it by design.
func secretsIn() []string {
	return []string{hex.EncodeToString(testK[:]), hex.EncodeToString(testOPc[:]), password}
}

func assertNoSecrets(t *testing.T, where, s string, extra ...string) {
	t.Helper()
	for _, secret := range append(secretsIn(), extra...) {
		if secret != "" && strings.Contains(strings.ToLower(s), strings.ToLower(secret)) {
			t.Errorf("%s contains a secret", where)
		}
	}
}

// failingStore fails every call once fail is set, with an error that names
// a subscriber, as an SDK error might.
type failingStore struct {
	store.Store
	fail atomic.Bool
}

func (f *failingStore) err() error {
	if f.fail.Load() {
		return errors.New("store unavailable while reading " + impi1)
	}
	return nil
}

func (f *failingStore) Subscription(ctx context.Context, impi string) (*store.Subscription, error) {
	if err := f.err(); err != nil {
		return nil, err
	}
	return f.Store.Subscription(ctx, impi)
}

func (f *failingStore) SubscriptionByIMPU(ctx context.Context, impu string) (*store.Subscription, error) {
	if err := f.err(); err != nil {
		return nil, err
	}
	return f.Store.SubscriptionByIMPU(ctx, impu)
}

func (f *failingStore) CreateSubscription(ctx context.Context, s *store.Subscription) (*store.Subscription, error) {
	if err := f.err(); err != nil {
		return nil, err
	}
	return f.Store.CreateSubscription(ctx, s)
}

func (f *failingStore) UpdateSubscription(ctx context.Context, old, s *store.Subscription) (*store.Subscription, error) {
	if err := f.err(); err != nil {
		return nil, err
	}
	return f.Store.UpdateSubscription(ctx, old, s)
}

func (f *failingStore) DeleteSubscription(ctx context.Context, s *store.Subscription) error {
	if err := f.err(); err != nil {
		return err
	}
	return f.Store.DeleteSubscription(ctx, s)
}

func (f *failingStore) Profile(ctx context.Context, id string) (*store.ServiceProfile, error) {
	if err := f.err(); err != nil {
		return nil, err
	}
	return f.Store.Profile(ctx, id)
}

func (f *failingStore) CreateProfile(ctx context.Context, p *store.ServiceProfile) (*store.ServiceProfile, error) {
	if err := f.err(); err != nil {
		return nil, err
	}
	return f.Store.CreateProfile(ctx, p)
}
