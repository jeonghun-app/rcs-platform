package regevent

import (
	"context"
	"fmt"
	"math/rand/v2"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/reginfo"
)

const (
	realm = "ims.mnc001.mcc001.3gppnetwork.org"
	impi1 = "001010000000001@" + realm
	impu1 = "sip:+15550100001@" + realm
	tel1  = "tel:+15550100001"
	impu2 = "sip:+15550100002@" + realm
	// pcscfPath is the Path the P-CSCF put on the UE's binding, and so its
	// P-Asserted-Identity when it subscribes (TS 24.229 §5.2.3).
	pcscfPath = "sip:term@pcscf." + realm + ";lr"
)

var (
	bg   = context.Background()
	t0   = time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	set1 = state.SetKey{IMPI: impi1, IMPU: impu1}
)

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

// sender records the NOTIFYs and answers them with status, or err.
type sender struct {
	mu     sync.Mutex
	sent   []*sip.Request
	status int
	err    error
}

func (s *sender) Send(_ context.Context, req *sip.Request) (*sip.Response, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, req)
	if s.err != nil {
		return nil, s.err
	}
	code := s.status
	if code == 0 {
		code = 200
	}
	return sip.NewResponse(req, code, "", "subscriber")
}

func (s *sender) notifies() []*sip.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*sip.Request(nil), s.sent...)
}

type env struct {
	t     *testing.T
	store *state.Memory
	clock *clock
	send  *sender
}

func newEnv(t *testing.T) *env {
	return &env{t: t, store: state.NewMemory(), clock: &clock{now: t0}, send: &sender{}}
}

func (e *env) notifier(seed uint64) *Notifier {
	e.t.Helper()
	u, err := sip.ParseURI("sip:scscf." + realm)
	if err != nil {
		e.t.Fatal(err)
	}
	n, err := New(Config{Store: e.store, Sender: e.send, Contact: u, Now: e.clock.Now, Rand: rand.NewChaCha8([32]byte{byte(seed)})})
	if err != nil {
		e.t.Fatal(err)
	}
	return n
}

// binding is a binding of the UE over the P-CSCF's flow.
func binding(n int, expires time.Duration) state.Contact {
	return state.Contact{
		URI:        fmt.Sprintf("sip:ue%d@192.0.2.%d:5060;transport=tcp", n, 10+n),
		InstanceID: fmt.Sprintf("<urn:uuid:00000000-0000-0000-0000-00000000000%d>", n),
		RegID:      1, Path: []string{"<" + pcscfPath + ">"}, Expires: t0.Add(expires),
		CallID: fmt.Sprintf("call-%d", n), CSeq: uint32(10 + n), FlowToken: "term",
	}
}

// registered stores impi1's set {impu1, tel1, impu2 barred} with contacts,
// every identity pointing at it.
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

// saved saves set, a change of a stored record, and returns it as stored.
func (e *env) saved(set *state.Registration) *state.Registration {
	e.t.Helper()
	s, err := e.store.SaveRegistration(bg, set)
	if err != nil {
		e.t.Fatal(err)
	}
	return s
}

// subscribe is an initial SUBSCRIBE for target from pai.
func subscribe(t *testing.T, target, pai string, expires int, extra ...string) *sip.Request {
	t.Helper()
	fields := []string{
		"SUBSCRIBE " + target + " SIP/2.0",
		"Via: SIP/2.0/TCP pcscf." + realm + ";branch=z9hG4bK-sub",
		"Max-Forwards: 70",
		"From: <sip:pcscf." + realm + ">;tag=pcscf-tag",
		"To: <" + target + ">",
		"Call-ID: sub-call-1",
		"CSeq: 1 SUBSCRIBE",
		"Contact: <sip:pcscf." + realm + ":5060;transport=tcp>",
		// The P-CSCF the bindings came over records the route, as it does
		// for a UE's SUBSCRIBE; its NOTIFYs go there first.
		"Record-Route: <sip:pcscf." + realm + ";lr>",
		"Event: reg",
		"P-Asserted-Identity: <" + pai + ">",
	}
	if expires >= 0 {
		fields = append(fields, fmt.Sprintf("Expires: %d", expires))
	}
	fields = append(fields, extra...)
	return parse(t, strings.Join(fields, "\r\n")+"\r\nContent-Length: 0\r\n\r\n")
}

// inDialog is a SUBSCRIBE in the dialog the 200 res set up.
func inDialog(t *testing.T, res *sip.Response, target, pai string, cseq, expires int) *sip.Request {
	t.Helper()
	to, err := res.Header.To()
	if err != nil {
		t.Fatal(err)
	}
	return parse(t, strings.Join([]string{
		"SUBSCRIBE " + target + " SIP/2.0",
		"Via: SIP/2.0/TCP pcscf." + realm + ";branch=z9hG4bK-sub" + fmt.Sprint(cseq),
		"Max-Forwards: 70",
		"From: <sip:pcscf." + realm + ">;tag=pcscf-tag",
		"To: " + to.String(),
		"Call-ID: sub-call-1",
		fmt.Sprintf("CSeq: %d SUBSCRIBE", cseq),
		"Event: reg",
		"P-Asserted-Identity: <" + pai + ">",
		fmt.Sprintf("Expires: %d", expires),
	}, "\r\n")+"\r\nContent-Length: 0\r\n\r\n")
}

func parse(t *testing.T, text string) *sip.Request {
	t.Helper()
	m, err := sip.ParseMessage([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return m.(*sip.Request)
}

func wantStatus(t *testing.T, res *sip.Response, code int) {
	t.Helper()
	if res.StatusCode != code {
		t.Fatalf("got %d %s, want %d", res.StatusCode, res.Reason, code)
	}
}

// info is the reginfo of a NOTIFY, with its CSeq and Subscription-State.
func info(t *testing.T, req *sip.Request) (*reginfo.Info, uint32, sip.SubscriptionState) {
	t.Helper()
	cseq, err := req.Header.CSeq()
	if err != nil {
		t.Fatal(err)
	}
	ss, err := req.Header.SubscriptionState()
	if err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("Content-Type") != reginfo.ContentType || req.Header.Get("Event") != "reg" {
		t.Errorf("NOTIFY Content-Type %q, Event %q", req.Header.Get("Content-Type"), req.Header.Get("Event"))
	}
	doc, err := reginfo.Parse(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	return doc, cseq.Seq, ss
}

// subscribed has the P-CSCF subscribe to impu1 and returns the 200 and the
// first NOTIFY.
func (e *env) subscribed(n *Notifier) (*sip.Response, *sip.Request) {
	e.t.Helper()
	res, after := n.Subscribe(bg, subscribe(e.t, impu1, pcscfPath, 600000))
	wantStatus(e.t, res, 200)
	before := len(e.send.notifies())
	after(bg)
	got := e.send.notifies()
	if len(got) != before+1 {
		e.t.Fatalf("%d NOTIFYs after the 200", len(got)-before)
	}
	return res, got[len(got)-1]
}
