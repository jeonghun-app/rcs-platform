package registrar

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/regevent"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// notifySender records the NOTIFYs a notifier sends, and answers them 200.
type notifySender struct {
	mu   sync.Mutex
	sent []*sip.Request
}

func (s *notifySender) Send(_ context.Context, req *sip.Request) (*sip.Response, error) {
	s.mu.Lock()
	s.sent = append(s.sent, req)
	s.mu.Unlock()
	return sip.NewResponse(req, 200, "", "sub")
}

func (s *notifySender) count() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.sent) }

// pcscfFlowPath is the Path the harness's P-CSCF puts on a binding.
const pcscfFlowPath = "sip:flow-token@pcscf." + realm + ";lr;ob"

// subscribeAsPCSCF has the P-CSCF subscribe to impu1 on n.
func subscribeAsPCSCF(t *testing.T, n *regevent.Notifier) {
	t.Helper()
	text := strings.Join([]string{
		"SUBSCRIBE " + impu1 + " SIP/2.0",
		"Via: SIP/2.0/TCP pcscf." + realm + ";branch=z9hG4bK-sub",
		"Max-Forwards: 70",
		"From: <sip:pcscf." + realm + ">;tag=pcscf-tag",
		"To: <" + impu1 + ">",
		"Call-ID: sub-call-1", "CSeq: 1 SUBSCRIBE",
		"Contact: <sip:pcscf." + realm + ":5060;transport=tcp>",
		"Event: reg", "P-Asserted-Identity: <" + pcscfFlowPath + ">", "Expires: 600000",
	}, "\r\n") + "\r\nContent-Length: 0\r\n\r\n"
	m, err := sip.ParseMessage([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	res, after := n.Subscribe(bg, m.(*sip.Request))
	wantStatus(t, res, 200)
	after(bg)
}

// withNotifier is instance 1 with a reg event notifier over the same store.
func withNotifier(t *testing.T, e *env) (*Registrar, *regevent.Notifier, *notifySender) {
	t.Helper()
	s := &notifySender{}
	u, _ := sip.ParseURI("sip:scscf." + realm)
	n, err := regevent.New(regevent.Config{Store: e.store, Sender: s, Contact: u, Now: e.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	return e.instance(1, func(c *Config) { c.Events = n }), n, s
}

// TestAnExpiryInAReassertingSweepIsNotified: one binding expires in the
// sweep that reasserts the set, and its subscriber hears of it (QA's m2 on
// #256).
func TestAnExpiryInAReassertingSweepIsNotified(t *testing.T) {
	e := newEnv(t)
	g, n, s := withNotifier(t, e)
	u := registered(t, e, g, 600, impu1, tel1)
	wantStatus(t, device(u, 2).registerWith(g, 1200), 200)
	n.Wait()
	subscribeAsPCSCF(t, n)
	reg, err := regOf(e, impu1)
	if err != nil {
		t.Fatal(err)
	}
	next := reg.Clone()
	next.Reassert = e.clock.Now().Add(300 * time.Second)
	must(e.store.SaveRegistration(bg, next))(t)
	k := s.count()
	e.clock.advance(601 * time.Second)
	if _, err := g.Sweep(bg, 10); err != nil {
		t.Fatal(err)
	}
	n.Wait()
	cur, _ := regOf(e, impu1)
	if len(cur.Contacts) != 1 || s.count() != k+1 {
		t.Errorf("contacts left %d, NOTIFYs after the sweep %d: want 1 and 1", len(cur.Contacts), s.count()-k)
	}
}
