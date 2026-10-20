package registrar

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/regevent"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
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

// troubledStore fails the next listings of subscriptions and deletes of a
// record, and every NextNotify while dead: an instance that stops before
// it numbers a NOTIFY.
type troubledStore struct {
	state.Store
	mu                  sync.Mutex
	listFails, delFails int
	dead                bool
}

func (s *troubledStore) failing(n *int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if *n > 0 {
		*n--
		return true
	}
	return false
}

func (s *troubledStore) SubscriptionsOf(ctx context.Context, impu string) ([]*state.Subscription, error) {
	if s.failing(&s.listFails) {
		return nil, errors.New("throttled")
	}
	return s.Store.SubscriptionsOf(ctx, impu)
}

func (s *troubledStore) DeleteRegistration(ctx context.Context, r *state.Registration) error {
	if s.failing(&s.delFails) {
		return errors.New("throttled")
	}
	return s.Store.DeleteRegistration(ctx, r)
}

func (s *troubledStore) NextNotify(ctx context.Context, id string, of int64) (uint32, uint32, error) {
	s.mu.Lock()
	dead := s.dead
	s.mu.Unlock()
	if dead {
		return 0, 0, errors.New("the instance has stopped")
	}
	return s.Store.NextNotify(ctx, id, of)
}

// TestAnRTRsEndOutlivesAStoreFailureAndAStop: the listing of the
// subscriptions fails once, the instance saves their ends and stops before
// it sends a NOTIFY or deletes the record; after a restart the sweep sends
// each subscriber its terminated NOTIFY once, and the HSS's next RTR
// finishes (#256 code review).
func TestAnRTRsEndOutlivesAStoreFailureAndAStop(t *testing.T) {
	e := newEnv(t)
	g, n, s := withNotifier(t, e)
	registered(t, e, g, 600, impu1)
	n.Wait()
	subscribeAsPCSCF(t, n)
	subscribeAsPCSCF(t, n)
	k := s.count()

	ts := &troubledStore{Store: e.store, listFails: 1, delFails: 1, dead: true}
	u, _ := sip.ParseURI("sip:scscf." + realm)
	stopped, err := regevent.New(regevent.Config{Store: ts, Sender: &notifySender{}, Contact: u, Now: e.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	doomed := e.instance(2, func(c *Config) { c.Store, c.Events = ts, stopped })
	rtr := &cx.RTR{UserName: impi1, DeregistrationReason: cx.DeregistrationReason{Code: cx.PermanentTermination}}
	if res := doomed.HandleRTR(bg, rtr); res == resultSuccess {
		t.Fatal("the RTR succeeded though the record's delete failed")
	}
	stopped.Wait()
	if s.count() != k {
		t.Fatal("a NOTIFY went before the restart")
	}

	ends := func() (all, rejected int) {
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, req := range s.sent[k:] {
			all++
			if ss, _ := req.Header.SubscriptionState(); ss.State == "terminated" {
				if r, _ := ss.Params.Get("reason"); r == "rejected" {
					rejected++
				}
			}
		}
		return all, rejected
	}
	// The ends were saved: the sweep sends them, without the HSS's retry.
	e.clock.advance(10 * time.Second)
	if _, err := n.Sweep(bg, 10); err != nil {
		t.Fatal(err)
	}
	if all, rejected := ends(); all != 2 || rejected != 2 {
		t.Errorf("after the sweep: %d NOTIFYs, %d terminated;reason=rejected; want one for each of the two subscriptions", all, rejected)
	}
	// The HSS's retry finishes the RTR, and tells no one again.
	wantResult(t, g.HandleRTR(bg, rtr), resultSuccess)
	n.Wait()
	if all, _ := ends(); all != 2 {
		t.Errorf("%d NOTIFYs after the retried RTR", all)
	}
	if _, err := regOf(e, impu1); err == nil {
		t.Error("the record outlived the retried RTR")
	}
	if subs, _ := e.store.SubscriptionsOf(bg, impu1); len(subs) != 0 {
		t.Errorf("%d subscriptions left", len(subs))
	}
}
