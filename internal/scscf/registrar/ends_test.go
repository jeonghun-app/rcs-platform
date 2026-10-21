package registrar

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/regevent"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// crashStore is instance 1's view of the store: listing tel1's
// subscriptions fails, and NextNotify (or Send, see crashSender) does not
// return until the test ends, as an instance that stopped.
type crashStore struct {
	*state.Memory
	failList string
	blockNum bool
	stopped  chan struct{}
}

var errThrottled = errors.New("qa: throttled")

func (c *crashStore) SubscriptionsOf(ctx context.Context, impu string) ([]*state.Subscription, error) {
	if impu == c.failList {
		return nil, errThrottled
	}
	return c.Memory.SubscriptionsOf(ctx, impu)
}

func (c *crashStore) NextNotify(ctx context.Context, id string, of int64) (uint32, uint32, error) {
	if c.blockNum {
		<-c.stopped // the instance stopped here
		return 0, 0, errors.New("stopped")
	}
	return c.Memory.NextNotify(ctx, id, of)
}

type crashSender struct{ stopped chan struct{} }

func (c crashSender) Send(context.Context, *sip.Request) (*sip.Response, error) {
	<-c.stopped
	return nil, errors.New("stopped")
}

type recSender struct {
	mu   sync.Mutex
	sent []*sip.Request
}

func (s *recSender) Send(_ context.Context, req *sip.Request) (*sip.Response, error) {
	s.mu.Lock()
	s.sent = append(s.sent, req)
	s.mu.Unlock()
	return sip.NewResponse(req, 200, "", "sub")
}

func (s *recSender) finals() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]string{}
	for _, r := range s.sent {
		ss, _ := r.Header.SubscriptionState()
		if ss.State == "terminated" {
			why, _ := ss.Params.Get("reason")
			out[r.Header.Get("Call-ID")] += why + ";"
		}
	}
	return out
}

func notifierOn(t *testing.T, e *env, st state.Store, s regevent.Sender) *regevent.Notifier {
	u, _ := sip.ParseURI("sip:scscf." + realm)
	n, err := regevent.New(regevent.Config{Store: st, Sender: s, Contact: u, Now: e.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func subReq(t *testing.T, target, pai, callID string) *sip.Request {
	text := strings.Join([]string{
		"SUBSCRIBE " + target + " SIP/2.0",
		"Via: SIP/2.0/TCP pcscf." + realm + ";branch=z9hG4bK-" + callID,
		"Max-Forwards: 70",
		"From: <sip:pcscf." + realm + ">;tag=t-" + callID,
		"To: <" + target + ">", "Call-ID: " + callID, "CSeq: 1 SUBSCRIBE",
		"Contact: <sip:pcscf." + realm + ":5060;transport=tcp>",
		"Event: reg", "P-Asserted-Identity: <" + pai + ">", "Expires: 600000",
	}, "\r\n") + "\r\nContent-Length: 0\r\n\r\n"
	m, err := sip.ParseMessage([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return m.(*sip.Request)
}

// TestAnEndListingFailureThenAStopLosesNoEnd: the user deregisters on
// instance 1; listing tel1's subscriptions fails there, and instance 1
// stops with impu1's final queued, before it is numbered or while it is
// being sent. Instance 2's sweeps deliver one terminated NOTIFY per
// subscription and leave nothing (QA's F1 on #256).
func TestAnEndListingFailureThenAStopLosesNoEnd(t *testing.T) {
	for _, mode := range []string{"stops before numbering", "stops after numbering, NOTIFY in flight"} {
		t.Run(mode, func(t *testing.T) {
			e := newEnv(t)
			s2 := &recSender{}
			n2 := notifierOn(t, e, e.store, s2)
			g2 := e.instance(2, func(c *Config) { c.Events = n2 })
			u := registered(t, e, g2, 600, impu1, tel1)
			n2.Wait()
			pcscf := "sip:flow-token@pcscf." + realm + ";lr;ob"
			for _, r := range []*sip.Request{subReq(t, impu1, pcscf, "pcscf-sub"), subReq(t, tel1, impu1, "ue-sub")} {
				res, after := n2.Subscribe(bg, r)
				wantStatus(t, res, 200)
				after(bg)
			}
			stopped := make(chan struct{})
			t.Cleanup(func() { close(stopped) })
			cs := &crashStore{Memory: e.store, failList: tel1, stopped: stopped}
			var sender regevent.Sender = &recSender{}
			if mode == "stops before numbering" {
				cs.blockNum = true
			} else {
				sender = crashSender{stopped: stopped}
			}
			n1 := notifierOn(t, e, cs, sender)
			g1 := e.instance(1, func(c *Config) { c.Events = n1 })
			wantStatus(t, u.registerWith(g1, 0), 200)
			// Instance 1 is gone. Instance 2 sweeps, every 10 s, for 5 min.
			for range 30 {
				e.clock.advance(10 * time.Second)
				_, _ = g2.Sweep(bg, 10)
				_, _ = n2.Sweep(bg, 10)
				n2.Wait()
			}
			f := s2.finals()
			left := len(must(e.store.SubscriptionsOf(bg, impu1))(t)) + len(must(e.store.SubscriptionsOf(bg, tel1))(t))
			_, recErr := regOf(e, impu1)
			if f["pcscf-sub"] == "" || f["ue-sub"] == "" || strings.Count(f["pcscf-sub"], ";") > 1 || strings.Count(f["ue-sub"], ";") > 1 || left != 0 || recErr == nil {
				t.Errorf("an end was lost or doubled: finals %v, left %d, record %v", f, left, recErr)
			}
		})
	}
}
