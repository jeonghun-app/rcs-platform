package registrar

import (
	"context"
	"errors"
	"fmt"
	"runtime"
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
// each subscriber its terminated NOTIFY once, and the registration sweep
// after the RTR's lease finishes (#256 code review). The RTR succeeds: its
// lease stands for the rest (#394 code review).
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
	wantResult(t, doomed.HandleRTR(bg, rtr), resultSuccess)
	if r := must(e.store.Registration(bg, set1))(t); len(r.Contacts) != 0 || r.Deregistering.IsZero() {
		t.Fatalf("the RTR left %+v, not its lease", r)
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
	// The sweep after the lease finishes the set, and tells no one again.
	e.clock.advance(state.SweepLease)
	if _, err := g.Sweep(bg, 10); err != nil {
		t.Fatal(err)
	}
	n.Wait()
	if all, _ := ends(); all != 2 {
		t.Errorf("%d NOTIFYs after the retried RTR", all)
	}
	if _, err := e.store.Registration(bg, set1); err == nil {
		t.Error("the record outlived the sweep")
	}
	if subs, _ := e.store.SubscriptionsOf(bg, impu1); len(subs) != 0 {
		t.Errorf("%d subscriptions left", len(subs))
	}
}

// TestAnRTRsEndTheSweepFinishesSaysRejected (#334): an RTR
// PERMANENT_TERMINATION whose subscriptions cannot be listed leaves the
// record under a lease; the sweep after it tells the subscribers the
// registrations were rejected, as the RTR would have.
func TestAnRTRsEndTheSweepFinishesSaysRejected(t *testing.T) {
	for name, c := range map[string]struct {
		code   cx.ReasonCode
		reason string
	}{
		"for good":         {cx.PermanentTermination, "rejected"},
		"for a new S-CSCF": {cx.NewServerAssigned, "deactivated"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			g, n, s := withNotifier(t, e)
			registered(t, e, g, 600, impu1)
			n.Wait()
			subscribeAsPCSCF(t, n)
			k := s.count()
			ts := &troubledStore{Store: e.store, listFails: 1 << 10}
			u, _ := sip.ParseURI("sip:scscf." + realm)
			failing, err := regevent.New(regevent.Config{Store: ts, Sender: s, Contact: u, Now: e.clock.Now})
			if err != nil {
				t.Fatal(err)
			}
			rtr := &cx.RTR{UserName: impi1, DeregistrationReason: cx.DeregistrationReason{Code: c.code}}
			wantResult(t, e.instance(2, func(cfg *Config) { cfg.Events = failing }).HandleRTR(bg, rtr), resultSuccess)
			if lease, err := regOf(e, impu1); err != nil || lease.Rejected != (c.reason == "rejected") {
				t.Fatalf("lease %+v, %v", lease, err)
			}
			e.clock.advance(2 * time.Minute)
			if _, err := g.Sweep(bg, 10); err != nil {
				t.Fatal(err)
			}
			n.Wait()
			s.mu.Lock()
			defer s.mu.Unlock()
			if len(s.sent) != k+1 {
				t.Fatalf("%d NOTIFYs after the sweep", len(s.sent)-k)
			}
			ss, _ := s.sent[k].Header.SubscriptionState()
			if r, _ := ss.Params.Get("reason"); ss.State != "terminated" || r != c.reason {
				t.Errorf("Subscription-State %s;reason=%s, want terminated;reason=%s", ss.State, r, c.reason)
			}
		})
	}
}

// failingNotifier is a notifier on e's store whose listings all fail, so
// that every Ended it is asked for fails.
func failingNotifier(t *testing.T, e *env, s regevent.Sender) *regevent.Notifier {
	t.Helper()
	ts := &troubledStore{Store: e.store, listFails: 1 << 20}
	u, _ := sip.ParseURI("sip:scscf." + realm)
	n, err := regevent.New(regevent.Config{Store: ts, Sender: s, Contact: u, Now: e.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// reasonsSent are the Subscription-States of the NOTIFYs s sent from the
// from-th on, as state;reason.
func reasonsSent(s *notifySender, from int) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, req := range s.sent[from:] {
		ss, _ := req.Header.SubscriptionState()
		r, _ := ss.Params.Get("reason")
		out = append(out, ss.State+";"+r)
	}
	return out
}

// TestAREGISTERDuringARejectedLeaseIsNotRejected (QA on #351): the user
// registers again while an RTR's rejected lease holds (the operator
// provisioned it again); the REGISTER succeeds, its record has no mark,
// and its later expiry says deactivated.
func TestAREGISTERDuringARejectedLeaseIsNotRejected(t *testing.T) {
	e := newEnv(t)
	g, n, s := withNotifier(t, e)
	u := registered(t, e, g, 600, impu1)
	n.Wait()
	subscribeAsPCSCF(t, n)
	rtr := &cx.RTR{UserName: impi1, DeregistrationReason: cx.DeregistrationReason{Code: cx.PermanentTermination}}
	wantResult(t, e.instance(2, func(cfg *Config) { cfg.Events = failingNotifier(t, e, s) }).HandleRTR(bg, rtr), resultSuccess)
	if !must(regOf(e, impu1))(t).Rejected {
		t.Fatal("no mark on the lease")
	}
	e.clock.advance(10 * time.Second)
	wantStatus(t, u.registerWith(g, 600), 200)
	n.Wait()
	r := must(regOf(e, impu1))(t)
	if r.Rejected || len(r.Contacts) == 0 || !r.Deregistering.IsZero() {
		t.Fatalf("record after the REGISTER: %+v", r)
	}
	subscribeAsPCSCF(t, n)
	k := s.count()
	e.clock.advance(601 * time.Second)
	for range 3 {
		_, _ = g.Sweep(bg, 10)
		n.Wait()
		e.clock.advance(state.SweepLease + time.Second)
	}
	for _, got := range reasonsSent(s, k) {
		if got == "terminated;rejected" {
			t.Errorf("an expiry after a new REGISTER said rejected: %v", reasonsSent(s, k))
		}
	}
}

// stoppingEvents stops the goroutine that tells it of an end, as an
// instance that stops there does, after noting what the store holds then.
type stoppingEvents struct {
	e    *env
	seen *state.Registration
}

func (s *stoppingEvents) Changed(context.Context, *state.Registration, *state.Registration, regevent.Cause) {
}

func (s *stoppingEvents) Ended(context.Context, *state.Registration, regevent.Cause) error {
	s.seen, _ = s.e.store.Registration(bg, state.SetKey{IMPI: impi1, IMPU: impu1})
	runtime.Goexit()
	return nil
}

// TestAnRTRCutShortAfterItsClaimIsFinishedByTheSweep (#368): the record is
// claimed, with its mark, before the subscribers are told, so an instance
// that stops there leaves a lease the sweep ends as rejected.
func TestAnRTRCutShortAfterItsClaimIsFinishedByTheSweep(t *testing.T) {
	e := newEnv(t)
	g, n, s := withNotifier(t, e)
	registered(t, e, g, 600, impu1)
	n.Wait()
	subscribeAsPCSCF(t, n)
	k := s.count()
	stop := &stoppingEvents{e: e}
	rtr := &cx.RTR{UserName: impi1, DeregistrationReason: cx.DeregistrationReason{Code: cx.PermanentTermination}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.instance(2, func(cfg *Config) { cfg.Events = stop }).HandleRTR(bg, rtr)
	}()
	<-done
	if stop.seen == nil || len(stop.seen.Contacts) != 0 || stop.seen.Deregistering.IsZero() || !stop.seen.Rejected {
		t.Fatalf("what the store held as the subscribers were to be told: %+v", stop.seen)
	}
	e.clock.advance(2 * time.Minute)
	if _, err := g.Sweep(bg, 10); err != nil {
		t.Fatal(err)
	}
	n.Wait()
	if got := reasonsSent(s, k); len(got) != 1 || got[0] != "terminated;rejected" {
		t.Errorf("NOTIFYs after the sweep %v", got)
	}
	if _, err := regOf(e, impu1); err == nil {
		t.Error("the record outlived the sweep")
	}
}

// failingSaves fails every SaveRegistration with err, a throttled write's
// when nil.
type failingSaves struct {
	state.Store
	err error
}

func (f failingSaves) SaveRegistration(context.Context, *state.Registration) (*state.Registration, error) {
	if f.err != nil {
		return nil, f.err
	}
	return nil, errors.New("throttled")
}

// TestAnRTRWhoseClaimCannotBeSavedTellsNoOne (#368): the subscribers are
// not told of an end the store does not hold. A store that may save it
// later has the RTR answered DIAMETER_TOO_BUSY, which the HSS sends again;
// one that refuses it as invalid, DIAMETER_UNABLE_TO_COMPLY (#394 code
// review).
func TestAnRTRWhoseClaimCannotBeSavedTellsNoOne(t *testing.T) {
	for name, c := range map[string]struct {
		err  error
		want cx.Result
	}{
		"throttled": {nil, resultTooBusy},
		"invalid":   {fmt.Errorf("store: %w", state.ErrInvalid), resultUnableToComply},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			g, n, s := withNotifier(t, e)
			registered(t, e, g, 600, impu1)
			n.Wait()
			subscribeAsPCSCF(t, n)
			k := s.count()
			rtr := &cx.RTR{UserName: impi1, DeregistrationReason: cx.DeregistrationReason{Code: cx.PermanentTermination}}
			wantResult(t, e.instance(2, func(cfg *Config) { cfg.Store, cfg.Events = failingSaves{e.store, c.err}, n }).HandleRTR(bg, rtr), c.want)
			n.Wait()
			if got := reasonsSent(s, k); len(got) != 0 {
				t.Errorf("NOTIFYs %v for an end the store does not hold", got)
			}
			if r := must(regOf(e, impu1))(t); len(r.Contacts) == 0 {
				t.Errorf("record %+v", r)
			}
		})
	}
}

// onceFailingSaves fails the first SaveRegistration, as a throttled write
// does, and saves the next ones.
type onceFailingSaves struct {
	state.Store
	once sync.Once
}

func (s *onceFailingSaves) SaveRegistration(ctx context.Context, r *state.Registration) (*state.Registration, error) {
	failed := false
	s.once.Do(func() { failed = true })
	if failed {
		return nil, errors.New("throttled")
	}
	return s.Store.SaveRegistration(ctx, r)
}

// TestAnRTRTriesItsClaimAgain (#394 code review): one throttled claim is
// tried again, and the RTR ends the set.
func TestAnRTRTriesItsClaimAgain(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	registered(t, e, g, 600, impu1)
	rtr := &cx.RTR{UserName: impi1, DeregistrationReason: cx.DeregistrationReason{Code: cx.PermanentTermination}}
	wantResult(t, e.instance(2, func(cfg *Config) { cfg.Store = &onceFailingSaves{Store: e.store} }).HandleRTR(bg, rtr), resultSuccess)
	if _, err := e.store.Registration(bg, set1); !errors.Is(err, state.ErrNotFound) {
		t.Errorf("the set is left: %v", err)
	}
}

// refreshingStore runs hook once before the first SaveRegistration it
// forwards: a REGISTER refresh that lands between an RTR's read and its
// claim.
type refreshingStore struct {
	state.Store
	once sync.Once
	hook func()
}

func (s *refreshingStore) SaveRegistration(ctx context.Context, r *state.Registration) (*state.Registration, error) {
	s.once.Do(s.hook)
	return s.Store.SaveRegistration(ctx, r)
}

// TestAnRTRWhoseClaimLosesToARefreshEndsTheSetAnyway (#394 code review):
// the claim conflicts, the record is read again with the refresh, and the
// set ends.
func TestAnRTRWhoseClaimLosesToARefreshEndsTheSetAnyway(t *testing.T) {
	e := newEnv(t)
	g, n, s := withNotifier(t, e)
	u := registered(t, e, g, 600, impu1)
	n.Wait()
	subscribeAsPCSCF(t, n)
	k := s.count()
	rs := &refreshingStore{Store: e.store}
	rs.hook = func() { wantStatus(t, u.registerWith(e.instance(3), 1200), 200) }
	rtr := &cx.RTR{UserName: impi1, DeregistrationReason: cx.DeregistrationReason{Code: cx.PermanentTermination}}
	wantResult(t, e.instance(2, func(cfg *Config) { cfg.Store, cfg.Events = rs, n }).HandleRTR(bg, rtr), resultSuccess)
	n.Wait()
	if _, err := e.store.Registration(bg, set1); !errors.Is(err, state.ErrNotFound) {
		t.Errorf("the set the refresh saved is left: %v", err)
	}
	if got := reasonsSent(s, k); len(got) != 1 || got[0] != "terminated;rejected" {
		t.Errorf("NOTIFYs %v", got)
	}
}

// endsFailing fails or stops at Ended.
type endsFailing struct{ stop bool }

func (endsFailing) Changed(context.Context, *state.Registration, *state.Registration, regevent.Cause) {
}

func (e endsFailing) Ended(context.Context, *state.Registration, regevent.Cause) error {
	if e.stop {
		runtime.Goexit()
	}
	return errors.New("listing failed")
}

// TestAnUnregisteredUsersRTRLeaseIsNotReassigned (#394 code review): an RTR
// of an unregistered user's record cut short after its claim leaves a
// lease that is live by the user's state; the sweep that finishes it does
// not take it for a registration that overtook the RTR, and does not
// assign the user at the HSS again.
func TestAnUnregisteredUsersRTRLeaseIsNotReassigned(t *testing.T) {
	for name, ev := range map[string]endsFailing{"stop at Ended": {true}, "Ended fails": {false}} {
		for _, code := range []cx.ReasonCode{cx.RemoveSCSCF, cx.PermanentTermination} {
			t.Run(name+"/"+fmt.Sprint(code), func(t *testing.T) {
				e := newEnv(t)
				e.akaUser(impi1, impu1, tel1)
				seed(t, e, impi1, []string{impu1, tel1}, func(r *state.Registration) { r.Unregistered = t0.Add(time.Hour) })
				done := make(chan struct{})
				go func() {
					defer close(done)
					e.instance(2, func(c *Config) { c.Events = ev }).HandleRTR(bg, &cx.RTR{UserName: impi1, DeregistrationReason: cx.DeregistrationReason{Code: code}})
				}()
				<-done
				k := len(e.hss.sarsOf())
				for range 3 {
					e.clock.advance(state.SweepLease + time.Second)
					if _, err := e.instance(1).Sweep(bg, 10); err != nil {
						t.Fatal(err)
					}
				}
				for _, sar := range e.hss.sarsOf()[k:] {
					if sar == cx.Registration || sar == cx.UnregisteredUser {
						t.Errorf("the sweep assigned the user again after an RTR %v: SARs %v", code, e.hss.sarsOf()[k:])
					}
				}
				if _, err := e.store.Registration(bg, set1); !errors.Is(err, state.ErrNotFound) {
					t.Errorf("the lease is left: %v", err)
				}
			})
		}
	}
}

// failOnceDeleteIdentity fails the first DeleteIdentity, as one throttled
// write whose SDK retries are spent does.
type failOnceDeleteIdentity struct {
	state.Store
	once sync.Once
}

func (s *failOnceDeleteIdentity) DeleteIdentity(ctx context.Context, i *state.Identity) error {
	failed := false
	s.once.Do(func() { failed = true })
	if failed {
		return errors.New("throttled")
	}
	return s.Store.DeleteIdentity(ctx, i)
}

// TestAFailureAfterOneSetsClaimLeavesNoOtherSetLive (#394 code review): an
// RTR for an IMPI with two sets, whose first set fails after its claim,
// leaves that one to the sweep and still ends the other.
func TestAFailureAfterOneSetsClaimLeavesNoOtherSetLive(t *testing.T) {
	e := newEnv(t)
	twoSets(t, e, e.instance(1))
	m := &counts{}
	st := &failOnceDeleteIdentity{Store: e.store}
	wantResult(t, e.instance(2, func(c *Config) { c.Store, c.Metrics = st, m }).HandleRTR(bg, &cx.RTR{UserName: impi1, DeregistrationReason: cx.DeregistrationReason{Code: cx.PermanentTermination}}), resultSuccess)
	for _, r := range must(e.store.RegistrationsOf(bg, impi1))(t) {
		if len(r.Contacts) > 0 || r.Deregistering.IsZero() {
			t.Errorf("%s is left live after the RTR: %d contacts, leased %v", r.Key.IMPU, len(r.Contacts), !r.Deregistering.IsZero())
		}
	}
	if m.get("registrar.rtr_left_to_sweep") != 1 {
		t.Errorf("registrar.rtr_left_to_sweep = %d", m.get("registrar.rtr_left_to_sweep"))
	}
}

// TestALaterRTRKeepsALeasesRejection (#368): a NEW_SERVER_ASSIGNED RTR on
// the lease a PERMANENT_TERMINATION's left keeps it rejected.
func TestALaterRTRKeepsALeasesRejection(t *testing.T) {
	e := newEnv(t)
	g, n, s := withNotifier(t, e)
	registered(t, e, g, 600, impu1)
	n.Wait()
	subscribeAsPCSCF(t, n)
	for _, code := range []cx.ReasonCode{cx.PermanentTermination, cx.NewServerAssigned} {
		rtr := &cx.RTR{UserName: impi1, DeregistrationReason: cx.DeregistrationReason{Code: code}}
		wantResult(t, e.instance(2, func(cfg *Config) { cfg.Events = failingNotifier(t, e, s) }).HandleRTR(bg, rtr), resultSuccess)
	}
	if !must(regOf(e, impu1))(t).Rejected {
		t.Error("the second RTR took the rejection off the lease")
	}
}

// sweepingEvents runs a registration sweep on another instance before it
// tells n of an end: a sweep that comes while the RTR tells the
// subscribers.
type sweepingEvents struct {
	n     *regevent.Notifier
	sweep func() int
	swept int
}

func (s *sweepingEvents) Changed(ctx context.Context, before, after *state.Registration, c regevent.Cause) {
	s.n.Changed(ctx, before, after, c)
}

func (s *sweepingEvents) Ended(ctx context.Context, before *state.Registration, c regevent.Cause) error {
	s.swept = s.sweep()
	return s.n.Ended(ctx, before, c)
}

// TestASweepLeavesAnRTRsLeaseWhileTheRTRTellsTheSubscribers (#394 QA): the
// claim holds the record for SweepLease, so a sweep in between takes
// nothing, and the subscribers hear of the end once.
func TestASweepLeavesAnRTRsLeaseWhileTheRTRTellsTheSubscribers(t *testing.T) {
	e := newEnv(t)
	g, n, s := withNotifier(t, e)
	registered(t, e, g, 600, impu1)
	n.Wait()
	subscribeAsPCSCF(t, n)
	k := s.count()
	ev := &sweepingEvents{n: n, sweep: func() int {
		k, err := e.instance(3).Sweep(bg, 10)
		if err != nil {
			t.Error(err)
		}
		return k
	}}
	rtr := &cx.RTR{UserName: impi1, DeregistrationReason: cx.DeregistrationReason{Code: cx.PermanentTermination}}
	wantResult(t, e.instance(2, func(cfg *Config) { cfg.Events = ev }).HandleRTR(bg, rtr), resultSuccess)
	n.Wait()
	if ev.swept != 0 {
		t.Errorf("the sweep took %d sets while the RTR held the lease", ev.swept)
	}
	if got := reasonsSent(s, k); len(got) != 1 || got[0] != "terminated;rejected" {
		t.Errorf("NOTIFYs %v", got)
	}
}
