package routing

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
)

// TestATerminatingRequestIsForkedToEveryLiveBindingAlongItsPath (TS 24.229
// §5.4.3.3): each binding's contact becomes a target, by its q, with its
// Path as routes; an expired one is left out; the S-CSCF records the
// route, and each branch carries the Request-URI in P-Called-Party-ID.
func TestATerminatingRequestIsForkedToEveryLiveBindingAlongItsPath(t *testing.T) {
	e := newEnv(t)
	low := binding(2, 0, 2*time.Hour)
	low.Q = 500
	e.registered(binding(1, 0, time.Hour), low, binding(3, 0, -time.Minute))
	rt := e.router(nil)
	r := request(t, "INVITE", impu1)
	d := rt.Terminating(bg, r)
	if got := uris(d.Targets); !slices.Equal(got, []string{binding(1, 0, 0).URI, binding(2, 0, 0).URI}) {
		t.Fatalf("targets %v", got)
	}
	if d.Targets[0].Q != 1000 || d.Targets[1].Q != 500 {
		t.Errorf("q %d, %d", d.Targets[0].Q, d.Targets[1].Q)
	}
	if rs := d.Targets[0].Routes; len(rs) != 1 || "<"+rs[0].URI.String()+">" != pathOf(1) {
		t.Errorf("routes %v, want the Path %s", rs, pathOf(1))
	}
	if len(d.RecordRoute) != 1 || d.RecordRoute[0].URI.Host != "scscf.rcs.local" {
		t.Errorf("Record-Route %v", d.RecordRoute)
	}
	branch := r.Message.Clone()
	branch.URI = d.Targets[0].URI
	if err := d.Prepare(bg, d.Targets[0], branch); err != nil {
		t.Fatal(err)
	}
	if got := branch.Header.Get("P-Called-Party-ID"); got != "<"+impu1+">" {
		t.Errorf("P-Called-Party-ID %q", got)
	}
	if r.Message.Header.Has("P-Called-Party-ID") {
		t.Error("Prepare changed the shared request")
	}
}

// TestTheTelFormOfAnIdentityReachesItsUser: the set has the user's tel URI
// too (#282), and a request for it finds the same bindings.
func TestTheTelFormOfAnIdentityReachesItsUser(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	rt := e.router(nil)
	for _, target := range []string{tel1, "tel:+1-555-010-0001", "sip:+15550100001@" + realm + ";user=phone"} {
		d := rt.Terminating(bg, request(t, "MESSAGE", target))
		if got := uris(d.Targets); !slices.Equal(got, []string{binding(1, 0, 0).URI}) {
			t.Errorf("%s: targets %v, status %d", target, got, d.Status)
		}
	}
}

// TestWhoCannotBeReachedIsAnswered: 404 for what is no public identity and
// for a barred one (§5.4.3.3), 480 for a user without a live binding.
func TestWhoCannotBeReachedIsAnswered(t *testing.T) {
	for name, c := range map[string]struct {
		setUp  func(e *env)
		target string
		status int
	}{
		"no public identity":  {func(e *env) { e.registered(binding(1, 0, time.Hour)) }, "sip:" + realm, 404},
		"barred":              {func(e *env) { e.registered(binding(1, 0, time.Hour)) }, impu2, 404},
		"unknown":             {func(*env) {}, "sip:+15550100004@" + realm, 480},
		"every binding gone":  {func(e *env) { e.registered(binding(1, 0, -time.Second)) }, impu1, 480},
		"being deregistered":  {func(e *env) { e.deregistering() }, impu1, 480},
		"left the set":        {func(e *env) { e.withoutTel() }, tel1, 480},
		"record gone already": {func(e *env) { e.recordGone() }, impu1, 480},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			c.setUp(e)
			d := e.router(nil).Terminating(bg, request(t, "INVITE", c.target))
			if d.Status != c.status || len(d.Targets) != 0 {
				t.Errorf("status %d with %d targets, want %d", d.Status, len(d.Targets), c.status)
			}
		})
	}
}

func (e *env) deregistering() {
	e.t.Helper()
	r := e.registered(binding(1, 0, time.Hour))
	r.Deregistering, r.Contacts = t0.Add(time.Minute), nil
	if _, err := e.store.SaveRegistration(bg, r); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) withoutTel() {
	e.t.Helper()
	r := e.registered(binding(1, 0, time.Hour))
	r.Identities = []state.SetIdentity{{IMPU: impu1}}
	if _, err := e.store.SaveRegistration(bg, r); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) recordGone() {
	e.t.Helper()
	r := e.registered(binding(1, 0, time.Hour))
	if err := e.store.DeleteRegistration(bg, r); err != nil {
		e.t.Fatal(err)
	}
}

// TestAnIdentityNamingAnotherIncarnationStillReachesItsUser: an interrupted
// REGISTER can leave an item naming an incarnation of the record that was
// never saved (#196); the live record is used, and the item repaired in the
// background (the lead's rule on #14).
func TestAnIdentityNamingAnotherIncarnationStillReachesItsUser(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	id, err := e.store.Identity(bg, tel1, t0)
	if err != nil {
		t.Fatal(err)
	}
	id.Incarnation = 9
	if _, err := e.store.SaveIdentity(bg, id, t0); err != nil {
		t.Fatal(err)
	}
	rt := e.router(nil)
	d := rt.Terminating(bg, request(t, "INVITE", tel1))
	if len(d.Targets) != 1 {
		t.Fatalf("status %d, %d targets", d.Status, len(d.Targets))
	}
	rt.Wait()
	if got, _ := e.store.Identity(bg, tel1, t0); got == nil || got.Incarnation != 7 || e.metrics.get("routing.identity_repaired") != 1 {
		t.Errorf("item after the repair: %+v", got)
	}
}

// TestARepairLosesToAREGISTERThatPointedTheItemMeanwhile: it is
// conditional on the version read.
func TestARepairLosesToAREGISTERThatPointedTheItemMeanwhile(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	id, _ := e.store.Identity(bg, tel1, t0)
	id.Incarnation = 9
	stale, _ := e.store.SaveIdentity(bg, id, t0)
	rt := e.router(&racingStore{Memory: e.store, before: func() {
		again := *stale
		again.Incarnation = 11
		if _, err := e.store.SaveIdentity(bg, &again, t0); err != nil {
			t.Error(err)
		}
	}})
	rt.Terminating(bg, request(t, "INVITE", tel1))
	rt.Wait()
	if got, _ := e.store.Identity(bg, tel1, t0); got.Incarnation != 11 || e.metrics.get("routing.identity_repair_failed") != 1 {
		t.Errorf("item %+v: the repair overwrote a later pointer", got)
	}
}

// racingStore runs before ahead of the first SaveIdentity.
type racingStore struct {
	*state.Memory
	before func()
}

func (s *racingStore) SaveIdentity(ctx context.Context, i *state.Identity, now time.Time) (*state.Identity, error) {
	if s.before != nil {
		s.before()
		s.before = nil
	}
	return s.Memory.SaveIdentity(ctx, i, now)
}

// failingStore fails every read of a registration.
type failingStore struct{ *state.Memory }

func (failingStore) Registration(context.Context, state.SetKey) (*state.Registration, error) {
	return nil, errors.New("throttled")
}

// TestAStoreThatCannotBeReadIs500WithRetryAfter: the caller tries again
// soon rather than taking the user for unreachable.
func TestAStoreThatCannotBeReadIs500WithRetryAfter(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	d := e.router(failingStore{e.store}).Terminating(bg, request(t, "INVITE", impu1))
	if d.Response == nil || d.Response.StatusCode != 500 || d.Response.Header.Get("Retry-After") == "" {
		t.Fatalf("decision %+v", d)
	}
	if to, _ := d.Response.Header.To(); to.Tag() == "" {
		t.Error("the 500 has no To tag")
	}
}

// TestOnlyTheLatestFlowOfAnInstanceIsTried: RFC 5626 §7 sends to one flow
// of an instance at a time; bindings without an instance are all tried.
func TestOnlyTheLatestFlowOfAnInstanceIsTried(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 1, time.Hour), binding(2, 1, 2*time.Hour), binding(3, 0, time.Hour), binding(4, 0, time.Hour))
	d := e.router(nil).Terminating(bg, request(t, "INVITE", impu1))
	if got := uris(d.Targets); !slices.Equal(got, []string{binding(2, 1, 0).URI, binding(3, 0, 0).URI, binding(4, 0, 0).URI}) {
		t.Errorf("targets %v", got)
	}
}

func failure(t proxy.Target, code int) proxy.BranchFailure {
	return proxy.BranchFailure{Target: t, Response: &sip.Response{StatusCode: code}}
}

// TestA430EndsTheBindingAndTriesTheInstancesNextFlow: the edge proxy no
// longer has the flow (RFC 5626 §5.3); the binding is ended as an expired
// one is, for the sweep to finish, and the instance's next flow is tried
// (§7), once.
func TestA430EndsTheBindingAndTriesTheInstancesNextFlow(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 1, time.Hour), binding(2, 1, 2*time.Hour), binding(3, 0, time.Hour))
	rt := e.router(nil)
	d := rt.Terminating(bg, request(t, "INVITE", impu1))
	if got := uris(d.Targets); !slices.Equal(got, []string{binding(2, 1, 0).URI, binding(3, 0, 0).URI}) {
		t.Fatalf("targets %v", got)
	}
	if more := d.OnBranchFailure(bg, failure(d.Targets[1], 486)); more != nil {
		t.Errorf("a 486 brought targets %v", uris(more))
	}
	next := d.OnBranchFailure(bg, failure(d.Targets[0], 430))
	if got := uris(next); !slices.Equal(got, []string{binding(1, 1, 0).URI}) {
		t.Fatalf("after the 430: %v", got)
	}
	if again := d.OnBranchFailure(bg, failure(next[0], 430)); len(again) != 0 {
		t.Errorf("after the last flow's 430: %v", uris(again))
	}
	set, _ := e.store.Registration(bg, set1)
	for _, c := range set.Contacts {
		ended := c.Expired(t0)
		if want := c.URI != binding(3, 0, 0).URI; ended != want {
			t.Errorf("%s ended %v, want %v", c.URI, ended, want)
		}
	}
	if e.metrics.get("routing.terminating.binding_ended") != 2 {
		t.Errorf("bindings ended %d", e.metrics.get("routing.terminating.binding_ended"))
	}
	// A 430 for a binding without an instance ends it, and that is all.
	if more := d.OnBranchFailure(bg, failure(d.Targets[1], 430)); len(more) != 0 {
		t.Errorf("a 430 without an instance brought %v", uris(more))
	}
	if set, _ := e.store.Registration(bg, set1); !set.Contacts[2].Expired(t0) {
		t.Error("the binding without an instance was not ended")
	}
}

// conflictStore loses the first save of a registration to another write.
type conflictStore struct {
	*state.Memory
	lost bool
}

func (s *conflictStore) SaveRegistration(ctx context.Context, r *state.Registration) (*state.Registration, error) {
	if !s.lost {
		s.lost = true
		cur, err := s.Memory.Registration(ctx, r.Key)
		if err != nil {
			return nil, err
		}
		next := cur.Clone()
		next.Contacts[0].CSeq++
		if _, err := s.Memory.SaveRegistration(ctx, next); err != nil {
			return nil, err
		}
	}
	return s.Memory.SaveRegistration(ctx, r)
}

// TestEndingABindingReadsTheRecordAgainAfterLosingARace: a REGISTER saved
// the set meanwhile; the binding is still ended, on what that REGISTER
// left.
func TestEndingABindingReadsTheRecordAgainAfterLosingARace(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	rt := e.router(&conflictStore{Memory: e.store})
	d := rt.Terminating(bg, request(t, "INVITE", impu1))
	d.OnBranchFailure(bg, failure(d.Targets[0], 430))
	set, _ := e.store.Registration(bg, set1)
	if !set.Contacts[0].Expired(t0) || set.Contacts[0].CSeq != 2 {
		t.Errorf("binding after the race: %+v", set.Contacts[0])
	}
}

// TestCallerPreferencesChooseTheBindings: RCS asks for the devices that
// registered its service (RFC 3841 with require and explicit).
func TestCallerPreferencesChooseTheBindings(t *testing.T) {
	chat := `+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session"`
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour, chat), binding(2, 0, time.Hour))
	rt := e.router(nil)
	r := request(t, "INVITE", impu1, "Accept-Contact: *;"+chat+";require;explicit")
	if got := uris(rt.Terminating(bg, r).Targets); !slices.Equal(got, []string{binding(1, 0, 0).URI}) {
		t.Errorf("targets %v, want the chat device only", got)
	}
	r = request(t, "INVITE", impu1, "Reject-Contact: *;"+chat)
	if got := uris(rt.Terminating(bg, r).Targets); !slices.Equal(got, []string{binding(2, 0, 0).URI}) {
		t.Errorf("targets %v, want the device without chat only", got)
	}
	r = request(t, "INVITE", impu1, `Accept-Contact: *;+g.3gpp.icsi-ref="urn%3Aother";require;explicit`)
	if d := rt.Terminating(bg, r); d.Status != 480 {
		t.Errorf("no device for the service: %d", d.Status)
	}
}
