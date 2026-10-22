package regevent

import (
	"context"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/reginfo"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

func TestTheSubscribersPCSCFSubscribesAndGetsTheFullState(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, time.Hour))
	res, notify := e.subscribed(e.notifier(1))
	if res.Header.Get("Expires") != "600000" {
		t.Errorf("Expires %q", res.Header.Get("Expires"))
	}
	if c := res.Header.Get("Contact"); c != "<sip:scscf."+realm+";transport=tcp>" {
		t.Errorf("Contact %q", c)
	}
	doc, cseq, ss := info(t, notify)
	if cseq != 1 || doc.Version != 0 || doc.State != reginfo.Full {
		t.Errorf("first NOTIFY: CSeq %d, version %d, %s", cseq, doc.Version, doc.State)
	}
	if exp, _ := ss.Expires(); ss.State != "active" || exp != 600000 {
		t.Errorf("Subscription-State %+v", ss)
	}
	// The set's identities but the barred one (TS 24.229 §5.4.1.2.2).
	var aors []string
	for _, reg := range doc.Registrations {
		aors = append(aors, reg.AOR)
		if reg.State != reginfo.Active || len(reg.Contacts) != 1 {
			t.Errorf("%s: %s with %d contacts", reg.AOR, reg.State, len(reg.Contacts))
			continue
		}
		c := reg.Contacts[0]
		inst, _ := c.Param("+sip.instance")
		if !c.Active() || c.Event != reginfo.Registered || inst != binding(1, 0).InstanceID || c.Expires == nil || *c.Expires != 3600 {
			t.Errorf("%s contact: %+v", reg.AOR, c)
		}
	}
	if !slices.Equal(aors, []string{impu1, tel1}) {
		t.Errorf("registrations %v, want impu1 and tel1, not the barred impu2", aors)
	}
	// The NOTIFY goes in the dialog: To is the subscriber with its tag,
	// From the S-CSCF with the 200's.
	to, _ := notify.Header.To()
	from, _ := notify.Header.From()
	resTo, _ := res.Header.To()
	if to.Tag() != "pcscf-tag" || from.Tag() != resTo.Tag() || notify.Header.Get("Call-ID") != "sub-call-1" {
		t.Errorf("NOTIFY To %v From %v", to, from)
	}
}

func TestTheUESubscribesAsOneOfItsIdentities(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, time.Hour))
	res, _ := e.notifier(1).Subscribe(bg, subscribe(t, impu1, tel1, 3600))
	wantStatus(t, res, 200)
}

func TestAnyoneElseMayNotSubscribe(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, time.Hour))
	n := e.notifier(1)
	for name, req := range map[string]*sip.Request{
		"another P-CSCF":       subscribe(t, impu1, "sip:term@pcscf.other.example;lr", 3600),
		"another user":         subscribe(t, impu1, "sip:+15550100003@"+realm, 3600),
		"not registered":       subscribe(t, "sip:+15550100004@"+realm, pcscfPath, 3600),
		"no asserted identity": parse(t, "SUBSCRIBE "+impu1+" SIP/2.0\r\nVia: SIP/2.0/TCP h;branch=z9hG4bK-x\r\nMax-Forwards: 70\r\nFrom: <sip:pcscf."+realm+">;tag=a\r\nTo: <"+impu1+">\r\nCall-ID: c\r\nCSeq: 1 SUBSCRIBE\r\nContact: <sip:pcscf."+realm+">\r\nEvent: reg\r\nContent-Length: 0\r\n\r\n"),
		"the Path of an expired binding": func() *sip.Request {
			return subscribe(t, impu1, pcscfPath, 3600)
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			if name == "the Path of an expired binding" {
				e.clock.advance(2 * time.Hour)
				defer e.clock.advance(-2 * time.Hour)
			}
			res, after := n.Subscribe(bg, req)
			wantStatus(t, res, 403)
			if after != nil {
				t.Error("a NOTIFY to send for a refused SUBSCRIBE")
			}
		})
	}
	if subs, _ := e.store.SubscriptionsOf(bg, impu1); len(subs) != 0 {
		t.Errorf("%d subscriptions stored", len(subs))
	}
}

func TestASubscribeForAnotherEventIs489(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, time.Hour))
	req := subscribe(t, impu1, pcscfPath, 3600)
	_ = req.Header.Set("Event", "presence")
	res, _ := e.notifier(1).Subscribe(bg, req)
	wantStatus(t, res, 489)
	if res.Header.Get("Allow-Events") != "reg" {
		t.Error("no Allow-Events")
	}
}

// TestARefreshMustMatchTheDialogItsOrderAndItsSubscriber: the lead's
// contract on #14 for in-dialog SUBSCRIBEs.
func TestARefreshMustMatchTheDialogItsOrderAndItsSubscriber(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, time.Hour))
	n := e.notifier(1)
	res, _ := e.subscribed(n)
	wrongTag := inDialog(t, res, impu1, pcscfPath, 2, 600)
	_ = wrongTag.Header.Set("To", "<"+impu1+">;tag=other")
	r, _ := n.Subscribe(bg, wrongTag)
	wantStatus(t, r, 481)
	r, _ = n.Subscribe(bg, inDialog(t, res, impu1, "sip:term@pcscf.other.example", 2, 600))
	wantStatus(t, r, 481)
	r, _ = n.Subscribe(bg, inDialog(t, res, impu1, pcscfPath, 0, 600))
	wantStatus(t, r, 500)

	// Another instance takes the refresh.
	e.clock.advance(time.Minute)
	r, after := e.notifier(2).Subscribe(bg, inDialog(t, res, impu1, pcscfPath, 2, 7200))
	wantStatus(t, r, 200)
	if r.Header.Get("Expires") != "7200" {
		t.Errorf("Expires %q", r.Header.Get("Expires"))
	}
	after(bg)
	got := e.send.notifies()
	doc, cseq, ss := info(t, got[len(got)-1])
	if exp, _ := ss.Expires(); cseq != 2 || doc.Version != 1 || exp != 7200 {
		t.Errorf("after the refresh: CSeq %d, version %d, expires %d", cseq, doc.Version, exp)
	}
	// Neither a lower CSeq (RFC 3261 §12.2.2) nor the same again, which a
	// repeat reaching another instance has (the lead's contract on #14).
	r, _ = n.Subscribe(bg, inDialog(t, res, impu1, pcscfPath, 1, 600))
	wantStatus(t, r, 500)
	r, _ = n.Subscribe(bg, inDialog(t, res, impu1, pcscfPath, 2, 600))
	wantStatus(t, r, 500)
}

func TestExpiresZeroInTheDialogEndsTheSubscription(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, time.Hour))
	n := e.notifier(1)
	res, _ := e.subscribed(n)
	r, after := n.Subscribe(bg, inDialog(t, res, impu1, pcscfPath, 2, 0))
	wantStatus(t, r, 200)
	after(bg)
	got := e.send.notifies()
	if _, _, ss := info(t, got[len(got)-1]); ss.State != "terminated" {
		t.Errorf("Subscription-State %+v", ss)
	}
	if subs, _ := e.store.SubscriptionsOf(bg, impu1); len(subs) != 0 {
		t.Errorf("%d subscriptions left", len(subs))
	}
	r, _ = n.Subscribe(bg, inDialog(t, res, impu1, pcscfPath, 3, 600))
	wantStatus(t, r, 481)
}

// TestAFetchGetsOneNotifyAndNoSubscription: an initial SUBSCRIBE with
// Expires 0 (RFC 6665 §4.4.3).
func TestAFetchGetsOneNotifyAndNoSubscription(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, time.Hour))
	res, after := e.notifier(1).Subscribe(bg, subscribe(t, impu1, pcscfPath, 0))
	wantStatus(t, res, 200)
	after(bg)
	got := e.send.notifies()
	if len(got) != 1 {
		t.Fatalf("%d NOTIFYs", len(got))
	}
	if _, _, ss := info(t, got[0]); ss.State != "terminated" {
		t.Errorf("Subscription-State %+v", ss)
	}
	if subs, _ := e.store.SubscriptionsOf(bg, impu1); len(subs) != 0 {
		t.Errorf("%d subscriptions stored", len(subs))
	}
}

// TestASubscriptionMadeAfterAChangeIsNotToldOfItAgain (#516): the
// registrar's fan-out of an initial REGISTER runs on a worker, after the
// SUBSCRIBE that followed the REGISTER may already have been answered. That
// subscription's first NOTIFY had the state the change made, so the fan-out
// sends it nothing; the next change is told as ever.
func TestASubscriptionMadeAfterAChangeIsNotToldOfItAgain(t *testing.T) {
	e := newEnv(t)
	after := e.registered(binding(1, time.Hour))
	n := e.notifier(1)
	e.subscribed(n)
	n.Changed(bg, nil, after, Registered)
	n.Wait()
	if got := len(e.send.notifies()); got != 1 {
		t.Fatalf("%d NOTIFYs, want the first one only", got)
	}
	next := after.Clone()
	next.Contacts = []state.Contact{binding(1, 2*time.Hour)}
	next = e.saved(next)
	n.Changed(bg, after, next, Registered)
	n.Wait()
	got := e.send.notifies()
	if len(got) != 2 {
		t.Fatalf("%d NOTIFYs after the next change, want 2", len(got))
	}
	if doc, cseq, _ := info(t, got[1]); cseq != 2 || doc.Version != 1 {
		t.Errorf("the next change's NOTIFY: CSeq %d version %d, want 2 and 1", cseq, doc.Version)
	}
}

// TestALateChangeStillTellsWhatItEnded (#516): a change's fan-out that runs
// after a later change was notified is still sent, as the subscription has
// had more than its first NOTIFY: the later one, from a state already
// without the binding the earlier change ended, did not list that end.
func TestALateChangeStillTellsWhatItEnded(t *testing.T) {
	e := newEnv(t)
	v0 := e.registered(binding(1, time.Hour), binding(2, time.Hour))
	n := e.notifier(1)
	e.subscribed(n)
	v1 := v0.Clone()
	v1.Contacts = []state.Contact{binding(1, time.Hour)}
	v1 = e.saved(v1)
	v2 := v1.Clone()
	v2.Contacts = []state.Contact{binding(1, 2*time.Hour)}
	v2 = e.saved(v2)
	n.Changed(bg, v1, v2, Registered)
	n.Wait()
	n.Changed(bg, v0, v1, Unregistered)
	n.Wait()
	got := e.send.notifies()
	if len(got) != 3 {
		t.Fatalf("%d NOTIFYs, want the first, the later change's and the earlier's", len(got))
	}
	doc, _, _ := info(t, got[2])
	reg, _ := doc.ByAOR(sip.URI{Scheme: "sip", User: "+15550100001", Host: realm})
	for _, c := range reg.Contacts {
		if c.URI == binding(2, 0).URI {
			if c.State != reginfo.ContactTerminated || c.Event != reginfo.Unregistered {
				t.Errorf("binding 2: %s %s, want terminated unregistered", c.State, c.Event)
			}
			return
		}
	}
	t.Error("the earlier change's NOTIFY does not list the binding it ended")
}

// TestAChangeIsNotifiedWithTheFullStateAndStableIDs: a new binding is
// registered, an old one unregistered and listed once as terminated; a
// binding keeps its id across NOTIFYs, and its ids under the sip and tel
// identities differ.
func TestAChangeIsNotifiedWithTheFullStateAndStableIDs(t *testing.T) {
	e := newEnv(t)
	before := e.registered(binding(1, time.Hour), binding(2, time.Hour))
	n := e.notifier(1)
	_, first := e.subscribed(n)
	firstDoc, _, _ := info(t, first)
	after := before.Clone()
	after.Contacts = []state.Contact{binding(1, 2*time.Hour), binding(3, time.Hour)}
	// As the registrar does: save, then tell.
	after = e.saved(after)
	n.Changed(bg, before, after, Registered)
	n.Wait()
	got := e.send.notifies()
	doc, cseq, _ := info(t, got[len(got)-1])
	if cseq != 2 || doc.Version != 1 {
		t.Errorf("CSeq %d version %d", cseq, doc.Version)
	}
	reg, _ := doc.ByAOR(sip.URI{Scheme: "sip", User: "+15550100001", Host: realm})
	events := map[string]reginfo.Event{}
	for _, c := range reg.Contacts {
		events[c.URI] = c.Event
	}
	want := map[string]reginfo.Event{
		binding(1, 0).URI: reginfo.Refreshed, binding(2, 0).URI: reginfo.Unregistered, binding(3, 0).URI: reginfo.Registered,
	}
	for uri, ev := range want {
		if events[uri] != ev {
			t.Errorf("%s: %s, want %s", uri, events[uri], ev)
		}
	}
	idOfBinding := func(d *reginfo.Info, aor, uri string) string {
		for _, r := range d.Registrations {
			if r.AOR != aor {
				continue
			}
			for _, c := range r.Contacts {
				if c.URI == uri {
					return c.ID
				}
			}
		}
		return ""
	}
	b1 := binding(1, 0).URI
	if a, b := idOfBinding(firstDoc, impu1, b1), idOfBinding(doc, impu1, b1); a == "" || a != b {
		t.Errorf("binding 1's id changed: %q then %q", a, b)
	}
	if idOfBinding(doc, impu1, b1) == idOfBinding(doc, tel1, b1) {
		t.Error("one binding has one id under two identities")
	}
}

func TestAnEndedSetEndsItsSubscriptions(t *testing.T) {
	for cause, reason := range map[Cause]string{Deactivated: "deactivated", Rejected: "rejected", Expired: "deactivated", Unregistered: "deactivated"} {
		t.Run(reason+string(rune('0'+cause)), func(t *testing.T) {
			e := newEnv(t)
			before := e.registered(binding(1, time.Hour))
			n := e.notifier(1)
			e.subscribed(n)
			n.Changed(bg, before, nil, cause)
			n.Wait()
			got := e.send.notifies()
			doc, _, ss := info(t, got[len(got)-1])
			if r, _ := ss.Params.Get("reason"); ss.State != "terminated" || r != reason {
				t.Errorf("Subscription-State %+v, want terminated;reason=%s", ss, reason)
			}
			for _, reg := range doc.Registrations {
				if reg.State != reginfo.Terminated || len(reg.Contacts) != 1 || reg.Contacts[0].Event != cause.endEvent() {
					t.Errorf("%s: %+v", reg.AOR, reg)
				}
			}
			if subs, _ := e.store.SubscriptionsOf(bg, impu1); len(subs) != 0 {
				t.Errorf("%d subscriptions left", len(subs))
			}
		})
	}
}

// TestASubscriberThatIsGoneEndsItsSubscription: the codes of RFC 6665
// §4.2.2, 408, 430 (a flow the edge no longer has), no flow or no answer
// end it; any other refusal, or a full queue, does not.
func TestASubscriberThatIsGoneEndsItsSubscription(t *testing.T) {
	type outcome struct {
		status int
		err    error
		ends   bool
	}
	cases := map[string]outcome{
		"no flow":    {err: transport.ErrNoFlow, ends: true},
		"timeout":    {err: context.DeadlineExceeded, ends: true},
		"queue full": {err: transport.ErrQueueFull},
	}
	for _, code := range []int{404, 405, 408, 410, 416, 430, 480, 481, 482, 483, 484, 485, 489, 501, 604} {
		cases[strconv.Itoa(code)] = outcome{status: code, ends: true}
	}
	for _, code := range []int{400, 403, 415, 486, 487, 488, 500, 503, 603} {
		cases[strconv.Itoa(code)] = outcome{status: code}
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			before := e.registered(binding(1, time.Hour))
			n := e.notifier(1)
			e.subscribed(n)
			e.send.mu.Lock()
			e.send.status, e.send.err = c.status, c.err
			e.send.mu.Unlock()
			after := before.Clone()
			after.Contacts[0].Expires = t0.Add(2 * time.Hour)
			n.Changed(bg, before, e.saved(after), Registered)
			n.Wait()
			subs, _ := e.store.SubscriptionsOf(bg, impu1)
			if (len(subs) == 0) != c.ends {
				t.Errorf("%d subscriptions left, want ended %v", len(subs), c.ends)
			}
		})
	}
}

// TestTwoInstancesNeverNumberTwoNotifiesAlike: the CSeq and version come
// from the store's NextNotify (ADR 0005).
func TestTwoInstancesNeverNumberTwoNotifiesAlike(t *testing.T) {
	e := newEnv(t)
	before := e.registered(binding(1, time.Hour))
	m := &counts{}
	a := newNotifierWith(t, e, e.store, e.send, func(c *Config) { c.Metrics = m })
	b := newNotifierWith(t, e, e.store, e.send, func(c *Config) { c.Metrics = m })
	e.subscribed(a)
	// The registrar saves each change before it tells of it.
	afters := make([]*state.Registration, 20)
	for i := range afters {
		after := before.Clone()
		if i > 0 {
			after = afters[i-1].Clone()
		}
		after.Contacts[0].Expires = t0.Add(time.Duration(i+2) * time.Hour)
		afters[i] = e.saved(after)
	}
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			[]*Notifier{a, b}[i%2].Changed(bg, before, afters[i], Registered)
		}()
	}
	wg.Wait()
	a.Wait()
	b.Wait()
	seen := map[[2]uint32]bool{}
	for _, req := range e.send.notifies() {
		doc, cseq, _ := info(t, req)
		k := [2]uint32{cseq, doc.Version}
		if seen[k] {
			t.Errorf("CSeq %d version %d sent twice", cseq, doc.Version)
		}
		seen[k] = true
	}
	// A change whose NOTIFY was waiting already merges into it.
	if got := len(seen) + int(m.get("regevent.notify_merged")); got != 21 {
		t.Errorf("%d distinct NOTIFYs and %d merged, want 21 in all", len(seen), m.get("regevent.notify_merged"))
	}
}

func TestTheSweepEndsAnExpiredSubscription(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 72*time.Hour))
	n := e.notifier(1)
	res, _ := n.Subscribe(bg, subscribe(t, impu1, pcscfPath, 3600))
	wantStatus(t, res, 200)
	e.clock.advance(3601 * time.Second)
	if k, err := n.Sweep(bg, 10); k != 1 || err != nil {
		t.Fatalf("swept %d, %v", k, err)
	}
	got := e.send.notifies()
	if _, _, ss := info(t, got[len(got)-1]); ss.State != "terminated" {
		t.Errorf("Subscription-State %+v", ss)
	} else if r, _ := ss.Params.Get("reason"); r != "timeout" {
		t.Errorf("reason %q", r)
	}
	if subs, _ := e.store.SubscriptionsOf(bg, impu1); len(subs) != 0 {
		t.Errorf("%d subscriptions left", len(subs))
	}
}

func TestASubscriptionLastsAtMostMaxExpires(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, time.Hour))
	n := e.notifier(1)
	res, _ := n.Subscribe(bg, subscribe(t, impu1, pcscfPath, 900000))
	wantStatus(t, res, 200)
	if res.Header.Get("Expires") != "600000" {
		t.Errorf("Expires %q, want MaxExpires", res.Header.Get("Expires"))
	}
	req := subscribe(t, impu1, pcscfPath, -1)
	_ = req.Header.Set("Call-ID", "sub-call-2")
	res, _ = n.Subscribe(bg, req)
	if res.Header.Get("Expires") != "3761" {
		t.Errorf("Expires %q without one asked for, want 3761 (RFC 3680 §4.4)", res.Header.Get("Expires"))
	}
}

// TestOnlyALiveBindingsPathAuthorisesAPCSCF: a binding that has expired,
// though not swept yet, no longer lets its P-CSCF subscribe, while another
// binding keeps the set registered.
func TestOnlyALiveBindingsPathAuthorisesAPCSCF(t *testing.T) {
	e := newEnv(t)
	other := binding(2, 2*time.Hour)
	other.Path = []string{"<sip:orig@pcscf2." + realm + ";lr>"}
	e.registered(binding(1, time.Hour), other)
	e.clock.advance(time.Hour + time.Second)
	res, _ := e.notifier(1).Subscribe(bg, subscribe(t, impu1, pcscfPath, 3600))
	wantStatus(t, res, 403)
}

// TestASubscriptionsNOTIFYsGoOnlyToAPCSCFTheSetCameOver (#256 security
// review): the first hop of the dialog, its first route or without one the
// subscriber's Contact, must be the P-CSCF of a live binding of the set,
// by host and port; anywhere else is refused, so that a SUBSCRIBE cannot
// have the set's state sent to an address of its choice.
func TestASubscriptionsNOTIFYsGoOnlyToAPCSCFTheSetCameOver(t *testing.T) {
	for name, c := range map[string]struct {
		route, contact string
		pai            string
		want           int
	}{
		"routed through the P-CSCF":         {"<sip:pcscf." + realm + ";lr>", "<sip:ue1@192.0.2.11:5060;transport=tcp>", impu1, 200},
		"the P-CSCF itself, no route":       {"", "<sip:pcscf." + realm + ":5060;transport=tcp>", pcscfPath, 200},
		"routed elsewhere":                  {"<sip:attacker.example.com;lr>", "<sip:pcscf." + realm + ":5060;transport=tcp>", pcscfPath, 403},
		"the P-CSCF's host on another port": {"<sip:pcscf." + realm + ":5099;lr>", "<sip:ue1@192.0.2.11:5060;transport=tcp>", impu1, 403},
		"straight to the UE":                {"", "<sip:ue1@192.0.2.11:5060;transport=tcp>", impu1, 403},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.registered(binding(1, time.Hour))
			m := &counts{}
			n := newNotifierWith(t, e, e.store, e.send, func(cfg *Config) { cfg.Metrics = m })
			req := subscribe(t, impu1, c.pai, 3600)
			req.Header.Del("Record-Route")
			if c.route != "" {
				_ = req.Header.Set("Record-Route", c.route)
			}
			_ = req.Header.Set("Contact", c.contact)
			res, _ := n.Subscribe(bg, req)
			wantStatus(t, res, c.want)
			if refused := m.get("regevent.refused_route"); (c.want == 403) != (refused == 1) {
				t.Errorf("regevent.refused_route = %d", refused)
			}
		})
	}
}
