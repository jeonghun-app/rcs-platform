package routing

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/ifc"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/registrar"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// sentRegisters records the third-party REGISTERs and answers each with
// answer (200 when nil); hold, when set, keeps every send until closed.
type sentRegisters struct {
	mu     sync.Mutex
	sent   []*sip.Request
	answer func(*sip.Request) (*sip.Response, error)
	hold   chan struct{}
	inside chan struct{}
}

func (s *sentRegisters) Send(ctx context.Context, req *sip.Request) (*sip.Response, error) {
	s.mu.Lock()
	s.sent = append(s.sent, req)
	answer, hold, inside := s.answer, s.hold, s.inside
	s.mu.Unlock()
	if inside != nil {
		inside <- struct{}{}
	}
	if hold != nil {
		select {
		case <-hold:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if answer != nil {
		return answer(req)
	}
	return sip.NewResponse(req, 200, "", "as")
}

func (s *sentRegisters) got() []*sip.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*sip.Request(nil), s.sent...)
}

// registerTrigger matches a REGISTER, of the given types if any.
func registerTrigger(types ...ifc.RegistrationType) *ifc.TriggerPoint {
	tp := method("REGISTER")
	tp.SPTs[0].RegistrationTypes = types
	return tp
}

// ueRegister is the UE's REGISTER and the registrar's 200 for it.
func ueRegister(t *testing.T) (*sip.Request, *sip.Response) {
	t.Helper()
	req := request(t, "REGISTER", "sip:"+realm, "Contact: <sip:ue1@192.0.2.11:5060;transport=tcp>", "Expires: 600")
	res, err := sip.NewResponse(req.Message, 200, "OK", "reg")
	if err != nil {
		t.Fatal(err)
	}
	return req.Message, res
}

// registration is a third-party registration of impu1 in set1.
func registration(t *testing.T, typ ifc.RegistrationType, expires time.Duration) registrar.ThirdPartyRegistration {
	req, res := ueRegister(t)
	return registrar.ThirdPartyRegistration{Set: set1, IMPU: impu1, Type: typ, Expires: expires, Request: req, Response: res}
}

func withSender(s Sender) func(*Config) { return func(c *Config) { c.Sender = s } }

// TestAServerWhoseCriterionTakesTheREGISTERGetsAThirdPartyREGISTER (TS
// 24.229 §5.4.1.7): to the server's URI, from the S-CSCF, for the user in
// To, with the set's Expires and the S-CSCF as Contact; a server whose
// criteria take only other requests gets none.
func TestAServerWhoseCriterionTakesTheREGISTERGetsAThirdPartyREGISTER(t *testing.T) {
	e := newEnv(t)
	e.profile(t0, criterion(10, rcsAS, method("INVITE"), ifc.SessionTerminated), criterion(40, rcsAS+";transport=tcp", registerTrigger(), ifc.SessionContinued))
	s := &sentRegisters{}
	rt := e.router(nil, withSender(s))
	rt.Registered(bg, registration(t, ifc.InitialRegistration, 599*time.Second+time.Millisecond))
	rt.Stop()
	got := s.got()
	if len(got) != 1 {
		t.Fatalf("%d REGISTERs", len(got))
	}
	r := got[0]
	from, _ := r.Header.From()
	to, _ := r.Header.To()
	cs, _ := r.Header.Contact()
	if r.Method != "REGISTER" || r.URI.String() != rcsAS+";transport=tcp" || to.URI.String() != impu1 || from.Tag() == "" || from.URI.Host != "scscf.rcs.local" {
		t.Errorf("%s %s, From %s, To %s", r.Method, r.URI.String(), from.String(), to.String())
	}
	if len(cs) != 1 || cs[0].URI.Host != "scscf.rcs.local" || r.Header.Get("Expires") != "600" || len(r.Body) != 0 {
		t.Errorf("Contact %v, Expires %q, body %d bytes", cs, r.Header.Get("Expires"), len(r.Body))
	}
	if e.metrics.get("routing.third_party.registered") != 1 {
		t.Error("not counted")
	}
}

// TestAServerAsksForTheREGISTERAndThe200InTheBody: message/sip each, both
// in multipart/mixed (§5.4.1.7).
func TestAServerAsksForTheREGISTERAndThe200InTheBody(t *testing.T) {
	for name, c := range map[string]struct {
		request, response bool
		parts             []string
	}{
		"the REGISTER": {true, false, []string{"REGISTER sip:"}},
		"the 200":      {false, true, []string{"SIP/2.0 200 OK"}},
		"both":         {true, true, []string{"REGISTER sip:", "SIP/2.0 200 OK"}},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			fc := criterion(40, rcsAS, registerTrigger(), ifc.SessionContinued)
			fc.ApplicationServer.IncludeRegisterRequest, fc.ApplicationServer.IncludeRegisterResponse = c.request, c.response
			e.profile(t0, fc)
			s := &sentRegisters{}
			rt := e.router(nil, withSender(s))
			rt.Registered(bg, registration(t, ifc.InitialRegistration, time.Hour))
			rt.Stop()
			r := s.got()[0]
			ct := r.Header.Get("Content-Type")
			switch len(c.parts) {
			case 1:
				if ct != "message/sip" || !bytes.HasPrefix(r.Body, []byte(c.parts[0])) {
					t.Errorf("Content-Type %q, body %q", ct, r.Body)
				}
				if _, err := sip.ParseMessage(r.Body); err != nil {
					t.Errorf("the part does not parse: %v", err)
				}
			default:
				_, boundary, ok := strings.Cut(ct, "boundary=")
				if !strings.HasPrefix(ct, "multipart/mixed") || !ok {
					t.Fatalf("Content-Type %q", ct)
				}
				parts := strings.Split(string(r.Body), "--"+boundary)
				if len(parts) != 4 || !strings.HasPrefix(parts[3], "--") {
					t.Fatalf("body %q", r.Body)
				}
				for i, want := range c.parts {
					head, part, _ := strings.Cut(parts[i+1], "\r\n\r\n")
					if !strings.Contains(head, "Content-Type: message/sip") || !strings.HasPrefix(part, want) {
						t.Errorf("part %d: %q", i, parts[i+1])
					}
				}
			}
		})
	}
}

// TestAnEndTheNetworkMadeIsSentWithoutABody: Expires 0, matched against a
// REGISTER for the user, as no UE's came; the profile the registrar had at
// hand serves, as the store's is gone.
func TestAnEndTheNetworkMadeIsSentWithoutABody(t *testing.T) {
	e := newEnv(t)
	fc := criterion(40, rcsAS, registerTrigger(ifc.DeRegistration), ifc.SessionContinued)
	fc.ApplicationServer.IncludeRegisterRequest, fc.ApplicationServer.IncludeRegisterResponse = true, true
	e.profile(t0, fc)
	p, err := e.store.Profile(bg, set1, t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.store.DeleteProfile(bg, set1); err != nil {
		t.Fatal(err)
	}
	s := &sentRegisters{}
	rt := e.router(nil, withSender(s))
	rt.Registered(bg, registrar.ThirdPartyRegistration{Set: set1, IMPU: impu1, Type: ifc.DeRegistration, Profile: p})
	rt.Stop()
	got := s.got()
	if len(got) != 1 || got[0].Header.Get("Expires") != "0" || len(got[0].Body) != 0 {
		t.Fatalf("%d REGISTERs: %v", len(got), got)
	}
}

// TestTheRegistrationTypeChoosesTheServers (TS 29.228 B.2.3): a criterion
// for de-registrations only takes none other.
func TestTheRegistrationTypeChoosesTheServers(t *testing.T) {
	e := newEnv(t)
	e.profile(t0, criterion(40, rcsAS, registerTrigger(ifc.DeRegistration), ifc.SessionContinued))
	s := &sentRegisters{}
	rt := e.router(nil, withSender(s))
	rt.Registered(bg, registration(t, ifc.ReRegistration, time.Hour))
	rt.Registered(bg, registration(t, ifc.DeRegistration, 0))
	rt.Stop()
	if got := s.got(); len(got) != 1 || got[0].Header.Get("Expires") != "0" {
		t.Errorf("%d sent, want the de-registration alone", len(got))
	}
}

// TestOneSetsRegistrationsGoInTheirOrder: the next waits for the one before,
// so that a server does not hear a registration after the deregistration
// that followed it; another set's does not wait.
func TestOneSetsRegistrationsGoInTheirOrder(t *testing.T) {
	e := newEnv(t)
	e.profile(t0, criterion(40, rcsAS, registerTrigger(), ifc.SessionContinued))
	s := &orderedSender{held: make(chan struct{}), finished: make(chan string, 8), expires: map[string][]string{}}
	rt := e.router(nil, withSender(s))
	rt.Registered(bg, registration(t, ifc.InitialRegistration, time.Hour))
	rt.Registered(bg, registration(t, ifc.DeRegistration, 0))
	other := registration(t, ifc.InitialRegistration, time.Hour)
	other.Set = state.SetKey{IMPI: "001010000000002@" + realm, IMPU: impu2}
	other.IMPU = impu2
	other.Profile = profileFor(t, e, other.Set, impu2)
	rt.Registered(bg, other)
	// The other set's goes while the first is held.
	if to := recv(t, s.finished); to != impu2 {
		t.Fatalf("%s finished first", to)
	}
	close(s.held)
	rt.Stop()
	close(s.finished)
	var order []string
	for to := range s.finished {
		order = append(order, to)
	}
	if len(order) != 2 || s.expires[impu1][0] != "3600" || s.expires[impu1][1] != "0" {
		t.Errorf("then %v, impu1's Expires in order %v", order, s.expires[impu1])
	}
}

// orderedSender holds the first REGISTER for impu1 until held is closed,
// and reports each REGISTER's To as it finishes.
type orderedSender struct {
	mu       sync.Mutex
	held     chan struct{}
	first    bool
	expires  map[string][]string
	finished chan string
}

func (s *orderedSender) Send(_ context.Context, req *sip.Request) (*sip.Response, error) {
	to, _ := req.Header.To()
	s.mu.Lock()
	hold := !s.first && to.URI.String() == impu1
	s.first = s.first || hold
	s.mu.Unlock()
	if hold {
		<-s.held
	}
	s.mu.Lock()
	s.expires[to.URI.String()] = append(s.expires[to.URI.String()], req.Header.Get("Expires"))
	s.mu.Unlock()
	s.finished <- to.URI.String()
	return sip.NewResponse(req, 200, "", "as")
}

// profileFor is a profile of set with a REGISTER criterion for impu.
func profileFor(t *testing.T, e *env, set state.SetKey, impu string) *state.Profile {
	t.Helper()
	sub := ifc.Subscription{PrivateID: set.IMPI, ServiceProfiles: []ifc.ServiceProfile{{
		PublicIdentities:      []ifc.PublicIdentity{{Identity: impu}},
		InitialFilterCriteria: []ifc.FilterCriteria{criterion(40, rcsAS, registerTrigger(), ifc.SessionContinued)},
	}}}
	data, err := sub.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return &state.Profile{Key: set, UserData: data, Received: t0, KeepUntil: t0.Add(time.Hour)}
}

// recv is the next value from ch, failing the test if none comes soon.
func recv[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(10 * time.Second):
		t.Fatal("nothing came")
	}
	panic("unreachable")
}

// otherSet is a registration of the n-th of other users' sets, with a
// REGISTER criterion to rcsAS.
func otherSet(t *testing.T, e *env, n int) registrar.ThirdPartyRegistration {
	t.Helper()
	impu := fmt.Sprintf("sip:user%03d@%s", n, realm)
	r := registration(t, ifc.InitialRegistration, time.Hour)
	r.Set = state.SetKey{IMPI: fmt.Sprintf("user%03d@%s", n, realm), IMPU: impu}
	r.IMPU, r.Profile = impu, profileFor(t, e, r.Set, impu)
	return r
}

// TestRegistrationsPastAServersQueueAreDropped: with the server's one slot
// held, four registrations of as many sets wait for it, and one more is
// counted and not sent.
func TestRegistrationsPastAServersQueueAreDropped(t *testing.T) {
	e := newEnv(t)
	s := &sentRegisters{hold: make(chan struct{}), inside: make(chan struct{}, 8)}
	rt := e.router(nil, withSender(s), func(c *Config) { c.MaxThirdParty = 1 })
	for n := range queuedPerServer + 1 {
		rt.Registered(bg, otherSet(t, e, n))
		if n == 0 {
			recv(t, s.inside)
		}
	}
	dropped := e.metrics.get("routing.third_party.dropped")
	close(s.hold)
	rt.Stop()
	if len(s.got()) != queuedPerServer || dropped != 1 {
		t.Errorf("%d sent, %d dropped", len(s.got()), dropped)
	}
}

// TestOneSetsQueueLeavesRoomForOthers (#379 code review and QA): a set's
// refreshes past queuedPerSet are dropped while its first is at the
// server, and another user's registration goes meanwhile.
func TestOneSetsQueueLeavesRoomForOthers(t *testing.T) {
	e := newEnv(t)
	e.profile(t0, criterion(40, rcsAS, registerTrigger(), ifc.SessionContinued))
	// Room for every send, so that a queue past its bound fails the test
	// rather than blocks it.
	s := &sentRegisters{hold: make(chan struct{}), inside: make(chan struct{}, 2*DefaultMaxThirdParty)}
	rt := e.router(nil, withSender(s))
	for range DefaultMaxThirdParty {
		rt.Registered(bg, registration(t, ifc.ReRegistration, time.Hour))
	}
	recv(t, s.inside)
	rt.Registered(bg, otherSet(t, e, 1))
	recv(t, s.inside)
	if got := s.got(); len(got) != 2 || got[1].Header.Get("To") != "<sip:user001@"+realm+">" {
		t.Errorf("sent %d; the other user's is not at the server", len(got))
	}
	close(s.hold)
	rt.Stop()
	if n, d := len(s.got()), e.metrics.get("routing.third_party.replaced"); n != queuedPerSet+1 || d != int64(DefaultMaxThirdParty-queuedPerSet) {
		t.Errorf("%d sent, %d replaced", n, d)
	}
}

// TestASetsEndTakesThePlaceOfItsLastWaitingRegistration (#379 code
// review): with the set's queue full behind a slow server, its end is not
// dropped but replaces the last refresh waiting, so that the server hears
// the end last.
func TestASetsEndTakesThePlaceOfItsLastWaitingRegistration(t *testing.T) {
	for name, c := range map[string]struct {
		max, refreshes, others int
	}{
		"the set's queue": {DefaultMaxThirdParty, queuedPerSet - 1, 0},
		// One slot, so four queued fill the server's queue: the set's
		// first and a refresh, and two other sets'.
		"the server's queue": {1, 1, queuedPerServer - 2},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.profile(t0, criterion(40, rcsAS, registerTrigger(), ifc.SessionContinued))
			s := &orderedExpires{hold: make(chan struct{}), inside: make(chan struct{}, 16)}
			rt := e.router(nil, withSender(s), func(cfg *Config) { cfg.MaxThirdParty = c.max })
			rt.Registered(bg, registration(t, ifc.InitialRegistration, time.Hour))
			recv(t, s.inside)
			for range c.refreshes {
				rt.Registered(bg, registration(t, ifc.ReRegistration, time.Hour))
			}
			for n := range c.others {
				rt.Registered(bg, otherSet(t, e, n))
			}
			rt.Registered(bg, registration(t, ifc.DeRegistration, 0))
			close(s.hold)
			rt.Stop()
			got := s.expiresOf(impu1)
			if len(got) == 0 || got[len(got)-1] != "0" || e.metrics.get("routing.third_party.replaced") != 1 || e.metrics.get("routing.third_party.dropped") != 0 {
				t.Errorf("the server heard %v for the set; replaced %d, dropped %d", got, e.metrics.get("routing.third_party.replaced"), e.metrics.get("routing.third_party.dropped"))
			}
		})
	}
}

// orderedExpires holds every REGISTER until hold is closed, signalling
// inside as each arrives, and records each one's To and Expires in order.
type orderedExpires struct {
	mu     sync.Mutex
	hold   chan struct{}
	inside chan struct{}
	sent   [][2]string
}

func (s *orderedExpires) Send(_ context.Context, req *sip.Request) (*sip.Response, error) {
	s.inside <- struct{}{}
	<-s.hold
	to, _ := req.Header.To()
	s.mu.Lock()
	s.sent = append(s.sent, [2]string{to.URI.String(), req.Header.Get("Expires")})
	s.mu.Unlock()
	return sip.NewResponse(req, 200, "", "as")
}

func (s *orderedExpires) expiresOf(impu string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, r := range s.sent {
		if r[0] == impu {
			out = append(out, r[1])
		}
	}
	return out
}

// TestWhatAServerAnswersIsCounted: a 2xx registers, another answer is the
// server's refusal, and no answer, a 408 or a 5xx leaves the registration
// to its default handling, which for SESSION_TERMINATED is counted apart.
func TestWhatAServerAnswersIsCounted(t *testing.T) {
	for name, c := range map[string]struct {
		answer   func(*sip.Request) (*sip.Response, error)
		handling ifc.DefaultHandling
		counted  string
	}{
		"200":                  {nil, ifc.SessionContinued, "routing.third_party.registered"},
		"403":                  {status(403), ifc.SessionTerminated, "routing.third_party.refused"},
		"408":                  {status(408), ifc.SessionContinued, "routing.third_party.unanswered"},
		"503":                  {status(503), ifc.SessionContinued, "routing.third_party.unanswered"},
		"no answer":            {func(*sip.Request) (*sip.Response, error) { return nil, errors.New("timeout") }, ifc.SessionContinued, "routing.third_party.unanswered"},
		"no answer, terminate": {func(*sip.Request) (*sip.Response, error) { return nil, errors.New("timeout") }, ifc.SessionTerminated, "routing.third_party.terminated_unanswered"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.profile(t0, criterion(40, rcsAS, registerTrigger(), c.handling))
			rt := e.router(nil, withSender(&sentRegisters{answer: c.answer}))
			rt.Registered(bg, registration(t, ifc.InitialRegistration, time.Hour))
			rt.Stop()
			if e.metrics.get(c.counted) != 1 {
				t.Errorf("%s not counted", c.counted)
			}
			if c.handling != ifc.SessionTerminated && e.metrics.get("routing.third_party.terminated_unanswered") != 0 {
				t.Error("a server whose session continues is counted as one that ends it")
			}
		})
	}
}

func status(code int) func(*sip.Request) (*sip.Response, error) {
	return func(req *sip.Request) (*sip.Response, error) { return sip.NewResponse(req, code, "", "as") }
}

// TestNothingIsSentWithoutASenderOrACriterion: and a ServerName that is no
// SIP URI is counted.
func TestNothingIsSentWithoutASenderOrACriterion(t *testing.T) {
	e := newEnv(t)
	e.profile(t0, criterion(40, "tel:+15550100005", registerTrigger(), ifc.SessionContinued))
	e.router(nil).Registered(bg, registration(t, ifc.InitialRegistration, time.Hour))
	s := &sentRegisters{}
	rt := e.router(nil, withSender(s))
	rt.Registered(bg, registration(t, ifc.InitialRegistration, time.Hour))
	rt.Stop()
	if len(s.got()) != 0 || e.metrics.get("routing.third_party.bad_server") != 1 {
		t.Errorf("%d sent, bad servers %d", len(s.got()), e.metrics.get("routing.third_party.bad_server"))
	}
	e2 := newEnv(t)
	rt = e2.router(nil, withSender(s))
	rt.Registered(bg, registration(t, ifc.InitialRegistration, time.Hour))
	rt.Stop()
	if len(s.got()) != 0 {
		t.Error("sent without a profile")
	}
}

// expiringSender holds each REGISTER whose Expires is in hold until that
// value is let go, and reports the Expires of each as it finishes.
type expiringSender struct {
	mu       sync.Mutex
	hold     map[string]chan struct{}
	finished chan string
}

func (s *expiringSender) Send(_ context.Context, req *sip.Request) (*sip.Response, error) {
	exp := req.Header.Get("Expires")
	s.mu.Lock()
	h := s.hold[exp]
	s.mu.Unlock()
	if h != nil {
		<-h
	}
	s.finished <- exp
	return sip.NewResponse(req, 200, "", "as")
}

// TestALaterRegistrationWaitsForEveryOneBeforeIt: when the first of a set's
// queued registrations ends, the set's queue still has the later ones, and
// one told of next waits for them too.
func TestALaterRegistrationWaitsForEveryOneBeforeIt(t *testing.T) {
	e := newEnv(t)
	e.profile(t0, criterion(40, rcsAS, registerTrigger(), ifc.SessionContinued))
	s := &expiringSender{hold: map[string]chan struct{}{"100": make(chan struct{}), "200": make(chan struct{})}, finished: make(chan string, 8)}
	rt := e.router(nil, withSender(s))
	for _, exp := range []time.Duration{100, 200, 300} {
		rt.Registered(bg, registration(t, ifc.ReRegistration, exp*time.Second))
	}
	close(s.hold["100"])
	if got := recv(t, s.finished); got != "100" {
		t.Fatalf("%s finished first", got)
	}
	rt.Registered(bg, registration(t, ifc.ReRegistration, 400*time.Second))
	close(s.hold["200"])
	rt.Stop()
	close(s.finished)
	var order []string
	for exp := range s.finished {
		order = append(order, exp)
	}
	if !slices.Equal(order, []string{"200", "300", "400"}) {
		t.Errorf("then in the order %v", order)
	}
}

type senderFunc func(context.Context, *sip.Request) (*sip.Response, error)

func (f senderFunc) Send(ctx context.Context, req *sip.Request) (*sip.Response, error) {
	return f(ctx, req)
}

// TestAServerThatDoesNotAnswerHoldsUpNoOther (#379 QA): an operator server
// that never answers, before rcs-as in priority, has its queue fill while
// rcs-as gets each of a burst of registrations at once.
func TestAServerThatDoesNotAnswerHoldsUpNoOther(t *testing.T) {
	e := newEnv(t)
	dead := make(chan struct{})
	toRCSAS := make(chan struct{}, 512)
	var atDead atomic.Int64
	s := senderFunc(func(ctx context.Context, req *sip.Request) (*sip.Response, error) {
		if req.URI.Host == "operator-as.rcs.local" {
			atDead.Add(1)
			<-dead
			return nil, errors.New("no answer")
		}
		toRCSAS <- struct{}{}
		return sip.NewResponse(req, 200, "", "as")
	})
	rt := e.router(nil, withSender(s))
	const n = 300
	for i := range n {
		r := otherSet(t, e, i)
		sub := ifc.Subscription{PrivateID: r.Set.IMPI, ServiceProfiles: []ifc.ServiceProfile{{
			PublicIdentities: []ifc.PublicIdentity{{Identity: r.IMPU}},
			InitialFilterCriteria: []ifc.FilterCriteria{
				criterion(10, operatorAS, registerTrigger(), ifc.SessionContinued),
				criterion(40, rcsAS, registerTrigger(), ifc.SessionContinued),
			},
		}}}
		data, err := sub.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		r.Profile.UserData = data
		rt.Registered(bg, r)
	}
	for range n {
		recv(t, toRCSAS)
	}
	if got := atDead.Load(); got > DefaultMaxThirdParty {
		t.Errorf("%d at the silent server at once, past %d", got, DefaultMaxThirdParty)
	}
	close(dead)
	rt.Stop()
	if d := e.metrics.get("routing.third_party.dropped"); d != 0 {
		t.Errorf("%d dropped", d)
	}
}

// TestASixHundredIsTheServersRefusal (§5.4.1.7, #379 code review): only no
// answer, a 408 and a 5xx have the default handling apply.
func TestASixHundredIsTheServersRefusal(t *testing.T) {
	for _, h := range []ifc.DefaultHandling{ifc.SessionContinued, ifc.SessionTerminated} {
		for _, code := range []int{600, 603, 604, 606} {
			e := newEnv(t)
			e.profile(t0, criterion(40, rcsAS, registerTrigger(), h))
			rt := e.router(nil, withSender(&sentRegisters{answer: status(code)}))
			rt.Registered(bg, registration(t, ifc.InitialRegistration, time.Hour))
			rt.Stop()
			if e.metrics.get("routing.third_party.refused") != 1 || e.metrics.get("routing.third_party.unanswered") != 0 {
				t.Errorf("handling %d, %d: not counted as refused", h, code)
			}
		}
	}
}

// TestRegistrationsToldWhileTheRouterStopsAreDroppedOrSent (#379 QA): Stop
// stops new ones, so that none is added to what it waits for meanwhile;
// each is sent or counted.
func TestRegistrationsToldWhileTheRouterStopsAreDroppedOrSent(t *testing.T) {
	e := newEnv(t)
	e.profile(t0, criterion(40, rcsAS, registerTrigger(), ifc.SessionContinued))
	s := &sentRegisters{}
	rt := e.router(nil, withSender(s))
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Go(func() {
			for range 4 {
				rt.Registered(bg, otherSet(t, e, i))
			}
		})
	}
	wg.Go(func() {
		for range 50 {
			rt.Stop()
		}
	})
	wg.Wait()
	rt.Stop()
	if n := int64(len(s.got())) + e.metrics.get("routing.third_party.dropped"); n != 64 {
		t.Errorf("%d sent or dropped of 64", n)
	}
	rt.Registered(bg, registration(t, ifc.InitialRegistration, time.Hour))
	if e.metrics.get("routing.third_party.dropped") == 0 {
		t.Error("a registration told after Stop was not dropped")
	}
}

// TestAThirdPartyREGISTERIsBoundedByThirdPartyTimeout (#379 QA).
func TestAThirdPartyREGISTERIsBoundedByThirdPartyTimeout(t *testing.T) {
	if DefaultThirdPartyTimeout != 10*time.Second {
		t.Errorf("DefaultThirdPartyTimeout %v", DefaultThirdPartyTimeout)
	}
	for _, c := range []struct{ cfg, want time.Duration }{{0, DefaultThirdPartyTimeout}, {150 * time.Millisecond, 150 * time.Millisecond}} {
		e := newEnv(t)
		e.profile(t0, criterion(40, rcsAS, registerTrigger(), ifc.SessionContinued))
		// The deadline is wall clock, the transaction's, not the S-CSCF's
		// injected time: it is set after start, so it is at least the
		// timeout past start, and before the send reads it, so at most the
		// timeout past then, however slow the scheduler.
		var sinceStart, untilEnd atomic.Int64
		start := time.Now()
		s := senderFunc(func(ctx context.Context, req *sip.Request) (*sip.Response, error) {
			now := time.Now()
			d, ok := ctx.Deadline()
			if !ok {
				return nil, errors.New("no deadline")
			}
			sinceStart.Store(int64(d.Sub(start)))
			untilEnd.Store(int64(d.Sub(now)))
			return sip.NewResponse(req, 200, "", "as")
		})
		rt := e.router(nil, withSender(s), func(cfg *Config) { cfg.ThirdPartyTimeout = c.cfg })
		rt.Registered(bg, registration(t, ifc.InitialRegistration, time.Hour))
		rt.Stop()
		if from, until := time.Duration(sinceStart.Load()), time.Duration(untilEnd.Load()); from < c.want || until > c.want {
			t.Errorf("deadline %v after the start and %v after the send, want at least and at most %v", from, until, c.want)
		}
	}
}

// TestAtMostTheBoundAreAtAServerAtOnce (#379 QA): of a burst past
// DefaultMaxThirdParty to one server that holds them, that many are at it,
// the rest wait, and every one is sent in the end.
func TestAtMostTheBoundAreAtAServerAtOnce(t *testing.T) {
	if DefaultMaxThirdParty != 256 {
		t.Errorf("DefaultMaxThirdParty %d", DefaultMaxThirdParty)
	}
	e := newEnv(t)
	s := &sentRegisters{hold: make(chan struct{}), inside: make(chan struct{}, 512)}
	rt := e.router(nil, withSender(s))
	const n = 300
	for i := range n {
		rt.Registered(bg, otherSet(t, e, i))
	}
	for range DefaultMaxThirdParty {
		recv(t, s.inside)
	}
	at := len(s.got())
	close(s.hold)
	rt.Stop()
	if at != DefaultMaxThirdParty || len(s.got()) != n || e.metrics.get("routing.third_party.dropped") != 0 {
		t.Errorf("%d at the server at once, %d sent, %d dropped", at, len(s.got()), e.metrics.get("routing.third_party.dropped"))
	}
}

// TestARegistrationOutlivesItsCallerAndWhatItChangesAfterward (#379 QA):
// the caller's context ending, and its REGISTER and 200 changing once
// Registered has returned, change nothing of what is sent; a 202 is a
// registration, and the S-CSCF's Contact names TCP.
func TestARegistrationOutlivesItsCallerAndWhatItChangesAfterward(t *testing.T) {
	e := newEnv(t)
	fc := criterion(40, rcsAS, registerTrigger(), ifc.SessionContinued)
	fc.ApplicationServer.IncludeRegisterRequest, fc.ApplicationServer.IncludeRegisterResponse = true, true
	e.profile(t0, fc)
	release := make(chan struct{})
	var sent atomic.Pointer[sip.Request]
	s := senderFunc(func(ctx context.Context, req *sip.Request) (*sip.Response, error) {
		<-release
		sent.Store(req)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return sip.NewResponse(req, 202, "", "as")
	})
	rt := e.router(nil, withSender(s))
	ctx, cancel := context.WithCancel(bg)
	r := registration(t, ifc.InitialRegistration, time.Hour)
	rt.Registered(ctx, r)
	cancel()
	_ = r.Request.Header.Set("Expires", "1")
	_ = r.Response.Header.Set("Expires", "2")
	close(release)
	rt.Stop()
	got := sent.Load()
	if got == nil || e.metrics.get("routing.third_party.registered") != 1 {
		t.Fatalf("registered %d, unanswered %d, refused %d", e.metrics.get("routing.third_party.registered"),
			e.metrics.get("routing.third_party.unanswered"), e.metrics.get("routing.third_party.refused"))
	}
	if bytes.Contains(got.Body, []byte("Expires: 1\r\n")) || bytes.Contains(got.Body, []byte("Expires: 2\r\n")) {
		t.Error("the body carries what the caller changed after Registered returned")
	}
	cs, _ := got.Header.Contact()
	if len(cs) != 1 {
		t.Fatalf("Contact %v", cs)
	}
	if tr, _ := cs[0].URI.Params.Get("transport"); tr != "tcp" {
		t.Errorf("Contact %v", cs)
	}
}

// TestAnOriginatingCriterionTakesTheREGISTER (#379 QA): the REGISTER is
// matched in the originating case (TS 29.228 B.2.3).
func TestAnOriginatingCriterionTakesTheREGISTER(t *testing.T) {
	e := newEnv(t)
	tp := registerTrigger()
	tp.SPTs = append(tp.SPTs, ifc.SPT{Condition: ifc.Originating, Groups: []int{1}})
	e.profile(t0, criterion(40, rcsAS, tp, ifc.SessionContinued))
	s := &sentRegisters{}
	rt := e.router(nil, withSender(s))
	rt.Registered(bg, registration(t, ifc.InitialRegistration, time.Hour))
	rt.Stop()
	if len(s.got()) != 1 {
		t.Errorf("%d sent", len(s.got()))
	}
}

// TestTheBodysREGISTERCarriesNoCredentials (#379, lead's decision): the
// Authorization and Proxy-Authorization of the UE's REGISTER stay out of
// the server's body.
func TestTheBodysREGISTERCarriesNoCredentials(t *testing.T) {
	e := newEnv(t)
	fc := criterion(40, rcsAS, registerTrigger(), ifc.SessionContinued)
	fc.ApplicationServer.IncludeRegisterRequest = true
	e.profile(t0, fc)
	s := &sentRegisters{}
	rt := e.router(nil, withSender(s))
	r := registration(t, ifc.InitialRegistration, time.Hour)
	for _, h := range []string{"Authorization", "Proxy-Authorization"} {
		if err := r.Request.Header.Add(h, `Digest username="001010000000001@`+realm+`", realm="`+realm+`", nonce="bm9uY2U=", uri="sip:`+realm+`", response="0123456789abcdef0123456789abcdef"`); err != nil {
			t.Fatal(err)
		}
	}
	rt.Registered(bg, r)
	rt.Stop()
	got := s.got()
	if len(got) != 1 {
		t.Fatalf("%d sent", len(got))
	}
	if b := string(got[0].Body); !strings.HasPrefix(b, "REGISTER ") || strings.Contains(b, "Authorization") || strings.Contains(b, "response=") {
		t.Errorf("body %q", b)
	}
	if r.Request.Header.Get("Authorization") == "" {
		t.Error("the caller's REGISTER lost its Authorization")
	}
}

// TestARegistrationWaitingForItsSetHoldsNoSlot (#379 QA): with two slots,
// set1's first at the server and two more queued behind it, another
// user's still reaches the server. The pause gives the queued ones the time
// to take the slots if they held one while waiting; the test passes
// without it on this code, whatever the scheduling.
func TestARegistrationWaitingForItsSetHoldsNoSlot(t *testing.T) {
	e := newEnv(t)
	e.profile(t0, criterion(40, rcsAS, registerTrigger(), ifc.SessionContinued))
	release := make(chan struct{})
	arrived := make(chan string, 8)
	s := senderFunc(func(ctx context.Context, req *sip.Request) (*sip.Response, error) {
		to, _ := req.Header.To()
		arrived <- to.URI.String()
		if to.URI.String() == impu1 {
			<-release
		}
		return sip.NewResponse(req, 200, "", "as")
	})
	rt := e.router(nil, withSender(s), func(c *Config) { c.MaxThirdParty = 2 })
	defer func() { close(release); rt.Stop() }()
	for range 3 {
		rt.Registered(bg, registration(t, ifc.ReRegistration, time.Hour))
	}
	if got := recv(t, arrived); got != impu1 {
		t.Fatalf("%s first", got)
	}
	time.Sleep(100 * time.Millisecond)
	rt.Registered(bg, otherSet(t, e, 1))
	select {
	case got := <-arrived:
		if got != "sip:user001@"+realm {
			t.Errorf("%s arrived, want the other user's", got)
		}
	case <-time.After(5 * time.Second):
		t.Error("the other user's registration waited for set1's queue: a waiting registration held a slot")
	}
}

// twoIdentities is a profile of set1 in which impu1 and impu2 both have
// the REGISTER criterion, and a registration of each.
func twoIdentities(t *testing.T, typ ifc.RegistrationType, expires time.Duration) (registrar.ThirdPartyRegistration, registrar.ThirdPartyRegistration) {
	t.Helper()
	sub := ifc.Subscription{PrivateID: set1.IMPI, ServiceProfiles: []ifc.ServiceProfile{{
		PublicIdentities:      []ifc.PublicIdentity{{Identity: impu1}, {Identity: impu2}},
		InitialFilterCriteria: []ifc.FilterCriteria{criterion(40, rcsAS, registerTrigger(), ifc.SessionContinued)},
	}}}
	data, err := sub.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	p := &state.Profile{Key: set1, UserData: data, Received: t0, KeepUntil: t0.Add(time.Hour)}
	a := registration(t, typ, expires)
	a.Profile = p
	b := a
	b.IMPU = impu2
	return a, b
}

// TestASetsEndIsNotDroppedWhenItsServersQueueIsFull (#420, QA on #379 and
// #446): with the server's queue full of other sets' registrations and
// nothing of the ending set's waiting, the end goes past the bound and
// reaches the server. A refresh past the bound is dropped; an end past the
// headroom too evicts the oldest refresh waiting, and is sent.
func TestASetsEndIsNotDroppedWhenItsServersQueueIsFull(t *testing.T) {
	e := newEnv(t)
	s := &orderedExpires{hold: make(chan struct{}), inside: make(chan struct{}, 16)}
	rt := e.router(nil, withSender(s), func(cfg *Config) { cfg.MaxThirdParty = 1 })
	// One slot, so four queued fill the server's queue: one at the server
	// and three waiting, all other sets'.
	for n := range queuedPerServer {
		rt.Registered(bg, otherSet(t, e, n))
		if n == 0 {
			recv(t, s.inside)
		}
	}
	end := registration(t, ifc.DeRegistration, 0)
	end.Profile = profileFor(t, e, set1, impu1)
	rt.Registered(bg, end)
	// A refresh of yet another set has no allowance past the bound, and
	// another end none past the headroom, MaxThirdParty, which the first
	// took: it evicts the oldest refresh waiting, user001's.
	rt.Registered(bg, otherSet(t, e, queuedPerServer))
	other := otherSet(t, e, queuedPerServer+1)
	other.Type, other.Expires = ifc.DeRegistration, 0
	rt.Registered(bg, other)
	close(s.hold)
	rt.Stop()
	if got := s.expiresOf(impu1); len(got) != 1 || got[0] != "0" {
		t.Errorf("the server heard %v for the ending set, want its end", got)
	}
	if got := s.expiresOf(other.IMPU); len(got) != 1 || got[0] != "0" {
		t.Errorf("the server heard %v for the other ending set, want its end", got)
	}
	if got := s.expiresOf("sip:user001@" + realm); len(got) != 0 {
		t.Errorf("the server heard %v for the evicted refresh", got)
	}
	for name, want := range map[string]int64{"end_past_bound": 1, "dropped": 1, "evicted": 1, "end_dropped": 0} {
		if got := e.metrics.get("routing.third_party." + name); got != want {
			t.Errorf("%s %d, want %d", name, got, want)
		}
	}
}

// TestAnEndIsDroppedOnlyWithNothingButEndsQueued (#446, the lead's decision
// on #420): with the server's queue and its headroom full of ends, none of
// them a refresh to evict, one more end is dropped and counted apart.
func TestAnEndIsDroppedOnlyWithNothingButEndsQueued(t *testing.T) {
	e := newEnv(t)
	s := &orderedExpires{hold: make(chan struct{}), inside: make(chan struct{}, 16)}
	rt := e.router(nil, withSender(s), func(cfg *Config) { cfg.MaxThirdParty = 1 })
	end := func(n int) registrar.ThirdPartyRegistration {
		r := otherSet(t, e, n)
		r.Type, r.Expires = ifc.DeRegistration, 0
		return r
	}
	for n := range queuedPerServer + 2 {
		rt.Registered(bg, end(n))
		if n == 0 {
			recv(t, s.inside)
		}
	}
	close(s.hold)
	rt.Stop()
	if got := len(s.sent); got != queuedPerServer+1 {
		t.Errorf("%d ends sent, want %d", got, queuedPerServer+1)
	}
	if got := e.metrics.get("routing.third_party.end_dropped"); got != 1 {
		t.Errorf("end_dropped %d, want 1", got)
	}
	if got := e.metrics.get("routing.third_party.dropped"); got != 0 {
		t.Errorf("dropped %d: an end counted as a dropped refresh", got)
	}
}

// TestEndsEvictWaitingRefreshesBeforeTheyAreDropped (#446 QA): a queue of
// refreshes, which could make room, and more ends of other sets than the
// headroom takes: every end reaches the server.
func TestEndsEvictWaitingRefreshesBeforeTheyAreDropped(t *testing.T) {
	e := newEnv(t)
	s := &orderedExpires{hold: make(chan struct{}), inside: make(chan struct{}, 64)}
	const max = 2
	rt := e.router(nil, withSender(s), func(cfg *Config) { cfg.MaxThirdParty = max })
	for n := range queuedPerServer * max {
		rt.Registered(bg, otherSet(t, e, n))
		if n < max {
			recv(t, s.inside)
		}
	}
	var ends []registrar.ThirdPartyRegistration
	for n := 100; n < 100+max+1; n++ {
		r := otherSet(t, e, n)
		r.Type, r.Expires = ifc.DeRegistration, 0
		ends = append(ends, r)
		rt.Registered(bg, r)
	}
	close(s.hold)
	rt.Stop()
	for _, r := range ends {
		if got := s.expiresOf(r.IMPU); len(got) != 1 || got[0] != "0" {
			t.Errorf("%s heard %v, want its end", r.IMPU, got)
		}
	}
	if got := e.metrics.get("routing.third_party.end_dropped"); got != 0 {
		t.Errorf("end_dropped %d with refreshes to evict", got)
	}
}

// TestBothIdentitiesHearTheirEndsAtAFullServerQueue (#446 QA): two
// identities of a set end while the server's queue is full of other sets'
// refreshes and has one slot: both hear Expires 0.
func TestBothIdentitiesHearTheirEndsAtAFullServerQueue(t *testing.T) {
	e := newEnv(t)
	s := &orderedExpires{hold: make(chan struct{}), inside: make(chan struct{}, 64)}
	rt := e.router(nil, withSender(s), func(cfg *Config) { cfg.MaxThirdParty = 1 })
	for n := range queuedPerServer {
		rt.Registered(bg, otherSet(t, e, n))
		if n == 0 {
			recv(t, s.inside)
		}
	}
	endA, endB := twoIdentities(t, ifc.DeRegistration, 0)
	rt.Registered(bg, endA)
	rt.Registered(bg, endB)
	close(s.hold)
	rt.Stop()
	for _, impu := range []string{impu1, impu2} {
		if got := s.expiresOf(impu); len(got) != 1 || got[0] != "0" {
			t.Errorf("%s heard %v, want its end", impu, got)
		}
	}
}

// TestASetsIdentitiesShareItsCap (#446 code review): the per-set cap counts
// a whole set, whatever its identities, so a set refreshing two identities
// eight times each leaves room for another user's registration.
func TestASetsIdentitiesShareItsCap(t *testing.T) {
	e := newEnv(t)
	s := &orderedExpires{hold: make(chan struct{}), inside: make(chan struct{}, 64)}
	rt := e.router(nil, withSender(s), func(cfg *Config) { cfg.MaxThirdParty = 2 })
	a, b := twoIdentities(t, ifc.ReRegistration, time.Hour)
	for range 8 {
		rt.Registered(bg, a)
		rt.Registered(bg, b)
	}
	rt.Registered(bg, otherSet(t, e, 1))
	close(s.hold)
	rt.Stop()
	if got := s.expiresOf("sip:user001@" + realm); len(got) != 1 {
		t.Errorf("another user's registration heard %v: one set took the server's queue", got)
	}
}

// TestASetWithManyIdentitiesTakesNoMoreThanItsCap (#446 QA): one set
// refreshing eight identities holds at most queuedPerSet of the server's
// queue, and another user's registration is sent.
func TestASetWithManyIdentitiesTakesNoMoreThanItsCap(t *testing.T) {
	e := newEnv(t)
	s := &orderedExpires{hold: make(chan struct{}), inside: make(chan struct{}, 256)}
	const max = 8
	rt := e.router(nil, withSender(s), func(cfg *Config) { cfg.MaxThirdParty = max })
	set := state.SetKey{IMPI: "big@" + realm, IMPU: "sip:big0@" + realm}
	for i := range 8 {
		impu := fmt.Sprintf("sip:big%d@%s", i, realm)
		for range queuedPerSet {
			r := registration(t, ifc.ReRegistration, time.Hour)
			r.Set, r.IMPU, r.Profile = set, impu, profileFor(t, e, set, impu)
			rt.Registered(bg, r)
		}
	}
	rt.tp.mu.Lock()
	q := rt.tp.servers[rcsAS].queued
	rt.tp.mu.Unlock()
	if q > queuedPerSet {
		t.Errorf("one set holds %d of the server's queue, want at most %d", q, queuedPerSet)
	}
	rt.Registered(bg, otherSet(t, e, 1))
	close(s.hold)
	rt.Stop()
	if got := s.expiresOf("sip:user001@" + realm); len(got) != 1 {
		t.Errorf("another user's registration heard %v", got)
	}
}

// TestEveryIdentityOfAnEndingSetHearsItsEnd (#420, code review on #379):
// the server keeps a registration per To, so the queue is per identity: a
// set registered under two identities that ends while its queue is full
// tells each of them Expires 0, the one not taking the other's place.
func TestEveryIdentityOfAnEndingSetHearsItsEnd(t *testing.T) {
	e := newEnv(t)
	s := &orderedExpires{hold: make(chan struct{}), inside: make(chan struct{}, 16)}
	rt := e.router(nil, withSender(s))
	a, b := twoIdentities(t, ifc.ReRegistration, time.Hour)
	// impu1's first is at the server; each identity then has its queue
	// full of refreshes.
	rt.Registered(bg, a)
	recv(t, s.inside)
	for range queuedPerSet - 1 {
		rt.Registered(bg, a)
	}
	for range queuedPerSet {
		rt.Registered(bg, b)
	}
	endA, endB := twoIdentities(t, ifc.DeRegistration, 0)
	rt.Registered(bg, endA)
	rt.Registered(bg, endB)
	close(s.hold)
	rt.Stop()
	for _, impu := range []string{impu1, impu2} {
		if got := s.expiresOf(impu); len(got) == 0 || got[len(got)-1] != "0" {
			t.Errorf("%s heard %v, want its end last", impu, got)
		}
	}
}
