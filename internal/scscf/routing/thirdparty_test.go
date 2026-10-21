package routing

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
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
	rt.Wait()
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
			rt.Wait()
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
	fc.ApplicationServer.IncludeRegisterRequest = true
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
	rt.Wait()
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
	rt.Wait()
	if len(s.got()) != 0 {
		t.Error("a re-registration went to a server for de-registrations")
	}
	rt.Registered(bg, registration(t, ifc.DeRegistration, 0))
	rt.Wait()
	if len(s.got()) != 1 {
		t.Error("the de-registration did not go")
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
	if to := <-s.finished; to != impu2 {
		t.Fatalf("%s finished first", to)
	}
	close(s.held)
	rt.Wait()
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

// TestRegistrationsPastTheBoundAreDropped: with every slot held, one more
// is counted and not sent.
func TestRegistrationsPastTheBoundAreDropped(t *testing.T) {
	e := newEnv(t)
	e.profile(t0, criterion(40, rcsAS, registerTrigger(), ifc.SessionContinued))
	s := &sentRegisters{hold: make(chan struct{}), inside: make(chan struct{}, 8)}
	rt := e.router(nil, withSender(s), func(c *Config) { c.MaxThirdParty = 1 })
	rt.Registered(bg, registration(t, ifc.InitialRegistration, time.Hour))
	<-s.inside
	rt.Registered(bg, registration(t, ifc.ReRegistration, time.Hour))
	close(s.hold)
	rt.Wait()
	if len(s.got()) != 1 || e.metrics.get("routing.third_party.dropped") != 1 {
		t.Errorf("%d sent, %d dropped", len(s.got()), e.metrics.get("routing.third_party.dropped"))
	}
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
			rt.Wait()
			if e.metrics.get(c.counted) != 1 {
				t.Errorf("%s not counted", c.counted)
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
	rt.Wait()
	if len(s.got()) != 0 || e.metrics.get("routing.third_party.bad_server") != 1 {
		t.Errorf("%d sent, bad servers %d", len(s.got()), e.metrics.get("routing.third_party.bad_server"))
	}
	e2 := newEnv(t)
	rt = e2.router(nil, withSender(s))
	rt.Registered(bg, registration(t, ifc.InitialRegistration, time.Hour))
	rt.Wait()
	if len(s.got()) != 0 {
		t.Error("sent without a profile")
	}
}
