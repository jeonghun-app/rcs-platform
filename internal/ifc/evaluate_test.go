package ifc

import (
	"reflect"
	"strings"
	"sync"
	"testing"
)

// sipRequest is the test implementation of Request. calls counts how often
// each part is read.
type sipRequest struct {
	method  string
	uri     string
	headers []HeaderField
	sdp     []string

	mu    sync.Mutex
	calls map[string]int
}

func (r *sipRequest) count(part string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.calls == nil {
		r.calls = map[string]int{}
	}
	r.calls[part]++
}

func (r *sipRequest) Method() string              { r.count("method"); return r.method }
func (r *sipRequest) RequestURI() string          { r.count("uri"); return r.uri }
func (r *sipRequest) HeaderFields() []HeaderField { r.count("headers"); return r.headers }
func (r *sipRequest) SDPLines() []string          { r.count("sdp"); return r.sdp }

func req(method, uri string, headers ...HeaderField) *sipRequest {
	return &sipRequest{method: method, uri: uri, headers: headers}
}

func from(v string) HeaderField { return HeaderField{Name: "From", Value: v} }

func compile(t *testing.T, criteria ...FilterCriteria) *Set {
	t.Helper()
	s, err := Compile(criteria)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return s
}

func criteria(priority int, tp *TriggerPoint) FilterCriteria {
	return FilterCriteria{Priority: priority, TriggerPoint: tp, ApplicationServer: ApplicationServer{ServerName: rcsAS}}
}

func matches(t *testing.T, s *Set, r Request, ctx Context) bool {
	t.Helper()
	_, ok := s.Next(r, ctx, -1)
	return ok
}

// The trigger "MESSAGE or INVITE, or OPTIONS not from a spam source" in both
// normal forms, the way TS 29.228 Annex C rewrites its own example. Both must
// give the same answer for every request.
var (
	spamSource = SIPHeader{Header: "From", Content: "spam"}

	sameTriggerInCNF = &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{
		{Groups: []int{0, 1}, Condition: Method("MESSAGE")},
		{Groups: []int{0, 1}, Condition: Method("INVITE")},
		{Groups: []int{0}, Condition: Method("OPTIONS")},
		{ConditionNegated: true, Groups: []int{1}, Condition: spamSource},
	}}
	sameTriggerInDNF = &TriggerPoint{ConditionTypeCNF: false, SPTs: []SPT{
		{Groups: []int{0}, Condition: Method("MESSAGE")},
		{Groups: []int{1}, Condition: Method("INVITE")},
		{Groups: []int{2}, Condition: Method("OPTIONS")},
		{ConditionNegated: true, Groups: []int{2}, Condition: spamSource},
	}}
)

func TestCNFAndDNFFormsOfOneTriggerAgree(t *testing.T) {
	cnf, dnf := compile(t, criteria(0, sameTriggerInCNF)), compile(t, criteria(0, sameTriggerInDNF))
	tests := []struct {
		name string
		r    *sipRequest
		want bool
	}{
		{"MESSAGE", req("MESSAGE", impu, from("<sip:spam@example.com>")), true},
		{"INVITE", req("INVITE", impu), true},
		{"OPTIONS from a friend", req("OPTIONS", impu, from("<"+tel+">")), true},
		{"OPTIONS from spam", req("OPTIONS", impu, from("\"Spam\" <sip:spam@example.com>")), false},
		{"SUBSCRIBE", req("SUBSCRIBE", impu), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := Context{Case: Originating}
			if got := matches(t, cnf, tc.r, ctx); got != tc.want {
				t.Errorf("CNF = %t, want %t", got, tc.want)
			}
			if got := matches(t, dnf, tc.r, ctx); got != tc.want {
				t.Errorf("DNF = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestCNFRequiresEveryGroupAndDNFAnyGroup(t *testing.T) {
	// (A or B) and (C or D) in CNF; (A and C) or (B and D) in DNF.
	var (
		a = Method("MESSAGE")
		b = Method("INVITE")
		c = SessionCase(Originating)
		d = SessionCase(TerminatingRegistered)
	)
	cnf := compile(t, criteria(0, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{
		{Groups: []int{0}, Condition: a},
		{Groups: []int{0}, Condition: b},
		{Groups: []int{1}, Condition: c},
		{Groups: []int{1}, Condition: d},
	}}))
	dnf := compile(t, criteria(0, &TriggerPoint{SPTs: []SPT{
		{Groups: []int{0}, Condition: a},
		{Groups: []int{0}, Condition: c},
		{Groups: []int{1}, Condition: b},
		{Groups: []int{1}, Condition: d},
	}}))
	tests := []struct {
		method       string
		sc           SessionCase
		cnfWant, dnf bool
	}{
		{"MESSAGE", Originating, true, true},
		{"MESSAGE", TerminatingRegistered, true, false},
		{"INVITE", TerminatingRegistered, true, true},
		{"INVITE", Originating, true, false},
		{"MESSAGE", OriginatingUnregistered, false, false},
		{"OPTIONS", Originating, false, false},
	}
	for _, tc := range tests {
		r, ctx := req(tc.method, impu), Context{Case: tc.sc}
		if got := matches(t, cnf, r, ctx); got != tc.cnfWant {
			t.Errorf("CNF %s/%d = %t, want %t", tc.method, tc.sc, got, tc.cnfWant)
		}
		if got := matches(t, dnf, r, ctx); got != tc.dnf {
			t.Errorf("DNF %s/%d = %t, want %t", tc.method, tc.sc, got, tc.dnf)
		}
	}
}

func TestNegatedHeaderWithoutContentMeansTheHeaderIsAbsent(t *testing.T) {
	s := compile(t, criteria(0, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{
		{ConditionNegated: true, Groups: []int{0}, Condition: SIPHeader{Header: "^P-Asserted-Identity$"}},
	}}))
	if matches(t, s, req("MESSAGE", impu, HeaderField{"P-Asserted-Identity", "<" + impu + ">"}), Context{}) {
		t.Error("matched although the header is present")
	}
	if !matches(t, s, req("MESSAGE", impu, from("<"+impu+">")), Context{}) {
		t.Error("did not match although the header is absent")
	}
}

func TestCriteriaWithoutTriggerPointAlwaysMatch(t *testing.T) {
	s := compile(t, criteria(3, nil))
	if !matches(t, s, req("BYE", "sip:anything"), Context{Case: OriginatingCDIV}) {
		t.Error("unconditional criterion did not match")
	}
}

func TestProfilePartSelectsCriteriaByRegistrationState(t *testing.T) {
	reg, unreg, both := criteria(1, nil), criteria(2, nil), criteria(3, nil)
	reg.ProfilePart, unreg.ProfilePart = ProfilePartRegistered, ProfilePartUnregistered
	s := compile(t, reg, unreg, both)
	tests := []struct {
		name string
		ctx  Context
		want []int
	}{
		{"originating registered", Context{Case: Originating}, []int{1, 3}},
		{"terminating registered", Context{Case: TerminatingRegistered}, []int{1, 3}},
		{"terminating unregistered", Context{Case: TerminatingUnregistered}, []int{2, 3}},
		{"originating unregistered", Context{Case: OriginatingUnregistered}, []int{2, 3}},
		{"diverted for an unregistered user", Context{Case: OriginatingCDIV, Unregistered: true}, []int{2, 3}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got []int
			for _, fc := range s.Match(req("INVITE", impu), tc.ctx) {
				got = append(got, fc.Priority)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("priorities = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRequestURIPatternsSeeTheHostportOrTelephoneSubscriber(t *testing.T) {
	tests := []struct {
		uri, part string
	}{
		{"sip:+15550100001@" + domain, domain},
		{"sip:+15550100001;npdi;rn=x@" + domain + ":5060;user=phone", domain + ":5060"},
		{"SIPS:alice@[2001:db8::1]:5061?Subject=x", "[2001:db8::1]:5061"},
		{"sip:" + domain + ";lr", domain},
		{"tel:+1-555-0100-001;phone-context=" + domain, "+1-555-0100-001;phone-context=" + domain},
		{"urn:service:sos", "urn:service:sos"},
		{"no-scheme", "no-scheme"},
	}
	for _, tc := range tests {
		if got := requestURIPart(tc.uri); got != tc.part {
			t.Errorf("requestURIPart(%q) = %q, want %q", tc.uri, got, tc.part)
		}
	}
	s := compile(t, criteria(0, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{
		{Groups: []int{0}, Condition: RequestURI(`^conf-factory\.ims\.`)},
	}}))
	if !matches(t, s, req("INVITE", "sip:groupchat@Conf-Factory.IMS.mnc001.mcc001.3gppnetwork.org"), Context{}) {
		t.Error("host pattern did not match a host in another case")
	}
	// The user part is not what the pattern sees.
	if matches(t, s, req("INVITE", "sip:conf-factory.ims.x@"+domain), Context{}) {
		t.Error("host pattern matched the user part")
	}
}

func TestHeaderPatternsMatchEachValueWithNormalisedWhiteSpace(t *testing.T) {
	s := compile(t, criteria(0, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{
		{Groups: []int{0}, Condition: SIPHeader{Header: "^accept-contact$", Content: `^\*;\+g\.3gpp\.icsi-ref="urn%3Aurn-7%3A3gpp-service\.ims\.icsi\.oma\.cpm\.session"$`}},
	}}))
	chat := `*;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session"`
	tests := map[string]struct {
		headers []HeaderField
		want    bool
	}{
		"exact value":              {[]HeaderField{{"Accept-Contact", chat}}, true},
		"name in another case":     {[]HeaderField{{"ACCEPT-CONTACT", chat}}, true},
		"white space around":       {[]HeaderField{{" Accept-Contact\t", "  " + chat + " \r\n "}}, true},
		"second of several values": {[]HeaderField{{"Accept-Contact", "*;audio"}, {"Accept-Contact", chat}}, true},
		"value in another case":    {[]HeaderField{{"Accept-Contact", strings.ToUpper(chat)}}, false},
		"other header":             {[]HeaderField{{"Contact", chat}}, false},
		"no headers":               {nil, false},
	}
	for name, tc := range tests {
		if got := matches(t, s, req("INVITE", impu, tc.headers...), Context{}); got != tc.want {
			t.Errorf("%s: %t, want %t", name, got, tc.want)
		}
	}
}

func TestSessionDescriptionPatternsMatchTypeAndValueOfEachLine(t *testing.T) {
	s := compile(t, criteria(0, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{
		{Groups: []int{0}, Condition: SessionDescription{Line: "^m$", Content: "^message [0-9]+ TCP/T?L?S?/?MSRP"}},
	}}))
	offer := &sipRequest{method: "INVITE", uri: impu, sdp: []string{
		"v=0", "o=- 1 1 IN IP4 192.0.2.1", "not an SDP line", "m=audio 49170 RTP/AVP 0\r", "m=message 9 TCP/MSRP *\r",
	}}
	if !matches(t, s, offer, Context{}) {
		t.Error("MSRP media line did not match")
	}
	audio := &sipRequest{method: "INVITE", uri: impu, sdp: []string{"v=0", "m=audio 49170 RTP/AVP 0"}}
	if matches(t, s, audio, Context{}) {
		t.Error("audio-only offer matched")
	}
	anyMedia := compile(t, criteria(0, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{
		{Groups: []int{0}, Condition: SessionDescription{Line: "m"}},
	}}))
	if !matches(t, anyMedia, audio, Context{}) || matches(t, anyMedia, req("INVITE", impu), Context{}) {
		t.Error("a Line without Content must test for the line's presence")
	}
}

func TestMethodsAreComparedExactly(t *testing.T) {
	s := compile(t, criteria(0, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{{Groups: []int{0}, Condition: Method("MESSAGE")}}}))
	if matches(t, s, req("message", impu), Context{}) {
		t.Error("method compared without regard to case")
	}
}

func TestRegisterTriggersHonourTheRegistrationType(t *testing.T) {
	s := compile(t, criteria(0, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{{
		Groups: []int{0}, Condition: Method("REGISTER"), RegistrationTypes: []RegistrationType{InitialRegistration, DeRegistration},
	}}}))
	tests := map[string]struct {
		rt   *RegistrationType
		want bool
	}{
		"initial registration":     {regtype(InitialRegistration), true},
		"re-registration":          {regtype(ReRegistration), false},
		"de-registration":          {regtype(DeRegistration), true},
		"unknown kind of REGISTER": {nil, true},
	}
	for name, tc := range tests {
		if got := matches(t, s, req("REGISTER", "sip:"+domain), Context{RegistrationType: tc.rt}); got != tc.want {
			t.Errorf("%s: %t, want %t", name, got, tc.want)
		}
	}
	// The types only narrow REGISTER; on another method they are ignored.
	other := compile(t, criteria(0, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{{
		Groups: []int{0}, Condition: Method("MESSAGE"), RegistrationTypes: []RegistrationType{ReRegistration},
	}}}))
	if !matches(t, other, req("MESSAGE", impu), Context{RegistrationType: regtype(InitialRegistration)}) {
		t.Error("RegistrationType applied to MESSAGE")
	}
}

func TestCriteriaAreEvaluatedInPriorityOrder(t *testing.T) {
	message := &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{{Groups: []int{0}, Condition: Method("MESSAGE")}}}
	invite := &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{{Groups: []int{0}, Condition: Method("INVITE")}}}
	s := compile(t, criteria(30, message), criteria(10, message), criteria(20, invite), criteria(0, message))
	if s.Len() != 4 {
		t.Fatalf("Len = %d", s.Len())
	}
	var chain []int
	after := -1
	for {
		fc, ok := s.Next(req("MESSAGE", impu), Context{}, after)
		if !ok {
			break
		}
		chain = append(chain, fc.Priority)
		after = fc.Priority
	}
	if !reflect.DeepEqual(chain, []int{0, 10, 30}) {
		t.Errorf("chain = %v, want [0 10 30]", chain)
	}
	var all []int
	for _, fc := range s.Match(req("MESSAGE", impu), Context{}) {
		all = append(all, fc.Priority)
	}
	if !reflect.DeepEqual(all, chain) {
		t.Errorf("Match = %v, want %v", all, chain)
	}
}

func TestEachPartOfTheRequestIsReadAtMostOncePerEvaluation(t *testing.T) {
	h := &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{
		{Groups: []int{0}, Condition: SIPHeader{Header: "X-A"}},
		{Groups: []int{0}, Condition: SIPHeader{Header: "X-B"}},
		{Groups: []int{0}, Condition: RequestURI("x")},
		{Groups: []int{0}, Condition: RequestURI("y")},
	}}
	s := compile(t, criteria(1, h), criteria(2, h))
	r := req("MESSAGE", impu)
	s.Match(r, Context{})
	if r.calls["headers"] != 1 || r.calls["uri"] != 1 || r.calls["sdp"] != 0 {
		t.Errorf("reads = %v, want headers and uri once, sdp never", r.calls)
	}
}

func TestCompileRefusesAmbiguousOrInvalidCriteria(t *testing.T) {
	one := func(c Condition) *TriggerPoint {
		return &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{{Groups: []int{0}, Condition: c}}}
	}
	tests := map[string][]FilterCriteria{
		"two criteria with one priority": {criteria(5, nil), criteria(5, nil)},
		"unbalanced parenthesis":         {criteria(1, one(RequestURI("("+domain)))},
		"Perl class in a header":         {criteria(1, one(SIPHeader{Header: `\d+`}))},
		"Perl flag in content":           {criteria(1, one(SIPHeader{Header: "From", Content: "(?i)" + impu}))},
		"non-greedy SDP pattern":         {criteria(1, one(SessionDescription{Line: "m", Content: "(?:a)"}))},
		"no condition":                   {criteria(1, &TriggerPoint{SPTs: []SPT{{Groups: []int{0}}}})},
		"no server":                      {{Priority: 1}},
	}
	for name, cs := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Compile(cs)
			if err == nil {
				t.Fatal("compiled")
			}
			if strings.Contains(err.Error(), domain) || strings.Contains(err.Error(), "15550100001") {
				t.Errorf("error quotes a pattern: %v", err)
			}
		})
	}
}

func TestEmptyPatternsMatchAnything(t *testing.T) {
	s := compile(t, criteria(0, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{
		{Groups: []int{0}, Condition: RequestURI("")},
		{Groups: []int{1}, Condition: SIPHeader{Header: ""}},
	}}))
	if !matches(t, s, req("INVITE", "", HeaderField{"Via", ""}), Context{}) {
		t.Error("empty patterns did not match")
	}
}

func TestOneSetServesConcurrentRequests(t *testing.T) {
	s := compile(t, criteria(0, sameTriggerInCNF), criteria(1, sameTriggerInDNF))
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			method := []string{"MESSAGE", "OPTIONS"}[i%2]
			if got := s.Match(req(method, impu, from("<"+tel+">")), Context{}); len(got) != 2 {
				t.Errorf("%s matched %d criteria", method, len(got))
			}
		}()
	}
	wg.Wait()
}
