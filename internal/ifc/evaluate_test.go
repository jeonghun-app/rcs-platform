package ifc

import (
	"errors"
	"fmt"
	"reflect"
	"regexp/syntax"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
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
	_, ok, err := s.Next(r, ctx, -1)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	return ok
}

func matchAll(t *testing.T, s *Set, r Request, ctx Context) []int {
	t.Helper()
	got, err := s.Match(r, ctx)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	var out []int
	for _, fc := range got {
		out = append(out, fc.Priority)
	}
	return out
}

// limitReached evaluates r with Next and Match and returns the limit both
// report, failing the test unless both fail with a *LimitError.
func limitReached(t *testing.T, s *Set, r Request) string {
	t.Helper()
	_, ok, err := s.Next(r, Context{}, -1)
	var le *LimitError
	if !errors.As(err, &le) || !errors.Is(err, ErrEvaluationLimit) || ok {
		t.Fatalf("Next = %t, %v; want a *LimitError", ok, err)
	}
	got, err := s.Match(r, Context{})
	var le2 *LimitError
	if !errors.As(err, &le2) || got != nil || le2.Limit != le.Limit {
		t.Fatalf("Match = %v, %v; want the *LimitError Next gave (%v)", got, err, le)
	}
	return le.Limit
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
			got := matchAll(t, s, req("INVITE", impu), tc.ctx)
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
		fc, ok, err := s.Next(req("MESSAGE", impu), Context{}, after)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			break
		}
		chain = append(chain, fc.Priority)
		after = fc.Priority
	}
	if !reflect.DeepEqual(chain, []int{0, 10, 30}) {
		t.Errorf("chain = %v, want [0 10 30]", chain)
	}
	all := matchAll(t, s, req("MESSAGE", impu), Context{})
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
	matchAll(t, s, r, Context{})
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

func TestEmptyValuePatternsMatchAnyValueButAnEmptyNameMatchesNoHeader(t *testing.T) {
	uri := compile(t, criteria(0, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{
		{Groups: []int{0}, Condition: RequestURI("")},
		{Groups: []int{1}, Condition: SessionDescription{Line: "", Content: ""}},
	}}))
	r := &sipRequest{method: "INVITE", uri: "", sdp: []string{"v=0"}}
	if !matches(t, uri, r, Context{}) {
		t.Error("empty Request-URI and SDP patterns did not match")
	}
	// A header name pattern matches the whole name, and no header has an
	// empty one.
	name := compile(t, criteria(0, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{
		{Groups: []int{0}, Condition: SIPHeader{Header: ""}},
	}}))
	if matches(t, name, req("INVITE", "", HeaderField{"Via", ""}), Context{}) {
		t.Error("empty header name pattern matched Via")
	}
}

func TestHeaderNamePatternsMatchTheWholeName(t *testing.T) {
	s := compile(t, criteria(0, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{
		{Groups: []int{0}, Condition: SIPHeader{Header: "Contact", Content: "oma\\.cpm"}},
	}}))
	chat := `*;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session"`
	tests := map[string]struct {
		name string
		want bool
	}{
		"Contact":        {"Contact", true},
		"contact":        {"contact", true},
		"Accept-Contact": {"Accept-Contact", false},
		"Reject-Contact": {"Reject-Contact", false},
		"Contacts":       {"Contacts", false},
	}
	for label, tc := range tests {
		if got := matches(t, s, req("INVITE", impu, HeaderField{tc.name, chat}), Context{}); got != tc.want {
			t.Errorf("%s: %t, want %t", label, got, tc.want)
		}
	}
	// Alternation stays inside the anchors.
	alt := compile(t, criteria(0, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{
		{Groups: []int{0}, Condition: SIPHeader{Header: "To|From"}},
	}}))
	if !matches(t, alt, req("INVITE", impu, from("<"+tel+">")), Context{}) ||
		matches(t, alt, req("INVITE", impu, HeaderField{"Reply-To", "<" + tel + ">"}), Context{}) {
		t.Error("an alternation in a name pattern escaped the anchors")
	}
}

func TestSDPLinesEndingInCarriageReturnMatchAnchoredPatterns(t *testing.T) {
	s := compile(t, criteria(0, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{
		{Groups: []int{0}, Condition: SessionDescription{Line: "^m$", Content: `^message 9 TCP/MSRP \*$`}},
	}}))
	if !matches(t, s, &sipRequest{method: "INVITE", uri: impu, sdp: []string{"m=message 9 TCP/MSRP *\r"}}, Context{}) {
		t.Error("the line's CR was matched as content")
	}
}

func TestCompileRefusesPatternsWithAHugeProgram(t *testing.T) {
	for name, pat := range map[string]string{
		"repetition chained":  strings.Repeat("[ab]{1000}", 100), // 1000 bytes, about 100 000 instructions
		"nested repetition":   "((a{100}){100}){100}",
		"just over the limit": strings.Repeat("abcdefghij", MaxPatternInstructions/10+1),
	} {
		t.Run(name, func(t *testing.T) {
			fc := criteria(0, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{{Groups: []int{0},
				Condition: SIPHeader{Header: "Subject", Content: pat}}}})
			_, err := Compile([]FilterCriteria{fc})
			if err == nil {
				t.Fatal("Compile accepted the pattern")
			}
			if strings.Contains(err.Error(), "abc") || strings.Contains(err.Error(), "[ab]") {
				t.Errorf("error quotes the pattern: %v", err)
			}
		})
	}
	// A pattern a person writes is far below the limit.
	if _, err := Compile([]FilterCriteria{criteria(0, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{{Groups: []int{0},
		Condition: SIPHeader{Header: "Accept-Contact", Content: `3gpp-service\.ims\.icsi\.oma\.cpm\.(session|msg|largemsg|filetransfer)`}}}})}); err != nil {
		t.Errorf("ordinary pattern refused: %v", err)
	}
}

// unclosedClasses is a bracket expression of n bytes full of "[:" that no
// ":]" closes: one character class, far below the instruction limits, on
// which Go's parser searches for ":]" from every "[:" (#96).
func unclosedClasses(n int) string {
	s := "[" + strings.Repeat("[:", (n-3)/2)
	return s + strings.Repeat("a", n-1-len(s)) + "]"
}

func TestCompileRefusesAPatternLongerThanMaxPatternBytes(t *testing.T) {
	over := unclosedClasses(MaxPatternBytes + 1)
	if len(over) != MaxPatternBytes+1 {
		t.Fatalf("pattern of %d bytes", len(over))
	}
	for _, c := range []Condition{RequestURI(over), SIPHeader{Header: over}, SIPHeader{Header: "Subject", Content: over},
		SessionDescription{Line: over}, SessionDescription{Line: "m", Content: over}} {
		_, err := Compile([]FilterCriteria{criteria(0, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{{Groups: []int{0}, Condition: c}}})})
		if err == nil || !strings.Contains(err.Error(), "MaxPatternBytes") {
			t.Errorf("%T of %d bytes: %v, want a refusal naming MaxPatternBytes", c, len(over), err)
		}
	}
	// Refused before any parse, Content's included: parsing the 256 KiB a
	// provisioning request may carry takes seconds. Correct code takes
	// microseconds, so the bound only shows a parse that came first.
	huge := unclosedClasses(256 << 10)
	start := time.Now()
	_, err := Compile([]FilterCriteria{criteria(0, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{{Groups: []int{0},
		Condition: SIPHeader{Header: "Subject", Content: huge}}}})})
	if err == nil || !strings.Contains(err.Error(), "MaxPatternBytes") {
		t.Fatalf("256 KiB Content: %v", err)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("refusing 256 KiB took %v: it was parsed first", d)
	}
}

// Patterns at the limit that are costly to compile still take milliseconds:
// about 1 ms for unclosed classes, whose parse is quadratic, and 3.5-10 ms
// for 1024 negated classes in a case-folded Request-URI, the slowest found
// in review, against seconds for the 240 KiB the API body would allow
// without the limit. Only the quadratic case is timed, against a bound
// hundreds of times its cost, so that a loaded host cannot fail the test;
// the negated classes are only shown to be accepted.
func TestCostlyPatternsWithinTheLimitCompile(t *testing.T) {
	for name, c := range map[string]Condition{
		"unclosed classes":        SIPHeader{Header: "Subject", Content: unclosedClasses(MaxPatternBytes)},
		"negated classes, folded": RequestURI(strings.Repeat("[^a]", MaxPatternBytes/4)),
	} {
		start := time.Now()
		_, err := Compile([]FilterCriteria{criteria(0, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{{Groups: []int{0}, Condition: c}}})})
		if err != nil {
			t.Fatalf("%s: a pattern at the limit refused: %v", name, err)
		}
		if d := time.Since(start); name == "unclosed classes" && d > 500*time.Millisecond {
			t.Fatalf("%s: compiling took %v", name, d)
		}
	}
}

// bulkyPattern compiles to a little under MaxPatternInstructions.
var bulkyPattern = "(" + strings.Repeat("[a-z]", 9) + "){150}"

func TestCompileRefusesASetLargerThanItsInstructionBudget(t *testing.T) {
	var cs []FilterCriteria
	for i := range 40 {
		cs = append(cs, criteria(i, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{{Groups: []int{0},
			Condition: SIPHeader{Header: "Subject", Content: bulkyPattern}}}}))
	}
	if _, err := Compile(cs[:1]); err != nil {
		t.Fatalf("one bulky pattern refused: %v", err)
	}
	if _, err := Compile(cs); err == nil {
		t.Error("forty bulky patterns accepted")
	}
}

// TestAMaximumSizeDocumentOfCostlyPatternsIsRefusedCheaply fills the
// document limit with patterns each just under the per-pattern limit. The
// set budget must stop Compile long before the memory and time the patterns
// would take.
func TestAMaximumSizeDocumentOfCostlyPatternsIsRefusedCheaply(t *testing.T) {
	var b strings.Builder
	for i := 0; ; i++ {
		fc := `<InitialFilterCriteria><Priority>` + strconv.Itoa(i) + `</Priority><TriggerPoint><ConditionTypeCNF>1</ConditionTypeCNF>` +
			`<SPT><Group>0</Group><SIPHeader><Header>Subject</Header><Content>` + bulkyPattern + `</Content></SIPHeader></SPT></TriggerPoint>` +
			`<ApplicationServer><ServerName>sip:a</ServerName></ApplicationServer></InitialFilterCriteria>`
		if len(doc(b.String()+fc)) > MaxDocumentSize {
			break
		}
		b.WriteString(fc)
	}
	s := mustParse(t, doc(b.String()))
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	_, err := Compile(s.ServiceProfiles[0].InitialFilterCriteria)
	elapsed := time.Since(start)
	runtime.ReadMemStats(&after)
	if err == nil {
		t.Fatalf("Compile accepted %d bulky criteria", len(s.ServiceProfiles[0].InitialFilterCriteria))
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 64<<20 {
		t.Errorf("Compile allocated %d MiB before refusing", alloc>>20)
	}
	// Generous: the bound is about the work done, not this host's speed.
	if elapsed > 5*time.Second {
		t.Errorf("Compile took %s before refusing", elapsed)
	}
}

func TestValuesOverTheirLimitFailTheEvaluationAndAreCounted(t *testing.T) {
	s := compile(t,
		criteria(1, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{{Groups: []int{0}, Condition: SIPHeader{Header: "Subject", Content: "x"}}}}),
		criteria(2, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{{Groups: []int{0}, Condition: RequestURI("x")}}}),
		criteria(3, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{{Groups: []int{0}, Condition: SessionDescription{Line: "a", Content: "x"}}}}),
	)
	within := func() *sipRequest {
		return &sipRequest{method: "MESSAGE", uri: "sip:" + strings.Repeat("x", MaxRequestURILength-4),
			headers: []HeaderField{{"Subject", strings.Repeat("x", MaxHeaderLength)}},
			sdp:     []string{"a=" + strings.Repeat("x", MaxSDPLineLength-2)}}
	}
	if got := matchAll(t, s, within(), Context{}); !reflect.DeepEqual(got, []int{1, 2, 3}) || s.OversizedValues() != 0 {
		t.Fatalf("values at their limits: matched %v, oversized %d", got, s.OversizedValues())
	}
	tests := map[string]struct {
		edit  func(*sipRequest)
		fc    int // the criterion that reads the part
		limit string
	}{
		"header value": {func(r *sipRequest) { r.headers[0].Value += "x" }, 0, "MaxHeaderLength"},
		"header name": {func(r *sipRequest) {
			r.headers = append(r.headers, HeaderField{strings.Repeat("S", MaxHeaderLength+1), "x"})
		}, 0, "MaxHeaderLength"},
		"Request-URI": {func(r *sipRequest) { r.uri += "x" }, 1, "MaxRequestURILength"},
		"SDP line":    {func(r *sipRequest) { r.sdp[0] += "x" }, 2, "MaxSDPLineLength"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := within()
			tc.edit(r)
			one := compile(t, s.criteria[tc.fc].fc)
			if got := limitReached(t, one, r); got != tc.limit {
				t.Errorf("limit = %s, want %s", got, tc.limit)
			}
			if one.OversizedValues() == 0 {
				t.Error("OversizedValues did not count the value")
			}
		})
	}
	// A negated condition on an unexamined value is an error too, not a
	// condition that holds.
	neg := compile(t, criteria(0, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{
		{ConditionNegated: true, Groups: []int{0}, Condition: SIPHeader{Header: "Subject", Content: "x"}}}}))
	r := within()
	r.headers[0].Value += "x"
	limitReached(t, neg, r)
}

// TestAPaddedRequestCannotBypassAnApplicationServer pads an INVITE so that
// its Accept-Contact lies beyond MaxHeaderBytes. Treating the unexamined
// header as absent would skip the chat AS; the evaluation must fail instead.
func TestAPaddedRequestCannotBypassAnApplicationServer(t *testing.T) {
	s := compile(t, criteria(0, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{
		{Groups: []int{0}, Condition: Method("INVITE")},
		{Groups: []int{1}, Condition: SIPHeader{Header: "Accept-Contact", Content: `3gpp-service\.ims\.icsi\.oma\.cpm\.session`}},
	}}))
	chat := HeaderField{"Accept-Contact", `*;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session"`}
	if !matches(t, s, req("INVITE", impu, chat), Context{}) {
		t.Fatal("unpadded INVITE did not match")
	}
	padding := slices.Repeat([]HeaderField{{"X-Padding", strings.Repeat("p", MaxHeaderLength-16)}}, 5)
	if got := limitReached(t, s, req("INVITE", impu, append(padding, chat)...)); got != "MaxHeaderBytes" {
		t.Errorf("limit = %s, want MaxHeaderBytes", got)
	}
}

func TestEvaluationExaminesABoundedAmountOfSDP(t *testing.T) {
	line := "a=" + strings.Repeat("a", MaxSDPLineLength-2)
	lines := slices.Repeat([]string{line}, 1024) // 1 MiB of SDP, every line within MaxSDPLineLength
	set := compile(t, criteria(0, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{{Groups: []int{0},
		Condition: SessionDescription{Line: "a", Content: "[ab]{100}c"}}}}))
	if got := limitReached(t, set, &sipRequest{method: "INVITE", uri: impu, sdp: lines}); got != "MaxSDPBytes" {
		t.Errorf("limit = %s, want MaxSDPBytes", got)
	}
	if set.OversizedValues() == 0 {
		t.Error("1 MiB of SDP in 1 KiB lines was examined in full")
	}
}

func TestEvaluationExaminesABoundedAmountOfHeaders(t *testing.T) {
	value := strings.Repeat("a", MaxHeaderLength-len("Subject"))
	headers := slices.Repeat([]HeaderField{{"Subject", value}}, 16) // 128 KiB, each field within MaxHeaderLength
	set := compile(t, criteria(0, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{{Groups: []int{0},
		Condition: SIPHeader{Header: "Subject", Content: "late"}}}}))
	if got := limitReached(t, set, req("MESSAGE", impu, headers...)); got != "MaxHeaderBytes" {
		t.Errorf("limit = %s, want MaxHeaderBytes", got)
	}
	// limitReached evaluates twice.
	if n, want := set.OversizedValues(), uint64(2*(16-MaxHeaderBytes/MaxHeaderLength)); n != want {
		t.Errorf("OversizedValues = %d, want %d", n, want)
	}
}

// TestAnEvaluationFailsWhenItsWorkBudgetIsSpent uses a pattern of about a
// thousand instructions over Subject values of a thousand bytes: each match
// costs more than the whole default budget.
func TestAnEvaluationFailsWhenItsWorkBudgetIsSpent(t *testing.T) {
	fc := criteria(0, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{{Groups: []int{0},
		Condition: SIPHeader{Header: "Subject", Content: "[ab]{999}c"}}}})
	r := req("MESSAGE", impu,
		HeaderField{"Subject", strings.Repeat("a", 1000)},
		HeaderField{"Subject", strings.Repeat("a", 999) + "c"})

	set := compile(t, fc)
	if got := limitReached(t, set, r); got != "MaxWork" {
		t.Errorf("limit = %s, want MaxWork", got)
	}
	// limitReached evaluated twice; the budget is per evaluation.
	if n := set.ExhaustedEvaluations(); n != 2 {
		t.Errorf("ExhaustedEvaluations = %d, want 2", n)
	}

	roomy, err := CompileWithLimits([]FilterCriteria{fc}, Limits{MaxWork: 3_000_000})
	if err != nil {
		t.Fatal(err)
	}
	if !matches(t, roomy, r, Context{}) || roomy.ExhaustedEvaluations() != 0 {
		t.Errorf("with a larger budget: exhausted %d", roomy.ExhaustedEvaluations())
	}
}

// TestAnOrdinaryProfileSpendsLittleOfTheBudget evaluates the kind of RCS
// profile an HSS provisions against a realistic chat INVITE: the error path
// is for abuse, so ordinary traffic must stay far from it.
func TestAnOrdinaryProfileSpendsLittleOfTheBudget(t *testing.T) {
	var cs []FilterCriteria
	for i, icsi := range []string{"session", "msg", "largemsg", "filetransfer", "deferred", "chatbot", "sm", "groupchat"} {
		for j, method := range []string{"INVITE", "MESSAGE", "OPTIONS"} {
			cs = append(cs, criteria(i*10+j, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{
				{Groups: []int{0}, Condition: Method(method)},
				{Groups: []int{1}, Condition: SIPHeader{Header: "Accept-Contact", Content: `urn%3Aurn-7%3A3gpp-service\.ims\.icsi\.oma\.cpm\.` + icsi}},
				{Groups: []int{1}, Condition: SIPHeader{Header: "Contact", Content: `\+g\.3gpp\.icsi-ref="[^"]*oma\.cpm\.` + icsi}},
				{Groups: []int{2}, Condition: SessionDescription{Line: "m", Content: "^message [0-9]+ TCP(/TLS)?/MSRP"}},
				{ConditionNegated: true, Groups: []int{3}, Condition: SIPHeader{Header: "P-Served-User"}},
			}}))
		}
	}
	s := compile(t, cs...)
	var headers []HeaderField
	for _, name := range []string{"Via", "Via", "Max-Forwards", "Route", "Record-Route", "From", "To", "Call-ID", "CSeq",
		"Contact", "Accept-Contact", "P-Asserted-Identity", "P-Preferred-Service", "Supported", "Allow", "User-Agent",
		"Content-Type", "Content-Length", "Session-Expires", "P-Access-Network-Info"} {
		headers = append(headers, HeaderField{name, strings.Repeat("v", 120)})
	}
	r := &sipRequest{method: "INVITE", uri: impu, headers: headers, sdp: []string{
		"v=0", "o=- 1 1 IN IP4 192.0.2.1", "s=-", "c=IN IP4 192.0.2.1", "t=0 0", "m=message 9 TCP/MSRP *",
		"a=accept-types:message/cpim application/im-iscomposing+xml", "a=path:msrp://192.0.2.1:9/abc;tcp", "a=setup:active",
	}}
	in := newInput(r, Context{}, s.maxWork)
	for i := range s.criteria {
		s.criteria[i].matches(in)
	}
	if in.limit != "" || DefaultMaxWork-in.work > DefaultMaxWork/4 {
		t.Errorf("an ordinary evaluation of %d criteria spent %d of %d units (limit %q)",
			len(cs), DefaultMaxWork-in.work, DefaultMaxWork, in.limit)
	}
}

// rcsICSIs are the services the realistic profiles below select.
var rcsICSIs = []string{"oma.cpm.msg", "oma.cpm.largemsg", "oma.cpm.deferred", "oma.cpm.filetransfer", "oma.cpm.session", "oma.cpm.systemmsg",
	"mmtel", "gsma.callcomposer", "gsma.callunanswered", "gsma.sharedmap", "gsma.sharedsketch", "gsma.chatbot"}

func TestAnINVITEMatchingNoCriterionOfADotStarProfileIsEvaluated(t *testing.T) {
	var cs []FilterCriteria
	for i := 0; i < 24; i++ {
		// Operators often pad unanchored patterns with .* at both ends.
		icsi := strings.ReplaceAll(rcsICSIs[i%len(rcsICSIs)], ".", `\.`)
		cs = append(cs, criteria(i, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{
			{Groups: []int{0}, Condition: Method("INVITE")}, {Groups: []int{0}, Condition: Method("MESSAGE")},
			{Groups: []int{1}, Condition: SIPHeader{Header: "Accept-Contact",
				Content: `.*\+g\.3gpp\.icsi-ref="urn%3Aurn-7%3A3gpp-service\.ims\.icsi\.` + icsi + `".*`}},
		}}))
	}
	s := compile(t, cs...)
	headers := []HeaderField{{"Accept-Contact", `*;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.unknown.service";` +
		`+g.3gpp.iari-ref="urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.fthttp,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.geopush";require;explicit`}}
	for _, name := range []string{"Via", "Via", "Max-Forwards", "Route", "Record-Route", "From", "To", "Call-ID", "CSeq", "Contact",
		"P-Asserted-Identity", "P-Charging-Vector", "P-Access-Network-Info", "Allow", "Supported", "User-Agent", "Content-Type", "Content-Length"} {
		headers = append(headers, HeaderField{name, strings.Repeat("v", 60)})
	}
	if _, ok, err := s.Next(&sipRequest{method: "INVITE", uri: impu, headers: headers}, Context{Case: Originating}, -1); err != nil || ok {
		t.Errorf("an ordinary INVITE that no criterion selects: ok=%v, err=%v", ok, err)
	}
}

// TestOuterDotStarChangesNeitherTheResultNorTheCost compiles each pattern
// with and without a leading and trailing ".*" and evaluates both against
// the same values.
func TestOuterDotStarChangesNeitherTheResultNorTheCost(t *testing.T) {
	values := []string{"", "chat", "a chat b", "x oma.cpm.session y", "oma.cpm", "OMA.CPM.SESSION", "ab\tcd"}
	for _, core := range []string{`oma\.cpm\.session`, `chat`, `(a|b)c`, `^a`, `b$`, `[0-9]+`, ``} {
		for _, padded := range []string{".*" + core, core + ".*", ".*" + core + ".*", ".*.*" + core + ".*.*"} {
			plain, dots := compile(t, contentCriteria(core)), compile(t, contentCriteria(padded))
			for _, v := range values {
				r := req("MESSAGE", impu, HeaderField{"Subject", v})
				inPlain, inDots := newInput(r, Context{}, DefaultMaxWork), newInput(r, Context{}, DefaultMaxWork)
				gotPlain, gotDots := plain.criteria[0].matches(inPlain), dots.criteria[0].matches(inDots)
				if gotPlain != gotDots || inPlain.work != inDots.work {
					t.Errorf("%q vs %q on %q: matched %t/%t, cost %d/%d", core, padded, v, gotPlain, gotDots,
						DefaultMaxWork-inPlain.work, DefaultMaxWork-inDots.work)
				}
			}
		}
	}
	// A ".*" inside the pattern, or in an alternation, is kept; a lone one
	// means "anything", and ".*?" is the ERE (.*)? and is kept too.
	strip := func(p string) string {
		tree, err := syntax.Parse(p, posixFlags)
		if err != nil {
			t.Fatal(err)
		}
		return withoutOuterDotStar(tree).String()
	}
	for p, want := range map[string]string{
		"a.*b":    "(?s:a.*b)",
		".*a|b.*": "(?s:.*a|b.*)",
		".*":      "(?:)",
		".*?a":    "(?s:(?:.*)?a)",
		".*0+?.*": "(?:0+)?",
	} {
		if got := strip(p); got != want {
			t.Errorf("stripping %q = %q, want %q", p, got, want)
		}
	}
	// The criteria keep the pattern as provisioned.
	fc := contentCriteria(".*chat.*")
	s := compile(t, fc)
	if c := s.criteria[0].fc.TriggerPoint.SPTs[0].Condition; c != (SIPHeader{Header: "Subject", Content: ".*chat.*"}) {
		t.Errorf("returned criteria hold %v", c)
	}
}

func contentCriteria(content string) FilterCriteria {
	return criteria(0, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{{Groups: []int{0},
		Condition: SIPHeader{Header: "Subject", Content: content}}}})
}

// TestARealisticProfileOverARegisterUsesAtMostHalfTheBudget evaluates 24
// RCS criteria, for REGISTER (third-party registration) as well as for
// INVITE and MESSAGE, against a REGISTER whose Contact carries 2 KB of
// feature tags, as RCS clients send.
func TestARealisticProfileOverARegisterUsesAtMostHalfTheBudget(t *testing.T) {
	var cs []FilterCriteria
	for i := 0; i < 24; i++ {
		icsi := strings.ReplaceAll(rcsICSIs[i%len(rcsICSIs)], ".", `\.`)
		cs = append(cs, criteria(i, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{
			{Groups: []int{0}, Condition: Method("REGISTER")},
			{Groups: []int{0}, Condition: Method("INVITE")},
			{Groups: []int{0}, Condition: Method("MESSAGE")},
			{Groups: []int{1}, Condition: SIPHeader{Header: "Contact", Content: `.*\+g\.3gpp\.icsi-ref="urn%3Aurn-7%3A3gpp-service\.ims\.icsi\.` + icsi + `".*`}},
			{Groups: []int{1}, Condition: SIPHeader{Header: "Accept-Contact", Content: `.*` + icsi + `.*`}},
			{ConditionNegated: true, Groups: []int{2}, Condition: SIPHeader{Header: "P-Served-User"}},
		}}))
	}
	s := compile(t, cs...)
	var tags strings.Builder
	tags.WriteString(`<sip:+15550100001@192.0.2.1:5060;transport=tcp>;+sip.instance="<urn:gsma:imei:00000000-000000-0>";expires=600000`)
	for tags.Len() < 2000 {
		tags.WriteString(`;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.unknown"`)
	}
	headers := []HeaderField{{"Contact", tags.String()}}
	for _, name := range []string{"Via", "Max-Forwards", "Route", "From", "To", "Call-ID", "CSeq", "Expires",
		"Authorization", "Supported", "Path", "Require", "P-Access-Network-Info", "P-Visited-Network-ID", "User-Agent"} {
		headers = append(headers, HeaderField{name, strings.Repeat("v", 120)})
	}
	in := newInput(&sipRequest{method: "REGISTER", uri: "sip:" + domain, headers: headers}, Context{}, s.maxWork)
	for i := range s.criteria {
		s.criteria[i].matches(in)
	}
	spent := DefaultMaxWork - in.work
	if in.limit != "" || spent > DefaultMaxWork/2 {
		t.Errorf("the REGISTER spent %d of %d units (limit %q)", spent, DefaultMaxWork, in.limit)
	}
}

func TestEverySPTIsEvaluatedOnceWhateverItsGroups(t *testing.T) {
	// 2000 SPTs, each alone in its own group and also in a shared one: a
	// DNF trigger that never matches visits every group.
	var spts []SPT
	for i := range 2000 {
		spts = append(spts, SPT{Groups: []int{i, 5000}, Condition: Method("NOTIFY")})
	}
	s := compile(t, criteria(0, &TriggerPoint{SPTs: spts}))
	r := req("MESSAGE", impu)
	if matches(t, s, r, Context{}) {
		t.Fatal("matched")
	}
	if n := r.calls["method"]; n > len(spts) {
		t.Errorf("Method read %d times for %d SPTs", n, len(spts))
	}
	tr := s.criteria[0].trigger
	entries := 0
	for _, m := range tr.members {
		entries += len(m)
	}
	if len(tr.members) != 2001 || entries != 4000 {
		t.Errorf("index has %d groups and %d entries, want 2001 and 4000", len(tr.members), entries)
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
			if got, err := s.Match(req(method, impu, from("<"+tel+">")), Context{}); len(got) != 2 || err != nil {
				t.Errorf("%s matched %d criteria", method, len(got))
			}
		}()
	}
	wg.Wait()
}

// negatedClasses is a case-folded Request-URI pattern of 1024 negated
// classes, the costliest shape per byte found in the review of #104.
func negatedClasses(priority int) FilterCriteria {
	return criteria(priority, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{{Groups: []int{0},
		Condition: RequestURI(strings.Repeat("[^a]", MaxPatternBytes/4))}}})
}

// Forty-seven patterns near MaxPatternBytes fit the instruction budget and
// took about half a second to compile (#111). The cost budget refuses the
// set at the first pattern that crosses it, so no more than one pattern's
// work is done past MaxSetCompileCost, on any host.
func TestASetCostlierThanMaxSetCompileCostIsRefusedAtThePatternThatCrossesIt(t *testing.T) {
	one := compile(t, negatedClasses(0)).CompileCost()
	if one <= 0 || one > MaxSetCompileCost/4 {
		t.Fatalf("one pattern costs %d units", one)
	}
	var cs []FilterCriteria
	for i := range 47 {
		cs = append(cs, negatedClasses(i))
	}
	_, err := Compile(cs)
	// Every pattern costs the same, so the one at index MaxSetCompileCost/one
	// is the first that does not fit.
	crossing := MaxSetCompileCost / one
	want := fmt.Sprintf("filter criteria with priority %d: SPT 1: the criteria cost more than MaxSetCompileCost (%d units)", crossing, MaxSetCompileCost)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("Compile = %v, want %q", err, want)
	}
	// As many as fit are accepted, and their cost is the sum of theirs.
	s, err := Compile(cs[:crossing])
	if err != nil || s.CompileCost() != crossing*one {
		t.Fatalf("%d patterns: cost %d, %v, want %d", crossing, s.CompileCost(), err, crossing*one)
	}
}

// A pattern whose source alone exceeds what is left of the budget is not
// parsed: an invalid one gets the cost error, not a syntax error.
func TestAPatternTheCostBudgetCannotPayForIsRefusedBeforeItIsParsed(t *testing.T) {
	b := setBudget{insts: MaxSetInstructions, cost: 1000}
	_, err := b.compile("Content", "("+strings.Repeat("a", 500), 0)
	if err == nil || !strings.Contains(err.Error(), "MaxSetCompileCost") || b.cost != 1000 {
		t.Fatalf("err %v, %d units left, want the cost error and nothing charged", err, b.cost)
	}
	if _, err := b.compile("Content", "(a", 0); err == nil || !strings.Contains(err.Error(), "not a POSIX") {
		t.Fatalf("a short invalid pattern: %v, want the syntax error", err)
	}
	p, err := b.compile("Content", "abc", 0)
	if err != nil || p.cost < patternCost(3, len("abc"), p.insts) || b.cost != 1000-p.cost {
		t.Fatalf("abc: %v, cost %d, %d left", err, p.cost, b.cost)
	}
	// So is a Content that would match every value.
	b = setBudget{insts: MaxSetInstructions, cost: 1000}
	if _, err := b.compileContent("Content", strings.Repeat("|", 500)); err == nil || b.cost != 1000 {
		t.Fatalf("a Content matching everything: %v, %d left", err, b.cost)
	}
}

// A Content that matches every value is not compiled, but it is parsed to
// find that out, which for 4 KiB of "|" takes about a millisecond; the parse
// is work the cost budget must pay for (QA's test from the review of #115).
func TestAContentParsedToSeeItMatchesEverythingIsCharged(t *testing.T) {
	content := strings.Repeat("|", MaxPatternBytes)
	for _, cond := range []Condition{
		SIPHeader{Header: "S", Content: content},
		SessionDescription{Line: "m", Content: content},
	} {
		s := compile(t, criteria(0, &TriggerPoint{SPTs: []SPT{{Groups: []int{0}, Condition: cond}}}))
		if s.CompileCost() < len(content) {
			t.Errorf("%T: CompileCost %d, want at least the %d bytes parsed", cond, s.CompileCost(), len(content))
		}
	}
	// Enough of them are refused like any other costly pattern, where
	// 64×64 of them were accepted at 45% of the bound and took 6.9 s.
	var cs []FilterCriteria
	for i := range 64 {
		var spts []SPT
		for range 64 {
			spts = append(spts, SPT{Groups: []int{0}, Condition: SIPHeader{Header: "S", Content: content}})
		}
		cs = append(cs, criteria(i, &TriggerPoint{ConditionTypeCNF: true, SPTs: spts}))
	}
	if _, err := Compile(cs); err == nil || !strings.Contains(err.Error(), "MaxSetCompileCost") {
		t.Fatalf("64×64 Contents matching everything: %v, want a refusal naming MaxSetCompileCost", err)
	}
}

// Every kind of condition charges each of its patterns, and charges exactly
// what compiling it costs.
func TestEveryConditionChargesEachOfItsPatterns(t *testing.T) {
	const fold, whole = patternFoldCase, patternFoldCase | patternWhole
	type part struct {
		source string
		mode   patternMode
		any    bool // a Content matching every value: only parsed
	}
	for _, tc := range []struct {
		cond  Condition
		parts []part
	}{
		{RequestURI("sip:[^@]+@ims"), []part{{"sip:[^@]+@ims", fold, false}}},
		{SIPHeader{Header: "Subj[a-z]ct"}, []part{{"Subj[a-z]ct", whole, false}, {"", 0, true}}},
		{SIPHeader{Header: "S", Content: "a[0-9]+b"}, []part{{"S", whole, false}, {"a[0-9]+b", 0, false}}},
		{SIPHeader{Header: "S", Content: ".*"}, []part{{"S", whole, false}, {".*", 0, true}}},
		{SessionDescription{Line: "m[a-z]"}, []part{{"m[a-z]", 0, false}, {"", 0, true}}},
		{SessionDescription{Line: "m", Content: "aud[a-z]o"}, []part{{"m", 0, false}, {"aud[a-z]o", 0, false}}},
	} {
		want := 0
		for _, p := range tc.parts {
			if p.any {
				want += sourceCost(len(p.source))
				continue
			}
			budget := MaxSetInstructions
			cp, err := compilePattern("P", p.source, p.mode, &budget)
			if err != nil {
				t.Fatal(err)
			}
			want += cp.cost
		}
		s := compile(t, criteria(0, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{{Groups: []int{0}, Condition: tc.cond}}}))
		if s.CompileCost() != want {
			t.Errorf("%#v: CompileCost %d, want %d", tc.cond, s.CompileCost(), want)
		}
	}
}

// The cost of the baseline shape is pinned, so a change of weight is a
// decision, not an accident; parse-dominated shapes, whose programs are
// small, are charged at least the share of the baseline's cost that their
// compile time took of the baseline's in review (#115), so that a set of
// them at the bound takes no longer than a set of the baseline shape.
func TestTheCostModelChargesEveryShapeAtLeastItsShareOfTheWork(t *testing.T) {
	cost := func(c Condition) int {
		return compile(t, criteria(0, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{{Groups: []int{0}, Condition: c}}})).CompileCost()
	}
	base := cost(negatedClasses(0).TriggerPoint.SPTs[0].Condition)
	if base != 108608 {
		t.Fatalf("1024 case-folded negated classes cost %d units, want 108608", base)
	}
	alternatives := func(word func(int) string) string {
		var b strings.Builder
		for i := 0; ; i++ {
			w := word(i)
			if b.Len()+len(w)+1 > MaxPatternBytes {
				return b.String()
			}
			if i > 0 {
				b.WriteByte('|')
			}
			b.WriteString(w)
		}
	}
	for _, tc := range []struct {
		name    string
		content string
		share   float64 // the most compile time it took, as a share of the baseline's
	}{
		{"0.|00| repeated", strings.Repeat("0.|00|", (MaxPatternBytes-3)/6) + "0.0", 0.33},
		{"unclosed [: in brackets", "([" + strings.Repeat("[:", (MaxPatternBytes-8)/2) + "a]){0}", 0.32},
		{"short literal alternatives", alternatives(func(i int) string { return "x" + strings.Repeat("y", i%40) + "z" }), 0.39},
		{"| matching everything", strings.Repeat("|", MaxPatternBytes), 0.24},
		{". repeated", strings.Repeat(".", 1900), 0.76},
	} {
		got := cost(SIPHeader{Header: "S", Content: tc.content})
		if float64(got) < tc.share*float64(base) {
			t.Errorf("%s: %d units, %.2f of the baseline's %d, want at least %.2f", tc.name, got, float64(got)/float64(base), base, tc.share)
		}
	}
}

// A profile of MaxCriteria (64) ordinary RCS criteria, each with six short
// patterns, fits every other limit (MaxSPTs, MaxSetInstructions, and the
// HSS's MaxDocumentSize at 65 KB of JSON) and must compile (QA's test from
// the review of #115; it costs about 921 000 units).
func TestAnOrdinaryProfileOfSixtyFourCriteriaCompiles(t *testing.T) {
	var cs []FilterCriteria
	for i := range 64 {
		icsi := strings.ReplaceAll(rcsICSIs[i%len(rcsICSIs)], ".", `\.`)
		cs = append(cs, criteria(i, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{
			{Groups: []int{0}, Condition: Method("INVITE")},
			{Groups: []int{0}, Condition: Method("MESSAGE")},
			{Groups: []int{1}, Condition: SIPHeader{Header: "Contact", Content: `.*\+g\.3gpp\.icsi-ref="urn%3Aurn-7%3A3gpp-service\.ims\.icsi\.` + icsi + `".*`}},
			{Groups: []int{1}, Condition: SIPHeader{Header: "Accept-Contact", Content: `.*` + icsi + `.*`}},
			{ConditionNegated: true, Groups: []int{2}, Condition: SIPHeader{Header: "P-Served-User"}},
			{Groups: []int{3}, Condition: RequestURI(`^(sip|tel):\+?[0-9]{6,15}(@ims\.mnc001\.mcc001\.3gppnetwork\.org)?(;.*)?$`)},
			{Groups: []int{3}, Condition: SIPHeader{Header: "(Accept|Reject)-Contact", Content: `.*\+g\.3gpp\.icsi-ref="[^"]*(oma\.cpm\.(msg|largemsg|session|filetransfer)|gsma\.rcs\.(chatbot|botversion))[^"]*".*`}},
			{Groups: []int{4}, Condition: SessionDescription{Line: "m", Content: `^(message|audio|video) [0-9]+ (TCP|TCP/TLS)/MSRP \*`}},
		}}))
	}
	if _, err := Compile(cs); err != nil {
		t.Fatalf("64 ordinary criteria refused: %v", err)
	}
}

// A set that costs exactly what is left fits: the bound refuses only what
// costs more, both before the parse and after the compile.
func TestAPatternThatCostsExactlyWhatIsLeftFits(t *testing.T) {
	budget := MaxSetInstructions
	p, err := compilePattern("Content", "abc", 0, &budget)
	if err != nil {
		t.Fatal(err)
	}
	for left, fits := range map[int]bool{p.cost: true, p.cost - 1: false} {
		b := setBudget{insts: MaxSetInstructions, cost: left}
		_, err := b.compile("Content", "abc", 0)
		if fits && (err != nil || b.cost != 0) || !fits && err == nil {
			t.Errorf("abc (%d units) with %d left: %v, %d left after", p.cost, left, err, b.cost)
		}
	}
	// A Content matching every value costs its source alone, which the
	// check before the parse compares.
	any := strings.Repeat("|", 100)
	for left, fits := range map[int]bool{sourceCost(len(any)): true, sourceCost(len(any)) - 1: false} {
		b := setBudget{insts: MaxSetInstructions, cost: left}
		_, err := b.compileContent("Content", any)
		if fits && (err != nil || b.cost != 0) || !fits && err == nil {
			t.Errorf("100 bars (%d units) with %d left: %v, %d left after", sourceCost(len(any)), left, err, b.cost)
		}
	}
}
