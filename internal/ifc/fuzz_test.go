package ifc

import (
	"bytes"
	"errors"
	"reflect"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"
)

// FuzzParseSubscription checks that whatever the parser accepts marshals,
// parses back to the same subscription and marshals to the same bytes.
func FuzzParseSubscription(f *testing.F) {
	f.Add([]byte(fullDocument))
	f.Add([]byte(doc("")))
	f.Add([]byte(doc(`<InitialFilterCriteria><Priority>1</Priority><TriggerPoint><ConditionTypeCNF>true</ConditionTypeCNF>` +
		`<SPT><ConditionNegated>1</ConditionNegated><Group>0</Group><SessionDescription><Line>m</Line></SessionDescription></SPT>` +
		`</TriggerPoint><ApplicationServer><ServerName>sip:as</ServerName><ServiceInfo>&amp;&#xD;</ServiceInfo></ApplicationServer>` +
		`</InitialFilterCriteria>`)))
	f.Add([]byte(`<!DOCTYPE s [<!ENTITY a "b">]><IMSSubscription/>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := ParseSubscription(data)
		if err != nil {
			return
		}
		out, err := s.Marshal()
		if errors.Is(err, ErrTooLarge) {
			// Marshal may write longer forms than the input used, such as
			// &#xD; for a carriage return, and refuses what the parser
			// would refuse.
			return
		}
		if err != nil {
			t.Fatalf("parsed subscription does not marshal: %v\n%+v", err, s)
		}
		back, err := ParseSubscription(out)
		if err != nil {
			t.Fatalf("marshalled document does not parse: %v\n%s", err, out)
		}
		if !reflect.DeepEqual(back, s) {
			t.Fatalf("round trip changed the subscription:\n%+v\n%+v", s, back)
		}
		if again, _ := back.Marshal(); !bytes.Equal(again, out) {
			t.Fatalf("second marshal differs:\n%s\n%s", out, again)
		}
		for _, p := range s.ServiceProfiles {
			if set, err := Compile(p.InitialFilterCriteria); err == nil {
				_, _ = set.Match(&sipRequest{method: "INVITE", uri: impu, headers: []HeaderField{{"From", impu}}, sdp: []string{"m=message 9 TCP/MSRP *"}}, Context{})
			}
		}
	})
}

// FuzzEvaluateTrigger compiles arbitrary patterns and evaluates them against
// arbitrary requests. Nothing may panic, and for a single trigger the normal
// form does not matter while negation inverts the answer.
func FuzzEvaluateTrigger(f *testing.F) {
	f.Add(uint8(0), "^conf\\.", "", "INVITE", "sip:conf.example.com", "Accept-Contact", "*;+g.oma.sip-im", "m=message 9 TCP/MSRP *")
	f.Add(uint8(2), "From", "spam|junk", "MESSAGE", "tel:+15550100001", "From", "<sip:junk@example.com>", "")
	f.Add(uint8(4), "m", "TCP/(TLS/)?MSRP", "INVITE", "sip:a@b", "", "", "m=message 9 TCP/TLS/MSRP *")
	f.Add(uint8(1), "MESSAGE", "", "MESSAGE", "", "", "", "")
	f.Add(uint8(3), "", "", "OPTIONS", "", "", "", "")
	f.Add(uint8(2), "Subject", `[\.]com|\x41`, "MESSAGE", "sip:a@b", "Subject", `\com`, "")
	f.Add(uint8(4), "[]^[:alpha:]]", "[[.a.]]|[[=a=]]|[^]a[]", "INVITE", "", "", "", "m=]")
	// Case pairs on adjacent code points, which the parser merges into
	// one range (#206 review).
	f.Add(uint8(2), "Subject", "|Ā|ā", "MESSAGE", "sip:a@b", "Subject", "ā", "")
	f.Add(uint8(2), "Subject", "|ā|[Ā]", "MESSAGE", "sip:a@b", "Subject", "Ā", "")
	f.Add(uint8(0), "[Ā]|[ā]|", "", "INVITE", "sip:ā@b", "", "", "")
	f.Fuzz(func(t *testing.T, kind uint8, p1, p2, method, uri, name, value, line string) {
		var c Condition
		switch kind % 5 {
		case 0:
			c = RequestURI(p1)
		case 1:
			c = Method(p1)
		case 2:
			c = SIPHeader{Header: p1, Content: p2}
		case 3:
			c = SessionCase(len(p1) % 5)
		default:
			c = SessionDescription{Line: p1, Content: p2}
		}
		r := &sipRequest{method: method, uri: uri, headers: []HeaderField{{name, value}}, sdp: []string{line}}
		results := map[[2]bool]bool{}
		for _, cnf := range []bool{true, false} {
			for _, negated := range []bool{true, false} {
				s, err := Compile([]FilterCriteria{criteria(0, &TriggerPoint{ConditionTypeCNF: cnf, SPTs: []SPT{
					{ConditionNegated: negated, Groups: []int{7}, Condition: c},
				}})})
				if err != nil {
					return
				}
				_, matched, err := s.Next(r, Context{Case: Originating}, -1)
				if err != nil {
					return // the fuzzer's values may exceed the limits
				}
				results[[2]bool{cnf, negated}] = matched
			}
		}
		if results[[2]bool{true, false}] != results[[2]bool{false, false}] ||
			results[[2]bool{true, true}] != results[[2]bool{false, true}] {
			t.Fatalf("CNF and DNF disagree on a single trigger: %v", results)
		}
		if results[[2]bool{true, false}] == results[[2]bool{true, true}] {
			t.Fatalf("negation did not invert the answer: %v", results)
		}
		// Dropping an outer ".*" must not change a content match on a
		// value without a newline, which is all evaluation ever sees.
		if !strings.Contains(value, "\n") {
			plain, err1 := Compile([]FilterCriteria{contentCriteria(p2)})
			padded, err2 := Compile([]FilterCriteria{contentCriteria(".*" + p2 + ".*")})
			if err1 == nil && err2 == nil {
				hr := req("MESSAGE", impu, HeaderField{"Subject", value})
				_, a, errA := plain.Next(hr, Context{}, -1)
				_, b, errB := padded.Next(hr, Context{}, -1)
				if errA == nil && errB == nil && a != b {
					t.Fatalf("%q and .*%q.* disagree on %q: %t, %t", p2, p2, value, a, b)
				}
			}
			// And the compiled pattern means what Go's POSIX compiler
			// says the ERE means (#61: "0+?" is (0+)?, not lazy).
			budget := MaxSetInstructions
			if got, err := compilePattern("Content", p2, 0, &budget); err == nil {
				if ref, err := regexp.CompilePOSIX(p2); err == nil && got.re.MatchString(value) != ref.MatchString(value) {
					t.Fatalf("%q on %q: compiled %t, POSIX %t", p2, value, got.re.MatchString(value), ref.MatchString(value))
				}
			}
		}
		// An ERE is refused only for its size or for a construct Go reads
		// differently from IEEE 1003.1, which the refusal names (#67), in
		// every mode.
		for _, p := range []string{p1, p2} {
			if _, err := syntax.Parse(p, posixFlags); err != nil {
				continue
			}
			departure := ereDeparture(p)
			for _, mode := range []patternMode{0, patternFoldCase, patternFoldCase | patternWhole} {
				budget := MaxSetInstructions
				_, err := compilePattern("Pattern", p, mode, &budget)
				switch {
				case departure != "" && (err == nil || !strings.Contains(err.Error(), departure)):
					t.Fatalf("%q (mode %d) uses %s but was not refused for it: %v", p, mode, departure, err)
				case departure == "" && err != nil && !strings.Contains(err.Error(), "instructions"):
					t.Fatalf("%q (mode %d) refused: %v", p, mode, err)
				}
			}
		}
	})
}
