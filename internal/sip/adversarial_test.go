package sip

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

// docs/architecture.md §8 requires every parser to be linear in its input, shown
// by parsing maximum-size adversarial input. Each shape below fills a header
// section of a given size with one pattern that a careless parser handles in
// quadratic time or allocations. The test parses and reads it at the default
// limit and at four times that, and checks the cost grows about four times.

const adversarialSmall = DefaultMaxHeaderBytes

// adversarialShapes build a header value of about n bytes.
var adversarialShapes = []struct {
	name   string
	header string
	value  func(n int) string
}{
	{"contacts with escaped parameter names", "Contact", func(n int) string {
		// Distinct names that share an escaped prefix, so comparing every pair
		// would need a full normalization each time.
		return fillList(n, ", ", func(i int) string {
			var b strings.Builder
			b.WriteString("<sip:u" + strconv.Itoa(i) + "@example.com")
			for j := 0; j < maxParams; j++ {
				b.WriteString(";%61%61%61%61%61%61" + strconv.Itoa(j))
			}
			return b.String() + ">"
		})
	}},
	{"vias with long similar parameter names", "Via", func(n int) string {
		prefix := strings.Repeat("p", 40)
		return fillList(n, ", ", func(i int) string {
			var b strings.Builder
			b.WriteString("SIP/2.0/UDP h" + strconv.Itoa(i) + ".example.com;branch=z9hG4bK" + strconv.Itoa(i))
			for j := 0; j < maxParams-1; j++ {
				b.WriteString(";" + prefix + strconv.Itoa(j))
			}
			return b.String()
		})
	}},
	{"routes with URI headers", "Route", func(n int) string {
		return fillList(n, ",", func(i int) string {
			var b strings.Builder
			b.WriteString("<sip:r" + strconv.Itoa(i) + ".example.com;lr?")
			for j := 0; j < maxParams; j++ {
				if j > 0 {
					b.WriteString("&")
				}
				b.WriteString("h=" + strconv.Itoa(j))
			}
			return b.String() + ">"
		})
	}},
	{"one-byte folded lines", "Subject", func(n int) string {
		return strings.Repeat("a\r\n ", n/4)
	}},
	{"quoted-pairs", "To", func(n int) string {
		return `"` + strings.Repeat(`\"`, n/2) + `" <sip:b@example.com>`
	}},
	{"accept-contact elements", "Accept-Contact", func(n int) string {
		return strings.TrimSuffix(strings.Repeat(`*;+g.oma.sip-im;require,`, n/24), ",")
	}},
	{"supported tokens", "Supported", func(n int) string {
		return strings.TrimSuffix(strings.Repeat("timer,", n/6), ",")
	}},
	{"escapes in a Request-URI user part", "P-Called-Party-ID", func(n int) string {
		return "<sip:" + strings.Repeat("%41", n/3) + "@example.com>"
	}},
}

// adversarialMessage puts value into a request that is otherwise minimal, sized
// so the header section is just under limit.
func adversarialMessage(header, value string) []byte {
	return []byte("OPTIONS sip:a@example.com SIP/2.0\r\n" + header + ": " + value + "\r\nContent-Length: 0\r\n\r\n")
}

// readEverything parses data and reads it the way a service would: every typed
// accessor, Validate, URI comparison and serialization.
func readEverything(tb testing.TB, data []byte, lim Limits) {
	m, err := ParseDatagram(data, lim)
	if err != nil {
		tb.Fatalf("ParseDatagram: %v", err)
	}
	h := m.Headers()
	_, _ = h.Via()
	cs, _ := h.Contact()
	for _, c := range cs {
		_, _, _ = c.Expires()
		_, _, _ = c.Q()
		_ = c.URI.Equal(c.URI)
	}
	routes, _ := h.Route()
	for _, r := range routes {
		_ = r.URI.Equal(r.URI)
	}
	_, _ = h.To()
	_, _ = h.Supported()
	_, _ = h.AcceptContact()
	_, _ = h.PCalledPartyID()
	_ = m.Validate()
	if _, err := m.Bytes(); err != nil {
		tb.Fatalf("Bytes: %v", err)
	}
}

func TestMaximumSizeAdversarialInputCostsLinearTime(t *testing.T) {
	small := Limits{MaxHeaderBytes: adversarialSmall}
	large := Limits{MaxHeaderBytes: 4 * adversarialSmall}
	for _, shape := range adversarialShapes {
		t.Run(shape.name, func(t *testing.T) {
			const overhead = 128
			s := adversarialMessage(shape.header, shape.value(adversarialSmall-overhead))
			l := adversarialMessage(shape.header, shape.value(4*adversarialSmall-overhead))
			if len(s) > adversarialSmall || len(s) < adversarialSmall/2 {
				t.Fatalf("small input is %d bytes", len(s))
			}

			// Allocations are deterministic, so they get the tight bound.
			as := testing.AllocsPerRun(5, func() { readEverything(t, s, small) })
			al := testing.AllocsPerRun(5, func() { readEverything(t, l, large) })
			if al > 6*as+16 {
				t.Errorf("allocations grow from %.0f to %.0f for four times the input", as, al)
			}

			// Time gets a loose bound: linear is about 4x, quadratic about 16x.
			ts, tl := fastest(func() { readEverything(t, s, small) }), fastest(func() { readEverything(t, l, large) })
			if tl > 10*ts+time.Millisecond {
				t.Errorf("time grows from %v to %v for four times the input", ts, tl)
			}
		})
	}
}

// The case from the security review of PR #27: a Contact list whose URIs carry
// the most parameters allowed, all with escaped names. Normalizing names once per
// pair made one Contact() call take 170,000 allocations.
func TestWorstCaseContactReadStaysAllocationLight(t *testing.T) {
	data := adversarialMessage("Contact", adversarialShapes[0].value(DefaultMaxHeaderBytes-128))
	m, err := ParseMessage(data)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := m.Headers().Contact()
	if err != nil {
		t.Fatal(err)
	}
	params := 0
	for _, c := range cs {
		params += len(c.URI.Params)
	}
	allocs := testing.AllocsPerRun(10, func() {
		if _, err := m.Headers().Contact(); err != nil {
			t.Fatal(err)
		}
	})
	// About one allocation per escaped name for its comparison key, plus a few
	// per contact; a per-pair normalization would be ~32 per parameter.
	if allocs > 3*float64(params) {
		t.Errorf("Contact() of %d contacts with %d parameters made %.0f allocations", len(cs), params, allocs)
	}
	eq := testing.AllocsPerRun(10, func() { _ = cs[0].URI.Equal(cs[1].URI) })
	if eq > 4*maxParams {
		t.Errorf("Equal of two %d-parameter URIs made %.0f allocations", maxParams, eq)
	}
}

// fillList joins elements until the next one would take the list past n bytes.
func fillList(n int, sep string, elem func(i int) string) string {
	var b strings.Builder
	for i := 0; ; i++ {
		e := elem(i)
		if i > 0 {
			e = sep + e
		}
		if b.Len()+len(e) > n {
			return b.String()
		}
		b.WriteString(e)
	}
}

func fastest(f func()) time.Duration {
	best := time.Duration(1<<63 - 1)
	for i := 0; i < 5; i++ {
		start := time.Now()
		f()
		if d := time.Since(start); d < best {
			best = d
		}
	}
	return best
}
