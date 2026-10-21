package xmlsafe

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"runtime"
	"strings"
	"testing"
)

var errPkg = errors.New("pkg: malformed")

var testDoc = Doc{MaxSize: 1 << 10, MaxDepth: 4, Malformed: errPkg}

func TestTheChecksRefuseWhatEncodingXMLLetsThrough(t *testing.T) {
	for name, tc := range map[string]struct {
		doc  string
		want error
	}{
		"a DTD":                         {`<!DOCTYPE a [<!ENTITY e "x">]><a/>`, ErrDTD},
		"too large":                     {"<a>" + strings.Repeat("x", 1<<10) + "</a>", ErrTooLarge},
		"nested too deep":               {"<a><b><c><d><e/></d></c></b></a>", errPkg},
		"two roots":                     {"<a/><b/>", errPkg},
		"no root":                       {"  ", errPkg},
		"text outside the root":         {"<a/>x", errPkg},
		"a repeated attribute":          {`<a x="1" x="2"/>`, errPkg},
		"attributes run together":       {`<a x="1"y="2"/>`, errPkg},
		"attributes run together ' ":    {`<a x='1'y='2'/>`, errPkg},
		"a surrogate in text":           {`<a>&#xD800;</a>`, errPkg},
		"a surrogate, decimal":          {`<a>&#57343;</a>`, errPkg},
		"a surrogate in an attribute":   {`<a x="&#xdfff;"/>`, errPkg},
		"an upper-case declaration":     {`<?XML version="1.0"?><a/>`, errPkg},
		"a mixed-case declaration":      {`<?xMl version="1.0"?><a/>`, errPkg},
		"unbalanced":                    {`<a><b></a>`, errPkg},
		"a declaration inside":          {`<a><?xml version="1.0"?></a>`, errPkg},
		"a declaration after a space":   {` <?xml version="1.0"?><a/>`, errPkg},
		"a declaration after a comment": {`<!--c--><?xml version="1.0"?><a/>`, errPkg},
	} {
		if err := testDoc.Check([]byte(tc.doc)); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	for name, doc := range map[string]string{
		"at the depth limit":           "<a><b><c><d/></c></b></a>",
		"a declaration and a BOM":      "\xef\xbb\xbf" + `<?xml version="1.0" encoding="UTF-8"?><a/>`,
		"attributes apart":             "<a x=\"1\"\ty='2' z=\"'\"/>",
		"the last attribute before />": `<a x="1"/>`,
		"other references":             `<a x="&#xD7FF;&#xE000;">&#x10FFFF;&#65533;&amp;#xD800;</a>`,
		"a surrogate in CDATA":         `<a><![CDATA[&#xD800;]]></a>`,
		"a comment and a PI":           `<!-- &#xD800; --><?pi x?><a/>`,
	} {
		if err := testDoc.Check([]byte(doc)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// SurrogateRefs lets one through, for a reader that skips its value.
	lenient := testDoc
	lenient.SurrogateRefs = true
	if err := lenient.Check([]byte(`<a x="&#xD800;">&#xDFFF;</a>`)); err != nil {
		t.Errorf("SurrogateRefs: %v", err)
	}
}

// A Doc without errors of its own reports the package-level ones, and an
// error never quotes the document.
func TestTheErrorsAreTheDocsAndQuoteNothing(t *testing.T) {
	plain := Doc{MaxSize: 64, MaxDepth: 4}
	if err := plain.Check([]byte(`<a x="secret"y="1"/>`)); !errors.Is(err, ErrMalformed) || strings.Contains(err.Error(), "secret") {
		t.Errorf("attributes run together: %v", err)
	}
	if err := plain.Check([]byte(`<a>&undefined-secret;</a>`)); !errors.Is(err, ErrMalformed) || strings.Contains(err.Error(), "secret") {
		t.Errorf("an undefined entity: %v", err)
	}
	own := Doc{MaxSize: 4, MaxDepth: 4, TooLarge: errPkg}
	if err := own.Check([]byte("<a></a>")); err != errPkg {
		t.Errorf("too large: %v", err)
	}
}

func TestAReaderReturnsTheTokensThenEOF(t *testing.T) {
	r, err := testDoc.NewReader([]byte(`<a x="1"><b>t</b></a>`))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for {
		_, err := r.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		n++
	}
	if n != 5 {
		t.Fatalf("%d tokens", n)
	}
}

func TestIsTextAndCollapse(t *testing.T) {
	for s, want := range map[string]bool{"a\tb\r\n": true, "\x01": false, "\uFFFE": false, "\xff": false, "\U0010FFFF": true, "\uFFFD": true} {
		if IsText(s) != want {
			t.Errorf("IsText(%q) != %v", s, want)
		}
	}
	if got := Collapse(" a \t\r\n b  "); got != "a b" {
		t.Errorf("Collapse: %q", got)
	}
}

func TestAWriterKeepsTheFirstError(t *testing.T) {
	var b bytes.Buffer
	w := NewWriter(&b)
	w.Start("a")
	w.Text("b", "x<y")
	w.End("a")
	if err := w.Close(); err != nil || b.String() != "<a><b>x&lt;y</b></a>" {
		t.Fatalf("%q, %v", b.String(), err)
	}
	w = NewWriter(&b)
	w.End("never-started")
	w.Start("a")
	if err := w.Close(); err == nil {
		t.Fatal("an unbalanced end tag wrote")
	}
}

// Security review on #403: Check is linear in its input. What it allocates
// for an adversarial document eight times as long grows at most about
// eight times, measured in bytes allocated (not time, which load skews,
// #317): many attributes, many character references, text in many short
// tokens, and nesting at the limit over and over.
func TestCheckIsLinearInItsInput(t *testing.T) {
	const small = 32 << 10
	big := Doc{MaxSize: 8 * small, MaxDepth: 32}
	for name, build := range map[string]func(n int) string{
		"attributes": func(n int) string {
			var b strings.Builder
			b.WriteString("<a")
			for i := 0; b.Len() < n-16; i++ {
				fmt.Fprintf(&b, ` x%d="&#x41;'"`, i)
			}
			b.WriteString("/>")
			return b.String()
		},
		"references": func(n int) string {
			return "<a>" + strings.Repeat("&#xD7FF;&#65;&amp;", (n-16)/18) + "</a>"
		},
		"short tokens": func(n int) string {
			return "<a>" + strings.Repeat("<b/>x<!--c-->", (n-16)/13) + "</a>"
		},
		"nesting": func(n int) string {
			one := strings.Repeat("<e>", 31) + strings.Repeat("</e>", 31)
			return "<a>" + strings.Repeat(one, (n-16)/len(one)) + "</a>"
		},
	} {
		t.Run(name, func(t *testing.T) {
			alloc := func(doc string) uint64 {
				data := []byte(doc)
				if err := big.Check(data); err != nil {
					t.Fatalf("%d bytes: %v", len(data), err)
				}
				least := uint64(math.MaxUint64)
				for range 3 {
					var before, after runtime.MemStats
					runtime.ReadMemStats(&before)
					_ = big.Check(data)
					runtime.ReadMemStats(&after)
					least = min(least, after.TotalAlloc-before.TotalAlloc)
				}
				return least
			}
			a, b := alloc(build(small)), alloc(build(8*small))
			if b > 12*a {
				t.Fatalf("8× the input allocated %d bytes against %d: not linear", b, a)
			}
		})
	}
}
