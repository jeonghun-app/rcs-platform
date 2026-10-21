package xmlsafe

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"testing"
)

// FuzzCheck compares Check with oldCheck, the document check each package
// carried before #17, frozen here: whatever the old one refused, Check
// refuses as the same kind (DTD, size, malformed), unless one of the
// rules #17 added stopped it earlier in the document; and whatever Check
// refuses that the old one took is one of those rules, each of which needs
// what the document holds (a reference to a surrogate, attributes run
// together, an xml PI target). And what Check takes holds none of the
// three, as independent scanners of the document see them. Check never
// panics.
func FuzzCheck(f *testing.F) {
	for _, s := range []string{
		`<a/>`, `<?xml version="1.0"?><a x="1"><b>&#xD800;</b></a>`, `<a x="1"y="2"/>`,
		`<!DOCTYPE a><a/>`, `<?XML version="1.0"?><a/>`, `<a><![CDATA[&#xD800;]]></a>`, "\xef\xbb\xbf<a>&amp;</a>",
		`<a><?xml version="1.0"?></a>`, `<a><b><c><d><e><f><g><h><i/></h></g></f></e></d></c></b></a>`,
	} {
		f.Add([]byte(s))
	}
	d := Doc{MaxSize: 4 << 10, MaxDepth: 8}
	together := regexp.MustCompile(`["'][^\s/>"']`)
	decl := regexp.MustCompile(`(?i)<\?xml`)
	f.Fuzz(func(t *testing.T, data []byte) {
		err, old := d.Check(data), oldCheck(data, d.MaxSize, d.MaxDepth)
		newRule := func() bool {
			msg := err.Error()
			return strings.HasSuffix(msg, "a character reference to a surrogate") && surrogateRef.Match(data) ||
				strings.HasSuffix(msg, "attributes not separated by white space") && together.Match(data) ||
				(strings.HasSuffix(msg, "an XML declaration not in lower case") || strings.HasSuffix(msg, "an XML declaration not at the start")) && decl.Match(data)
		}
		if err == nil {
			if what := notWellFormed(WithoutBOM(data)); what != "" {
				t.Fatalf("Check took %s", what)
			}
		}
		switch {
		case old != nil && err == nil:
			t.Fatalf("the old check refused it (%v), Check took it", old)
		case old != nil:
			if kind(err) != kind(old) && !newRule() {
				t.Fatalf("refused as %v, the old check as %v", err, old)
			}
		case err != nil:
			if !newRule() {
				t.Fatalf("Check refused what the old check took, by no rule of #17: %v", err)
			}
		}
	})
}

var (
	// skipped are the parts of a document whose text is no markup, and
	// pis its processing instructions.
	skipped      = regexp.MustCompile(`(?s)<!\[CDATA\[.*?\]\]>|<!--.*?-->`)
	pis          = regexp.MustCompile(`(?s)<\?.*?\?>`)
	startTag     = regexp.MustCompile(`<[A-Za-z_:][^<]*?>`)
	runTogether  = regexp.MustCompile(`=\s*("[^"<]*"|'[^'<]*')[^\s/>]`)
	xmlTarget    = regexp.MustCompile(`(?i)<\?xml[\s?]`)
	surrogateRef = regexp.MustCompile(`&#(x0*[dD][89a-fA-F][0-9a-fA-F]{2}|0*(5529[6-9]|55[3-9][0-9]{2}|56[0-9]{3}|57[0-2][0-9]{2}|573[0-3][0-9]|5734[0-3]));`)
)

// notWellFormed says which of #17's rules data breaks, found without
// encoding/xml: a reference to a surrogate outside CDATA and comments,
// attributes run together in a start tag, or an xml PI target in another
// case or after anything but white space.
func notWellFormed(data []byte) string {
	blank := func(b []byte) []byte { return bytes.Repeat([]byte(" "), len(b)) }
	markup := skipped.ReplaceAllFunc(data, blank)
	elements := pis.ReplaceAllFunc(markup, blank)
	if surrogateRef.Match(elements) {
		return "a reference to a surrogate"
	}
	for _, tag := range startTag.FindAll(elements, -1) {
		if runTogether.Match(tag) {
			return "attributes run together"
		}
	}
	for _, at := range pis.FindAllIndex(markup, -1) {
		pi := markup[at[0]:at[1]]
		late := len(bytes.Trim(data[:at[0]], " \t\r\n")) > 0 // data, not markup, keeps a comment before it
		if xmlTarget.Match(pi) && xmlTarget.FindIndex(pi)[0] == 0 && (late || !bytes.HasPrefix(pi, []byte("<?xml"))) {
			return "an xml PI target in another case or not at the start"
		}
	}
	return ""
}

func kind(err error) error {
	switch {
	case errors.Is(err, ErrDTD):
		return ErrDTD
	case errors.Is(err, ErrTooLarge):
		return ErrTooLarge
	}
	return ErrMalformed
}

// oldCheck is checkDocument as internal/conference/xml.go had it on main
// before #17 (44a7658), with its limits as arguments and its errors the
// package-level ones, for FuzzCheck to compare with.
func oldCheck(data []byte, maxSize, maxDepth int) error {
	if len(data) > maxSize {
		return ErrTooLarge
	}
	d := xml.NewDecoder(bytes.NewReader(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))))
	depth, roots := 0, 0
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: decode", ErrMalformed)
		}
		switch t := tok.(type) {
		case xml.Directive:
			return ErrDTD
		case xml.StartElement:
			if depth == 0 {
				roots++
			}
			depth++
			if roots > 1 || depth > maxDepth || hasRepeatedAttr(t.Attr) {
				return ErrMalformed
			}
		case xml.EndElement:
			depth--
		case xml.CharData:
			if depth == 0 && len(bytes.Trim(t, " \t\r\n")) > 0 {
				return ErrMalformed
			}
		}
	}
	if roots == 0 {
		return ErrMalformed
	}
	return nil
}
