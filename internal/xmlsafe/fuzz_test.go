package xmlsafe

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"testing"
)

// A document Check accepts reads through encoding/xml without an error, has
// one root, and never holds a reference to a surrogate outside CDATA; and
// Check never panics.
func FuzzCheck(f *testing.F) {
	for _, s := range []string{
		`<a/>`, `<?xml version="1.0"?><a x="1"><b>&#xD800;</b></a>`, `<a x="1"y="2"/>`,
		`<!DOCTYPE a><a/>`, `<?XML version="1.0"?><a/>`, `<a><![CDATA[&#xD800;]]></a>`, "\xef\xbb\xbf<a>&amp;</a>",
	} {
		f.Add([]byte(s))
	}
	d := Doc{MaxSize: 4 << 10, MaxDepth: 8}
	f.Fuzz(func(t *testing.T, data []byte) {
		if d.Check(data) != nil {
			return
		}
		dec := xml.NewDecoder(bytes.NewReader(WithoutBOM(data)))
		roots, depth := 0, 0
		for {
			tok, err := dec.Token()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatalf("accepted, but encoding/xml says %v", err)
			}
			switch tok.(type) {
			case xml.StartElement:
				if depth == 0 {
					roots++
				}
				depth++
			case xml.EndElement:
				depth--
			case xml.Directive:
				t.Fatal("accepted a DTD")
			}
		}
		if roots != 1 {
			t.Fatalf("accepted %d roots", roots)
		}
	})
}
