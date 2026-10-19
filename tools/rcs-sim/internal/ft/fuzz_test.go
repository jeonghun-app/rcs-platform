package ft

import (
	"bytes"
	"testing"
)

// FuzzDocuments feeds the document reader whatever a server might answer:
// it never panics, and an upload-info document it accepts always describes
// at least one held byte from byte 0.
func FuzzDocuments(f *testing.F) {
	f.Add([]byte(`<?xml version="1.0"?><file xmlns="urn:gsma:params:xml:ns:rcs:rcs:fthttp"><file-info type="file"><file-size>7</file-size>` +
		`<file-name>a.jpg</file-name><content-type>image/jpeg</content-type><data url="https://ft.example.test/dl?id=x" until="2026-01-01T00:00:00Z"/></file-info></file>`))
	f.Add([]byte(`<file-resume-info xmlns="urn:gsma:params:xml:ns:rcs:rcs:fthttp"><file-range start="0" end="5242879"/><data url="/ft/t"/></file-resume-info>`))
	f.Add([]byte(`<!DOCTYPE file [<!ENTITY x "y">]><file/>`))
	f.Add([]byte(`<file-resume-info xmlns="urn:gsma:params:xml:ns:rcs:rcs:fthttp"><file-range start="0" end="-1"/></file-resume-info>`))
	// end+1 would overflow (found in review of #68).
	f.Add([]byte(`<file-resume-info xmlns="urn:gsma:params:xml:ns:rcs:rcs:fthttp"><file-range start="0" end="9223372036854775807"/></file-resume-info>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var d FileDocument
		_ = decode(bytes.NewReader(data), &d)
		_, _ = d.Info("file")
		var r ResumeDocument
		if decode(bytes.NewReader(data), &r) != nil {
			return
		}
		if held, err := r.Held(); err == nil && held < 1 {
			t.Fatalf("accepted a range holding %d bytes", held)
		}
	})
}
