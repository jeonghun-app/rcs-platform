package imdn

import "testing"

// FuzzParseNotification checks that ParseNotification never panics and that
// any document it accepts marshals to one that parses to the same
// notification.
func FuzzParseNotification(f *testing.F) {
	f.Add([]byte(doc(validBody + delivered(""))))
	f.Add([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<imdn xmlns="urn:ietf:params:xml:ns:imdn" xmlns:x="urn:example:ext">
  <message-id> abc </message-id>
  <datetime>2026-10-18T09:30:00.25+09:00</datetime>
  <recipient-uri>` + bob + `</recipient-uri>
  <original-recipient-uri>` + focus + `</original-recipient-uri>
  <subject xml:lang="en">a &amp; b&#xD;</subject>
  <processing-notification><status><x:why/><stored/></status></processing-notification>
</imdn>`))
	f.Add([]byte(`<!DOCTYPE imdn [<!ENTITY x "y">]><imdn/>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		n, err := ParseNotification(data)
		if err != nil {
			return
		}
		out, err := n.Marshal()
		if err != nil {
			t.Fatalf("Marshal of a parsed notification failed: %v\n%+v", err, n)
		}
		back, err := ParseNotification(out)
		if err != nil || back != n {
			t.Fatalf("round trip changed the notification:\n%+v\n%+v, %v", n, back, err)
		}
	})
}

// FuzzParseDispositions checks that an accepted Disposition-Notification value
// formats back to the same set.
func FuzzParseDispositions(f *testing.F) {
	f.Add("positive-delivery, negative-delivery")
	f.Add("display;x=1 , future , processing")
	f.Fuzz(func(t *testing.T, v string) {
		d, err := ParseDispositions(v)
		if err != nil {
			return
		}
		back, err := ParseDispositions(d.String())
		if err != nil || back != d {
			t.Fatalf("ParseDispositions(%q) = %v, then %q gave %v, %v", v, d, d.String(), back, err)
		}
	})
}
