package sdp

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func addSeeds(f *testing.F) {
	for _, s := range []string{chatOffer, chatAnswer, fileOffer, everyField, coreChatOffer, head} {
		f.Add([]byte(s))
		f.Add([]byte(strings.ReplaceAll(s, "\r\n", "\n")))
	}
}

// FuzzParse checks that whatever the parser accepts serializes, and that the
// serialized form parses back to the same session and serializes to the same
// bytes: parse → serialize → parse is stable.
func FuzzParse(f *testing.F) {
	addSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := Parse(data)
		if err != nil {
			return
		}
		out, err := s.Marshal()
		if err != nil {
			t.Fatalf("accepted description does not serialize: %v\ninput %q", err, data)
		}
		// CRLF output can be longer than LF input near the limit.
		s2, err := Parser{MaxSize: len(out)}.Parse(out)
		if err != nil {
			t.Fatalf("serialized description does not parse: %v\n%q", err, out)
		}
		if !reflect.DeepEqual(s, s2) {
			t.Fatalf("round trip changed the session:\n%+v\n%+v", s, s2)
		}
		out2, err := s2.Marshal()
		if err != nil || !bytes.Equal(out, out2) {
			t.Fatalf("second serialization differs (%v):\n%q\n%q", err, out, out2)
		}
	})
}

// FuzzMediaAttributes feeds arbitrary attribute lines to every typed getter.
// None may panic, and a value a getter returns must be accepted by the
// matching setter and read back unchanged.
func FuzzMediaAttributes(f *testing.F) {
	for _, s := range []string{chatOffer, fileOffer} {
		_, media, _ := strings.Cut(s, "m=message 9 ")
		_, attrLines, _ := strings.Cut(media, "\r\n")
		f.Add(attrLines)
	}
	f.Add("a=file-selector\r\na=file-range:5-*\r\na=connection:new\r\n")
	f.Fuzz(func(t *testing.T, lines string) {
		s, err := Parse([]byte(head + "m=message 9 TCP/MSRP *\r\n" + lines))
		if err != nil {
			return
		}
		for i := range s.Media {
			m := &s.Media[i]
			_, _ = m.FileSelector()
			_, _ = m.FileTransferID()
			_, _ = m.FileDisposition()
			_, _ = m.FileDate()
			_, _ = m.FileIcon()
			_, _ = m.FileRange()
			_, _ = m.TCPConnection()
			_, _ = s.MediaSetup(i)
			_, _ = s.MediaDirection(i)
			if v, err := m.Path(); err == nil {
				roundTrip(t, "path", v, m.SetPath, m.Path)
			}
			if v, err := m.AcceptTypes(); err == nil {
				roundTrip(t, "accept-types", v, m.SetAcceptTypes, m.AcceptTypes)
			}
			if v, err := m.AcceptWrappedTypes(); err == nil {
				roundTrip(t, "accept-wrapped-types", v, m.SetAcceptWrappedTypes, m.AcceptWrappedTypes)
			}
			if v, err := m.MaxSize(); err == nil {
				roundTrip(t, "max-size", v, m.SetMaxSize, m.MaxSize)
			}
			if v, err := m.Setup(); err == nil {
				roundTrip(t, "setup", v, m.SetSetup, m.Setup)
			}
			if v, err := m.Direction(); err == nil {
				roundTrip(t, "direction", v, m.SetDirection, m.Direction)
			}
		}
		if _, err := s.Marshal(); err != nil {
			t.Fatalf("setters produced an unserializable session: %v", err)
		}
	})
}

func roundTrip[T any](t *testing.T, name string, v T, set func(T) error, get func() (T, error)) {
	t.Helper()
	if err := set(v); err != nil {
		t.Fatalf("%s: setter refused %v that the getter returned: %v", name, v, err)
	}
	if got, err := get(); err != nil || !reflect.DeepEqual(got, v) {
		t.Fatalf("%s: read back %v, %v; want %v", name, got, err, v)
	}
}

// FuzzOfferAnswerAndRewrite answers and rewrites every media line of an
// arbitrary offer. Whatever either helper produces must serialize and parse
// again, and a refused rewrite must leave the session unchanged.
func FuzzOfferAnswerAndRewrite(f *testing.F) {
	addSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		offer, err := Parse(data)
		if err != nil {
			return
		}
		ans := NewAnswer(offer, asOrigin, asConnection)
		for i := range offer.Media {
			for _, path := range []string{"msrp://10.0.1.20:2855/a;tcp", "msrps://10.0.1.20:2855/a;tcp"} {
				local := asEndpoint()
				local.Path = []string{path}
				if m, err := NegotiateMSRP(offer, i, local); err == nil {
					ans.Media[i] = m
				}
			}
		}
		out, err := ans.Marshal()
		if err != nil {
			t.Fatalf("answer does not serialize: %v", err)
		}
		if _, err := (Parser{MaxSize: len(out)}).Parse(out); err != nil {
			t.Fatalf("answer does not parse: %v\n%q", err, out)
		}

		for i := range offer.Media {
			before, _ := offer.Marshal()
			err := offer.RewriteMSRP(i, relayToCore)
			after, merr := offer.Marshal()
			if merr != nil {
				t.Fatalf("rewritten session does not serialize: %v", merr)
			}
			if err != nil && !bytes.Equal(before, after) {
				t.Fatalf("refused rewrite (%v) changed the session", err)
			}
			if err == nil {
				if p, perr := offer.Media[i].Path(); perr != nil || !reflect.DeepEqual(p, relayToCore.Path) {
					t.Fatalf("rewritten path = %q, %v", p, perr)
				}
			} else if !errors.Is(err, ErrNotMSRP) && !errors.Is(err, ErrMediaDisabled) && offer.Media[i].IsMSRP() {
				// The only other refusal for valid rewrite input is a
				// malformed a=path in the description itself.
				if _, perr := offer.Media[i].Path(); perr == nil {
					t.Fatalf("rewrite refused a line with a valid path: %v", err)
				}
			}
		}
	})
}
