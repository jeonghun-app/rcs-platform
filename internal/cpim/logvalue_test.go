package cpim

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
)

// untimedLoggers write JSON and text lines without the time attribute, so
// that a search for leaked digits cannot find them in the timestamp (#99).
func untimedLoggers(js, text io.Writer) (*slog.Logger, *slog.Logger) {
	opts := &slog.HandlerOptions{ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		if len(groups) == 0 && a.Key == slog.TimeKey {
			return slog.Attr{}
		}
		return a
	}}
	return slog.New(slog.NewJSONHandler(js, opts)), slog.New(slog.NewTextHandler(text, opts))
}

// A CPIM address names a subscriber in its URI and a person in its formal
// name. Logged directly, in a plain slice or in a struct field, as JSON or
// text, it shows its URI's scheme and host only (#109).
func TestAddressesLogNeitherTheirUserNorTheirFormalName(t *testing.T) {
	from := Address{Name: "Alice Secret", URI: alice}
	to := []Address{{URI: "im:bob.secret@ims.mnc001.mcc001.3gppnetwork.org"}, {Name: "Carol", URI: "tel:+15550100003"}}
	direct, err := json.Marshal(struct {
		From Address
		To   []Address
	}{from, to})
	if err != nil {
		t.Fatal(err)
	}
	var js, text bytes.Buffer
	jsonLog, textLog := untimedLoggers(&js, &text)
	jsonLog.Info("x", "from", from, "to", to)
	textLog.Info("x", "from", from)
	for name, out := range map[string]string{"json.Marshal": string(direct), "JSON handler": js.String(), "text handler": text.String()} {
		if strings.Contains(out, "time=") || strings.Contains(out, `"time"`) {
			t.Fatalf("%s: the line has a timestamp whose digits could match a secret:\n%s", name, out)
		}
		for _, secret := range []string{"15550100001", "15550100003", "Alice Secret", "bob.secret", "Carol"} {
			if strings.Contains(out, secret) {
				t.Errorf("%s output contains %q:\n%s", name, secret, out)
			}
		}
	}
	for _, want := range []string{
		`"from":{"uri":"sip:***01@ims.mnc001.mcc001.3gppnetwork.org"}`,
		`"to":[{"uri":"im:***et@ims.mnc001.mcc001.3gppnetwork.org"},{"uri":"tel:+***03"}]`,
	} {
		if !strings.Contains(js.String(), want) {
			t.Errorf("JSON log lacks %s:\n%s", want, js.String())
		}
	}
	if !strings.Contains(text.String(), "from.uri=sip:***01@ims.mnc001.mcc001.3gppnetwork.org") {
		t.Errorf("text log = %s", text.String())
	}
}
