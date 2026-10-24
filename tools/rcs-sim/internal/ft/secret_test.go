package ft_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/ft"
)

// verbs are the valid verbs and invalid ones such as %p, %w and %t, for
// which fmt calls no method and prints the fields by reflection; a
// mismatched one such as %s also prints a nested pointer's target in full.
var verbs = []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%t", "%x", "%X", "%o", "%O", "%b", "%p", "%#p", "%w", "%c", "%U", "%e", "%f", "%g"}

// leakForms are the ways pw's bytes could show up in text: as is, as hex,
// and as fmt renders a byte slice under each verb.
func leakForms(pw string) []string {
	forms := []string{pw, hex.EncodeToString([]byte(pw)), strings.ToUpper(hex.EncodeToString([]byte(pw)))}
	for _, verb := range verbs {
		if s := fmt.Sprintf(verb, []byte(pw)); strings.HasPrefix(s, "[") {
			forms = append(forms, strings.Trim(s, "[]"))
		}
	}
	return forms
}

func TestNoVerbPrintsTheFTPassword(t *testing.T) {
	const pw = "ft-print-probe-password"
	c := &ft.Client{User: "u", Password: ft.NewSecret(pw)}
	holder := &struct{ C ft.Client }{}
	holder.C.Password = ft.NewSecret(pw)
	values := map[string]any{"Secret": ft.NewSecret(pw), "*Client": c, "a struct holding a Client": holder}

	forms := leakForms(pw)
	for name, v := range values {
		var outs []string
		for _, verb := range verbs {
			for _, w := range []any{v, []any{v}, struct{ V any }{v}} {
				outs = append(outs, fmt.Sprintf(verb, w), fmt.Errorf(verb, w).Error())
			}
		}
		var buf bytes.Buffer
		slog.New(slog.NewJSONHandler(&buf, nil)).Info("m", "v", v, "nested", struct{ V any }{v})
		slog.New(slog.NewTextHandler(&buf, nil)).Info("m", "v", v, "nested", struct{ V any }{v})
		outs = append(outs, buf.String())
		for _, out := range outs {
			for _, f := range forms {
				if strings.Contains(out, f) {
					t.Errorf("%s prints the password: %q", name, out)
					break
				}
			}
		}
	}
}
