package proxy

import (
	"fmt"
	"strings"
	"testing"
)

// The proxy's hash key prints as its placeholder under these verbs, valid
// ones and the invalid %p and %w, which call no method and print the
// fields: neither in hex of either case nor as %d writes bytes (#570).
func TestTheProxysKeyNeverPrints(t *testing.T) {
	h := newHarness(t, Config{})
	key := h.p.key.Reveal()
	if len(key) == 0 {
		t.Fatal("no key")
	}
	forms := []string{fmt.Sprintf("%x", key[:6]), fmt.Sprintf("%X", key[:6]), strings.Trim(fmt.Sprint(key[:6]), "[]")}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%t", "%x", "%X", "%o", "%b", "%p", "%w", "%c", "%e"} {
		out := fmt.Sprintf(verb, h.p)
		for _, form := range forms {
			if strings.Contains(out, form) {
				t.Errorf("%s printed the key as %q", verb, form)
			}
		}
	}
}
