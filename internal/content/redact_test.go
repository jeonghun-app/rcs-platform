package content

import (
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/content/contenttest"
)

// No fmt verb, valid or not, slog record or JSON encoding shows a Body,
// alone, behind a pointer or inside a struct, slice or map (#530).
func TestABodyIsPrintedNowhere(t *testing.T) {
	const chat = "meet me at the usual place"
	b := BodyOf([]byte(chat))
	holder := struct {
		B   Body
		Ptr *Body
	}{b, &b}
	contenttest.Hidden(t, chat, b, &b, holder, &holder, []Body{b}, map[string]Body{"b": b})
}
