package cpim

import (
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/content"
	"github.com/jeonghun-app/rcs-platform/internal/content/contenttest"
)

// No fmt verb, valid or not, slog record or JSON encoding shows a CPIM
// message's body (#547): Format and LogValue covered the valid verbs and
// slog, but %p and %w print the fields as they are.
func TestABodyIsPrintedNowhere(t *testing.T) {
	const chat = "meet me at the usual place"
	m := Message{Headers: []Header{{Name: "From", Value: "<" + alice + ">"}},
		ContentHeaders: []Field{{Name: "Content-Type", Value: "text/plain"}}, Body: content.BodyOf([]byte(chat))}
	holder := struct {
		M   Message
		Ptr *Message
	}{m, &m}
	contenttest.Hidden(t, chat, m, &m, holder, &holder, []Message{m}, map[string]*Message{"m": &m})
}
