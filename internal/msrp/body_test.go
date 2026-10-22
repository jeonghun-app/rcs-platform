package msrp

import (
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/content/contenttest"
)

// chat is content no verb may show.
const chat = "meet me at the usual place"

// No fmt verb, valid or not, slog record or JSON encoding shows a message
// body (#530), nor a chunk of one (#547): %p and %w print their argument
// field by field and call no method, so the body is behind a pointer,
// which they print as an address.
func TestABodyIsPrintedNowhere(t *testing.T) {
	m := Message{TransactionID: "t1", Method: MethodSend, ContentType: "text/plain", Body: BodyOf([]byte(chat))}
	out := Outgoing{ContentType: "text/plain", Body: BodyOf([]byte(chat))}
	chunks, err := Split([]byte(chat), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	holder := struct {
		M   Message
		O   Outgoing
		B   Body
		C   Chunk
		Ptr *Message
	}{m, out, m.Body, chunks[0], &m}
	contenttest.Hidden(t, chat, m, &m, out, &out, m.Body, &m.Body, chunks[0], &chunks[0], chunks,
		holder, &holder, []Message{m}, map[string]Body{"b": m.Body})
}
