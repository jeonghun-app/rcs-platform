package sipas

import (
	"bytes"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// FuzzInviteBody: inviteBody takes any body apart without panicking, and
// the parts it returns lie inside it, a description always among them.
func FuzzInviteBody(f *testing.F) {
	f.Add(`multipart/mixed;boundary="boundary1"`, firstMessageBody([2]string{sdpType, "v=0\r\n"}, [2]string{"message/cpim", "From: <x>\r\n"}))
	f.Add("application/sdp", "v=0\r\n")
	f.Add("multipart/mixed;boundary=b", "--b\r\n\r\nx\r\n--b--")
	f.Add("multipart/mixed;boundary=b", "--b\r\nContent-Type: application/sdp\r\n\r\n--b\r\n")
	f.Fuzz(func(t *testing.T, contentType, body string) {
		var h sip.Header
		if h.Add("Content-Type", contentType) != nil {
			return
		}
		desc, first, err := inviteBody(&h, []byte(body))
		if err != nil {
			return
		}
		if desc == nil {
			t.Fatal("no description and no error")
		}
		for _, p := range [][]byte{desc, first} {
			if p != nil && !bytes.Contains([]byte(body), p) {
				t.Fatalf("part %q is not in the body", p)
			}
		}
	})
}
