package sipas

import (
	"bytes"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/resourcelists"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// FuzzInviteBody: inviteParts takes any body apart without panicking, and
// the parts it returns lie inside it, a description always among them;
// inviteBody and groupBody return only what it found.
func FuzzInviteBody(f *testing.F) {
	f.Add(`multipart/mixed;boundary="boundary1"`, firstMessageBody([2]string{sdpType, "v=0\r\n"}, [2]string{"message/cpim", "From: <x>\r\n"}))
	f.Add(`multipart/mixed;boundary="boundary1"`, firstMessageBody([2]string{sdpType, "v=0\r\n"}, [2]string{resourcelists.ContentType, groupList(bob)}))
	f.Add("application/sdp", "v=0\r\n")
	f.Add("multipart/mixed;boundary=b", "--b\r\n\r\nx\r\n--b--")
	f.Add("multipart/mixed;boundary=b", "--b\r\nContent-Type: application/sdp\r\n\r\n--b\r\n")
	f.Fuzz(func(t *testing.T, contentType, body string) {
		var h sip.Header
		if h.Add("Content-Type", contentType) != nil {
			return
		}
		p, err := inviteParts(&h, []byte(body))
		if err != nil {
			return
		}
		if p.desc == nil {
			t.Fatal("no description and no error")
		}
		for _, part := range [][]byte{p.desc, p.first, p.list} {
			if part != nil && !bytes.Contains([]byte(body), part) {
				t.Fatalf("part %q is not in the body", part)
			}
		}
		if desc, first, err := inviteBody(&h, []byte(body)); err == nil && (p.list != nil || !bytes.Equal(desc, p.desc) || !bytes.Equal(first, p.first)) {
			t.Fatal("inviteBody took a resource list, or other parts")
		}
		for _, factory := range []bool{true, false} {
			if desc, list, err := groupBody(&h, []byte(body), factory); err == nil &&
				(p.first != nil || factory != (list != nil) || !bytes.Equal(desc, p.desc) || !bytes.Equal(list, p.list)) {
				t.Fatalf("groupBody(%v) took a first message, or other parts", factory)
			}
		}
	})
}
