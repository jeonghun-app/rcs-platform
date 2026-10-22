package messaging

import (
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/content"
	"github.com/jeonghun-app/rcs-platform/internal/content/contenttest"
)

// No fmt verb, valid or not, slog record or JSON encoding shows the CPIM
// of a message on its way through the engine: what Submit and SubmitGroup
// take, the Message the engine reads from it, and what a Deliverer is
// handed (#547).
func TestACPIMIsPrintedNowhere(t *testing.T) {
	const chat = "meet me at the usual place"
	body := content.BodyOf([]byte(chat))
	o := Origin{Sender: "sip:+15550100001@ims.mnc001.mcc001.3gppnetwork.org", Recipient: "sip:+15550100002@ims.mnc001.mcc001.3gppnetwork.org", CPIM: body}
	g := GroupOrigin{Group: "sip:group-1@ims.mnc001.mcc001.3gppnetwork.org", Sender: o.Sender, CPIM: body}
	d := Delivery{Recipient: o.Recipient, Sender: o.Sender, CPIM: body}
	m, err := ParseMessage([]byte("From: <"+o.Sender+">\r\nTo: <"+o.Recipient+">\r\n\r\nContent-Type: text/plain\r\n\r\n"+chat), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	contenttest.Hidden(t, chat, o, &o, g, &g, d, &d, *m, m, []Origin{o}, map[string]Delivery{"d": d})
}
