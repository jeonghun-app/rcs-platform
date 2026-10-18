package transaction

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// handoffTU answers every request from a goroutine of its own, as the TU contract
// asks.
type handoffTU struct{ code int }

func (u handoffTU) Request(tx *ServerTransaction) {
	go func() {
		if res, err := sip.NewResponse(tx.Request(), u.code, "", "x"); err == nil {
			tx.Respond(res)
		}
	}()
}
func (handoffTU) Stray(transport.Inbound)                {}
func (handoffTU) ServerFailed(*ServerTransaction, error) {}

// QA regression (PR #35 review): A sends a burst of INVITEs to B over one TCP
// connection. B's immediate 100 Trying and A's ACK for each 503 are written from
// the goroutines reading that connection; when those writes were synchronous,
// both sides blocked writing to a peer that was not reading, and the connection
// died at WriteTimeout with every transaction on it.
func TestInviteBurstOverOneTCPConnectionCompletes(t *testing.T) {
	total := 20000
	if raceEnabled {
		total = 4000
	}
	for _, v := range []struct {
		code  int
		delay bool
	}{{503, false}, {200, false}, {503, true}} {
		t.Run(fmt.Sprintf("%d DelayTrying=%v", v.code, v.delay), func(t *testing.T) {
			mk := func(code int) (*transport.Transport, *Layer, netip.AddrPort) {
				var layer *Layer
				tr, err := transport.New(transport.Config{WriteTimeout: 3 * time.Second}, func(in transport.Inbound) { layer.Receive(in) })
				if err != nil {
					t.Fatal(err)
				}
				layer = New(tr, handoffTU{code}, Config{DelayTrying: v.delay})
				a, err := tr.Listen(transport.ListenerConfig{Network: transport.TCP, Addr: "127.0.0.1:0"})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { layer.Close(); tr.Close() })
				return tr, layer, a
			}
			atr, al, _ := mk(200)
			btr, _, baddr := mk(v.code)
			body := []byte(strings.Repeat("a=x\r\n", 800)) // 4 KiB
			var final, failed atomic.Int64
			var wg sync.WaitGroup
			for w := range 8 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := range total / 8 {
						req := newOutgoing(t, transport.TCP, "INVITE", fmt.Sprintf("z9hG4bK-%d-%d", w, i), "", 1)
						req.Header.Set("Call-ID", fmt.Sprintf("%d-%d@example.com", w, i))
						req.Header.Add("Contact", "<sip:a@127.0.0.1>")
						req.Header.Add("Content-Type", "application/sdp")
						req.Body = body
						_, err := al.Request(req, transport.Destination{Network: transport.TCP, Addr: baddr}, func(res *sip.Response, err error) {
							if err != nil {
								failed.Add(1)
							} else if res.StatusCode >= 200 {
								final.Add(1)
							}
						})
						if err != nil {
							failed.Add(1)
						}
					}
				}()
			}
			wg.Wait()
			for deadline := time.Now().Add(40 * time.Second); final.Load()+failed.Load() < int64(total) && time.Now().Before(deadline); {
				time.Sleep(20 * time.Millisecond)
			}
			if failed.Load() > 0 || final.Load() != int64(total) {
				t.Errorf("final=%d failed=%d of %d; WriteErrors A=%d B=%d", final.Load(), failed.Load(), total,
					atr.Stats().WriteErrors, btr.Stats().WriteErrors)
			}
		})
	}
}
