package transaction

import (
	"fmt"
	"net/netip"
	"strconv"
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

// sourceTU answers every request from a goroutine of its own and reports where
// the first one came from.
type sourceTU struct {
	code  int
	first chan transport.Source
	once  sync.Once
}

func (u *sourceTU) Request(tx *ServerTransaction) {
	u.once.Do(func() { u.first <- tx.Source() })
	handoffTU{u.code}.Request(tx)
}
func (*sourceTU) Stray(transport.Inbound)                {}
func (*sourceTU) ServerFailed(*ServerTransaction, error) {}

// QA regression (PR #35 re-verification): both ends of one TCP connection send
// a burst of large INVITEs to each other at once, A to B's address and B back
// over A's flow, so each side's reading goroutine answers while its own writer
// is busy with the other burst.
func TestTwoWayInviteBurstOverOneTCPConnectionCompletes(t *testing.T) {
	total := 1200
	if raceEnabled {
		total = 300
	}
	for _, code := range []int{200, 486} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			mk := func() (*transport.Transport, *Layer, *sourceTU, netip.AddrPort) {
				tu := &sourceTU{code: code, first: make(chan transport.Source, 1)}
				var layer *Layer
				tr, err := transport.New(transport.Config{}, func(in transport.Inbound) { layer.Receive(in) })
				if err != nil {
					t.Fatal(err)
				}
				layer = New(tr, tu, Config{})
				a, err := tr.Listen(transport.ListenerConfig{Network: transport.TCP, Addr: "127.0.0.1:0"})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { layer.Close(); tr.Close() })
				return tr, layer, tu, a
			}
			atr, al, _, _ := mk()
			btr, bl, btu, baddr := mk()
			body := []byte(strings.Repeat("a=x\r\n", 32<<10/5)) // 32 KiB

			var final, failed atomic.Int64
			collect := func(res *sip.Response, err error) {
				if err != nil {
					failed.Add(1)
				} else if res.StatusCode >= 200 {
					final.Add(1)
				}
			}
			invite := func(side string, i int) *sip.Request {
				req := newOutgoing(t, transport.TCP, "INVITE", fmt.Sprintf("z9hG4bK-%s-%d", side, i), "", 1)
				req.Header.Set("Call-ID", fmt.Sprintf("%s-%d@example.com", side, i))
				req.Header.Add("Contact", "<sip:x@127.0.0.1>")
				req.Header.Add("Content-Type", "application/sdp")
				req.Body = body
				return req
			}
			// The first INVITE opens the connection and tells B its flow.
			if _, err := al.Request(invite("a", 0), transport.Destination{Network: transport.TCP, Addr: baddr}, collect); err != nil {
				t.Fatal(err)
			}
			toA := transport.Destination{Flow: (<-btu.first).Flow}

			var wg sync.WaitGroup
			send := func(l *Layer, side string, dst transport.Destination, from int) {
				defer wg.Done()
				for i := from; i < total; i += 4 {
					if _, err := l.Request(invite(side, i), dst, collect); err != nil {
						failed.Add(1)
					}
				}
			}
			for w := range 4 {
				wg.Add(2)
				go send(al, "a", transport.Destination{Network: transport.TCP, Addr: baddr}, 1+w)
				go send(bl, "b", toA, w)
			}
			wg.Wait()
			want := int64(2 * total) // each side sends total INVITEs, A's first included
			for deadline := time.Now().Add(40 * time.Second); final.Load()+failed.Load() < want && time.Now().Before(deadline); {
				time.Sleep(20 * time.Millisecond)
			}
			as, bs := atr.Stats(), btr.Stats()
			if failed.Load() > 0 || final.Load() != want || as.Dialed != 1 || bs.Dialed != 0 ||
				as.QueueOverflows+bs.QueueOverflows+as.WriteErrors+bs.WriteErrors > 0 {
				t.Errorf("final=%d failed=%d of %d; A %+v; B %+v", final.Load(), failed.Load(), want, as, bs)
			}
		})
	}
}
