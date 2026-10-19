package transaction

import (
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

func TestNothingReachesTheHandlerAfterItsError(t *testing.T) {
	var got []string
	d := delivery{h: func(res *sip.Response, err error) {
		if err != nil {
			got = append(got, err.Error())
		} else {
			got = append(got, strconv.Itoa(res.StatusCode))
		}
	}}
	d.deliver(&sip.Response{StatusCode: 180}, nil)
	d.deliver(nil, ErrTerminated)
	// A response the state machine produced before Terminate, delivered late.
	d.deliver(&sip.Response{StatusCode: 183}, nil)
	d.deliver(nil, ErrTimeout)
	check(t, "delivered", got, []string{"180", ErrTerminated.Error()})
}

func TestHandlerMayTerminateItsOwnTransaction(t *testing.T) {
	h := newHarness(t, transport.UDP, Config{})
	var tx *ClientTransaction
	var got []string
	var err error
	tx, err = h.layer.Request(request(t, "INVITE", "z9hG4bKself"), transport.Destination{Network: transport.UDP},
		func(res *sip.Response, err error) {
			if err != nil {
				got = append(got, "error: "+err.Error())
				return
			}
			got = append(got, label(res))
			tx.Terminate() // the TU gives up on the first provisional
			got = append(got, "terminate returned")
		})
	if err != nil {
		t.Fatal(err)
	}
	h.receive(response(t, tx.Request(), 180))
	h.receive(response(t, tx.Request(), 183))
	check(t, "delivered", got, []string{"180", "terminate returned", "error: " + ErrTerminated.Error()})
	check(t, "strays", h.tu.take(), []string{"stray 183"})
}

func TestHandlerCallsNeverOverlapAndStopAtTheError(t *testing.T) {
	for range 50 {
		h := newHarness(t, transport.UDP, Config{})
		var inside, overlaps, afterError atomic.Int32
		var ended atomic.Bool
		tx, err := h.layer.Request(request(t, "INVITE", "z9hG4bKrace"), transport.Destination{Network: transport.UDP},
			func(res *sip.Response, err error) {
				if inside.Add(1) > 1 {
					overlaps.Add(1)
				}
				if ended.Load() {
					afterError.Add(1)
				}
				if err != nil {
					ended.Store(true)
				}
				inside.Add(-1)
			})
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		for i := range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				h.receive(response(t, tx.Request(), 180+i%3))
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			tx.Terminate()
		}()
		wg.Wait()
		if overlaps.Load() != 0 || afterError.Load() != 0 || !ended.Load() {
			t.Fatalf("overlaps %d, deliveries after the error %d, ended %v", overlaps.Load(), afterError.Load(), ended.Load())
		}
	}
}
