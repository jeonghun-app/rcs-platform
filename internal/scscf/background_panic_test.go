package scscf

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/panics"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/regevent"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
)

// testGuard is a Guard that logs nowhere.
func testGuard() *panics.Guard {
	return panics.New(panics.Config{Metric: metricBackgroundPanics, Message: "test", Log: slog.New(slog.DiscardHandler)})
}

// subscriptionSweepPanics is the memory store, whose first listing for a
// subscription sweep panics, and which counts the listings.
type subscriptionSweepPanics struct {
	*state.Memory
	calls atomic.Int64
}

func (s *subscriptionSweepPanics) ExpiringSubscriptions(ctx context.Context, now time.Time, limit int) ([]*state.Subscription, error) {
	if s.calls.Add(1) == 1 {
		panic("scscf test panic")
	}
	return s.Memory.ExpiringSubscriptions(ctx, now, limit)
}

// TestAPanickingSubscriptionSweepEndsThatRoundOnly (#488): a round whose
// listing panics is recovered and counted, and the next tick sweeps again.
func TestAPanickingSubscriptionSweepEndsThatRoundOnly(t *testing.T) {
	store := &subscriptionSweepPanics{Memory: state.NewMemory()}
	n, err := regevent.New(regevent.Config{Store: store, Sender: &sender{layer: func() *transaction.Layer { return nil }}, Contact: mustURI("sip:scscf.rcs.local")})
	if err != nil {
		t.Fatal(err)
	}
	guard := testGuard()
	ctx, cancel := context.WithCancel(bg)
	done := make(chan struct{})
	go func() {
		defer close(done)
		runSubscriptionSweeps(ctx, n, time.Millisecond, 10, slog.New(slog.DiscardHandler), guard)
	}()
	waitFor(t, "a sweep after the panicking one", func() bool { return store.calls.Load() >= 2 })
	cancel()
	<-done
	if guard.Panics() != 1 {
		t.Errorf("%d panics recovered, want 1", guard.Panics())
	}
}

// TestAPanickingFirstNOTIFYIsWaitedForNoMore (#488): a SUBSCRIBE's first
// NOTIFY that panics is recovered and counted, and released, so that the
// stop's wait for the first NOTIFYs returns.
func TestAPanickingFirstNOTIFYIsWaitedForNoMore(t *testing.T) {
	f := firstNotifies{panics: testGuard()}
	f.hold().run(func() { panic("scscf test panic") })
	ctx, cancel := context.WithTimeout(bg, realWait)
	defer cancel()
	if !f.wait(ctx) {
		t.Fatal("the wait for the first NOTIFYs did not return after the panic")
	}
	if f.panics.Panics() != 1 {
		t.Errorf("%d panics recovered, want 1", f.panics.Panics())
	}
}

// TestAPanickingMetricsReportIsCounted (#488): a metrics report that
// panics is recovered and counted, and the next interval reports again.
func TestAPanickingMetricsReportIsCounted(t *testing.T) {
	guard := testGuard()
	var calls atomic.Int64
	ctx, cancel := context.WithCancel(bg)
	done := make(chan struct{})
	go func() {
		defer close(done)
		reportEvery(ctx, time.Millisecond, func() {
			if calls.Add(1) == 1 {
				panic("scscf test panic")
			}
		}, guard)
	}()
	waitFor(t, "a report after the panicking one", func() bool { return calls.Load() >= 2 })
	cancel()
	<-done
	if guard.Panics() != 1 {
		t.Errorf("%d panics recovered, want 1", guard.Panics())
	}
}

// panickingDialer panics when it opens a connection to addr.
type panickingDialer struct{ addr string }

func (p panickingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if address == p.addr {
		panic("scscf test panic")
	}
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

// TestScscfCountsAPanicInItsBackgroundWork (#488): the service gives its
// background work its guard: a third-party REGISTER whose dial panics is
// counted as background.panics in scscf's metrics, without the panic's
// value in the output, and the service stops as before.
func TestScscfCountsAPanicInItsBackgroundWork(t *testing.T) {
	hss := startHSS(t)
	dialer := panickingDialer{addr: "127.0.0.1:9"}
	uri := "sip:" + dialer.addr + ";transport=tcp"
	hss.asURI.Store(&uri)
	r := startSCSCFWith(t, hss, state.NewMemory(), 1, func(_ *ServiceConfig, d *deps) { d.sipDialer = dialer })
	p := dialSCSCF(t, r)
	p.registerFully(t, deviceAt("127.0.0.1:5070", 1), 600)
	waitFor(t, "the panic counted", func() bool {
		v, _ := r.h.Metric(metricBackgroundPanics)
		return v >= 1
	})
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(r.h.Output(), "scscf test panic") {
		t.Error("the output holds the panic's value")
	}
}

// TestAHoldWhoseNOTIFYNeverStartedIsReleased (#527 code review): a hold
// dropped before its NOTIFY ran, as a panic in the SUBSCRIBE's answer
// drops it, is waited for no more; one that ran is not released twice.
func TestAHoldWhoseNOTIFYNeverStartedIsReleased(t *testing.T) {
	f := firstNotifies{panics: testGuard()}
	f.hold().drop()
	ran := f.hold()
	done := make(chan struct{})
	ran.run(func() { close(done) })
	ran.drop()
	<-done
	ctx, cancel := context.WithTimeout(bg, realWait)
	defer cancel()
	if !f.wait(ctx) {
		t.Fatal("the wait for the first NOTIFYs did not return")
	}
}

// TestAPanicAfterASUBSCRIBEsAnswerLeavesTheStopNothingToWaitFor (#527 code
// review): the hook after the SUBSCRIBE's 200 panics, before its first
// NOTIFY starts. The stop does not wait out its budget for that NOTIFY.
func TestAPanicAfterASUBSCRIBEsAnswerLeavesTheStopNothingToWaitFor(t *testing.T) {
	hss := startHSS(t)
	silent := startSilentPeer(t)
	var once atomic.Bool
	r := startSCSCFWith(t, hss, state.NewMemory(), 1, func(_ *ServiceConfig, d *deps) {
		d.subscribeAnswered = func() {
			if once.CompareAndSwap(false, true) {
				panic("scscf test panic")
			}
		}
	})
	p := dialSCSCF(t, r)
	dv := deviceAt(silent.addr, 1)
	p.registerFully(t, dv, 600)
	p.subscribeReg(t, dv.path, silent.addr, "panic-sub")
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	if logs := r.h.Logs("left NOTIFYs to the sweeps of the other tasks"); len(logs) != 0 {
		t.Errorf("the stop waited out the first NOTIFY that never started: %v", logs)
	}
}

// TestAPanickingReportAtTheStopEndsItAsEver (#527 code review): the metrics
// report panics, at every interval and at the stop; the stop goes on to
// its goodbye all the same.
func TestAPanickingReportAtTheStopEndsItAsEver(t *testing.T) {
	hss := startHSS(t)
	var dprs atomic.Int64
	r := startSCSCFWith(t, hss, state.NewMemory(), 1, func(c *ServiceConfig, d *deps) {
		c.CxTimeout = 25 * time.Second
		d.dial = dprDial(hss, true, &dprs)
		d.reported = func() { panic("scscf test panic") }
	})
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	if dprs.Load() == 0 {
		t.Error("no DPR was written: the panicking report ended the stop")
	}
	if n, _ := r.h.Metric(metricBackgroundPanics); n < 1 {
		t.Errorf("%v panics counted, want the report's", n)
	}
}
