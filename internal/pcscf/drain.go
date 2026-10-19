package pcscf

import (
	"context"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// drain closes the client flows one by one, evenly spread over d, so that
// the clients of a stopping task reconnect and re-register over the stop
// timeout rather than all at once (ADR 0003): hss and scscf are sized for
// that burst. A flow that ended meanwhile takes no time of its own. ctx
// ending stops the spacing, and the rest are closed at once. sleep waits
// for the spacing, and now is its clock.
//
// Each wait runs to the next close's place on a schedule fixed at the
// start, not for a gap from the last wake-up: timers wake late under load,
// and the delays would add up and leave the last flows to close together
// at the deadline (QA of #188).
func drain(ctx context.Context, ids []transport.FlowID, d time.Duration, closeFlow func(transport.FlowID) bool,
	sleep func(context.Context, time.Duration) error, now func() time.Time) {
	if len(ids) == 0 {
		return
	}
	gap := d / time.Duration(len(ids))
	start, closed := now(), 0
	for i, id := range ids {
		if !closeFlow(id) || i == len(ids)-1 || ctx.Err() != nil {
			continue
		}
		closed++
		if wait := start.Add(time.Duration(closed) * gap).Sub(now()); wait > 0 {
			_ = sleep(ctx, wait)
		}
	}
}

// sleepCtx waits d or until ctx ends.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
