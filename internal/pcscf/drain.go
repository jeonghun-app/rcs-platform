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
// for the spacing.
func drain(ctx context.Context, ids []transport.FlowID, d time.Duration, closeFlow func(transport.FlowID) bool, sleep func(context.Context, time.Duration) error) {
	if len(ids) == 0 {
		return
	}
	gap := d / time.Duration(len(ids))
	for i, id := range ids {
		if !closeFlow(id) || i == len(ids)-1 || ctx.Err() != nil {
			continue
		}
		_ = sleep(ctx, gap)
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
