package rcsas

import (
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/msrp"
)

// metricPathStalled counts the MSRP connections from msrp-relay that rcs-as
// ended because their probe went unanswered (msrp.ErrPathStalled, #517).
// msrp-relay counts the stalls it ends itself as Core.Closed.PathStalled;
// one this side ends, it sees as Core.Closed.PeerGone.
const metricPathStalled = "msrp.path_stalled"

// pathStallLogEvery spaces the warnings of stalled connections: the count
// holds them all.
const pathStallLogEvery = time.Minute

// pathStalls is the MSRP connections' OnEvent: it counts each one ended as
// stalled, and logs one at most every pathStallLogEvery, with no
// identifier of the connection or its sessions.
type pathStalls struct {
	metrics interface{ Count(name string, n int64) }
	log     *slog.Logger
	now     func() time.Time
	// logged is the UnixNano of the last line, 0 before the first.
	logged atomic.Int64
}

func (p *pathStalls) onEvent(e msrp.Event) {
	if e.Kind != msrp.EventClosed || !errors.Is(e.Err, msrp.ErrPathStalled) {
		return
	}
	p.metrics.Count(metricPathStalled, 1)
	now := p.now().UnixNano()
	last := p.logged.Load()
	if (last == 0 || now-last >= int64(pathStallLogEvery)) && p.logged.CompareAndSwap(last, now) {
		p.log.Warn("rcs-as: an MSRP connection from msrp-relay stalled and was closed", slog.String("reason", "probe unanswered"))
	}
}
