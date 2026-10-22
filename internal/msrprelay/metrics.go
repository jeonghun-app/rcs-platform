package msrprelay

import (
	"errors"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
)

// Metric names. Every name and every suffix comes from a fixed set, never
// from what a peer sent, and none carries an identifier (architecture §8).
// docs/msrp-relay.md lists them.
const (
	mBindingsCreated  = "BindingsCreated"
	mBindingsReleased = "BindingsReleased"
	mBindingsClaimed  = "BindingsClaimed"
	// mBindingsExpired counts bridges ended because their binding expired
	// or was released while they ran.
	mBindingsExpired   = "BindingsExpired"
	mActiveBridges     = "ActiveBridges"
	mClientConnections = "ClientConnections"
	mBytesFromClients  = "BytesFromClients"
	mBytesToClients    = "BytesToClients"
	mHealthChecks      = "ProxyHealthChecks"
	mIdleClosed        = "ClientsClosedIdle"
	// mUnboundClosed counts client connections closed for naming no
	// session within FirstBindTimeout.
	mUnboundClosed = "ClientsClosedUnbound"
	mStoreErrors   = "StoreErrors"
	// mBudgetUntracked counts lookups let through because the lookup
	// budget's table was full (see lookupBudget.take).
	mBudgetUntracked = "LookupBudgetUntracked"
	// mRefusedPrefix starts a refusal by the relay itself: "Refused." and a
	// reason* constant.
	mRefusedPrefix = "Refused."
	// mClientPrefix and mCorePrefix start what internal/msrp reported on a
	// client connection or a connection to rcs-as: "Client.Refused.481",
	// "Core.Closed.KeepAliveTimeout".
	mClientPrefix = "Client."
	mCorePrefix   = "Core."
)

// Reasons the relay refuses a connection, a bind or a control call.
const (
	reasonConnectionLimit = "ConnectionLimit"
	reasonSourceLimit     = "SourceLimit"
	reasonProxyHeader     = "ProxyHeader"
	reasonBindOverload    = "BindOverload"
	reasonUnknownSession  = "UnknownSession"
	// reasonEndedSession: the connection names a session whose bridge on
	// this same connection has ended; not a second connection.
	reasonEndedSession = "EndedSession"
	// reasonSourceBudget: the source has used up its lookup budget.
	reasonSourceBudget    = "SourceLookupBudget"
	reasonIncomplete      = "IncompleteBinding"
	reasonClaimed         = "AlreadyClaimed"
	reasonCoreUnreachable = "CoreUnreachable"
	reasonStore           = "StoreUnavailable"
	reasonUnauthorized    = "ControlUnauthorized"
	reasonForbidden       = "ControlForbidden"
	reasonInvalid         = "ControlInvalid"
	// reasonDraining: refused because the task is stopping, so that the
	// noise of a rolling update stays out of the capacity and store counts.
	reasonDraining = "Draining"
)

// counters accumulates counts between flushes, so a busy relay writes a
// handful of EMF lines a minute rather than one per event (#25 asks the same
// of internal/runtime). Bytes are counted on every read and write, so they
// have atomics of their own; the rest are rare enough for a map.
type counters struct {
	bytesIn, bytesOut atomic.Int64
	bridges, conns    atomic.Int64

	mu     sync.Mutex
	counts map[string]int64
}

func newCounters() *counters { return &counters{counts: map[string]int64{}} }

func (m *counters) add(name string, n int64) {
	m.mu.Lock()
	m.counts[name] += n
	m.mu.Unlock()
}

func (m *counters) refuse(reason string) { m.add(mRefusedPrefix+reason, 1) }

// Count counts n as name until the next flush, for a panics.Guard.
func (m *counters) Count(name string, n int64) { m.add(name, n) }

// flush writes what was counted since the last flush and the two gauges,
// which are written every time so that their absence means no data rather
// than zero.
func (m *counters) flush(out *runtime.Metrics) {
	m.mu.Lock()
	counts := m.counts
	m.counts = map[string]int64{}
	m.mu.Unlock()
	// Bytes go out with the Bytes unit, so CloudWatch can scale them.
	if n := m.bytesIn.Swap(0); n > 0 {
		out.Bytes(mBytesFromClients, n)
	}
	if n := m.bytesOut.Swap(0); n > 0 {
		out.Bytes(mBytesToClients, n)
	}
	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		out.Count(name, counts[name])
	}
	out.Gauge(mActiveBridges, m.bridges.Load())
	out.Gauge(mClientConnections, m.conns.Load())
}

// onEvent counts what internal/msrp reports; prefix says which side.
func (m *counters) onEvent(prefix string) func(msrp.Event) {
	return func(e msrp.Event) {
		switch e.Kind {
		case msrp.EventRefused:
			m.add(prefix+"Refused."+strconv.Itoa(e.Code), 1)
		case msrp.EventDropped:
			m.add(prefix+"Dropped."+errName(e.Err), 1)
		case msrp.EventClosed:
			m.add(prefix+"Closed."+errName(e.Err), 1)
		}
	}
}

// eventErrNames names the errors an msrp.Event may carry.
var eventErrNames = []struct {
	err  error
	name string
}{
	{msrp.ErrHandlerBusy, "HandlerBusy"},
	{msrp.ErrReassemblyTimeout, "ReassemblyTimeout"},
	{msrp.ErrMalformedResponse, "MalformedResponse"},
	{msrp.ErrTooManyUnknownSessions, "TooManyUnknownSessions"},
	{msrp.ErrKeepAliveNotSent, "KeepAliveNotSent"},
	{msrp.ErrPanicked, "Panicked"},
	{msrp.ErrPeerNotReading, "PeerNotReading"},
	{msrp.ErrKeepAliveTimeout, "KeepAliveTimeout"},
	{msrp.ErrUnbound, "Unbound"},
	{msrp.ErrFraming, "Framing"},
	{msrp.ErrWriteTimeout, "WriteTimeout"},
	{msrp.ErrConnClosed, "Closed"},
	{msrp.ErrPeerGone, "PeerGone"},
}

func errName(err error) string {
	if err == nil {
		return "None"
	}
	for _, n := range eventErrNames {
		if errors.Is(err, n.err) {
			return n.name
		}
	}
	return "Other"
}
