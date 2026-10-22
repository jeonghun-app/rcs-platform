package regevent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// Defaults of Config.
const (
	// DefaultExpires is the duration of a subscription that names none
	// (RFC 3680 §4.4).
	DefaultExpires = 3761 * time.Second
	// DefaultMaxExpires caps what a subscriber asks for: the UE asks for
	// 600000 s (TS 24.229 §5.1.1.3).
	DefaultMaxExpires = 600000 * time.Second
	// DefaultNotifyTimeout bounds one NOTIFY's transaction.
	DefaultNotifyTimeout = 10 * time.Second
	// DefaultWorkers prepare NOTIFYs at a time (the store's reads and
	// writes), and DefaultQueue more wait; the wait for an answer is not a
	// worker's.
	DefaultWorkers = 8
	DefaultQueue   = 4096
	// DefaultSetConcurrency NOTIFYs of one set, and DefaultHopConcurrency to
	// one next hop, are under way at a time, so that a subscriber or a
	// P-CSCF task that is slow to answer holds back its own NOTIFYs only.
	// A UE's NOTIFYs go through its P-CSCF too, so a hop takes more than a
	// set: a few slow UEs must not hold back everyone behind their P-CSCF.
	DefaultSetConcurrency = 2
	DefaultHopConcurrency = 32
	// DefaultMaxPerSubscriber is how many subscriptions one subscriber
	// keeps to one identity: the UE and the P-CSCF need one, and a second
	// covers a new one set up before the old one is gone.
	DefaultMaxPerSubscriber = 2
	// DefaultMaxPerSet is how many subscriptions all subscribers keep to a
	// set: the UE's devices and their P-CSCFs, with room to spare. The UE's
	// may take three quarters (MaxUEPerSet), so that the P-CSCF always has
	// room.
	DefaultMaxPerSet = 16
)

// pendingMargin is how much longer than a NOTIFY's transaction
// (NotifyTimeout) a final NOTIFY's subscription is held (pendingEnd): the
// store's round trips between the hold and the send.
const pendingMargin = 5 * time.Second

// pendingEnd is how far ahead a subscription's expiry is set when it is
// terminated, and again when its final NOTIFY is numbered (hold): if the
// queue drops the NOTIFY, or the instance stops, the next sweep after it
// sends it (state.SweepSubscriptions), within seconds; but never while this
// instance's send may still be waiting for its answer, or the same final
// would go out twice at once (#336).
func (n *Notifier) pendingEnd() time.Duration { return n.cfg.NotifyTimeout + pendingMargin }

// storeRetryAfter is the Retry-After of a 500 for a store failure, in
// seconds: DynamoDB throttling and timeouts pass within seconds.
const storeRetryAfter = "5"

// Sender sends a request in a client transaction to its dialog's next hop
// and returns the final response, or an error when there is none (a timeout,
// a transport failure).
type Sender interface {
	Send(ctx context.Context, req *sip.Request) (*sip.Response, error)
}

// Metrics receives the notifier's counters; *runtime.Metrics implements it.
type Metrics interface {
	Count(name string, n int64)
}

// Config configures a Notifier.
type Config struct {
	// Store is the state every scscf instance shares.
	Store state.Store
	// Sender carries NOTIFY requests.
	Sender Sender
	// Contact is the S-CSCF's own URI, the Contact of its dialogs, as for
	// registrar.Config.ServiceRoute; transport=tcp is added unless it names
	// a transport, as the P-CSCF reaches the core over TCP only.
	Contact sip.URI
	// DefaultExpires and MaxExpires are the duration of a subscription that
	// names none and the most one gets.
	DefaultExpires, MaxExpires time.Duration
	// NotifyTimeout bounds each NOTIFY sent for a change.
	NotifyTimeout time.Duration
	// Workers bounds the NOTIFYs of changes and sweeps being prepared at a
	// time, Queue those waiting, and SetConcurrency and HopConcurrency those
	// under way, from the store's first read to the subscriber's answer, per
	// set and per next hop (#256 security and code reviews: the request that
	// changed a set must not wait for its subscribers, and a slow subscriber
	// or P-CSCF task must not hold back anyone else's NOTIFYs). A quarter of
	// Queue at most waits for one next hop.
	Workers, Queue                 int
	SetConcurrency, HopConcurrency int
	// MaxPerSubscriber bounds the subscriptions of one subscriber to one
	// identity: one more replaces the subscriber's oldest. MaxUEPerSet
	// bounds the UE's subscriptions to a set's identities: one more replaces
	// the oldest of them. MaxPerSet bounds all subscriptions to the set: a
	// P-CSCF's replaces the oldest of the UE's, and once the set has only
	// P-CSCF subscriptions one more is refused with 403 (RFC 6665 §4.2.1.1
	// lets the notifier refuse), so a P-CSCF is never refused for the UE's.
	// They keep what a subscriber can store, and what a change of the set
	// costs, small. MaxUEPerSet is three quarters of MaxPerSet when 0.
	MaxPerSubscriber, MaxUEPerSet, MaxPerSet int
	Now                                      func() time.Time
	// Rand makes tags and branches; crypto/rand when nil.
	Rand    io.Reader
	Logger  *slog.Logger
	Metrics Metrics
}

// Notifier serves reg event subscriptions.
type Notifier struct {
	cfg Config
	ids sip.IDGenerator
	log *slog.Logger
	// wg counts the tasks queued and not done (schedule.go).
	wg sync.WaitGroup
	sc scheduler
}

// New validates cfg and returns a Notifier.
func New(cfg Config) (*Notifier, error) {
	if cfg.Store == nil || cfg.Sender == nil {
		return nil, errors.New("regevent: Store and Sender are required")
	}
	if !cfg.Contact.IsSIP() || cfg.Contact.Host == "" {
		return nil, errors.New("regevent: Contact must be a SIP URI")
	}
	if _, ok := cfg.Contact.Param("transport"); !ok {
		cfg.Contact.Params = append(sip.Params(nil), cfg.Contact.Params...)
		cfg.Contact.Params.Set("transport", "tcp")
	}
	if cfg.DefaultExpires <= 0 {
		cfg.DefaultExpires = DefaultExpires
	}
	if cfg.MaxExpires <= 0 {
		cfg.MaxExpires = DefaultMaxExpires
	}
	if cfg.DefaultExpires > cfg.MaxExpires {
		return nil, errors.New("regevent: DefaultExpires above MaxExpires")
	}
	if cfg.NotifyTimeout <= 0 {
		cfg.NotifyTimeout = DefaultNotifyTimeout
	}
	if cfg.Workers <= 0 {
		cfg.Workers = DefaultWorkers
	}
	if cfg.Queue <= 0 {
		cfg.Queue = DefaultQueue
	}
	if cfg.SetConcurrency <= 0 {
		cfg.SetConcurrency = DefaultSetConcurrency
	}
	if cfg.HopConcurrency <= 0 {
		cfg.HopConcurrency = DefaultHopConcurrency
	}
	if cfg.MaxPerSubscriber <= 0 {
		cfg.MaxPerSubscriber = DefaultMaxPerSubscriber
	}
	if cfg.MaxPerSet <= 0 {
		cfg.MaxPerSet = DefaultMaxPerSet
	}
	if cfg.MaxUEPerSet <= 0 {
		cfg.MaxUEPerSet = max(cfg.MaxPerSet*3/4, 1)
	}
	if cfg.MaxUEPerSet > cfg.MaxPerSet {
		return nil, errors.New("regevent: MaxUEPerSet above MaxPerSet")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	if cfg.Metrics == nil {
		cfg.Metrics = noMetrics{}
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Notifier{cfg: cfg, ids: sip.IDGenerator{Rand: cfg.Rand}, log: log, sc: newScheduler()}, nil
}

type noMetrics struct{}

func (noMetrics) Count(string, int64) {}

func (n *Notifier) count(name string) { n.cfg.Metrics.Count(name, 1) }

// Wait returns once every task queued by Changed, Sweep or a replaced
// subscription has run, its NOTIFY answered: for a shutdown, and for tests.
func (n *Notifier) Wait() { n.wg.Wait() }

// WaitFor waits as Wait does, but no longer than ctx lasts, for a shutdown
// with a deadline, once the registrar tells it of no more changes; it
// reports whether everything was done. What a stop leaves undone is a
// sweep's: every end is saved before its NOTIFY is queued, and a change's
// NOTIFY that is lost is made good by the next.
func (n *Notifier) WaitFor(ctx context.Context) bool {
	done := make(chan struct{})
	go func() {
		n.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-ctx.Done():
		return false
	}
}

// subscriptionID is the store key of the subscription of a dialog: a digest
// of its identifier (dialog.Dialog.ID), so that any instance finds it from
// an in-dialog SUBSCRIBE and the key is short whatever the Call-ID.
func subscriptionID(dialogID string) string {
	sum := sha256.Sum256([]byte("scscf/reg-subscription|" + dialogID))
	return hex.EncodeToString(sum[:16])
}
