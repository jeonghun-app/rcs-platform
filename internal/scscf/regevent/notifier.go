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
	// (RFC 3680 §6.1).
	DefaultExpires = 3761 * time.Second
	// DefaultMaxExpires caps what a subscriber asks for: the UE asks for
	// 600000 s (TS 24.229 §5.1.1.3).
	DefaultMaxExpires = 600000 * time.Second
	// DefaultNotifyTimeout bounds one NOTIFY's transaction.
	DefaultNotifyTimeout = 10 * time.Second
)

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
	Now           func() time.Time
	// Rand makes tags and branches; crypto/rand when nil.
	Rand    io.Reader
	Logger  *slog.Logger
	Metrics Metrics
}

// Notifier serves reg event subscriptions.
type Notifier struct {
	cfg  Config
	ids  sip.IDGenerator
	log  *slog.Logger
	wg   sync.WaitGroup
	host string
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
	return &Notifier{cfg: cfg, ids: sip.IDGenerator{Rand: cfg.Rand}, log: log, host: cfg.Contact.Host}, nil
}

type noMetrics struct{}

func (noMetrics) Count(string, int64) {}

func (n *Notifier) count(name string) { n.cfg.Metrics.Count(name, 1) }

// Wait returns once every NOTIFY that Changed started has been sent: for a
// shutdown, and for tests.
func (n *Notifier) Wait() { n.wg.Wait() }

// subscriptionID is the store key of the subscription of a dialog: a digest
// of its identifier (dialog.Dialog.ID), so that any instance finds it from
// an in-dialog SUBSCRIBE and the key is short whatever the Call-ID.
func subscriptionID(dialogID string) string {
	sum := sha256.Sum256([]byte("scscf/reg-subscription|" + dialogID))
	return hex.EncodeToString(sum[:16])
}
