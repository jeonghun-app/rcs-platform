package messaging

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/pii"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
)

// Defaults for the zero fields of Config; docs/rcs-as.md has the settings
// that set them.
const (
	// DefaultMaxMessageSize leaves room within DynamoDB's 400 KB item
	// limit for the rest of a queued message.
	DefaultMaxMessageSize = 256 << 10
	// DefaultPagerLimit is the largest body sent in pager mode; larger
	// content needs an MSRP session (RCC.07 standalone messaging).
	DefaultPagerLimit = 1300
	// DefaultStoreTTL is how long an undelivered message is kept (ADR 0004).
	DefaultStoreTTL = 7 * 24 * time.Hour
	// DefaultSentTTL is how long notifications about a sent message are
	// accepted. A display notification may come long after delivery, when
	// the recipient opens the conversation.
	DefaultSentTTL         = 30 * 24 * time.Hour
	DefaultDeliveryTimeout = 30 * time.Second
	DefaultInviteTimeout   = 2 * time.Minute
	DefaultStoreTimeout    = 5 * time.Second
	DefaultSweepInterval   = time.Minute
	DefaultBatch           = 50
	DefaultWorkers         = 32
	DefaultMaxTracked      = 100_000
)

// Default rates. A person types far below 60 messages a minute; a client
// catching up after being offline answers each stored message with up to
// two notifications, hence the larger allowance for those.
var (
	DefaultSenderRate       = Rate{PerMinute: 60, Burst: 30}
	DefaultNotificationRate = Rate{PerMinute: 600, Burst: 300}
)

// Config configures an Engine. Zero fields take the defaults.
type Config struct {
	// InstanceID names this task in claims; it must differ between the
	// tasks sharing a store. Empty means a random one.
	InstanceID string
	// MSRPHost and MSRPPort are this task's instance address for MSRP
	// (ADR 0005), the authority of every local MSRP URI.
	MSRPHost string
	MSRPPort int
	// Self are the URIs by which notifications are routed through rcs-as
	// (IMDN-Route, RFC 5438 §8).
	Self []string
	// Intermediaries are the identities, besides a message's recipients,
	// allowed to send processing and negative delivery notifications about
	// it (RFC 5438 §8.2), for example another network's messaging server.
	Intermediaries []string

	MaxMessageSize   int
	PagerLimit       int
	StoreTTL         time.Duration
	SentTTL          time.Duration
	SenderRate       Rate
	NotificationRate Rate
	// DeliveryTimeout bounds one delivery attempt: a pager request, or an
	// MSRP send and the success report that confirms it.
	DeliveryTimeout time.Duration
	// InviteTimeout is how long a terminating session asked for is waited
	// for before another may be asked for.
	InviteTimeout time.Duration
	// StoreTimeout bounds each store call made while a client waits.
	StoreTimeout  time.Duration
	SweepInterval time.Duration
	// Batch is how many queued messages one store read returns.
	Batch int
	// Workers bounds the recipients whose queues are delivered at once.
	Workers int
	// MaxTracked bounds the senders, recipients and sessions whose state
	// is kept in memory: rate buckets, pager-only markers, pending
	// invitations.
	MaxTracked int

	// MSRP tunes the MSRP connections; its Clock and Rand are replaced by
	// the Engine's, and its MaxMessageSize by MaxMessageSize.
	MSRP msrp.Config
	// Clock and Rand are injected for tests; nil means the system clock
	// and crypto/rand.
	Clock  msrp.Clock
	Rand   io.Reader
	Logger *slog.Logger
}

// Counter counts events for metrics; *runtime.Metrics is one.
type Counter interface {
	Count(name string, n int64)
}

// Engine is the rcs-as messaging core. Its methods are safe for concurrent
// use.
type Engine struct {
	cfg       Config
	msrpCfg   msrp.Config
	store     store.Store
	deliverer Deliverer
	metrics   Counter
	clock     msrp.Clock
	rand      io.Reader
	log       *slog.Logger
	registry  msrp.Registry

	senders, notifiers *limiter

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu        sync.Mutex
	wake      *sync.Cond
	closed    bool
	queue     []string
	state     map[string]runState
	legs      map[legKey][]*Leg
	invites   map[legKey]time.Time
	pagerOnly map[string]struct{}
}

type runState uint8

const (
	queued runState = iota + 1
	running
	runAgain
)

// legKey names the legs a queued message may be delivered on: those of its
// recipient whose peer is its sender, in its mode.
type legKey struct {
	user, peer string
	mode       store.Mode
}

// New returns an engine and starts its delivery workers; Close stops them.
func New(cfg Config, st store.Store, d Deliverer, metrics Counter) (*Engine, error) {
	if st == nil || d == nil || metrics == nil {
		return nil, errors.New("messaging: New needs a store, a deliverer and a counter")
	}
	if cfg.MSRPHost == "" || cfg.MSRPPort <= 0 || cfg.MSRPPort > 65535 {
		return nil, errors.New("messaging: MSRPHost and MSRPPort must name this task")
	}
	cfg = cfg.withDefaults()
	e := &Engine{
		cfg: cfg, store: st, deliverer: d, metrics: metrics, clock: cfg.Clock, log: cfg.Logger,
		rand:      &lockedReader{r: cfg.Rand},
		senders:   newLimiter(cfg.SenderRate, cfg.MaxTracked),
		notifiers: newLimiter(cfg.NotificationRate, cfg.MaxTracked),
		state:     map[string]runState{},
		legs:      map[legKey][]*Leg{},
		invites:   map[legKey]time.Time{},
		pagerOnly: map[string]struct{}{},
	}
	e.wake = sync.NewCond(&e.mu)
	if e.cfg.InstanceID == "" {
		id, err := e.randomHex(8)
		if err != nil {
			return nil, err
		}
		e.cfg.InstanceID = id
	}
	e.msrpCfg = cfg.MSRP
	e.msrpCfg.Clock, e.msrpCfg.Rand = e.clock, e.rand
	e.msrpCfg.MaxMessageSize = int64(cfg.MaxMessageSize)
	e.ctx, e.cancel = context.WithCancel(context.Background())
	for range cfg.Workers {
		e.wg.Add(1)
		go e.work()
	}
	return e, nil
}

func (c Config) withDefaults() Config {
	setDefault(&c.MaxMessageSize, DefaultMaxMessageSize)
	setDefault(&c.PagerLimit, DefaultPagerLimit)
	setDefault(&c.StoreTTL, DefaultStoreTTL)
	setDefault(&c.SentTTL, DefaultSentTTL)
	setDefault(&c.DeliveryTimeout, DefaultDeliveryTimeout)
	setDefault(&c.InviteTimeout, DefaultInviteTimeout)
	setDefault(&c.StoreTimeout, DefaultStoreTimeout)
	setDefault(&c.SweepInterval, DefaultSweepInterval)
	setDefault(&c.Batch, DefaultBatch)
	setDefault(&c.Workers, DefaultWorkers)
	setDefault(&c.MaxTracked, DefaultMaxTracked)
	if c.SenderRate == (Rate{}) {
		c.SenderRate = DefaultSenderRate
	}
	if c.NotificationRate == (Rate{}) {
		c.NotificationRate = DefaultNotificationRate
	}
	if c.Clock == nil {
		c.Clock = systemClock{}
	}
	if c.Rand == nil {
		c.Rand = rand.Reader
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return c
}

func setDefault[T int | time.Duration](v *T, def T) {
	if *v <= 0 {
		*v = def
	}
}

// Close stops delivering and waits for deliveries in progress to end. It
// does not close legs, which the SIP layer owns.
func (e *Engine) Close() {
	e.mu.Lock()
	e.closed = true
	e.wake.Broadcast()
	e.mu.Unlock()
	e.cancel()
	e.wg.Wait()
}

// Origin describes a message arriving from the originating side.
type Origin struct {
	// Sender is the sender's asserted identity.
	Sender string
	// Identities are the other identities the sender may name in the CPIM
	// From, for example its tel URI beside its SIP URI.
	Identities []string
	// Recipient is the identity the message is for.
	Recipient    string
	Conversation Conversation
	Mode         store.Mode
	// Pager marks a message that arrived in a SIP MESSAGE, which must fit
	// the pager limit.
	Pager bool
	CPIM  []byte
}

// Submit runs a message through the pipeline and queues it for delivery.
// It returns a *Rejection for a message refused, which the caller answers
// (MSRPStatus for MSRP, a SIP status for pager mode), and another error when
// rcs-as could not take the message, which the client may retry.
func (e *Engine) Submit(ctx context.Context, o Origin) error {
	if o.Mode != store.Chat && o.Mode != store.Standalone {
		return errors.New("messaging: Origin.Mode must be Chat or Standalone")
	}
	err := e.submit(ctx, o)
	var r *Rejection
	if errors.As(err, &r) {
		e.metrics.Count("message.rejected."+string(r.Reason), 1)
		if c := r.cpimReason(); c != "" {
			e.metrics.Count("cpim.rejected."+string(c), 1)
		}
	} else if err != nil {
		e.metrics.Count("store.failed", 1)
		e.log.Warn("message not stored", pii.URI("recipient", o.Recipient), slog.String("error", err.Error()))
	}
	return err
}

func (e *Engine) submit(ctx context.Context, o Origin) error {
	if o.Pager && len(o.CPIM) > e.cfg.PagerLimit {
		return reject(ReasonTooLarge, nil)
	}
	m, err := ParseMessage(o.CPIM, e.cfg.MaxMessageSize)
	if err != nil {
		return err
	}
	e.countDeviations(m.CPIM.Deviations())
	now := e.clock.Now()
	limit := e.senders
	if m.Notification != nil {
		limit = e.notifiers
	}
	if !limit.allow(o.Sender, now) {
		return reject(ReasonRateLimited, nil)
	}
	if m.From.URI != AnonymousURI && m.From.URI != o.Sender && !slices.Contains(o.Identities, m.From.URI) {
		return reject(ReasonFromMismatch, nil)
	}
	ctx, cancel := e.withTimeout(ctx, e.cfg.StoreTimeout)
	defer cancel()
	if m.Notification != nil {
		return e.submitNotification(ctx, o, m, now)
	}
	return e.submitMessage(ctx, o, m, now)
}

func (e *Engine) submitMessage(ctx context.Context, o Origin, m *Message, now time.Time) error {
	if m.IncompleteRequest {
		e.metrics.Count("imdn.incomplete_request", 1)
	}
	if req := m.Request; req.Dispositions != 0 {
		err := e.store.RecordSent(ctx, store.Sent{
			Sender: o.Sender, MessageID: req.MessageID, Recipients: []string{o.Recipient},
			Dispositions: req.Dispositions, Expires: now.Add(e.cfg.SentTTL),
		}, now)
		if errors.Is(err, store.ErrExists) {
			// A client that resends a message after a failed session
			// sends the same CPIM body, Message-ID included, and the
			// recipient's client drops the duplicate by it. The same ID
			// to someone else is not a resend.
			s, err := e.store.Sent(ctx, o.Sender, req.MessageID, now)
			if err != nil {
				return err
			}
			if !slices.Contains(s.Recipients, o.Recipient) {
				return reject(ReasonMessageIDReused, nil)
			}
			e.metrics.Count("message.resent", 1)
		} else if err != nil {
			return err
		}
	}
	return e.enqueue(ctx, o, m, now, o.CPIM)
}

func (e *Engine) enqueue(ctx context.Context, o Origin, m *Message, now time.Time, body []byte) error {
	id, err := e.newID(now)
	if err != nil {
		return err
	}
	q := store.Message{
		Recipient: o.Recipient, ID: id, Sender: o.Sender,
		Conversation: o.Conversation.ID, Contribution: o.Conversation.Contribution, InReplyTo: o.Conversation.InReplyTo,
		Mode: o.Mode, Notification: m.Notification != nil, MessageID: m.Request.MessageID,
		CPIM: body, Enqueued: now, Expires: now.Add(e.cfg.StoreTTL),
	}
	if err := e.store.Enqueue(ctx, q); err != nil {
		return err
	}
	if q.Notification {
		e.metrics.Count("message.accepted.notification", 1)
	} else {
		e.metrics.Count("message.accepted", 1)
	}
	e.kick(o.Recipient)
	return nil
}

func (e *Engine) countDeviations(d cpim.Deviation) {
	for f := cpim.Deviation(1); f != 0; f <<= 1 {
		if d.Has(f) {
			e.metrics.Count("cpim.deviation."+f.String(), 1)
		}
	}
}

// UserRegistered tells the engine that user registered, possibly on a new
// flow: it may take terminating sessions again (ADR 0004) and its stored
// messages are tried at once.
func (e *Engine) UserRegistered(user string) {
	e.mu.Lock()
	delete(e.pagerOnly, user)
	for k := range e.invites {
		if k.user == user {
			delete(e.invites, k)
		}
	}
	e.mu.Unlock()
	e.kick(user)
}

// InviteFailed reports that the session Invite asked for did not come
// about. ErrNoSessions marks the recipient as reachable by pager mode only
// until it registers again, and sends it what fits; for any other error the
// next invitation waits for InviteTimeout or the next registration.
func (e *Engine) InviteFailed(inv Invitation, err error) {
	key := legKey{inv.Recipient, inv.Peer, inv.Mode}
	e.mu.Lock()
	if errors.Is(err, ErrNoSessions) {
		delete(e.invites, key)
		e.markPagerOnly(inv.Recipient)
		e.mu.Unlock()
		e.metrics.Count("invite.no_sessions", 1)
		e.kick(inv.Recipient)
		return
	}
	e.invites[key] = e.clock.Now().Add(e.cfg.InviteTimeout)
	e.mu.Unlock()
	e.metrics.Count("invite.failed", 1)
}

// markPagerOnly needs e.mu.
func (e *Engine) markPagerOnly(user string) {
	if len(e.pagerOnly) >= e.cfg.MaxTracked {
		for k := range e.pagerOnly {
			delete(e.pagerOnly, k)
			break
		}
	}
	e.pagerOnly[user] = struct{}{}
}

// LocalURI returns a fresh local MSRP URI, for the SDP offer of a
// terminating session; OpenLeg takes it back once the answer arrives.
func (e *Engine) LocalURI() (msrp.URI, error) {
	id, err := msrp.NewSessionID(e.rand)
	if err != nil {
		return msrp.URI{}, err
	}
	return msrp.URI{Host: e.cfg.MSRPHost, Port: e.cfg.MSRPPort, SessionID: id, Transport: "tcp"}, nil
}

// Serve accepts MSRP connections from msrp-relay on l until ctx ends or l
// fails. rcs-as is always the passive side (ADR 0004).
func (e *Engine) Serve(ctx context.Context, l net.Listener) error {
	stop := context.AfterFunc(ctx, func() { l.Close() })
	defer stop()
	for {
		nc, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if _, err := e.ServeConn(nc); err != nil {
			nc.Close()
		}
	}
}

// ServeConn serves one accepted MSRP connection; its sessions are the open
// legs.
func (e *Engine) ServeConn(nc net.Conn) (*msrp.Conn, error) {
	return msrp.NewPassiveConn(nc, &e.registry, e.msrpCfg)
}

// parseCPIM parses a stored body, which was parsed once when it was
// accepted.
func (e *Engine) parseCPIM(body []byte) (*cpim.Message, error) {
	return cpim.Limits{MaxSize: e.cfg.MaxMessageSize}.Parse(body)
}

// withTimeout is context.WithTimeout on the engine's clock.
func (e *Engine) withTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx)
	t := e.clock.AfterFunc(d, cancel)
	return ctx, func() { t.Stop(); cancel() }
}

// newID returns a queue ID that sorts by time, so Pending returns a queue
// oldest first; the random part orders nothing and keeps IDs from colliding.
func (e *Engine) newID(now time.Time) (string, error) {
	r, err := e.randomHex(8)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%016x", uint64(now.UnixNano())) + r, nil
}

func (e *Engine) randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(e.rand, b); err != nil {
		return "", fmt.Errorf("messaging: random source: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// lockedReader lets the workers share a Rand that is not safe for
// concurrent use, as test sources are not.
type lockedReader struct {
	mu sync.Mutex
	r  io.Reader
}

func (l *lockedReader) Read(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.r.Read(p)
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func (systemClock) AfterFunc(d time.Duration, f func()) msrp.Timer { return time.AfterFunc(d, f) }
