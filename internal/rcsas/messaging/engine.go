package messaging

import (
	"context"
	"crypto/rand"
	"encoding/binary"
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
	// DefaultSentMargin is how much longer than StoreTTL notifications
	// about a sent message are accepted: a message delivered on its last
	// day may still be answered. The record says who wrote to whom, so it
	// is kept no longer (threat model T10).
	DefaultSentMargin = 24 * time.Hour
	// DefaultMaxQueueMessages and DefaultMaxQueueBytes bound one
	// recipient's queue: room for a long absence, not for a flood.
	DefaultMaxQueueMessages = 1000
	DefaultMaxQueueBytes    = 16 << 20
	// DefaultQueueSenderShare: one sender may hold an eighth of a
	// recipient's queue, so that no single sender can fill it and lock the
	// others out (threat model T10).
	DefaultQueueSenderShare = 8
	// GroupNotificationsShare: all group notifications in a queue, from
	// every group, hold at most a quarter of it together, beside each
	// group's sender share of them: an author in many groups is not locked
	// out of 1-to-1 messages by receipts (threat model T10, T11).
	GroupNotificationsShare = 4
	// GroupSummariesShare: the summaries of group notifications in a
	// queue (#166) hold at most an eighth of it, beside the notifications'
	// quarter, so that the two together never lock out 1-to-1 messages.
	GroupSummariesShare    = 8
	DefaultDeliveryTimeout = 30 * time.Second
	DefaultInviteTimeout   = 2 * time.Minute
	// DefaultAnswerTimeout is how long an offered leg waits for its
	// answer: the INVITE client transaction's limit (RFC 3261 §17.1.1.2,
	// 64 × T1).
	DefaultAnswerTimeout    = 32 * time.Second
	DefaultRetryInterval    = time.Minute
	DefaultMaxRetryInterval = time.Hour
	DefaultStoreTimeout     = 5 * time.Second
	// DefaultFanoutTimeout leaves a group message's sender its answer well
	// within the 30 s an MSRP client waits for one (rcsjta's transaction
	// timeout).
	DefaultFanoutTimeout = 20 * time.Second
	DefaultSweepInterval = time.Minute
	DefaultBatch         = 50
	DefaultWorkers       = 32
	DefaultMaxTracked    = 100_000
)

// Bounds on identifiers that become store keys: DynamoDB keys hold at
// most 2048 (partition) and 1024 (sort) bytes, and nothing real comes near
// these.
const (
	MaxIdentityLength  = 256
	MaxMessageIDLength = 128
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
	// TrustedRoutes are the URIs a notification may be routed through,
	// compared exactly: the platform's own application servers and CSCFs.
	// IMDN-Record-Route and IMDN-Route entries are written by clients, so
	// any other entry is dropped (threat model T10).
	TrustedRoutes []string
	// Intermediaries are the identities, besides a message's recipients,
	// allowed to send processing and negative delivery notifications about
	// it (RFC 5438 §8.2), for example another network's messaging server.
	Intermediaries []string

	MaxMessageSize int
	PagerLimit     int
	StoreTTL       time.Duration
	// SentTTL is how long notifications about a sent message are
	// accepted; zero means StoreTTL plus DefaultSentMargin.
	SentTTL          time.Duration
	MaxQueueMessages int
	MaxQueueBytes    int64
	// QueueSenderShare is how many senders' worth a queue holds: each
	// sender may hold 1/QueueSenderShare of its messages and bytes. 1 lets
	// one sender fill it.
	QueueSenderShare int
	SenderRate       Rate
	NotificationRate Rate
	// DeliveryTimeout bounds one delivery attempt: a pager request, or an
	// MSRP send and the success report that confirms it.
	DeliveryTimeout time.Duration
	// InviteTimeout is how long a terminating session asked for is waited
	// for before another may be asked for.
	InviteTimeout time.Duration
	// AnswerTimeout is how long a leg from Offer waits for Answer.
	AnswerTimeout time.Duration
	// RetryInterval is the first wait before a queue that could not be
	// delivered is tried again; it doubles up to MaxRetryInterval.
	RetryInterval    time.Duration
	MaxRetryInterval time.Duration
	// StoreTimeout bounds each store call.
	StoreTimeout time.Duration
	// FanoutTimeout bounds the queueing of one group message for all its
	// recipients, one store call after another; those not reached by then
	// are not queued, and the sender is answered as for a store failure,
	// after which its user may send the message again.
	FanoutTimeout time.Duration
	SweepInterval time.Duration
	// Batch is how many queued messages one store read returns.
	Batch int
	// Workers bounds the recipients whose queues are delivered at once.
	Workers int
	// MaxTracked bounds the senders and recipients whose state is kept in
	// memory: rate buckets, pager-only markers, pending invitations, marks
	// of participants that left a group.
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
	limit     store.Limit

	senders, notifiers *limiter
	// composing bounds the is-composing indications one participant
	// sends in one group.
	composing *limiter

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu         sync.Mutex
	wake       *sync.Cond
	closed     bool
	queue      []string
	recipients map[string]*recipient
	legs       map[legKey][]*Leg
	invites    map[inviteKey]time.Time
	pagerOnly  map[string]struct{}
	groups     GroupHandler
	// departed marks the participants that left a group on this task
	// (ParticipantLeft), until when their copies could still be queued.
	departed map[legKey]time.Time
	// groupLegs counts the open group legs of each group on this task.
	groupLegs map[string]int
	lastID    int64
	sweepAt   string
}

// legKey names the chat legs a queued message may be delivered on: those
// of its recipient whose peer is its sender.
type legKey struct{ user, peer string }

// inviteKey names one terminating session asked for: a chat session, or a
// large-mode session for one queued message.
type inviteKey struct {
	user, peer string
	mode       store.Mode
	id         string
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
		rand:       &lockedReader{r: cfg.Rand},
		limit:      queueLimit(cfg),
		senders:    newLimiter(cfg.SenderRate, cfg.MaxTracked),
		notifiers:  newLimiter(cfg.NotificationRate, cfg.MaxTracked),
		composing:  newLimiter(IsComposingRate, cfg.MaxTracked),
		recipients: map[string]*recipient{},
		legs:       map[legKey][]*Leg{},
		invites:    map[inviteKey]time.Time{},
		pagerOnly:  map[string]struct{}{},
		departed:   map[legKey]time.Time{},
		groupLegs:  map[string]int{},
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

// queueLimit is the bound of each recipient's queue and of each sender's
// share of it.
func queueLimit(c Config) store.Limit {
	l := store.Limit{
		Count: c.MaxQueueMessages, Bytes: c.MaxQueueBytes,
		GroupCount:   (c.MaxQueueMessages + GroupNotificationsShare - 1) / GroupNotificationsShare,
		GroupBytes:   c.MaxQueueBytes / GroupNotificationsShare,
		SummaryCount: (c.MaxQueueMessages + GroupSummariesShare - 1) / GroupSummariesShare,
		SummaryBytes: c.MaxQueueBytes / GroupSummariesShare,
	}
	if c.QueueSenderShare > 1 {
		l.SenderCount = (c.MaxQueueMessages + c.QueueSenderShare - 1) / c.QueueSenderShare
		l.SenderBytes = c.MaxQueueBytes / int64(c.QueueSenderShare)
	}
	return l
}

func (c Config) withDefaults() Config {
	setDefault(&c.MaxMessageSize, DefaultMaxMessageSize)
	setDefault(&c.PagerLimit, DefaultPagerLimit)
	setDefault(&c.StoreTTL, DefaultStoreTTL)
	setDefault(&c.SentTTL, c.StoreTTL+DefaultSentMargin)
	setDefault(&c.MaxQueueMessages, DefaultMaxQueueMessages)
	setDefault(&c.MaxQueueBytes, DefaultMaxQueueBytes)
	setDefault(&c.QueueSenderShare, DefaultQueueSenderShare)
	setDefault(&c.DeliveryTimeout, DefaultDeliveryTimeout)
	setDefault(&c.InviteTimeout, DefaultInviteTimeout)
	setDefault(&c.AnswerTimeout, DefaultAnswerTimeout)
	setDefault(&c.RetryInterval, DefaultRetryInterval)
	setDefault(&c.MaxRetryInterval, DefaultMaxRetryInterval)
	setDefault(&c.StoreTimeout, DefaultStoreTimeout)
	setDefault(&c.FanoutTimeout, DefaultFanoutTimeout)
	setDefault(&c.SweepInterval, DefaultSweepInterval)
	setDefault(&c.Batch, DefaultBatch)
	setDefault(&c.Workers, DefaultWorkers)
	setDefault(&c.MaxTracked, DefaultMaxTracked)
	c.MaxRetryInterval = max(c.MaxRetryInterval, c.RetryInterval)
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

func setDefault[T int | int64 | time.Duration](v *T, def T) {
	if *v <= 0 {
		*v = def
	}
}

// Close stops the engine. It takes no new delivery work, lets attempts in
// progress finish, for at most a delivery and two store calls, so that what
// they achieved is recorded, and then cancels what is left. Without the
// wait, a message delivered during a shutdown would stay claimed and go out
// again from another task once the claim lapsed. Close does not close legs,
// which the SIP layer owns.
func (e *Engine) Close() {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	e.closed = true
	for _, r := range e.recipients {
		if r.retry != nil {
			r.retry.Stop()
			r.retry = nil
		}
	}
	e.wake.Broadcast()
	e.mu.Unlock()
	idle := make(chan struct{})
	go func() { e.wg.Wait(); close(idle) }()
	bound := e.clock.AfterFunc(e.cfg.DeliveryTimeout+2*e.cfg.StoreTimeout, e.cancel)
	<-idle
	bound.Stop()
	e.cancel()
}

func (e *Engine) isClosed() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.closed
}

// Origin describes a message arriving from the originating side.
type Origin struct {
	// Sender is the sender's asserted identity.
	Sender string
	// Identities are the other identities the sender may name in the CPIM
	// From, for example its tel URI beside its SIP URI.
	Identities []string
	// Recipient is the identity the message is for.
	Recipient string
	// Conversation is empty for a notification that came without the
	// conversation headers, as pager-mode ones do.
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
//
// A notification that repeats one already accepted (same message, same
// notifier, same kind) is taken and dropped: it is how a client's
// retransmission looks, and forwarding it would let one receipt be sent
// any number of times.
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
	for _, id := range append([]string{o.Sender, o.Recipient}, o.Identities...) {
		if id == "" || len(id) > MaxIdentityLength {
			return reject(ReasonMalformed, errors.New("identity empty or too long"))
		}
	}
	if o.Pager && len(o.CPIM) > e.cfg.PagerLimit {
		return reject(ReasonTooLarge, nil)
	}
	m, err := ParseMessage(o.CPIM, e.cfg.MaxMessageSize)
	if err != nil {
		return err
	}
	e.countDeviations(m.CPIM.Deviations())
	if m.Notification != nil && len(o.CPIM) > e.cfg.PagerLimit {
		// Notifications travel in pager mode when no session is open; a
		// real one is well under a kilobyte (SEC4).
		return reject(ReasonTooLarge, nil)
	}
	now := e.clock.Now()
	limit := e.senders
	if m.Notification != nil {
		limit = e.notifiers
	}
	if !limit.allow(o.Sender, now) {
		return reject(ReasonRateLimited, nil)
	}
	if !namesSender(m.From.URI, o.Sender, o.Identities) {
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
			if s.Group != "" || !slices.Contains(s.Recipients, o.Recipient) {
				return reject(ReasonMessageIDReused, nil)
			}
			e.metrics.Count("message.resent", 1)
		} else if err != nil {
			return err
		}
	}
	id, err := e.newID(now)
	if err != nil {
		return err
	}
	q := queued(o, id, o.CPIM, false, m.Request.MessageID, now, e.cfg.StoreTTL)
	err = e.enqueue(ctx, q)
	if errors.Is(err, store.ErrQueueFull) || errors.Is(err, store.ErrSenderShareFull) {
		// The sender learns of it twice, as a refusal and, if it asked,
		// as the negative delivery notification a store-and-forward
		// server sends for a message it cannot keep.
		if n, err := e.notification(q, failedDelivery, q.ID+"-f", now); err == nil {
			_ = e.enqueueNotification(ctx, n, failedDelivery.status)
		}
		if errors.Is(err, store.ErrSenderShareFull) {
			return reject(ReasonQueueShareFull, nil)
		}
		return reject(ReasonQueueFull, nil)
	}
	return err
}

// queued is the queue item for a message from o.
func queued(o Origin, id string, body []byte, notification bool, messageID string, now time.Time, ttl time.Duration) store.Message {
	return store.Message{
		Recipient: o.Recipient, ID: id, Sender: o.Sender,
		Conversation: o.Conversation.ID, Contribution: o.Conversation.Contribution, InReplyTo: o.Conversation.InReplyTo,
		Mode: o.Mode, Notification: notification, MessageID: messageID,
		CPIM: body, Enqueued: now, Expires: now.Add(ttl),
	}
}

// enqueue stores q within the queue limit and has it delivered.
func (e *Engine) enqueue(ctx context.Context, q store.Message) error {
	if err := e.store.Enqueue(ctx, q, e.limit); err != nil {
		return err
	}
	if q.Notification {
		e.metrics.Count("message.accepted.notification", 1)
	} else {
		e.metrics.Count("message.accepted", 1)
	}
	e.kickNew(q)
	return nil
}

func (e *Engine) countDeviations(d cpim.Deviation) {
	for f := cpim.Deviation(1); f != 0; f <<= 1 {
		if d.Has(f) {
			e.metrics.Count("cpim.deviation."+f.String(), 1)
		}
	}
}

// UserRegistered tells the engine that user registered. A registration on
// a new flow may take terminating sessions again (ADR 0004): the
// pager-only marker and pending invitations are cleared and every stored
// message is tried at once. A refresh on the same flow changes nothing for
// messages waiting for a session, so only a queue that found the user
// unreachable is tried again.
func (e *Engine) UserRegistered(user string, newFlow bool) {
	e.mu.Lock()
	if newFlow {
		delete(e.pagerOnly, user)
		for k := range e.invites {
			if k.user == user {
				delete(e.invites, k)
			}
		}
	} else if r := e.recipients[user]; r != nil && r.hold == holdWaiting {
		e.mu.Unlock()
		return
	}
	e.mu.Unlock()
	e.kickEvent(user)
}

// InviteFailed reports that the session Invite asked for did not come
// about. ErrNoSessions marks the recipient as reachable by pager mode only
// until it registers on a new flow, and sends it what fits; for any other
// error the next invitation waits for InviteTimeout or the next
// registration on a new flow.
func (e *Engine) InviteFailed(inv Invitation, err error) {
	key := inviteKey{inv.Recipient, inv.Peer, inv.Mode, inv.QueueID}
	e.mu.Lock()
	if errors.Is(err, ErrNoSessions) {
		delete(e.invites, key)
		e.markPagerOnly(inv.Recipient)
		e.mu.Unlock()
		e.metrics.Count("invite.no_sessions", 1)
		e.kickEvent(inv.Recipient)
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

// Serve accepts MSRP connections from msrp-relay on l until ctx ends or l
// is closed. rcs-as is always the passive side (ADR 0004). A failure to
// accept that may pass, such as running out of file descriptors, is waited
// out with a growing pause, as net/http does, rather than ending the
// listener for good.
func (e *Engine) Serve(ctx context.Context, l net.Listener) error {
	stop := context.AfterFunc(ctx, func() { l.Close() })
	defer stop()
	var delay time.Duration
	for {
		nc, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			delay = min(max(2*delay, 5*time.Millisecond), time.Second)
			e.metrics.Count("msrp.accept_failed", 1)
			e.log.Warn("MSRP accept failed", slog.String("error", pii.Redact(err.Error())))
			wait := make(chan struct{})
			t := e.clock.AfterFunc(delay, func() { close(wait) })
			select {
			case <-wait:
			case <-ctx.Done():
				t.Stop()
				return ctx.Err()
			}
			continue
		}
		delay = 0
		if _, err := e.ServeConn(nc); err != nil {
			nc.Close()
		}
	}
}

// ServeConn serves one accepted MSRP connection; its sessions are the legs.
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

// recordCtx is the context of a store call that records what an attempt
// achieved. It survives Close's cancellation: the attempt is over, and
// losing its record would make another task repeat it.
func (e *Engine) recordCtx() (context.Context, context.CancelFunc) {
	return e.withTimeout(context.WithoutCancel(e.ctx), e.cfg.StoreTimeout)
}

// newID returns a queue ID that sorts by time, so Pending returns a queue
// oldest first. Within a task the time part only grows, so messages taken
// in the same nanosecond, or across a clock step back, keep their order;
// the random part keeps IDs of different tasks from colliding.
func (e *Engine) newID(now time.Time) (string, error) {
	r, err := e.randomHex(8)
	if err != nil {
		return "", err
	}
	e.mu.Lock()
	n := max(now.UnixNano(), e.lastID+1)
	e.lastID = n
	e.mu.Unlock()
	return fmt.Sprintf("%016x", uint64(n)) + r, nil
}

// randomIndex returns a random index into a list of n, 0 when n is 0.
func (e *Engine) randomIndex(n int) (int, error) {
	if n <= 1 {
		return 0, nil
	}
	var b [4]byte
	if _, err := io.ReadFull(e.rand, b[:]); err != nil {
		return 0, fmt.Errorf("messaging: random source: %w", err)
	}
	return int(binary.BigEndian.Uint32(b[:]) % uint32(n)), nil
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
