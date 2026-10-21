package group

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/groupstore"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
)

// Defaults for the zero fields of Config; docs/rcs-as.md has the settings.
const (
	DefaultMaxParticipants = 100
	// LimitParticipants is the largest MaxParticipants: a group keeps as
	// many former participants as current ones at most, and both must fit
	// in one stored group (groupstore.MaxEntries).
	LimitParticipants = groupstore.MaxEntries / 2
	DefaultIdleTTL    = 30 * 24 * time.Hour
	// DefaultTouchInterval is how often a group in use has its activity
	// written: often enough for a 30-day idle limit, rarely enough not to
	// cost a write per message.
	DefaultTouchInterval = time.Hour
	DefaultMaxTracked    = 100_000
	// DefaultPendingTTL is how long a new group lasts until its creator's
	// session is set up (Established): long enough for the client to try
	// its INVITE again after a CANCEL or a failure, short enough that a
	// group no session came of does not linger.
	DefaultPendingTTL = 2 * time.Minute
	// maxAttempts bounds the rereads of a group whose update keeps meeting
	// another writer's; each attempt loses only to a write that landed.
	maxAttempts = 32
)

// Default rates. A participant writes in a group as fast as in a 1-to-1
// chat. The fan-out budget is deliveries per group: a full group of 100 may
// carry about one message a second. Its burst grows with the size limit
// (DefaultFanoutBurst). Adding is bounded per adder, creating per creator:
// a group of strangers is the spam this guards against (threat model T11).
// The add burst is at least a full group's invitees, so that the largest
// group can be created at once.
var (
	DefaultSenderRate = messaging.Rate{PerMinute: 60, Burst: 30}
	DefaultFanoutRate = messaging.Rate{PerMinute: 6000, Burst: 1000}
	DefaultAddRate    = messaging.Rate{PerMinute: 30, Burst: 100}
	DefaultCreateRate = messaging.Rate{PerMinute: 5, Burst: 10}
)

// FanoutSenderShare is how many senders' worth a group's fan-out budget
// holds: one sender may use at most 1/FanoutSenderShare of it, in rate and
// in burst, so that a participant writing as fast as its own rate allows
// leaves the rest of the budget to the others (threat model T11).
const FanoutSenderShare = 4

// FanoutSenderMessages is how many messages in a row one sender's share of
// the fan-out burst must cover in a full group. People send a few short
// messages in quick succession; the reference client ends its session with
// the group when one of them is refused (rcsjta
// GroupChatSession.msrpTransferError).
const FanoutSenderMessages = 10

// DefaultFanoutBurst is the fan-out burst for a group size limit: enough
// for one sender's share to cover FanoutSenderMessages messages to a full
// group, and DefaultFanoutRate's burst at least. The rate stays the same,
// so only how much may go at once grows, not how much a minute.
func DefaultFanoutBurst(maxParticipants int) int {
	return max(DefaultFanoutRate.Burst, FanoutSenderShare*FanoutSenderMessages*(maxParticipants-1))
}

// DefaultAddBurst is the add burst for a group size limit: the default,
// or a full group's invitees if that is more.
func DefaultAddBurst(maxParticipants int) int { return max(DefaultAddRate.Burst, maxParticipants-1) }

// Errors the operations return; the SIP layer answers them (for example
// 404, 403, 486).
var (
	// ErrNoGroup: no such group, or it has ended.
	ErrNoGroup = errors.New("group: no such group")
	// ErrNotParticipant: whoever asked is not a current participant, or
	// the participant concerned is not one.
	ErrNotParticipant = errors.New("group: not a participant")
	// ErrNotChairman: only the chairman may remove others.
	ErrNotChairman = errors.New("group: only the chairman may do that")
	// ErrTooMany: the group would exceed RCSAS_GROUP_MAX_PARTICIPANTS.
	ErrTooMany = errors.New("group: too many participants")
	// ErrInvalid: a request that makes no sense, such as a group without
	// anyone to chat with or an identity that is empty or too long.
	ErrInvalid = errors.New("group: invalid request")
	// ErrRateLimited: whoever asked has used up its allowance.
	ErrRateLimited = errors.New("group: rate limited")
	// ErrBusy: the group kept changing under the update; try again.
	ErrBusy = errors.New("group: too many concurrent changes")
	// ErrTaken: a group already has the Contribution-ID a Create names,
	// and is not one its creator may take up again.
	ErrTaken = errors.New("group: the Contribution-ID names another group")
)

// Config configures a Service. Zero fields take the defaults.
type Config struct {
	// ConferenceHost is the host of the conference URIs the focus
	// allocates, sip:chat-<32 hex digits>@ConferenceHost; it must route to
	// rcs-as. Required.
	ConferenceHost string
	// HomeDomain is the operator's IMS domain (RCS_IMS_DOMAIN), at which
	// a SIP URI whose user part is a global number names that number, as
	// the SIP layer and the engine take it (messaging.UserOf).
	HomeDomain      string
	MaxParticipants int
	IdleTTL         time.Duration
	// PendingTTL is how long a group lasts until Established.
	PendingTTL time.Duration
	// SenderRate bounds the messages one participant writes in one group;
	// FanoutRate the deliveries one group makes, a message counting once
	// per recipient, of which one sender may use 1/FanoutSenderShare;
	// AddRate the participants one user adds, in groups it creates too;
	// CreateRate the groups one user creates. A zero FanoutRate or AddRate
	// takes its default rate with DefaultFanoutBurst or DefaultAddBurst of
	// MaxParticipants.
	SenderRate    messaging.Rate
	FanoutRate    messaging.Rate
	AddRate       messaging.Rate
	CreateRate    messaging.Rate
	TouchInterval time.Duration
	// MaxTracked bounds the rate buckets and activity marks kept in
	// memory.
	MaxTracked int
	// Task is this task's id, random at every start, and SIP its SIP
	// instance address (host:port), as the owner of the groups it serves
	// (#121); an empty Task is a random one. TaskHeartbeat, TaskLease and
	// TaskSkew time its heartbeat (StartHeartbeat).
	Task, SIP                          string
	TaskHeartbeat, TaskLease, TaskSkew time.Duration
	Clock                              msrp.Clock
	Rand                               io.Reader
}

func (c Config) withDefaults() Config {
	if c.MaxParticipants <= 0 {
		c.MaxParticipants = DefaultMaxParticipants
	}
	if c.IdleTTL <= 0 {
		c.IdleTTL = DefaultIdleTTL
	}
	if c.PendingTTL <= 0 || c.PendingTTL >= c.IdleTTL {
		c.PendingTTL = min(DefaultPendingTTL, c.IdleTTL/2)
	}
	if c.TouchInterval <= 0 {
		c.TouchInterval = DefaultTouchInterval
	}
	if c.MaxTracked <= 0 {
		c.MaxTracked = DefaultMaxTracked
	}
	if c.TaskHeartbeat <= 0 {
		c.TaskHeartbeat = DefaultTaskHeartbeat
	}
	if c.TaskLease <= 0 {
		c.TaskLease = DefaultTaskLease
	}
	if c.TaskSkew <= 0 {
		c.TaskSkew = DefaultTaskSkew
	}
	addRate := messaging.Rate{PerMinute: DefaultAddRate.PerMinute, Burst: DefaultAddBurst(c.MaxParticipants)}
	fanoutRate := messaging.Rate{PerMinute: DefaultFanoutRate.PerMinute, Burst: DefaultFanoutBurst(c.MaxParticipants)}
	for _, r := range []struct {
		v   *messaging.Rate
		def messaging.Rate
	}{{&c.SenderRate, DefaultSenderRate}, {&c.FanoutRate, fanoutRate}, {&c.AddRate, addRate}, {&c.CreateRate, DefaultCreateRate}} {
		if *r.v == (messaging.Rate{}) {
			*r.v = r.def
		}
	}
	if c.Clock == nil {
		c.Clock = systemClock{}
	}
	if c.Rand == nil {
		c.Rand = rand.Reader
	}
	return c
}

// Notifier is what the package needs from the SIP layer to tell the
// subscribers of a group's conference event package (RFC 4575) what
// changed: it sends Document in a NOTIFY to each subscription of Group.
type Notifier interface {
	RosterChanged(ctx context.Context, u RosterUpdate)
}

// RosterUpdate is one change to a group's roster.
type RosterUpdate struct {
	Group   string
	Version uint32
	// Full marks a full document, sent when the group is created; every
	// later change is a partial document of the participants it touched,
	// one version above the last (RFC 4575 §4.6). The versions count per
	// group across every task, so a subscriber that misses one sees the
	// gap and refreshes its subscription for a full document (Roster).
	Full     bool
	Document []byte
	// Departed are the participants the change took out of the group:
	// who left, declined or was removed. Their subscriptions end with it,
	// so that they get no later change (#340).
	Departed []string
}

// Invitee names someone to add to a group.
type Invitee struct {
	Identity    string
	DisplayName string
}

// CreateRequest is a client's request to the conference factory for a new
// group.
type CreateRequest struct {
	// Creator is the asserted identity of whoever sent the request.
	Creator     string
	CreatorName string
	// Invitees are the others to add; the creator, duplicates and empty
	// entries are left out.
	Invitees []Invitee
	Subject  string
	// Conversation is the Conversation-ID of the request, a token as in
	// 1-to-1 chat (messaging.ValidID); empty means one is generated.
	Conversation string
	// Contribution is the request's Contribution-ID, which names the chat
	// to its clients (rcsjta's chat ID), a token too. When set, the
	// conference URI is made from it, so that a creator trying its INVITE
	// again after a CANCEL or a failure finds the group it made rather
	// than making another under the same chat ID; anyone else naming it
	// is refused (ErrTaken). Empty means a random URI.
	Contribution string
}

// Service runs groups. Its methods are safe for concurrent use.
type Service struct {
	cfg      Config
	store    groupstore.Store
	engine   *messaging.Engine
	notifier Notifier
	metrics  messaging.Counter
	rand     io.Reader

	senders, fanout, adds, creates *messaging.Limiter
	// fanoutShare is each sender's part of its group's fan-out budget.
	fanoutShare *messaging.Limiter

	// maxFormer is how many former participants a group keeps
	// (formerLimit).
	maxFormer int

	mu      sync.Mutex
	touched map[string]time.Time
	// owned holds the groups this task owns, with the epoch it owns them
	// at; beating and lastBeat its heartbeat (StartHeartbeat).
	owned map[string]groupstore.Owner
	// others holds the groups another task was found to own, until when
	// Owns takes that for granted.
	others   map[string]time.Time
	beating  bool
	lastBeat time.Time
}

// New returns a Service and makes it the engine's GroupHandler.
func New(cfg Config, st groupstore.Store, engine *messaging.Engine, n Notifier, metrics messaging.Counter) (*Service, error) {
	if st == nil || engine == nil || n == nil || metrics == nil {
		return nil, errors.New("group: New needs a store, an engine, a notifier and a counter")
	}
	if cfg.ConferenceHost == "" {
		return nil, errors.New("group: ConferenceHost is required")
	}
	cfg = cfg.withDefaults()
	if cfg.MaxParticipants > LimitParticipants {
		return nil, fmt.Errorf("group: MaxParticipants above %d", LimitParticipants)
	}
	former, err := formerLimit(cfg.ConferenceHost, cfg.MaxParticipants)
	if err != nil {
		return nil, err
	}
	if cfg.FanoutRate.PerMinute > 0 && cfg.FanoutRate.Burst/FanoutSenderShare < FanoutSenderMessages*(cfg.MaxParticipants-1) {
		return nil, fmt.Errorf("group: a sender's part of the fan-out burst (1/%d) must cover %d messages to a full group",
			FanoutSenderShare, FanoutSenderMessages)
	}
	if cfg.AddRate.PerMinute > 0 && cfg.AddRate.Burst < cfg.MaxParticipants-1 {
		// Otherwise a full group could never be created.
		return nil, errors.New("group: the add burst must cover a full group's invitees")
	}
	share := messaging.Rate{PerMinute: -1}
	if r := cfg.FanoutRate; r.PerMinute > 0 {
		share = messaging.Rate{PerMinute: max(r.PerMinute/FanoutSenderShare, 1), Burst: r.Burst / FanoutSenderShare}
	}
	s := &Service{
		cfg: cfg, store: st, engine: engine, notifier: n, metrics: metrics, rand: &lockedReader{r: cfg.Rand},
		senders:     messaging.NewLimiter(cfg.SenderRate, cfg.MaxTracked),
		fanout:      messaging.NewLimiter(cfg.FanoutRate, cfg.MaxTracked),
		fanoutShare: messaging.NewLimiter(share, cfg.MaxTracked),
		adds:        messaging.NewLimiter(cfg.AddRate, cfg.MaxTracked),
		creates:     messaging.NewLimiter(cfg.CreateRate, cfg.MaxTracked),
		touched:     map[string]time.Time{},
		owned:       map[string]groupstore.Owner{},
		others:      map[string]time.Time{},
		maxFormer:   former,
	}
	if s.cfg.Task == "" {
		if s.cfg.Task, err = s.randomHex(16); err != nil {
			return nil, err
		}
	}
	engine.SetGroupHandler(s)
	return s, nil
}

// Create makes a group of the creator, its chairman and already joined
// (its INVITE is what creates it), and the invitees, invited. The group
// lasts PendingTTL until Established, so that one no session came of
// ends on its own.
//
// A Create whose Contribution names a group that exists returns that
// group if the same creator made it and it is not yet established: its
// INVITE is being tried again, with the group as it was first made. Any
// other is ErrTaken, so that nobody, a participant the chairman removed
// say, makes a group that its members' clients would take for the first
// one (security review on #279).
func (s *Service) Create(ctx context.Context, r CreateRequest) (groupstore.Group, error) {
	creator, ok := s.canonical(r.Creator)
	if !ok || !validText(r.Subject, MaxSubjectLength) || r.Conversation != "" && !messaging.ValidID(r.Conversation) ||
		r.Contribution != "" && !messaging.ValidID(r.Contribution) {
		return groupstore.Group{}, ErrInvalid
	}
	r.Creator = creator
	dropped := 0
	if !validText(r.CreatorName, MaxDisplayNameLength) {
		r.CreatorName, dropped = "", 1
	}
	if len(r.Invitees) > s.cfg.MaxParticipants {
		// Refused before any work on the list, which the client sizes:
		// even with the creator and a repeat in it, it cannot fit.
		return groupstore.Group{}, ErrTooMany
	}
	invitees, d := s.canonicalInvitees(r.Invitees)
	dropped += d
	invitees = slices.DeleteFunc(invitees, func(in Invitee) bool { return in.Identity == creator })
	names := groupstore.Group{Participants: []groupstore.Participant{{Identity: creator, DisplayName: r.CreatorName}}}
	for i, in := range invitees {
		if nameTaken(&names, in.Identity, in.DisplayName) {
			invitees[i].DisplayName = ""
			dropped++
		}
		names.Participants = append(names.Participants, groupstore.Participant{Identity: in.Identity, DisplayName: invitees[i].DisplayName})
	}
	switch {
	case len(invitees) == 0:
		return groupstore.Group{}, ErrInvalid
	case 1+len(invitees) > s.cfg.MaxParticipants:
		return groupstore.Group{}, ErrTooMany
	}
	now := s.cfg.Clock.Now()
	if !s.creates.Allow(r.Creator, now, 1) || !s.adds.Allow(r.Creator, now, len(invitees)) {
		s.metrics.Count("group.rejected.rate_limited", 1)
		return groupstore.Group{}, ErrRateLimited
	}
	id, err := s.conferenceID(r.Contribution)
	if err != nil {
		return groupstore.Group{}, err
	}
	token, err := s.randomHex(8)
	if err != nil {
		return groupstore.Group{}, err
	}
	conv := r.Conversation
	if conv == "" && r.Contribution != "" {
		conv = groupConversationID(r.Contribution)
	} else if conv == "" {
		if conv, err = s.randomUUID(); err != nil {
			return groupstore.Group{}, err
		}
	}
	g := groupstore.Group{
		URI: "sip:chat-" + id + "@" + s.cfg.ConferenceHost, Conversation: conv, Subject: r.Subject, Creator: r.Creator,
		Participants: []groupstore.Participant{{
			Identity: r.Creator, DisplayName: r.CreatorName, Role: groupstore.Chairman, State: groupstore.Joined, Since: now,
		}},
		Version: 1, Created: now, Active: now, Expires: now.Add(s.cfg.PendingTTL),
	}
	for _, in := range invitees {
		g.Participants = append(g.Participants, groupstore.Participant{
			Identity: in.Identity, DisplayName: in.DisplayName, Role: groupstore.Member, State: groupstore.Invited, AddedBy: r.Creator, Since: now,
		})
	}
	doc, err := fullDocument(g)
	if err != nil {
		return groupstore.Group{}, ErrInvalid
	}
	if !s.alive(now) {
		// Its heartbeat has lapsed: another task may own what it made.
		return groupstore.Group{}, ErrNotOwner
	}
	if err := s.store.Create(ctx, g, s.me(), token, now); errors.Is(err, groupstore.ErrExists) && r.Contribution != "" {
		return s.retried(ctx, g.URI, creator)
	} else if err != nil {
		return groupstore.Group{}, err
	}
	// The owner record's epoch goes on from the URI's last group's (Create):
	// the first write reads it, and remembers it.
	g.Rev = 1
	s.metrics.Count("group.created", 1)
	s.metrics.Count("group.name_dropped", int64(dropped))
	s.notifier.RosterChanged(ctx, RosterUpdate{Group: g.URI, Version: g.Version, Full: true, Document: doc})
	return g, nil
}

// conferenceID is the identifier of a new group's conference URI, 32
// lower-case hex digits: made from contribution, when there is one, or
// random. A Contribution-ID is no secret from the group's participants,
// who know the conference URI anyway, and the URI grants nothing: every
// request to it is checked against the roster.
func (s *Service) conferenceID(contribution string) (string, error) {
	if contribution == "" {
		return s.randomHex(16)
	}
	sum := sha256.Sum256([]byte("rcs-as group chat\x00" + contribution))
	return hex.EncodeToString(sum[:16]), nil
}

// retried is the group uri for its creator trying its INVITE again
// (Create), or ErrTaken.
func (s *Service) retried(ctx context.Context, uri, creator string) (groupstore.Group, error) {
	g, err := s.get(ctx, uri)
	switch {
	case errors.Is(err, ErrNoGroup):
		// It ended in between: the client tries again, and makes it.
		return groupstore.Group{}, ErrBusy
	case err != nil:
		return groupstore.Group{}, err
	case g.Creator != creator || !s.pending(g):
		s.metrics.Count("group.rejected.taken", 1)
		return groupstore.Group{}, ErrTaken
	}
	s.metrics.Count("group.create_retried", 1)
	return g, nil
}

// pending reports a group not yet Established: it still expires
// PendingTTL after it was made, which any later write moves on.
func (s *Service) pending(g groupstore.Group) bool {
	return !g.Expires.After(g.Created.Add(s.cfg.PendingTTL))
}

// Established records that the group's creator has its session, so that
// the group lasts as any other, RCSAS_GROUP_IDLE_TTL from its last use,
// and that a Create naming its Contribution-ID is no longer its creator
// trying again. It changes no roster and sends no NOTIFY.
func (s *Service) Established(ctx context.Context, uri string) error {
	for range maxAttempts {
		g, err := s.get(ctx, uri)
		if err != nil {
			return err
		}
		if !s.pending(g) {
			return nil
		}
		g.Expires = s.cfg.Clock.Now().Add(s.cfg.IdleTTL)
		owner, err := s.owner(ctx, g)
		if err != nil {
			return err
		}
		token, err := s.randomHex(8)
		if err != nil {
			return err
		}
		err = s.store.Update(ctx, g, owner, token)
		switch {
		case errors.Is(err, groupstore.ErrConflict):
			continue
		case errors.Is(err, groupstore.ErrNotFound):
			return ErrNoGroup
		case errors.Is(err, groupstore.ErrNotOwner):
			s.disown(uri)
			return ErrNotOwner
		}
		return err
	}
	return ErrBusy
}

// canonicalInvitees puts the invitees' identities in canonical form,
// leaving out the repeats that canonical form reveals and anyone whose
// identity is no SIP or tel URI the group can hold (counted as
// group.invitee_skipped): a client's list is not refused for one entry,
// and the caller finds who was added in the group it gets back. A name
// that is not valid text is dropped, the invitee kept; it returns how many
// were. Callers bound the list's length first.
func (s *Service) canonicalInvitees(in []Invitee) ([]Invitee, int) {
	out := make([]Invitee, 0, len(in))
	seen := make(map[string]bool, len(in))
	skipped, dropped := 0, 0
	for _, x := range in {
		id, ok := s.canonical(x.Identity)
		if !ok {
			skipped++
			continue
		}
		if !validText(x.DisplayName, MaxDisplayNameLength) {
			x.DisplayName = ""
			dropped++
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, Invitee{Identity: id, DisplayName: x.DisplayName})
		}
	}
	s.metrics.Count("group.invitee_skipped", int64(skipped))
	return out, dropped
}

// Join records that who joined the group: an invited participant
// answering, or a joined one setting up its session again. Who is not a
// current participant cannot join (ErrNotParticipant).
//
// A Join refused that way also tells the engine that who is not in the
// group (messaging.Engine.ParticipantLeft): a copy queued before it left
// or was removed is then given up, not kept to invite it again.
func (s *Service) Join(ctx context.Context, uri, who, displayName string) (groupstore.Group, error) {
	who, ok := s.canonical(who)
	if !ok {
		return groupstore.Group{}, ErrInvalid
	}
	g, err := s.join(ctx, uri, who, displayName)
	if errors.Is(err, ErrNotParticipant) {
		s.engine.ParticipantLeft(uri, who)
	}
	return g, err
}

func (s *Service) join(ctx context.Context, uri, who, displayName string) (groupstore.Group, error) {
	dropped := false
	g, err := s.change(ctx, uri, func(g *groupstore.Group, now time.Time) ([]string, error) {
		i := index(g, who)
		if i < 0 || !g.Participants[i].State.Active() {
			return nil, ErrNotParticipant
		}
		p := &g.Participants[i]
		// A name that is not valid text, or that someone else goes by, is
		// not refused but dropped: whoever asks still joins, under the
		// name it had (one an adder gave it, or none), and passes for
		// nobody. A rename dropped so is no change, and costs nothing.
		name := displayName
		dropped = name != "" && (!validText(name, MaxDisplayNameLength) || nameTaken(g, who, name))
		if dropped {
			name = p.DisplayName
		}
		if p.State == groupstore.Joined && (displayName == "" || name == p.DisplayName) {
			return nil, nil
		}
		if p.State == groupstore.Joined && !s.senders.Allow(uri+"\x00"+who, now, 1) {
			// A new name is a roster change sent to every subscriber; a
			// participant renaming itself in a loop would spam them all.
			return nil, ErrRateLimited
		}
		if p.State != groupstore.Joined {
			p.State, p.Since = groupstore.Joined, now
		}
		if displayName != "" {
			p.DisplayName = name
		}
		return []string{who}, nil
	})
	if err == nil && dropped {
		s.metrics.Count("group.name_dropped", 1)
	}
	return g, err
}

// Leave records that who left the group, by a BYE or by declining the
// focus's INVITE. A chairman's role passes on (successor); when nobody is
// left, the group ends. What is still queued for who from the group is
// given up (messaging.Engine.ParticipantLeft).
func (s *Service) Leave(ctx context.Context, uri, who string) error {
	who, ok := s.canonical(who)
	if !ok {
		return ErrInvalid
	}
	_, err := s.change(ctx, uri, func(g *groupstore.Group, now time.Time) ([]string, error) {
		i := index(g, who)
		if i < 0 || !g.Participants[i].State.Active() {
			return nil, ErrNotParticipant
		}
		changed := []string{who}
		p := &g.Participants[i]
		chairman := p.Role == groupstore.Chairman
		p.State, p.Since, p.Role = groupstore.Left, now, groupstore.Member
		if chairman {
			if next := successor(g); next >= 0 {
				g.Participants[next].Role = groupstore.Chairman
				changed = append(changed, g.Participants[next].Identity)
			}
		}
		if activeCount(g) == 0 {
			// The group ends: Get reports it gone from now on.
			g.Expires = now
		}
		return changed, nil
	})
	if err == nil {
		s.engine.ParticipantLeft(uri, who)
	}
	return err
}

// successor returns the participant who takes over as chairman: the one
// joined longest, else the one invited longest ago, or -1. Since is when
// each entered its state, so someone who left and came back counts from
// its return, not from its place in the list, which Add keeps.
func successor(g *groupstore.Group) int {
	for _, want := range []groupstore.State{groupstore.Joined, groupstore.Invited} {
		best := -1
		for i, p := range g.Participants {
			if p.State == want && (best < 0 || p.Since.Before(g.Participants[best].Since)) {
				best = i
			}
		}
		if best >= 0 {
			return best
		}
	}
	return -1
}

// Add adds participants, invited, on behalf of by, a joined participant.
// Current participants are left as they are; former ones are invited
// again, and messages are kept for them once more
// (messaging.Engine.ParticipantAdded). Only the chairman adds back someone
// who was removed.
func (s *Service) Add(ctx context.Context, uri, by string, who []Invitee) error {
	by, ok := s.canonical(by)
	if !ok {
		return ErrInvalid
	}
	if len(who) > s.cfg.MaxParticipants-1 {
		// As in Create: the group has someone in it already.
		return ErrTooMany
	}
	who, invalidNames := s.canonicalInvitees(who)
	if len(who) == 0 {
		return ErrInvalid
	}
	now := s.cfg.Clock.Now()
	if !s.adds.Allow(by, now, len(who)) {
		s.metrics.Count("group.rejected.rate_limited", 1)
		return ErrRateLimited
	}
	var added []string
	dropped := 0
	_, err := s.change(ctx, uri, func(g *groupstore.Group, now time.Time) ([]string, error) {
		added, dropped = nil, invalidNames
		adder := index(g, by)
		if adder < 0 || g.Participants[adder].State != groupstore.Joined {
			return nil, ErrNotParticipant
		}
		var changed []string
		names := nameOwners(g)
		for _, in := range who {
			i := index(g, in.Identity)
			key := nameKey(in.DisplayName)
			switch {
			case i >= 0 && g.Participants[i].State.Active():
				continue
			case (i >= 0 && g.Participants[i].State == groupstore.Removed || slices.Contains(g.Removed, in.Identity)) &&
				g.Participants[adder].Role != groupstore.Chairman:
				// Otherwise any participant could undo the chairman's
				// removal at once (threat model T11).
				return nil, ErrNotChairman
			}
			g.Removed = slices.DeleteFunc(g.Removed, func(id string) bool { return id == in.Identity })
			name := in.DisplayName
			switch {
			case key != "" && names[key] != "" && names[key] != in.Identity:
				// Someone else's: the invitee comes in without one.
				name = ""
				dropped++
			case key != "":
				names[key] = in.Identity
			}
			changed = append(changed, in.Identity)
			p := groupstore.Participant{Identity: in.Identity, DisplayName: name, Role: groupstore.Member,
				State: groupstore.Invited, AddedBy: by, Since: now}
			if i >= 0 {
				g.Participants[i] = p
			} else {
				g.Participants = append(g.Participants, p)
			}
		}
		if activeCount(g) > s.cfg.MaxParticipants {
			return nil, ErrTooMany
		}
		added = changed
		return changed, nil
	})
	if err == nil {
		for _, who := range added {
			s.engine.ParticipantAdded(uri, who)
		}
		s.metrics.Count("group.name_dropped", int64(dropped))
	}
	return err
}

// Remove removes who from the group on behalf of by, its chairman.
func (s *Service) Remove(ctx context.Context, uri, by, who string) error {
	by, ok := s.canonical(by)
	who, ok2 := s.canonical(who)
	if !ok || !ok2 {
		return ErrInvalid
	}
	_, err := s.change(ctx, uri, func(g *groupstore.Group, now time.Time) ([]string, error) {
		i := index(g, by)
		switch {
		case i < 0 || g.Participants[i].State != groupstore.Joined:
			return nil, ErrNotParticipant
		case g.Participants[i].Role != groupstore.Chairman:
			return nil, ErrNotChairman
		case who == by:
			// Leaving is Leave, which also hands the role on.
			return nil, ErrInvalid
		}
		j := index(g, who)
		if j < 0 || !g.Participants[j].State.Active() {
			return nil, ErrNotParticipant
		}
		g.Participants[j].State, g.Participants[j].Since = groupstore.Removed, now
		return []string{who}, nil
	})
	if err == nil {
		s.engine.ParticipantLeft(uri, who)
	}
	return err
}

// Roster returns the full conference-info document of the group, for the
// first NOTIFY of a subscription by who, a current participant (RFC 4575
// §4.6). Others get ErrNotParticipant: the roster says who talks to whom.
func (s *Service) Roster(ctx context.Context, uri, who string) ([]byte, uint32, error) {
	who, ok := s.canonical(who)
	if !ok {
		return nil, 0, ErrInvalid
	}
	g, err := s.get(ctx, uri)
	if err != nil {
		return nil, 0, err
	}
	if i := index(&g, who); i < 0 || !g.Participants[i].State.Active() {
		return nil, 0, ErrNotParticipant
	}
	doc, err := fullDocument(g)
	return doc, g.Version, err
}

// FullRoster returns the group and its full conference-info document, for
// whoever checks for itself who may read it: the SIP layer, to bring the
// subscriptions of a group that missed a change up to date with one read
// of the group for all of them (code review on #340).
func (s *Service) FullRoster(ctx context.Context, uri string) (groupstore.Group, []byte, error) {
	g, err := s.get(ctx, uri)
	if err != nil {
		return groupstore.Group{}, nil, err
	}
	doc, err := fullDocument(g)
	return g, doc, err
}

// Get returns the group, ErrNoGroup if there is none.
func (s *Service) Get(ctx context.Context, uri string) (groupstore.Group, error) {
	return s.get(ctx, uri)
}

func (s *Service) get(ctx context.Context, uri string) (groupstore.Group, error) {
	g, err := s.store.Get(ctx, uri, s.cfg.Clock.Now())
	if errors.Is(err, groupstore.ErrNotFound) {
		return groupstore.Group{}, ErrNoGroup
	}
	return g, err
}

// change applies f to the stored group and writes the result
// conditionally, computing it again from the new state when another
// writer came first. f returns the identities whose entries it changed;
// none means nothing to write. Every write raises the roster version by
// one and is followed by the partial document of the change.
func (s *Service) change(ctx context.Context, uri string, f func(g *groupstore.Group, now time.Time) ([]string, error)) (groupstore.Group, error) {
	for range maxAttempts {
		now := s.cfg.Clock.Now()
		g, err := s.get(ctx, uri)
		if err != nil {
			return groupstore.Group{}, err
		}
		changed, err := f(&g, now)
		if err != nil {
			s.metrics.Count("group.rejected."+reasonOf(err), 1)
			return groupstore.Group{}, err
		}
		if len(changed) == 0 {
			return g, nil
		}
		deleted := s.forget(&g)
		g.Version++
		g.Active = now
		if g.Expires.After(now) {
			g.Expires = now.Add(s.cfg.IdleTTL)
		}
		// Both documents are built before the write: one the group could
		// not be written as must not be stored.
		doc, err := partialDocument(g, changed, deleted)
		if err == nil {
			_, err = fullDocument(g)
		}
		if err != nil {
			s.metrics.Count("group.rejected.invalid", 1)
			return groupstore.Group{}, ErrInvalid
		}
		owner, err := s.owner(ctx, g)
		if err != nil {
			return groupstore.Group{}, err
		}
		token, err := s.randomHex(8)
		if err != nil {
			return groupstore.Group{}, err
		}
		err = s.store.Update(ctx, g, owner, token)
		if errors.Is(err, groupstore.ErrConflict) {
			s.metrics.Count("group.update_conflict", 1)
			continue
		}
		if errors.Is(err, groupstore.ErrNotFound) {
			return groupstore.Group{}, ErrNoGroup
		}
		if errors.Is(err, groupstore.ErrNotOwner) {
			s.disown(uri)
			return groupstore.Group{}, ErrNotOwner
		}
		if err != nil {
			return groupstore.Group{}, err
		}
		g.Rev++
		s.metrics.Count("group.roster_changed", 1)
		var departed []string
		for _, id := range changed {
			if p, ok := g.Participant(id); ok && !p.State.Active() {
				departed = append(departed, id)
			}
		}
		s.notifier.RosterChanged(ctx, RosterUpdate{Group: g.URI, Version: g.Version, Document: doc, Departed: departed})
		return g, nil
	}
	return groupstore.Group{}, ErrBusy
}

// forget drops the oldest former participants of g beyond maxFormer of
// them and returns who it dropped. Without it, adding and removing one
// stranger after another would grow the stored group, and its roster,
// without bound. Those who left go first. A removed one dropped from the
// roster is still kept in g.Removed, identity only, so that only the
// chairman can add it back however many leave after it (the roster of a
// group of 200 keeps only 9 former participants); beyond
// groupstore.MaxRemoved, the one removed longest ago is forgotten.
func (s *Service) forget(g *groupstore.Group) []string {
	var deleted []string
	for len(g.Participants)-activeCount(g) > s.maxFormer {
		oldest := -1
		for _, want := range []groupstore.State{groupstore.Left, groupstore.Removed} {
			for i, p := range g.Participants {
				if p.State == want && (oldest < 0 || p.Since.Before(g.Participants[oldest].Since)) {
					oldest = i
				}
			}
			if oldest >= 0 {
				break
			}
		}
		p := g.Participants[oldest]
		if p.State == groupstore.Removed {
			g.Removed = append(g.Removed, p.Identity)
		}
		deleted = append(deleted, p.Identity)
		g.Participants = slices.Delete(g.Participants, oldest, oldest+1)
	}
	if n := len(g.Removed) - groupstore.MaxRemoved; n > 0 {
		g.Removed = slices.Delete(g.Removed, 0, n)
	}
	return deleted
}

func reasonOf(err error) string {
	switch {
	case errors.Is(err, ErrNotParticipant):
		return "not_participant"
	case errors.Is(err, ErrNotChairman):
		return "not_chairman"
	case errors.Is(err, ErrTooMany):
		return "too_many"
	case errors.Is(err, ErrInvalid):
		return "invalid"
	}
	return "other"
}

func index(g *groupstore.Group, identity string) int {
	return slices.IndexFunc(g.Participants, func(p groupstore.Participant) bool { return p.Identity == identity })
}

func activeCount(g *groupstore.Group) int {
	n := 0
	for _, p := range g.Participants {
		if p.State.Active() {
			n++
		}
	}
	return n
}

// Recipients implements messaging.GroupHandler: only a joined participant
// writes in a group, under its rate per group and the group's fan-out
// budget, and a message goes to every other current participant; an
// is-composing indication only to the joined ones, which have a session to
// show it on. The sender's name is the one the roster holds.
func (s *Service) Recipients(ctx context.Context, uri, sender string, kind messaging.GroupKind) (messaging.Audience, error) {
	sender, ok := s.canonical(sender)
	if !ok {
		return messaging.Audience{}, messaging.Reject(messaging.ReasonNotParticipant)
	}
	g, err := s.get(ctx, uri)
	if errors.Is(err, ErrNoGroup) {
		return messaging.Audience{}, messaging.Reject(messaging.ReasonNoGroup)
	}
	if err != nil {
		return messaging.Audience{}, err
	}
	i := index(&g, sender)
	if i < 0 || g.Participants[i].State != groupstore.Joined {
		return messaging.Audience{}, messaging.Reject(messaging.ReasonNotParticipant)
	}
	now := s.cfg.Clock.Now()
	aud := messaging.Audience{SenderName: g.Participants[i].DisplayName}
	for _, p := range g.Participants {
		if p.Identity == sender || !p.State.Active() || kind == messaging.GroupComposing && p.State != groupstore.Joined {
			continue
		}
		aud.Recipients = append(aud.Recipients, p.Identity)
	}
	switch kind {
	case messaging.GroupNotification:
		return messaging.Audience{}, nil
	case messaging.GroupText:
		if !s.senders.Allow(uri+"\x00"+sender, now, 1) {
			return messaging.Audience{}, messaging.Reject(messaging.ReasonRateLimited)
		}
		if !s.fanoutShare.Allow(uri+"\x00"+sender, now, len(aud.Recipients)) {
			s.metrics.Count("group.fanout_share_exceeded", 1)
			return messaging.Audience{}, messaging.Reject(messaging.ReasonRateLimited)
		}
		if !s.fanout.Allow(uri, now, len(aud.Recipients)) {
			s.metrics.Count("group.fanout_budget_exceeded", 1)
			return messaging.Audience{}, messaging.Reject(messaging.ReasonRateLimited)
		}
		// Every copy is queued under the group's owner, this task (#121).
		if aud.Fence, err = s.fence(ctx, g); err != nil {
			return messaging.Audience{}, err
		}
		s.touch(ctx, g, now)
	}
	return aud, nil
}

// Member implements messaging.GroupHandler: whether user is a current
// participant, invited or joined.
func (s *Service) Member(ctx context.Context, uri, user string) (bool, error) {
	user, ok := s.canonical(user)
	if !ok {
		return false, nil
	}
	g, err := s.get(ctx, uri)
	switch {
	case errors.Is(err, ErrNoGroup):
		return false, nil
	case err != nil:
		return false, err
	}
	i := index(&g, user)
	return i >= 0 && g.Participants[i].State.Active(), nil
}

// touch writes that the group is in use, at most once per TouchInterval
// per task.
func (s *Service) touch(ctx context.Context, g groupstore.Group, now time.Time) {
	s.mu.Lock()
	last, ok := s.touched[g.URI]
	if ok && now.Sub(last) < s.cfg.TouchInterval || now.Sub(g.Active) < s.cfg.TouchInterval {
		s.mu.Unlock()
		return
	}
	if len(s.touched) >= s.cfg.MaxTracked {
		clear(s.touched)
	}
	s.touched[g.URI] = now
	s.mu.Unlock()
	owner, err := s.owner(ctx, g)
	if err != nil {
		return // the owner touches it
	}
	switch err := s.store.Touch(ctx, g.URI, owner, now, now.Add(s.cfg.IdleTTL)); {
	case err == nil:
		s.metrics.Count("group.touched", 1)
	case errors.Is(err, groupstore.ErrNotOwner):
		s.disown(g.URI)
	}
}

// A group created without a Conversation-ID gets one in the UUID form OMA
// CPM asks of it (Conversation Functions, Appendix C.1.1; #305). Groups
// stored before keep the 32 hex digits they were made with: a
// Conversation-ID is opaque, and is read and compared as stored.

// randomUUID is a random UUID (RFC 9562 §5.4, version 4), for a group
// created without a Contribution-ID either.
func (s *Service) randomUUID() (string, error) {
	u := make([]byte, 16)
	if _, err := io.ReadFull(s.rand, u); err != nil {
		return "", fmt.Errorf("group: random source: %w", err)
	}
	return uuidString(u, 4), nil
}

// groupNamespace is the UUID namespace of groupConversationID's
// name-based UUIDs, chosen for rcs-as's groups; it is not
// messaging.PairConversationID's.
var groupNamespace = [16]byte{0xe5, 0x1a, 0xd9, 0x37, 0x23, 0x61, 0x43, 0x3b, 0xa3, 0xe7, 0x28, 0x3a, 0x7e, 0xf6, 0x41, 0xae}

// groupConversationID is the Conversation-ID of a group made with a
// Contribution-ID and no Conversation-ID: a name-based UUID (RFC 9562
// §5.5, version 5) of the Contribution-ID alone, as the conference URI is
// (conferenceID). rcsjta restarts a group that ended
// (RestartGroupChatSession) at the factory under the same Contribution-ID,
// from whichever participant writes next, not only its creator; the
// restarted group so gets the same conference URI and Conversation-ID, and
// a client that threads by it keeps one thread (lead's decision on #381).
// A version 5 UUID never equals a version 4 one, the version digit
// differing.
func groupConversationID(contribution string) string {
	h := sha1.New()
	h.Write(groupNamespace[:])
	h.Write([]byte(contribution))
	return uuidString(h.Sum(nil)[:16], 5)
}

// uuidString sets u's version and the RFC 9562 variant, and writes it in
// the 8-4-4-4-12 form.
func uuidString(u []byte, version byte) string {
	u[6] = u[6]&0x0f | version<<4
	u[8] = u[8]&0x3f | 0x80
	x := hex.EncodeToString(u)
	return x[0:8] + "-" + x[8:12] + "-" + x[12:16] + "-" + x[16:20] + "-" + x[20:32]
}

func (s *Service) randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(s.rand, b); err != nil {
		return "", fmt.Errorf("group: random source: %w", err)
	}
	return hex.EncodeToString(b), nil
}

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
