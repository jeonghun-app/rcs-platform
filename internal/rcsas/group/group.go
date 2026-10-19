package group

import (
	"context"
	"crypto/rand"
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
	// maxAttempts bounds the rereads of a group whose update keeps meeting
	// another writer's; each attempt loses only to a write that landed.
	maxAttempts = 32
)

// Default rates. A participant writes in a group as fast as in a 1-to-1
// chat. The fan-out budget is deliveries per group: a full group of 100 may
// carry about one message a second, and its burst covers one message to
// every participant. Adding is bounded per adder, creating per creator: a
// group of strangers is the spam this guards against (threat model T11).
var (
	DefaultSenderRate = messaging.Rate{PerMinute: 60, Burst: 30}
	DefaultFanoutRate = messaging.Rate{PerMinute: 6000, Burst: 1000}
	DefaultAddRate    = messaging.Rate{PerMinute: 30, Burst: 100}
	DefaultCreateRate = messaging.Rate{PerMinute: 5, Burst: 10}
)

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
)

// Config configures a Service. Zero fields take the defaults.
type Config struct {
	// ConferenceHost is the host of the conference URIs the focus
	// allocates, sip:chat-<random>@ConferenceHost; it must route to
	// rcs-as. Required.
	ConferenceHost  string
	MaxParticipants int
	IdleTTL         time.Duration
	// SenderRate bounds the messages one participant writes in one group;
	// FanoutRate the deliveries one group makes, a message counting once
	// per recipient; AddRate the participants one user adds, in groups it
	// creates too; CreateRate the groups one user creates.
	SenderRate    messaging.Rate
	FanoutRate    messaging.Rate
	AddRate       messaging.Rate
	CreateRate    messaging.Rate
	TouchInterval time.Duration
	// MaxTracked bounds the rate buckets and activity marks kept in
	// memory.
	MaxTracked int
	Clock      msrp.Clock
	Rand       io.Reader
}

func (c Config) withDefaults() Config {
	if c.MaxParticipants <= 0 {
		c.MaxParticipants = DefaultMaxParticipants
	}
	if c.IdleTTL <= 0 {
		c.IdleTTL = DefaultIdleTTL
	}
	if c.TouchInterval <= 0 {
		c.TouchInterval = DefaultTouchInterval
	}
	if c.MaxTracked <= 0 {
		c.MaxTracked = DefaultMaxTracked
	}
	for _, r := range []struct {
		v   *messaging.Rate
		def messaging.Rate
	}{{&c.SenderRate, DefaultSenderRate}, {&c.FanoutRate, DefaultFanoutRate}, {&c.AddRate, DefaultAddRate}, {&c.CreateRate, DefaultCreateRate}} {
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
	// Conversation is the Conversation-ID of the request; empty means one
	// is generated.
	Conversation string
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

	mu      sync.Mutex
	touched map[string]time.Time
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
	if cfg.FanoutRate.PerMinute > 0 && cfg.FanoutRate.Burst < cfg.MaxParticipants-1 {
		// Otherwise a message to a full group could never be sent.
		return nil, errors.New("group: the fan-out burst must cover a full group")
	}
	s := &Service{
		cfg: cfg, store: st, engine: engine, notifier: n, metrics: metrics, rand: &lockedReader{r: cfg.Rand},
		senders: messaging.NewLimiter(cfg.SenderRate, cfg.MaxTracked),
		fanout:  messaging.NewLimiter(cfg.FanoutRate, cfg.MaxTracked),
		adds:    messaging.NewLimiter(cfg.AddRate, cfg.MaxTracked),
		creates: messaging.NewLimiter(cfg.CreateRate, cfg.MaxTracked),
		touched: map[string]time.Time{},
	}
	engine.SetGroupHandler(s)
	return s, nil
}

// Bounds on what a client names: they are stored once per participant,
// and the group's item must stay well inside DynamoDB's 400 KB.
const (
	MaxDisplayNameLength = 256
	MaxSubjectLength     = 256
)

func validIdentity(id string) bool { return id != "" && len(id) <= messaging.MaxIdentityLength }

// Create makes a group of the creator, its chairman and already joined
// (its INVITE is what creates it), and the invitees, invited.
func (s *Service) Create(ctx context.Context, r CreateRequest) (groupstore.Group, error) {
	if !validIdentity(r.Creator) || len(r.CreatorName) > MaxDisplayNameLength || len(r.Subject) > MaxSubjectLength ||
		len(r.Conversation) > messaging.MaxIDLength {
		return groupstore.Group{}, ErrInvalid
	}
	var invitees []Invitee
	seen := map[string]bool{r.Creator: true}
	for _, in := range r.Invitees {
		if !validIdentity(in.Identity) || len(in.DisplayName) > MaxDisplayNameLength {
			return groupstore.Group{}, ErrInvalid
		}
		if !seen[in.Identity] {
			seen[in.Identity] = true
			invitees = append(invitees, in)
		}
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
	id, err := s.randomHex(16)
	if err != nil {
		return groupstore.Group{}, err
	}
	token, err := s.randomHex(8)
	if err != nil {
		return groupstore.Group{}, err
	}
	conv := r.Conversation
	if conv == "" {
		if conv, err = s.randomHex(16); err != nil {
			return groupstore.Group{}, err
		}
	}
	g := groupstore.Group{
		URI: "sip:chat-" + id + "@" + s.cfg.ConferenceHost, Conversation: conv, Subject: r.Subject, Creator: r.Creator,
		Participants: []groupstore.Participant{{
			Identity: r.Creator, DisplayName: r.CreatorName, Role: groupstore.Chairman, State: groupstore.Joined, Since: now,
		}},
		Version: 1, Created: now, Active: now, Expires: now.Add(s.cfg.IdleTTL),
	}
	for _, in := range invitees {
		g.Participants = append(g.Participants, groupstore.Participant{
			Identity: in.Identity, DisplayName: in.DisplayName, Role: groupstore.Member, State: groupstore.Invited, AddedBy: r.Creator, Since: now,
		})
	}
	if err := s.store.Create(ctx, g, token, now); err != nil {
		return groupstore.Group{}, err
	}
	g.Rev = 1
	doc, err := fullDocument(g)
	if err != nil {
		return groupstore.Group{}, err
	}
	s.metrics.Count("group.created", 1)
	s.notifier.RosterChanged(ctx, RosterUpdate{Group: g.URI, Version: g.Version, Full: true, Document: doc})
	return g, nil
}

// Join records that who joined the group: an invited participant
// answering, or a joined one setting up its session again. Who is not a
// current participant cannot join (ErrNotParticipant).
func (s *Service) Join(ctx context.Context, uri, who, displayName string) (groupstore.Group, error) {
	if len(displayName) > MaxDisplayNameLength {
		return groupstore.Group{}, ErrInvalid
	}
	return s.change(ctx, uri, func(g *groupstore.Group, now time.Time) ([]string, error) {
		i := index(g, who)
		if i < 0 || !g.Participants[i].State.Active() {
			return nil, ErrNotParticipant
		}
		p := &g.Participants[i]
		if p.State == groupstore.Joined && (displayName == "" || displayName == p.DisplayName) {
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
			p.DisplayName = displayName
		}
		return []string{who}, nil
	})
}

// Leave records that who left the group. A chairman's role passes to the
// participant in the group longest, joined ones first; when nobody is
// left, the group ends.
func (s *Service) Leave(ctx context.Context, uri, who string) error {
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
	return err
}

// successor returns the participant who takes over as chairman: the
// longest-standing joined one, else the longest-standing invited one, or -1.
func successor(g *groupstore.Group) int {
	for _, want := range []groupstore.State{groupstore.Joined, groupstore.Invited} {
		if i := slices.IndexFunc(g.Participants, func(p groupstore.Participant) bool { return p.State == want }); i >= 0 {
			return i
		}
	}
	return -1
}

// Add adds participants, invited, on behalf of by, a joined participant.
// Current participants are left as they are; former ones are invited
// again.
func (s *Service) Add(ctx context.Context, uri, by string, who []Invitee) error {
	for _, in := range who {
		if !validIdentity(in.Identity) || len(in.DisplayName) > MaxDisplayNameLength {
			return ErrInvalid
		}
	}
	now := s.cfg.Clock.Now()
	if !s.adds.Allow(by, now, len(who)) {
		s.metrics.Count("group.rejected.rate_limited", 1)
		return ErrRateLimited
	}
	_, err := s.change(ctx, uri, func(g *groupstore.Group, now time.Time) ([]string, error) {
		if i := index(g, by); i < 0 || g.Participants[i].State != groupstore.Joined {
			return nil, ErrNotParticipant
		}
		var changed []string
		for _, in := range who {
			i := index(g, in.Identity)
			if i >= 0 && g.Participants[i].State.Active() || slices.Contains(changed, in.Identity) {
				continue
			}
			changed = append(changed, in.Identity)
			p := groupstore.Participant{Identity: in.Identity, DisplayName: in.DisplayName, Role: groupstore.Member,
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
		return changed, nil
	})
	return err
}

// Remove removes who from the group on behalf of by, its chairman.
func (s *Service) Remove(ctx context.Context, uri, by, who string) error {
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
	return err
}

// Roster returns the full conference-info document of the group, for the
// first NOTIFY of a subscription by who, a current participant (RFC 4575
// §4.6). Others get ErrNotParticipant: the roster says who talks to whom.
func (s *Service) Roster(ctx context.Context, uri, who string) ([]byte, uint32, error) {
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
		token, err := s.randomHex(8)
		if err != nil {
			return groupstore.Group{}, err
		}
		err = s.store.Update(ctx, g, token)
		if errors.Is(err, groupstore.ErrConflict) {
			s.metrics.Count("group.update_conflict", 1)
			continue
		}
		if errors.Is(err, groupstore.ErrNotFound) {
			return groupstore.Group{}, ErrNoGroup
		}
		if err != nil {
			return groupstore.Group{}, err
		}
		g.Rev++
		doc, err := partialDocument(g, changed, deleted)
		if err != nil {
			return groupstore.Group{}, err
		}
		s.metrics.Count("group.roster_changed", 1)
		s.notifier.RosterChanged(ctx, RosterUpdate{Group: g.URI, Version: g.Version, Document: doc})
		return g, nil
	}
	return groupstore.Group{}, ErrBusy
}

// forget drops the oldest former participants of g beyond MaxParticipants
// of them and returns who it dropped. Without it, adding and removing one
// stranger after another would grow the stored group without bound.
func (s *Service) forget(g *groupstore.Group) []string {
	var deleted []string
	for len(g.Participants)-activeCount(g) > s.cfg.MaxParticipants {
		oldest := -1
		for i, p := range g.Participants {
			if !p.State.Active() && (oldest < 0 || p.Since.Before(g.Participants[oldest].Since)) {
				oldest = i
			}
		}
		deleted = append(deleted, g.Participants[oldest].Identity)
		g.Participants = slices.Delete(g.Participants, oldest, oldest+1)
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
// show it on.
func (s *Service) Recipients(ctx context.Context, uri, sender string, kind messaging.GroupKind) ([]string, error) {
	g, err := s.get(ctx, uri)
	if errors.Is(err, ErrNoGroup) {
		return nil, messaging.Reject(messaging.ReasonNoGroup)
	}
	if err != nil {
		return nil, err
	}
	if i := index(&g, sender); i < 0 || g.Participants[i].State != groupstore.Joined {
		return nil, messaging.Reject(messaging.ReasonNotParticipant)
	}
	now := s.cfg.Clock.Now()
	var to []string
	for _, p := range g.Participants {
		if p.Identity == sender || !p.State.Active() || kind == messaging.GroupComposing && p.State != groupstore.Joined {
			continue
		}
		to = append(to, p.Identity)
	}
	switch kind {
	case messaging.GroupNotification:
		return nil, nil
	case messaging.GroupText:
		if !s.senders.Allow(uri+"\x00"+sender, now, 1) {
			return nil, messaging.Reject(messaging.ReasonRateLimited)
		}
		if !s.fanout.Allow(uri, now, len(to)) {
			s.metrics.Count("group.fanout_budget_exceeded", 1)
			return nil, messaging.Reject(messaging.ReasonRateLimited)
		}
		s.touch(ctx, g, now)
	}
	return to, nil
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
	if err := s.store.Touch(ctx, g.URI, now, now.Add(s.cfg.IdleTTL)); err == nil {
		s.metrics.Count("group.touched", 1)
	}
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
