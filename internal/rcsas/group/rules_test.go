package group

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/rcsas/groupstore"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
)

func TestAGroupIsCreatedWithItsCreatorAsChairman(t *testing.T) {
	r := newRig(t, Config{})
	g, err := r.s.Create(t.Context(), CreateRequest{Creator: alice, CreatorName: "Alice", Subject: "Lunch",
		Invitees: []Invitee{{Identity: bob, DisplayName: "Bob"}, {Identity: carol}, {Identity: bob}, {Identity: alice}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(g.URI, "sip:chat-") || !strings.HasSuffix(g.URI, "@"+host) || len(g.URI) < len("sip:chat-@")+32 ||
		g.Conversation == "" || g.Version != 1 || g.Creator != alice || len(g.Participants) != 3 {
		t.Fatalf("group %+v", g)
	}
	want := []groupstore.Participant{
		{Identity: alice, DisplayName: "Alice", Role: groupstore.Chairman, State: groupstore.Joined},
		{Identity: bob, DisplayName: "Bob", Role: groupstore.Member, State: groupstore.Invited, AddedBy: alice},
		{Identity: carol, Role: groupstore.Member, State: groupstore.Invited, AddedBy: alice},
	}
	for i, p := range g.Participants {
		p.Since = want[i].Since
		if p != want[i] {
			t.Errorf("participant %d = %+v, want %+v", i, p, want[i])
		}
	}
	stored, err := r.s.Get(t.Context(), g.URI)
	if err != nil || stored.Version != 1 || len(stored.Participants) != 3 {
		t.Fatalf("Get = %+v, %v", stored, err)
	}
	if u := r.n.all(); len(u) != 1 || !u[0].Full || u[0].Version != 1 || u[0].Group != g.URI {
		t.Fatalf("roster updates %+v", u)
	}
}

func TestCreationIsBounded(t *testing.T) {
	r := newRig(t, Config{MaxParticipants: 3})
	for name, c := range map[string]struct {
		req  CreateRequest
		want error
	}{
		"nobody to chat with": {CreateRequest{Creator: alice, Invitees: []Invitee{{Identity: alice}}}, ErrInvalid},
		"no creator":          {CreateRequest{Invitees: []Invitee{{Identity: bob}}}, ErrInvalid},
		"an empty identity":   {CreateRequest{Creator: alice, Invitees: []Invitee{{Identity: ""}}}, ErrInvalid},
		"an overlong identity": {CreateRequest{Creator: alice,
			Invitees: []Invitee{{Identity: "sip:" + strings.Repeat("x", messaging.MaxIdentityLength) + "@x"}}}, ErrInvalid},
		"beyond the size limit": {CreateRequest{Creator: alice, Invitees: []Invitee{{Identity: bob}, {Identity: carol}, {Identity: dave}}}, ErrTooMany},
		"an overlong subject": {CreateRequest{Creator: alice, Subject: strings.Repeat("s", MaxSubjectLength+1),
			Invitees: []Invitee{{Identity: bob}}}, ErrInvalid},
		// Kept, without the name.
		"an overlong name": {CreateRequest{Creator: alice,
			Invitees: []Invitee{{Identity: bob, DisplayName: strings.Repeat("n", MaxDisplayNameLength+1)}}}, nil},
		"an overlong Conversation-ID": {CreateRequest{Creator: alice, Conversation: strings.Repeat("c", messaging.MaxIDLength+1),
			Invitees: []Invitee{{Identity: bob}}}, ErrInvalid},
		"a Conversation-ID with a space": {CreateRequest{Creator: alice, Conversation: "a b", Invitees: []Invitee{{Identity: bob}}}, ErrInvalid},
		"a Conversation-ID with a CRLF":  {CreateRequest{Creator: alice, Conversation: "a\r\nX: y", Invitees: []Invitee{{Identity: bob}}}, ErrInvalid},
		"a Conversation-ID with a quote": {CreateRequest{Creator: alice, Conversation: `a"b`, Invitees: []Invitee{{Identity: bob}}}, ErrInvalid},
	} {
		if _, err := r.s.Create(t.Context(), c.req); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	if _, err := r.s.Create(t.Context(), CreateRequest{Creator: alice, Invitees: []Invitee{{Identity: bob}, {Identity: carol}}}); err != nil {
		t.Errorf("at the size limit: %v", err)
	}
}

// The authorisation rules, each as a (who, what, to whom) case against a
// group of alice (chairman, joined), bob (joined), carol (invited), dave
// (left) and erin (removed).
func TestOnlyTheRightParticipantsMayChangeAGroup(t *testing.T) {
	type op func(r *rig, g string) error
	add := func(by, who string) op {
		return func(r *rig, g string) error { return r.s.Add(context.Background(), g, by, []Invitee{{Identity: who}}) }
	}
	remove := func(by, who string) op {
		return func(r *rig, g string) error { return r.s.Remove(context.Background(), g, by, who) }
	}
	leave := func(who string) op {
		return func(r *rig, g string) error { return r.s.Leave(context.Background(), g, who) }
	}
	join := func(who string) op {
		return func(r *rig, g string) error { _, err := r.s.Join(context.Background(), g, who, ""); return err }
	}
	stranger := "sip:stranger@example.net"
	for name, c := range map[string]struct {
		do   op
		want error
	}{
		"a joined participant adds":                 {add(bob, stranger), nil},
		"the chairman adds":                         {add(alice, stranger), nil},
		"an invited participant adds":               {add(carol, stranger), ErrNotParticipant},
		"a former participant adds":                 {add(dave, stranger), ErrNotParticipant},
		"a stranger adds":                           {add(stranger, "sip:x@example.net"), ErrNotParticipant},
		"adding someone who left invites them":      {add(bob, dave), nil},
		"a participant adds someone removed":        {add(bob, erin), ErrNotChairman},
		"the chairman adds someone removed":         {add(alice, erin), nil},
		"adding a current participant does nothing": {add(bob, carol), nil},
		"the chairman removes":                      {remove(alice, bob), nil},
		"the chairman removes an invitee":           {remove(alice, carol), nil},
		"a participant removes":                     {remove(bob, carol), ErrNotChairman},
		"a stranger removes":                        {remove(stranger, bob), ErrNotParticipant},
		"the chairman removes itself":               {remove(alice, alice), ErrInvalid},
		"the chairman removes someone gone":         {remove(alice, dave), ErrNotParticipant},
		"a participant leaves":                      {leave(bob), nil},
		"an invitee declines":                       {leave(carol), nil},
		"someone gone leaves again":                 {leave(dave), ErrNotParticipant},
		"an invitee joins":                          {join(carol), nil},
		"a joined participant joins again":          {join(bob), nil},
		"someone who left joins":                    {join(dave), ErrNotParticipant},
		"someone removed joins":                     {join(erin), ErrNotParticipant},
		"a stranger joins":                          {join(stranger), ErrNotParticipant},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, Config{})
			g := r.create(bob, dave, erin)
			if err := r.s.Add(t.Context(), g.URI, alice, []Invitee{{Identity: carol}}); err != nil {
				t.Fatal(err)
			}
			if err := r.s.Leave(t.Context(), g.URI, dave); err != nil {
				t.Fatal(err)
			}
			if err := r.s.Remove(t.Context(), g.URI, alice, erin); err != nil {
				t.Fatal(err)
			}
			if err := c.do(r, g.URI); !errors.Is(err, c.want) {
				t.Fatalf("%v, want %v", err, c.want)
			}
		})
	}
}

func TestAddingRespectsTheSizeLimitAndTheAddersRate(t *testing.T) {
	r := newRig(t, Config{MaxParticipants: 4, AddRate: messaging.Rate{PerMinute: 1, Burst: 5}})
	g := r.create(bob)
	if err := r.s.Add(t.Context(), g.URI, bob, []Invitee{{Identity: carol}, {Identity: dave}, {Identity: erin}}); !errors.Is(err, ErrTooMany) {
		t.Fatalf("beyond the limit: %v", err)
	}
	if err := r.s.Add(t.Context(), g.URI, bob, []Invitee{{Identity: carol}, {Identity: dave}}); err != nil {
		t.Fatalf("up to the limit: %v", err)
	}
	// alice's burst went on creating the group with bob (1) and another
	// with three (3) ...
	if _, err := r.s.Create(t.Context(), CreateRequest{Creator: alice, Invitees: []Invitee{{Identity: bob}, {Identity: carol}, {Identity: dave}}}); err != nil {
		t.Fatal(err)
	}
	var many []Invitee
	for i := range 3 {
		many = append(many, Invitee{Identity: fmt.Sprintf("sip:u%d@example.net", i)})
	}
	if err := r.s.Add(t.Context(), g.URI, alice, many); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("beyond alice's burst: %v", err)
	}
	if err := r.s.Add(t.Context(), g.URI, bob, []Invitee{{Identity: ""}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an empty identity: %v", err)
	}
	if r.m.get("group.rejected.too_many") != 1 || r.m.get("group.rejected.rate_limited") != 1 {
		t.Fatalf("metrics %v", r.m)
	}
}

// The security review (PR #118, round 2): an invitation list is bounded
// by its length before any identity in it is looked at, so a list of tens
// of thousands costs nothing. The invalid identity at its end shows the
// order: it would be ErrInvalid if the list were read first.
func TestAnOverlongInvitationListIsRefusedUnread(t *testing.T) {
	r := newRig(t, Config{MaxParticipants: 5})
	g := r.create(bob)
	list := func(n int) []Invitee {
		in := make([]Invitee, n)
		for i := range in[:n-1] {
			in[i] = Invitee{Identity: fmt.Sprintf("sip:u%d@example.net", i)}
		}
		in[n-1] = Invitee{Identity: "not a URI"}
		return in
	}
	for _, n := range []int{6, 30_000} {
		if _, err := r.s.Create(t.Context(), CreateRequest{Creator: alice, Invitees: list(n)}); !errors.Is(err, ErrTooMany) {
			t.Errorf("Create with %d: %v", n, err)
		}
		if err := r.s.Add(t.Context(), g.URI, bob, list(n-1)); !errors.Is(err, ErrTooMany) {
			t.Errorf("Add of %d: %v", n-1, err)
		}
	}
	// At the bound, the list is read: the bad identity is left out and
	// the others are invited.
	if c, err := r.s.Create(t.Context(), CreateRequest{Creator: alice, Invitees: list(5)}); err != nil || len(c.Participants) != 5 {
		t.Errorf("Create with 5: %v, %d participants", err, len(c.Participants))
	}
	if err := r.s.Add(t.Context(), g.URI, bob, list(4)); err != nil {
		t.Errorf("Add of 4: %v", err)
	}
	if r.m.get("group.invitee_skipped") != 2 {
		t.Errorf("metrics %v", r.m)
	}
	// A list with the creator and repeats in it still fits.
	if _, err := r.s.Create(t.Context(), CreateRequest{Creator: alice, Invitees: []Invitee{
		{Identity: alice}, {Identity: bob}, {Identity: "tel:+1-555-010-0002"}, {Identity: carol}, {Identity: dave},
	}}); err != nil {
		t.Errorf("a list with the creator and a repeat: %v", err)
	}
}

func TestCreatingIsRateLimitedPerCreator(t *testing.T) {
	r := newRig(t, Config{CreateRate: messaging.Rate{PerMinute: 1, Burst: 2}})
	req := CreateRequest{Creator: alice, Invitees: []Invitee{{Identity: bob}}}
	for i := range 2 {
		if _, err := r.s.Create(t.Context(), req); err != nil {
			t.Fatalf("group %d: %v", i, err)
		}
	}
	if _, err := r.s.Create(t.Context(), req); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("beyond the burst: %v", err)
	}
	req.Creator = bob
	req.Invitees = []Invitee{{Identity: alice}}
	if _, err := r.s.Create(t.Context(), req); err != nil {
		t.Fatalf("another creator: %v", err)
	}
}

func TestTheChairmanRoleOutlivesTheChairman(t *testing.T) {
	r := newRig(t, Config{})
	g := r.create(bob, carol)
	if err := r.s.Leave(t.Context(), g.URI, alice); err != nil {
		t.Fatal(err)
	}
	got, _ := r.s.Get(t.Context(), g.URI)
	if p, _ := got.Participant(bob); p.Role != groupstore.Chairman {
		t.Fatalf("bob = %+v", p)
	}
	if err := r.s.Remove(t.Context(), g.URI, bob, carol); err != nil {
		t.Fatalf("the new chairman removes: %v", err)
	}
	// The last one out ends the group.
	if err := r.s.Leave(t.Context(), g.URI, bob); err != nil {
		t.Fatal(err)
	}
	if _, err := r.s.Get(t.Context(), g.URI); !errors.Is(err, ErrNoGroup) {
		t.Fatalf("Get of an ended group = %v", err)
	}
	if err := r.s.Leave(t.Context(), "sip:chat-none@"+host, bob); !errors.Is(err, ErrNoGroup) {
		t.Fatalf("Leave of no group = %v", err)
	}
}

// QA's reproduction (PR #118): the role goes to whoever has been joined
// longest, not to whoever comes first in the list. bob left and was added
// back into his old place; carol was there all along.
func TestTheChairmanPassesToTheLongestJoined(t *testing.T) {
	r := newRig(t, Config{})
	g := r.create(bob, carol)
	r.clock.Advance(time.Minute)
	if err := r.s.Leave(t.Context(), g.URI, bob); err != nil {
		t.Fatal(err)
	}
	r.clock.Advance(time.Minute)
	if err := r.s.Add(t.Context(), g.URI, alice, []Invitee{{Identity: bob}}); err != nil {
		t.Fatal(err)
	}
	r.clock.Advance(time.Minute)
	if _, err := r.s.Join(t.Context(), g.URI, bob, ""); err != nil {
		t.Fatal(err)
	}
	r.clock.Advance(time.Minute)
	if err := r.s.Leave(t.Context(), g.URI, alice); err != nil {
		t.Fatal(err)
	}
	got, _ := r.s.Get(t.Context(), g.URI)
	if p, _ := got.Participant(carol); p.Role != groupstore.Chairman {
		t.Fatalf("carol = %+v; bob = %+v", p, got.Participants[1])
	}
}

// A joined participant takes the role before an invitee who was added
// earlier, and among invitees the one invited first.
func TestAJoinedParticipantTakesTheChairBeforeAnEarlierInvitee(t *testing.T) {
	r := newRig(t, Config{})
	g, err := r.s.Create(t.Context(), CreateRequest{Creator: alice, Invitees: []Invitee{{Identity: bob}}})
	if err != nil {
		t.Fatal(err)
	}
	r.clock.Advance(time.Minute)
	if err := r.s.Add(t.Context(), g.URI, alice, []Invitee{{Identity: carol}, {Identity: dave}}); err != nil {
		t.Fatal(err)
	}
	r.clock.Advance(time.Minute)
	if _, err := r.s.Join(t.Context(), g.URI, dave, ""); err != nil {
		t.Fatal(err)
	}
	if err := r.s.Leave(t.Context(), g.URI, alice); err != nil {
		t.Fatal(err)
	}
	got, _ := r.s.Get(t.Context(), g.URI)
	if p, _ := got.Participant(dave); p.Role != groupstore.Chairman {
		t.Fatalf("dave = %+v", p)
	}
	// dave leaves too: bob, invited first, takes it over carol.
	if err := r.s.Leave(t.Context(), g.URI, dave); err != nil {
		t.Fatal(err)
	}
	got, _ = r.s.Get(t.Context(), g.URI)
	if p, _ := got.Participant(bob); p.Role != groupstore.Chairman {
		t.Fatalf("bob = %+v", p)
	}
}

func TestAnInviteeTakesTheChairWhenNobodyHasJoined(t *testing.T) {
	r := newRig(t, Config{})
	g, err := r.s.Create(t.Context(), CreateRequest{Creator: alice, Invitees: []Invitee{{Identity: bob}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.s.Leave(t.Context(), g.URI, alice); err != nil {
		t.Fatal(err)
	}
	got, _ := r.s.Get(t.Context(), g.URI)
	if p, _ := got.Participant(bob); p.Role != groupstore.Chairman || p.State != groupstore.Invited {
		t.Fatalf("bob = %+v", p)
	}
}

func TestOnlyCurrentParticipantsReadTheRoster(t *testing.T) {
	r := newRig(t, Config{})
	g := r.create(bob, carol)
	if err := r.s.Leave(t.Context(), g.URI, carol); err != nil {
		t.Fatal(err)
	}
	doc, version, err := r.s.Roster(t.Context(), g.URI, bob)
	if err != nil || version != 4 || roster(t, doc).Version != 4 {
		t.Fatalf("Roster = v%d, %v", version, err)
	}
	for _, who := range []string{carol, "sip:stranger@example.net"} {
		if _, _, err := r.s.Roster(t.Context(), g.URI, who); !errors.Is(err, ErrNotParticipant) {
			t.Errorf("%s: %v", who, err)
		}
	}
	if _, _, err := r.s.Roster(t.Context(), "sip:chat-none@"+host, bob); !errors.Is(err, ErrNoGroup) {
		t.Errorf("no group: %v", err)
	}
}

func TestNewChecksItsDependenciesAndBudget(t *testing.T) {
	r := newRig(t, Config{})
	if _, err := New(Config{ConferenceHost: host}, nil, r.e, r.n, r.m); err == nil {
		t.Error("New without a store")
	}
	if _, err := New(Config{}, groupstore.NewMemory(), r.e, r.n, r.m); err == nil {
		t.Error("New without a conference host")
	}
	if _, err := New(Config{ConferenceHost: host, MaxParticipants: 100, FanoutRate: messaging.Rate{PerMinute: 10, Burst: 50}},
		groupstore.NewMemory(), r.e, r.n, r.m); err == nil {
		t.Error("a fan-out burst smaller than a full group")
	}
	if _, err := New(Config{ConferenceHost: host, MaxParticipants: 100, FanoutRate: messaging.Rate{PerMinute: 6000, Burst: 3959}},
		groupstore.NewMemory(), r.e, r.n, r.m); err == nil {
		t.Error("a sender's quarter of the fan-out burst smaller than ten messages to a full group")
	}
	if _, err := New(Config{ConferenceHost: host, MaxParticipants: 100, AddRate: messaging.Rate{PerMinute: 30, Burst: 98}},
		groupstore.NewMemory(), r.e, r.n, r.m); err == nil {
		t.Error("an add burst smaller than a full group's invitees")
	}
	if _, err := New(Config{ConferenceHost: host, MaxParticipants: LimitParticipants + 1}, groupstore.NewMemory(), r.e, r.n, r.m); err == nil {
		t.Error("a size limit whose roster would not fit in one item")
	}
	// Exactly enough is enough, and an unlimited budget needs no burst.
	for _, c := range []Config{
		{MaxParticipants: 100, FanoutRate: messaging.Rate{PerMinute: 6000, Burst: 3960}, AddRate: messaging.Rate{PerMinute: 30, Burst: 99}},
		{MaxParticipants: 100, FanoutRate: messaging.Rate{PerMinute: -1}, AddRate: messaging.Rate{PerMinute: -1}},
		{MaxParticipants: LimitParticipants},
	} {
		c.ConferenceHost = host
		if _, err := New(c, groupstore.NewMemory(), r.e, r.n, r.m); err != nil {
			t.Errorf("%+v: %v", c, err)
		}
	}
	if got := DefaultAddBurst(LimitParticipants); got != LimitParticipants-1 {
		t.Errorf("DefaultAddBurst(%d) = %d", LimitParticipants, got)
	}
	for max, want := range map[int]int{2: DefaultFanoutRate.Burst, 100: 3960, 200: 7960} {
		if got := DefaultFanoutBurst(max); got != want {
			t.Errorf("DefaultFanoutBurst(%d) = %d, want %d", max, got, want)
		}
	}
}

// A new name is a roster change for every subscriber: renaming is
// rate-limited, and names are bounded.
func TestRenamingInAGroupIsBounded(t *testing.T) {
	r := newRig(t, Config{SenderRate: messaging.Rate{PerMinute: 1, Burst: 2}})
	g := r.create(bob)
	for i := range 2 {
		if _, err := r.s.Join(t.Context(), g.URI, bob, fmt.Sprint("Bob ", i)); err != nil {
			t.Fatalf("rename %d: %v", i, err)
		}
	}
	if _, err := r.s.Join(t.Context(), g.URI, bob, "Bob again"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("beyond the rate: %v", err)
	}
	// An overlong name is dropped, not refused: bob keeps the name he
	// had, carol is added without one.
	r.clock.Advance(time.Minute)
	if g, err := r.s.Join(t.Context(), g.URI, bob, strings.Repeat("n", MaxDisplayNameLength+1)); err != nil {
		t.Fatalf("an overlong name: %v", err)
	} else if p, _ := g.Participant(bob); p.DisplayName != "Bob 1" {
		t.Fatalf("bob %+v", p)
	}
	if err := r.s.Add(t.Context(), g.URI, bob, []Invitee{{Identity: carol, DisplayName: strings.Repeat("n", MaxDisplayNameLength+1)}}); err != nil {
		t.Fatalf("adding with an overlong name: %v", err)
	}
	if r.m.get("group.name_dropped") != 2 {
		t.Fatalf("metrics %v", r.m)
	}
}

// #305: a group created without a Conversation-ID gets a random UUID
// (version 4), the form OMA CPM Appendix C.1.1 asks for; one the client
// gives is kept, and a group stored with the 32 hex digits groups were
// given before is read and used as it is.
func TestAGroupsConversationIDIsAUUID(t *testing.T) {
	r := newRig(t, Config{})
	uuid4 := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	seen := map[string]bool{}
	for range 3 {
		g, err := r.s.Create(t.Context(), CreateRequest{Creator: alice, Invitees: []Invitee{{Identity: bob}}})
		if err != nil {
			t.Fatal(err)
		}
		if !uuid4.MatchString(g.Conversation) || seen[g.Conversation] {
			t.Fatalf("Conversation-ID %q", g.Conversation)
		}
		seen[g.Conversation] = true
	}
	given, err := r.s.Create(t.Context(), CreateRequest{Creator: alice, Invitees: []Invitee{{Identity: bob}}, Conversation: "given-1"})
	if err != nil || given.Conversation != "given-1" {
		t.Fatalf("given %q, %v", given.Conversation, err)
	}
	old := r.create(bob)
	old.Conversation = "0123456789abcdef0123456789abcdef"
	if err := r.groups.Update(t.Context(), old, "old"); err != nil {
		t.Fatal(err)
	}
	if g, err := r.s.Get(t.Context(), old.URI); err != nil || g.Conversation != old.Conversation {
		t.Fatalf("the old group %+v, %v", g, err)
	}
	if _, err := r.s.Recipients(t.Context(), old.URI, alice, messaging.GroupText); err != nil {
		t.Fatalf("writing in the old group: %v", err)
	}
}
