package group

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/groupstore"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
)

// Values internal/conference could not write, or that no identity is.
var (
	badIdentities = map[string]string{
		"no scheme":        "bob",
		"not SIP or tel":   "mailto:bob@example.net",
		"no user":          "sip:example.net",
		"a space":          "sip:bob @example.net",
		"angle brackets":   "<sip:bob@example.net>",
		"URI headers":      "sip:bob@example.net?Subject=x",
		"a local number":   "tel:5550100",
		"a control":        "sip:bob\x01@example.net",
		"invalid UTF-8":    "sip:\xff@example.net",
		"an empty one":     "",
		"a password":       "sip:bob:secret@example.net",
		"a CRLF in a user": "sip:bob\r\nX: y@example.net",
		"an ampersand":     "sip:b&b@example.net",
		"an apostrophe":    "sip:o'b@example.net",
	}
	badNames = map[string]string{
		"a NUL":         "a\x00b",
		"a line break":  "Bob\r\nX-Evil: 1",
		"a tab":         "Bob\tB",
		"a C1 control":  "Bob\u0085",
		"a nonchar":     "Bob\ufffe",
		"invalid UTF-8": "Bob\xff",
		"DEL":           "Bob\x7f",
	}
)

// A request with a value the roster could not be written with is refused
// before anything is stored, so it cannot make the roster unreadable for
// everyone else.
func TestABadValueNeverBreaksTheRoster(t *testing.T) {
	r := newRig(t, Config{})
	g := r.create(bob)
	if err := r.s.Add(t.Context(), g.URI, alice, []Invitee{{Identity: carol}}); err != nil {
		t.Fatal(err)
	}
	check := func(what string, err error) {
		t.Helper()
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", what, err)
		}
		doc, _, err := r.s.Roster(t.Context(), g.URI, alice)
		if err != nil {
			t.Fatalf("after %s, Roster = %v", what, err)
		}
		roster(t, doc)
	}
	for name, id := range badIdentities {
		check("adding "+name, r.s.Add(t.Context(), g.URI, bob, []Invitee{{Identity: id}}))
		_, err := r.s.Create(t.Context(), CreateRequest{Creator: alice, Invitees: []Invitee{{Identity: id}}})
		check("creating with "+name, err)
		_, err = r.s.Create(t.Context(), CreateRequest{Creator: id, Invitees: []Invitee{{Identity: bob}}})
		check("a creator with "+name, err)
	}
	// A bad name, or subject, is never stored either. A subject is the
	// creator's to fix; a name is dropped and its owner comes in without
	// one, under its identity alone.
	for name, n := range badNames {
		_, err := r.s.Create(t.Context(), CreateRequest{Creator: alice, Subject: n, Invitees: []Invitee{{Identity: bob}}})
		check("a subject with "+name, err)
	}
	var names []string
	for _, n := range badNames {
		names = append(names, n)
	}
	if _, err := r.s.Join(t.Context(), g.URI, carol, names[0]); err != nil {
		t.Fatalf("carol joining with a bad name: %v", err)
	}
	for i, n := range names {
		who := fmt.Sprintf("sip:u%d@example.net", i)
		if err := r.s.Add(t.Context(), g.URI, bob, []Invitee{{Identity: who, DisplayName: n}}); err != nil {
			t.Fatalf("adding with a bad name: %v", err)
		}
		c, err := r.s.Create(t.Context(), CreateRequest{Creator: who, CreatorName: n, Invitees: []Invitee{{Identity: bob, DisplayName: n}}})
		if err != nil {
			t.Fatalf("creating with a bad name: %v", err)
		}
		for _, p := range c.Participants {
			if p.DisplayName != "" {
				t.Fatalf("a bad name was stored: %+v", p)
			}
		}
	}
	got, _ := r.s.Get(t.Context(), g.URI)
	for _, p := range got.Participants {
		if p.DisplayName != "" && p.Identity != alice {
			t.Fatalf("a bad name was stored: %+v", p)
		}
	}
	doc, _, err := r.s.Roster(t.Context(), g.URI, alice)
	if err != nil {
		t.Fatal(err)
	}
	roster(t, doc)
	// carol renames herself as she asks.
	if _, err := r.s.Join(t.Context(), g.URI, carol, "Carol Ünïcode 😀"); err != nil {
		t.Fatal(err)
	}
	if n := r.m.get("group.name_dropped"); n != int64(1+3*len(names)) {
		t.Fatalf("%d names dropped; metrics %v", n, r.m)
	}
}

// Identities are compared in canonical form, so one person added in
// another spelling is the same participant.
func TestIdentitiesAreComparedInCanonicalForm(t *testing.T) {
	r := newRig(t, Config{})
	g, err := r.s.Create(t.Context(), CreateRequest{Creator: alice, Invitees: []Invitee{
		{Identity: "sip:Bob@EXAMPLE.net;user=phone"}, {Identity: "sip:Bob@example.NET"}, {Identity: "tel:+1-555-010-0003"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Participants) != 3 {
		t.Fatalf("participants %+v", g.Participants)
	}
	if _, ok := g.Participant("sip:Bob@example.net"); !ok {
		t.Fatalf("participants %+v", g.Participants)
	}
	if _, err := r.s.Join(t.Context(), g.URI, "sip:Bob@example.net", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := r.s.Join(t.Context(), g.URI, carol, ""); err != nil {
		t.Fatalf("carol, added as a number with separators: %v", err)
	}
	if err := r.s.Add(t.Context(), g.URI, "SIP:Bob@Example.Net", []Invitee{{Identity: "tel:+1.555.010.0004"}}); err != nil {
		t.Fatal(err)
	}
	if ok, err := r.s.Member(t.Context(), g.URI, dave); err != nil || !ok {
		t.Fatalf("dave = %v, %v", ok, err)
	}
	// A creator who invites itself in another spelling is not invited.
	if _, err := r.s.Create(t.Context(), CreateRequest{Creator: alice, Invitees: []Invitee{{Identity: "tel:+1-555-010-0001"}}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a group of alice alone: %v", err)
	}
	for _, f := range []func() error{
		func() error { return r.s.Leave(t.Context(), g.URI, "bob") },
		func() error { return r.s.Remove(t.Context(), g.URI, alice, "bob") },
		func() error { return r.s.Remove(t.Context(), g.URI, "alice", bob) },
		func() error { return r.s.Add(t.Context(), g.URI, "alice", []Invitee{{Identity: erin}}) },
		func() error { _, _, err := r.s.Roster(t.Context(), g.URI, "alice"); return err },
		func() error { _, err := r.s.Join(t.Context(), g.URI, "carol", ""); return err },
	} {
		if err := f(); !errors.Is(err, ErrInvalid) {
			t.Errorf("an identity that is no URI: %v", err)
		}
	}
	if ok, err := r.s.Member(t.Context(), g.URI, "bob"); err != nil || ok {
		t.Fatalf("Member(bob) = %v, %v", ok, err)
	}
	if _, err := r.s.Recipients(t.Context(), g.URI, "bob", 1); err == nil {
		t.Fatal("a sender that is no URI wrote")
	}
}

// A subscriber's SIP URI at the home domain and its tel URI are one
// participant, as they are one user to the SIP layer and the engine
// (messaging.UserOf): bob added by his SIP URI joins by his tel URI, and a
// leg opened under his SIP URI gets the copies queued for him (#137, the
// lead's decision on #242).
func TestASubscribersSIPAndTelURIsAreOneParticipant(t *testing.T) {
	const home = "ims.example.net"
	ecfg := engineConfig()
	ecfg.HomeDomain = home
	r := newRigWith(t, Config{HomeDomain: home}, ecfg, store.NewMemory(), groupstore.NewMemory(), newFakeClock(), 1)
	bobSIP := "sip:+15550100002@IMS.example.net;transport=tcp"
	g, err := r.s.Create(t.Context(), CreateRequest{Creator: "sip:+15550100001@" + home, Invitees: []Invitee{{Identity: bobSIP}, {Identity: bob}, {Identity: carol}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Participants) != 3 || g.Creator != alice {
		t.Fatalf("creator %q, participants %+v", g.Creator, g.Participants)
	}
	if _, ok := g.Participant(bob); !ok {
		t.Fatalf("participants %+v", g.Participants)
	}
	if _, err := r.s.Join(t.Context(), g.URI, bob, ""); err != nil {
		t.Fatal(err)
	}
	a := r.connect(g, "sip:+15550100001@"+home, nil)
	b := r.connect(g, bobSIP, nil)
	if code := a.send(t, message(t, alice, "m1", "hello", 0)); code != msrp.StatusOK {
		t.Fatalf("alice's message answered %d", code)
	}
	// The author is named as the group names alice, whichever URI her
	// session asserted.
	got := asSeen(t, b.next(t))
	if from, _ := fromTo(t, got); from.URI != alice || string(got.Body) != "hello" {
		t.Fatalf("bob got From %v: %q", from, got.Body)
	}
	// Someone else's number at another host is no form of bob's.
	if ok, err := r.s.Member(t.Context(), g.URI, "sip:+15550100002@other.example.net"); err != nil || ok {
		t.Fatalf("bob's number at another host = %v, %v", ok, err)
	}
}

// The documents are built before the write: a stored group that could not
// be written as one (here, written by something else with a participant
// twice) is not changed further, and nothing is notified.
func TestAGroupIsNotWrittenUnlessItsRosterCanBe(t *testing.T) {
	r := newRig(t, Config{})
	g := r.create(bob)
	stored, err := r.groups.Get(t.Context(), g.URI, r.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	stored.Participants = append(stored.Participants, stored.Participants[1])
	if err := r.groups.Update(t.Context(), stored, r.owner(t, g.URI), "corrupt"); err != nil {
		t.Fatal(err)
	}
	before := len(r.n.all())
	if err := r.s.Add(t.Context(), g.URI, alice, []Invitee{{Identity: carol}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Add = %v", err)
	}
	after, err := r.groups.Get(t.Context(), g.URI, r.clock.Now())
	if err != nil || after.Rev != stored.Rev+1 || len(r.n.all()) != before {
		t.Fatalf("rev %d, want %d; %d updates", after.Rev, stored.Rev+1, len(r.n.all())-before)
	}
	if _, ok := after.Participant(carol); ok {
		t.Fatal("carol was stored")
	}
	if r.m.get("group.rejected.invalid") != 1 {
		t.Fatalf("metrics %v", r.m)
	}
}

// Decision for #118 (round 4), from the code review's and QA's
// reproductions: a name is never a reason to keep someone out. A name that
// someone else in the roster, current or former, goes by (compared as
// nameKey does), or that is too long, is dropped: its owner joins under its
// identity alone, so that nobody passes for anyone else and everyone gets
// in.
func TestANameSomeoneElseGoesByIsDroppedNotRefused(t *testing.T) {
	r := newRig(t, Config{SenderRate: rateOff})
	g, err := r.s.Create(t.Context(), CreateRequest{Creator: alice, CreatorName: "Mom", Invitees: []Invitee{
		{Identity: bob}, {Identity: carol}, {Identity: dave, DisplayName: "Dave"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.s.Leave(t.Context(), g.URI, dave); err != nil {
		t.Fatal(err)
	}
	nameOf := func(who string) string {
		t.Helper()
		got, err := r.s.Get(t.Context(), g.URI)
		if err != nil {
			t.Fatal(err)
		}
		p, _ := got.Participant(who)
		return p.DisplayName
	}
	// Two people called Kim: the first is Kim, the second nameless.
	for _, who := range []string{bob, carol} {
		if err := joinErr(r, g, who, "Kim"); err != nil {
			t.Fatalf("%s joining as Kim: %v", who, err)
		}
	}
	if nameOf(bob) != "Kim" || nameOf(carol) != "" {
		t.Fatalf("bob %q, carol %q", nameOf(bob), nameOf(carol))
	}
	// QA's: bob may join as Mom, the creator's name, and does, nameless.
	r2 := newRig(t, Config{})
	g2, err := r2.s.Create(t.Context(), CreateRequest{Creator: alice, CreatorName: "Mom", Invitees: []Invitee{{Identity: bob}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := joinErr(r2, g2, bob, "Mom"); err != nil {
		t.Fatalf("bob cannot join: %v", err)
	}
	// Spellings a reader could not tell apart are the same name.
	for i, n := range []string{"  KIM ", "K\u200bim", "\u202aKim\u202c", "K\u2060im", "K\u00adim", "Ki\u180em", "K\u034fim",
		"Kim\ufe0f", "Kim\U000e0061", "Kim\u3164", "Kim\uffa0", "dave"} {
		who := fmt.Sprintf("sip:k%d@example.net", i)
		if err := r.s.Add(t.Context(), g.URI, alice, []Invitee{{Identity: who, DisplayName: n}}); err != nil {
			t.Fatalf("adding %q: %v", n, err)
		}
		if got := nameOf(who); got != "" {
			t.Errorf("%q was stored as %q beside Kim and dave", n, got)
		}
	}
	// A group of two invited Kims is made, the second nameless; so is one
	// added with a name someone in the list already has.
	g3, err := r.s.Create(t.Context(), CreateRequest{Creator: erin, Invitees: []Invitee{
		{Identity: bob, DisplayName: "Kim"}, {Identity: carol, DisplayName: "kim"},
	}})
	if err != nil {
		t.Fatalf("a group of two Kims: %v", err)
	}
	if p, _ := g3.Participant(bob); p.DisplayName != "Kim" {
		t.Fatalf("bob %+v", p)
	}
	if p, _ := g3.Participant(carol); p.DisplayName != "" {
		t.Fatalf("carol %+v", p)
	}
	// A 35-character Hangul name (105 bytes) is too long: its owner joins
	// nameless.
	long := strings.Repeat("김", 35)
	if err := r.s.Add(t.Context(), g.URI, alice, []Invitee{{Identity: "sip:long@example.net"}}); err != nil {
		t.Fatal(err)
	}
	if err := joinErr(r, g, "sip:long@example.net", long); err != nil || nameOf("sip:long@example.net") != "" {
		t.Fatalf("a long name: %v, stored %q", err, nameOf("sip:long@example.net"))
	}
	// A rename to someone else's name, or to one too long, leaves the old
	// name, and costs none of the renaming allowance.
	r4 := newRig(t, Config{SenderRate: messaging.Rate{PerMinute: 1, Burst: 1}})
	g4, err := r4.s.Create(t.Context(), CreateRequest{Creator: alice, CreatorName: "Alice", Invitees: []Invitee{
		{Identity: bob}, {Identity: carol, DisplayName: "Carol"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := joinErr(r4, g4, bob, "Bob"); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"alice", strings.Repeat("b", MaxDisplayNameLength+1), "ALICE "} {
		if err := joinErr(r4, g4, bob, n); err != nil {
			t.Fatalf("bob renaming to %q: %v", n, err)
		}
	}
	if err := joinErr(r4, g4, carol, "Alice"); err != nil {
		t.Fatalf("carol joining as Alice: %v", err)
	}
	got4, _ := r4.s.Get(t.Context(), g4.URI)
	if p, _ := got4.Participant(bob); p.DisplayName != "Bob" {
		t.Fatalf("bob %+v", p)
	}
	if p, _ := got4.Participant(carol); p.DisplayName != "Carol" || p.State != groupstore.Joined {
		t.Fatalf("carol %+v", p)
	}
	if err := joinErr(r4, g4, bob, "Robert"); err != nil {
		t.Fatalf("bob's one real rename: %v", err)
	}
	// One's own name, a new one, and others are fine.
	for _, c := range []struct{ who, name string }{{bob, "Kim"}, {bob, "kim "}, {carol, "Carol"}, {bob, "Kimberly"}} {
		if err := joinErr(r, g, c.who, c.name); err != nil || nameOf(c.who) != c.name {
			t.Errorf("%s as %q: %v, stored %q", c.who, c.name, err, nameOf(c.who))
		}
	}
	if r.m.get("group.name_dropped") == 0 || r.m.get("group.rejected.invalid") != 0 {
		t.Fatalf("metrics %v", r.m)
	}
}

func joinErr(r *rig, g groupstore.Group, who, name string) error {
	_, err := r.s.Join(r.t.Context(), g.URI, who, name)
	return err
}
