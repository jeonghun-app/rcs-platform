package group

import (
	"errors"
	"testing"
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
	for name, n := range badNames {
		_, err := r.s.Join(t.Context(), g.URI, carol, n)
		check("joining with "+name, err)
		check("adding with "+name, r.s.Add(t.Context(), g.URI, bob, []Invitee{{Identity: dave, DisplayName: n}}))
		_, err = r.s.Create(t.Context(), CreateRequest{Creator: alice, Subject: n, Invitees: []Invitee{{Identity: bob}}})
		check("a subject with "+name, err)
		_, err = r.s.Create(t.Context(), CreateRequest{Creator: alice, CreatorName: n, Invitees: []Invitee{{Identity: bob}}})
		check("a creator's name with "+name, err)
	}
	if got, _ := r.s.Get(t.Context(), g.URI); got.Version != g.Version+1 {
		t.Fatalf("version %d: a refused request changed the group", got.Version)
	}
	// carol can still join, and is named as she asks.
	if _, err := r.s.Join(t.Context(), g.URI, carol, "Carol Ünïcode 😀"); err != nil {
		t.Fatal(err)
	}
	if r.m.get("group.created") != 1 {
		t.Fatalf("metrics %v", r.m)
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
	if err := r.groups.Update(t.Context(), stored, "corrupt"); err != nil {
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
