package group

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/conference"
	"github.com/jeonghun-app/rcs-platform/internal/ims/identity"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/groupstore"
)

// longest is the i-th identity of the longest length the group stores.
func longest(i int) string {
	suffix := fmt.Sprintf("@%d.example.net", i)
	return "sip:" + strings.Repeat("x", identity.MaxLength-len("sip:")-len(suffix)) + suffix
}

// widest is the i-th display name that is longest once XML-escaped.
func widest(i int) string {
	n := fmt.Sprint(i)
	return strings.Repeat("&", MaxDisplayNameLength-len(n)) + n
}

// The largest group a configuration allows, every name and identity at
// its longest and as many former participants as it keeps, has a roster
// within conference.MaxDocumentSize that internal/conference reads back,
// in full and in every partial document on the way; and the last ones can
// still leave.
func TestTheLargestRosterFitsTheDocumentLimit(t *testing.T) {
	for _, size := range []int{DefaultMaxParticipants, LimitParticipants} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			r := newRig(t, Config{MaxParticipants: size, AddRate: rateOff, SenderRate: rateOff})
			chair := longest(0)
			var in []Invitee
			for i := 1; i < size; i++ {
				in = append(in, Invitee{Identity: longest(i), DisplayName: widest(i)})
			}
			g, err := r.s.Create(t.Context(), CreateRequest{Creator: chair, CreatorName: widest(0), Invitees: in,
				Subject: strings.Repeat("&", MaxSubjectLength)})
			if err != nil {
				t.Fatal(err)
			}
			// Remove one and add another, until the roster holds as many
			// former participants as it keeps, and a few beyond.
			next := size
			for i := range r.s.maxFormer + 3 {
				if err := r.s.Remove(t.Context(), g.URI, chair, longest(1+i)); err != nil {
					t.Fatalf("removal %d: %v", i, err)
				}
				if err := r.s.Add(t.Context(), g.URI, chair, []Invitee{{Identity: longest(next), DisplayName: widest(next)}}); err != nil {
					t.Fatalf("addition %d: %v", i, err)
				}
				next++
			}
			got, err := r.s.Get(t.Context(), g.URI)
			if err != nil || activeCount(&got) != size || len(got.Participants) != size+r.s.maxFormer {
				t.Fatalf("%d entries, %d current, %v", len(got.Participants), activeCount(&got), err)
			}
			doc, _, err := r.s.Roster(t.Context(), g.URI, chair)
			if err != nil {
				t.Fatal(err)
			}
			bound, err := rosterBound(host, size+r.s.maxFormer)
			if err != nil || len(doc) > bound || bound > conference.MaxDocumentSize {
				t.Fatalf("roster %d bytes, bound %d (%v), limit %d", len(doc), bound, err, conference.MaxDocumentSize)
			}
			// The last ones can leave, the chairman too.
			for _, who := range []string{longest(next - 1), chair} {
				if err := r.s.Leave(t.Context(), g.URI, who); err != nil {
					t.Fatalf("Leave: %v", err)
				}
			}
			for i, u := range r.n.all() {
				if len(u.Document) > conference.MaxDocumentSize {
					t.Fatalf("update %d: %d bytes", i, len(u.Document))
				}
				if _, err := conference.Parse(u.Document); err != nil {
					t.Fatalf("update %d of %d bytes: %v", i, len(u.Document), err)
				}
			}
			if _, err := conference.Parse(doc); err != nil || !bytes.Contains(doc, []byte("&amp;&amp;")) {
				t.Fatalf("the full roster: %v", err)
			}
		})
	}
}

// A size limit is accepted only if its largest roster fits; the former
// participants a group keeps give way first.
func TestTheSizeLimitIsCheckedAgainstTheLargestRoster(t *testing.T) {
	for max, want := range map[int]int{2: 2, DefaultMaxParticipants: DefaultMaxParticipants} {
		if got, err := formerLimit(host, max); err != nil || got != want {
			t.Errorf("formerLimit(%d) = %d, %v, want %d", max, got, err, want)
		}
	}
	if got, err := formerLimit(host, LimitParticipants); err != nil || got <= 0 || got >= LimitParticipants {
		t.Errorf("formerLimit(%d) = %d, %v", LimitParticipants, got, err)
	}
	if _, err := formerLimit(host, 2*LimitParticipants); err == nil {
		t.Error("a size limit whose current participants alone overflow the roster")
	}
	b, err := rosterBound(host, groupstore.MaxEntries)
	if err != nil || b <= conference.MaxDocumentSize {
		t.Fatalf("the bound of %d entries = %d, %v", groupstore.MaxEntries, b, err)
	}
}

// The security review's reproduction (PR #118, round 2): one Add of 98
// identities and names at their longest, in characters XML escapes, made
// a 376 KB roster that internal/conference refused to read. Such
// identities are refused now; the names alone fit.
func TestOneAddOfTheLongestValuesKeepsTheRosterReadable(t *testing.T) {
	r := newRig(t, Config{})
	g := r.create(bob)
	var amp, ok []Invitee
	for i := range DefaultMaxParticipants - 2 {
		user := strings.Repeat("&", 255-len("sip:")-len("@example.net")-6) + fmt.Sprintf("u%05d", i)
		amp = append(amp, Invitee{Identity: "sip:" + user + "@example.net", DisplayName: widest(i)})
		ok = append(ok, Invitee{Identity: longest(i), DisplayName: widest(i)})
	}
	if err := r.s.Add(t.Context(), g.URI, bob, amp); err == nil {
		t.Fatal("identities that XML escapes were added")
	}
	if err := r.s.Add(t.Context(), g.URI, bob, ok); err != nil {
		t.Fatal(err)
	}
	doc, _, err := r.s.Roster(t.Context(), g.URI, alice)
	if err != nil {
		t.Fatal(err)
	}
	ups := r.n.all()
	for _, d := range [][]byte{doc, ups[len(ups)-1].Document} {
		if _, err := conference.Parse(d); err != nil {
			t.Fatalf("%d-byte document: %v", len(d), err)
		}
	}
}

// QA's reproduction (PR #118, round 3): with 200 members a roster keeps 9
// former participants, so once 9 others left, a removed participant was
// forgotten and any participant could add them back. Those who left are
// forgotten first, and a removed one forgotten by the roster is still
// known as removed.
func TestAForgottenRemovedParticipantStaysRemoved(t *testing.T) {
	r := newRig(t, Config{MaxParticipants: LimitParticipants})
	var in []Invitee
	var ids []string
	for i := range 30 {
		ids = append(ids, fmt.Sprintf("sip:u%d@example.net", i))
		in = append(in, Invitee{Identity: ids[i]})
	}
	g, err := r.s.Create(t.Context(), CreateRequest{Creator: alice, Invitees: in})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if _, err := r.s.Join(t.Context(), g.URI, id, ""); err != nil {
			t.Fatal(err)
		}
	}
	mallory := ids[0]
	if err := r.s.Remove(t.Context(), g.URI, alice, mallory); err != nil {
		t.Fatal(err)
	}
	for _, id := range ids[2:12] {
		r.clock.Advance(time.Second)
		if err := r.s.Leave(t.Context(), g.URI, id); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := r.s.Get(t.Context(), g.URI)
	if p, ok := got.Participant(mallory); !ok || p.State != groupstore.Removed {
		t.Fatalf("mallory left the roster before those who left after her: %+v", got.Participants)
	}
	if err := r.s.Add(t.Context(), g.URI, ids[1], []Invitee{{Identity: mallory}}); !errors.Is(err, ErrNotChairman) {
		t.Fatalf("a participant added the removed mallory back: %v", err)
	}
	// Remove more than the roster keeps: the removed are dropped from the
	// roster, and known as removed all the same.
	for _, id := range ids[12:25] {
		r.clock.Advance(time.Second)
		if err := r.s.Remove(t.Context(), g.URI, alice, id); err != nil {
			t.Fatal(err)
		}
	}
	got, _ = r.s.Get(t.Context(), g.URI)
	if _, ok := got.Participant(mallory); ok || !slices.Contains(got.Removed, mallory) {
		t.Fatalf("roster %d entries, removed %v", len(got.Participants), got.Removed)
	}
	for _, id := range []string{mallory, ids[12]} {
		if err := r.s.Add(t.Context(), g.URI, ids[1], []Invitee{{Identity: id}}); !errors.Is(err, ErrNotChairman) {
			t.Fatalf("a participant added the removed %s back: %v", id, err)
		}
		if ok, _ := r.s.Member(t.Context(), g.URI, id); ok {
			t.Fatalf("%s is a member", id)
		}
	}
	// The chairman can, and then they are no longer listed as removed.
	if err := r.s.Add(t.Context(), g.URI, alice, []Invitee{{Identity: mallory}}); err != nil {
		t.Fatal(err)
	}
	got, _ = r.s.Get(t.Context(), g.URI)
	if slices.Contains(got.Removed, mallory) {
		t.Fatalf("removed %v", got.Removed)
	}
	if _, err := r.s.Join(t.Context(), g.URI, mallory, ""); err != nil {
		t.Fatal(err)
	}
}

// The removed identities are bounded too: beyond groupstore.MaxRemoved,
// the one removed longest ago is forgotten.
func TestTheRemovedAGroupRemembersAreBounded(t *testing.T) {
	s := &Service{maxFormer: 0}
	g := groupstore.Group{}
	for i := range groupstore.MaxRemoved + 5 {
		g.Participants = append(g.Participants, groupstore.Participant{Identity: fmt.Sprint("sip:r", i, "@example.net"),
			State: groupstore.Removed, Since: time.Unix(int64(i), 0)})
		s.forget(&g)
	}
	if len(g.Removed) != groupstore.MaxRemoved || g.Removed[0] != "sip:r5@example.net" || len(g.Participants) != 0 {
		t.Fatalf("%d removed, first %s, %d entries", len(g.Removed), g.Removed[0], len(g.Participants))
	}
}
