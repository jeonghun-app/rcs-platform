package group

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

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
