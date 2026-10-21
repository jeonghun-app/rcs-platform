package sipas

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// convHeaders reads the three conversation headers of a request rcs-as sent.
func convHeaders(req *sip.Request) [3]string {
	h := &req.Header
	return [3]string{h.Get("Conversation-ID"), h.Get("Contribution-ID"), h.Get("InReplyTo-Contribution-ID")}
}

// convHeadersPresent reports which of the three headers are present at all.
func convHeadersPresent(req *sip.Request) [3]bool {
	h := &req.Header
	return [3]bool{h.Has("Conversation-ID"), h.Has("Contribution-ID"), h.Has("InReplyTo-Contribution-ID")}
}

// QA on #302: pager MESSAGEs through the real engine are delivered with the
// conversation headers they came with, and, for one with a Contribution-ID
// and no Conversation-ID, the pair's (messaging.PairConversationID), which
// a sender must include (OMA CPM Appendix C.1.1).
func TestPagerConversationHeadersThroughTheEngine(t *testing.T) {
	core := newFakeCore(t)
	a, _ := startEngine(t, core, messaging.Config{})
	p := a.dial(t)
	const cid = "0123456789abcdef0123456789abcdef" // rcsjta-like hex id
	pair := messaging.PairConversationID(alice, bob)
	for i, c := range []struct {
		name   string
		fields []string
		code   int
		want   [3]string
	}{
		{"rcsjta pager, neither header", nil, 202, [3]string{}},
		{"contribution only", []string{"Contribution-ID: " + cid}, 202, [3]string{pair, cid, ""}},
		{"reply, no conversation", []string{"Contribution-ID: c2", "InReplyTo-Contribution-ID: " + cid}, 202, [3]string{pair, "c2", cid}},
		{"same contribution again", []string{"Contribution-ID: " + cid}, 202, [3]string{pair, cid, ""}},
		{"both", []string{"Conversation-ID: conv1", "Contribution-ID: c3"}, 202, [3]string{"conv1", "c3", ""}},
		{"all three", []string{"Conversation-ID: conv1", "Contribution-ID: c4", "InReplyTo-Contribution-ID: c3"}, 202, [3]string{"conv1", "c4", "c3"}},
		{"blank conversation + contribution", []string{"Conversation-ID:   ", "Contribution-ID: c5"}, 202, [3]string{pair, "c5", ""}},
		{"lower-case names", []string{"contribution-id: c6", "conversation-id: conv6"}, 202, [3]string{"conv6", "c6", ""}},
		{"conversation only", []string{"Conversation-ID: conv1"}, 400, [3]string{}},
		{"reply only", []string{"InReplyTo-Contribution-ID: c1"}, 400, [3]string{}},
		{"conversation + reply", []string{"Conversation-ID: conv1", "InReplyTo-Contribution-ID: c1"}, 400, [3]string{}},
		{"bad conversation + good contribution", []string{"Conversation-ID: <x>", "Contribution-ID: c7"}, 400, [3]string{}},
		{"contribution with CRLF smuggle", []string{"Contribution-ID: c8;x=y"}, 400, [3]string{}},
		{"overlong contribution", []string{"Contribution-ID: " + strings.Repeat("a", messaging.MaxIDLength+1)}, 400, [3]string{}},
		{"max-length contribution", []string{"Contribution-ID: " + strings.Repeat("a", messaging.MaxIDLength)}, 202, [3]string{pair, strings.Repeat("a", messaging.MaxIDLength), ""}},
	} {
		m := pager(cpimBody(fmt.Sprint("q", i), "hi"))
		m.fields = append(m.fields, c.fields...)
		res := p.send(m)
		if res.StatusCode != c.code {
			t.Errorf("%s: answered %d, want %d", c.name, res.StatusCode, c.code)
			continue
		}
		if c.code != 202 {
			continue
		}
		req := core.nextOf(t, "MESSAGE")
		if got := convHeaders(req); got != c.want {
			t.Errorf("%s: delivered with %q, want %q", c.name, got, c.want)
		}
		has := convHeadersPresent(req)
		for k := range 3 {
			if has[k] != (c.want[k] != "") {
				t.Errorf("%s: header %d present=%v with want %q", c.name, k, has[k], c.want[k])
			}
		}
	}
	// No stray deliveries for the refused ones.
	select {
	case req := <-core.got:
		t.Fatalf("extra delivery %s %q", req.Method, convHeaders(req))
	default:
	}
}

// QA on #302: bob's receipt for a contribution-only message finds it, and
// the notification to alice, which came without conversation headers,
// carries none.
func TestAReceiptForAContributionOnlyMessage(t *testing.T) {
	core := newFakeCore(t)
	a, _ := startEngine(t, core, messaging.Config{})
	p := a.dial(t)
	m := pagerAs(bob, cpimFrom("<"+messaging.AnonymousURI+">", "m1", imdn.PositiveDelivery, "hi"), "<"+alice+">")
	m.fields = append(m.fields, "Contribution-ID: c0ntr1")
	if res := p.send(m); res.StatusCode != 202 {
		t.Fatalf("alice's message answered %d", res.StatusCode)
	}
	if got := convHeaders(core.nextOf(t, "MESSAGE")); got != [3]string{messaging.PairConversationID(alice, bob), "c0ntr1", ""} {
		t.Fatalf("delivered %q", got)
	}
	if res := p.send(pagerAs(alice, deliveredBody(t, "m1"), "<"+bob+">")); res.StatusCode != 202 {
		t.Fatalf("bob's receipt answered %d", res.StatusCode)
	}
	n := core.nextOf(t, "MESSAGE")
	if n.Header.Has("Conversation-ID") {
		t.Fatalf("notification made up a Conversation-ID %q", n.Header.Get("Conversation-ID"))
	}
}

// QA on #302: chat INVITEs in each header shape: what is refused is
// refused, and what is taken reaches bob's INVITE (and the stored message)
// with its own headers, the pair's Conversation-ID filling in a missing one.
func TestChatInviteConversationShapes(t *testing.T) {
	pair := messaging.PairConversationID(alice, bob)
	for name, c := range map[string]struct {
		fields []string
		first  bool
		code   int
		want   [3]string
	}{
		"rcsjta: contribution only":                 {fields: []string{"Contribution-ID: c0ntr1"}, code: 200, want: [3]string{pair, "c0ntr1", ""}},
		"rcsjta: contribution only + first message": {fields: []string{"Contribution-ID: c0ntr1"}, first: true, code: 200, want: [3]string{pair, "c0ntr1", ""}},
		"neither":                       {code: 200},
		"both":                          {fields: []string{"Conversation-ID: c0nv1", "Contribution-ID: c0ntr1"}, code: 200, want: [3]string{"c0nv1", "c0ntr1", ""}},
		"contribution + reply":          {fields: []string{"Contribution-ID: c0ntr2", "InReplyTo-Contribution-ID: c0ntr1"}, code: 200, want: [3]string{pair, "c0ntr2", "c0ntr1"}},
		"conversation only":             {fields: []string{"Conversation-ID: c0nv1"}, code: 400},
		"conversation only + first msg": {fields: []string{"Conversation-ID: c0nv1"}, first: true, code: 400},
		"reply only":                    {fields: []string{"InReplyTo-Contribution-ID: c0ntr1"}, code: 400},
	} {
		t.Run(name, func(t *testing.T) {
			r := newChatRig(t, messaging.Config{})
			toBob := relayPath()
			r.core.setReply(func(req *sip.Request) []*sip.Response {
				if req.Method == "INVITE" {
					return []*sip.Response{r.answerInvite(t, req, toBob, "active")}
				}
				res, _ := sip.NewResponse(req, 200, "", "core1")
				return []*sip.Response{res}
			})
			p := r.a.dial(t)
			fromAlice := relayPath()
			var m msg
			if c.first {
				body := firstMessageBody([2]string{sdpType, offerSDP(fromAlice, "active")}, [2]string{cpim.ContentType, chatCPIM("first1", "hello in the INVITE")})
				m = r.withFirstMessage(body)
			} else {
				m = r.chatInvite(offerSDP(fromAlice, "active"))
			}
			m.fields = slices.DeleteFunc(m.fields, func(f string) bool {
				return f == "Conversation-ID: c0nv1" || f == "Contribution-ID: c0ntr1"
			})
			m.fields = append(m.fields, c.fields...)
			res := p.send(m)
			if res.StatusCode != c.code {
				t.Fatalf("answered %d, want %d (fields %q)", res.StatusCode, c.code, m.fields)
			}
			if c.code != 200 {
				select {
				case req := <-r.core.got:
					t.Fatalf("core got %s after a refusal", req.Method)
				default:
				}
				return
			}
			s := answeredBy(t, res)
			p.ack(s)
			relayA := r.connect(t, fromAlice, s.path)
			if !c.first {
				if code := relayA.send(t, chatCPIM("m1", "hi bob")); code != 200 {
					t.Fatalf("alice's message reported %d", code)
				}
			}
			inv := r.core.nextOf(t, "INVITE")
			if got := convHeaders(inv); got != c.want {
				t.Fatalf("bob's INVITE carries %q, want %q", got, c.want)
			}
			has := convHeadersPresent(inv)
			for k := range 3 {
				if has[k] != (c.want[k] != "") {
					t.Errorf("header %d present=%v with want %q", k, has[k], c.want[k])
				}
			}
			toLeg, _ := offered(t, inv)
			relayB := r.connect(t, toBob, toLeg)
			if got := relayB.next(t); got == nil {
				t.Fatal("bob got nothing")
			}
			// A follow-up on alice's session goes on bob's session, no new INVITE.
			if code := relayA.send(t, chatCPIM("m2", "follow-up")); code != 200 {
				t.Fatalf("follow-up reported %d", code)
			}
			if got := relayB.next(t); !strings.Contains(string(got.Body), "follow-up") {
				t.Fatalf("bob got %q", got.Body)
			}
			select {
			case req := <-r.core.got:
				if req.Method == "INVITE" {
					t.Fatalf("second INVITE %q", convHeaders(req))
				}
			default:
			}
		})
	}
}
