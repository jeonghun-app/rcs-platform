package hss

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
)

func TestHostPatternsMatchWithinOneLabel(t *testing.T) {
	for _, c := range []struct {
		pattern, host string
		want          bool
	}{
		{"scscf-*.rcs.local", "scscf-1a2b.rcs.local", true},
		{"scscf-*.rcs.local", "SCSCF-1A2B.RCS.LOCAL", true},
		{"scscf-*.rcs.local", "scscf-.rcs.local", true},
		{"scscf-*.rcs.local", "scscf-x.evil.rcs.local", false},
		{"scscf-*.rcs.local", "icscf-1.rcs.local", false},
		{"scscf-*.rcs.local", "scscf-1.rcs.local.evil", false},
		{"*-scscf.rcs.local", "a-scscf.rcs.local", true},
		{"s*f.rcs.local", "scscf.rcs.local", true},
		{"s*f.rcs.local", "sf.rcs.local", true},
		{"scscf-**.rcs.local", "scscf-1.rcs.local", false},
		{"scscf.rcs.local", "scscf.rcs.local", true},
	} {
		if got := hostMatcher(c.pattern)(c.host); got != c.want {
			t.Errorf("%s ~ %s = %t, want %t", c.pattern, c.host, got, c.want)
		}
	}
}

// pusherOn returns a Pusher on the HSS task's node, trying peers in the
// order of their host names.
func pusherOn(n *hssNode) *Pusher {
	return NewPusher(n.node, PusherOptions{
		SCSCFHostPattern: "scscf-*.rcs.local",
		Shuffle: func(p []*diameter.Peer) {
			slices.SortFunc(p, func(a, b *diameter.Peer) int { return strings.Compare(a.Host(), b.Host()) })
		},
	})
}

func TestRTRGoesToAConnectedSCSCFNamedAsDestinationHost(t *testing.T) {
	e := newEnv(t)
	n := serveHSS(t, e.h, "hss-a.rcs.local")
	icscf := connectCSCF(t, n, "icscf-1.rcs.local")
	scscf := connectCSCF(t, n, "scscf-1.rcs.local")
	err := pusherOn(n).Deregister(context.Background(), &cx.RTR{
		UserName: impi1, PublicIdentities: []string{impu1},
		DeregistrationReason: cx.DeregistrationReason{Code: cx.PermanentTermination},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rtrs, _ := icscf.received(); len(rtrs) != 0 {
		t.Error("the I-CSCF got an RTR")
	}
	rtrs, _ := scscf.received()
	if len(rtrs) != 1 {
		t.Fatalf("S-CSCF got %d RTRs", len(rtrs))
	}
	r := rtrs[0]
	if r.DestinationHost != "scscf-1.rcs.local" || r.DestinationRealm != domain || r.UserName != impi1 ||
		!slices.Equal(r.PublicIdentities, []string{impu1}) || r.DeregistrationReason.Code != cx.PermanentTermination {
		t.Errorf("RTR = %+v", r)
	}
	if e.metrics.get("push.rtr.sent") != 0 {
		t.Error("the pusher without metrics counted into the HSS's")
	}
}

func TestPushMovesToTheNextSCSCFWhenOneIsBusy(t *testing.T) {
	e := newEnv(t)
	n := serveHSS(t, e.h, "hss-a.rcs.local")
	first := connectCSCF(t, n, "scscf-1.rcs.local")
	second := connectCSCF(t, n, "scscf-2.rcs.local")
	first.setBusy(true)
	if err := pusherOn(n).PushProfile(context.Background(), &cx.PPR{UserName: impi1, UserData: []byte("<x/>")}); err != nil {
		t.Fatal(err)
	}
	_, a := first.received()
	_, b := second.received()
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("PPRs: %d to the busy peer, %d to the next", len(a), len(b))
	}
	if b[0].DestinationHost != "scscf-2.rcs.local" || b[0].SessionID != a[0].SessionID {
		t.Errorf("retry = %+v; it must keep the Session-Id and name its own peer", b[0])
	}
	second.mu.Lock()
	defer second.mu.Unlock()
	if second.flags[0]&diameter.FlagRetransmit == 0 {
		t.Error("the retry is not marked as a potential retransmission")
	}
}

func TestPushFailsWithoutAnSCSCFAndOnARejection(t *testing.T) {
	e := newEnv(t)
	n := serveHSS(t, e.h, "hss-a.rcs.local")
	connectCSCF(t, n, "icscf-1.rcs.local")
	p := pusherOn(n)
	m := &countingMetrics{}
	p.metrics = m
	err := p.Deregister(context.Background(), &cx.RTR{UserName: impi1})
	if !errors.Is(err, ErrNoSCSCF) || m.get("push.rtr.no_peer") != 1 || m.get("push.rtr.failed") != 0 {
		t.Fatalf("without an S-CSCF: %v, metrics %v", err, m.counts)
	}
	scscf := connectCSCF(t, n, "scscf-1.rcs.local")
	scscf.setAnswer(exp(cx.ErrorUserUnknown))
	err = p.PushProfile(context.Background(), &cx.PPR{UserName: impi1, UserData: []byte("<x/>")})
	var rejected *RejectedError
	if !errors.As(err, &rejected) || rejected.Result != exp(cx.ErrorUserUnknown) || !strings.Contains(err.Error(), "5001") {
		t.Fatalf("rejected PPR: %v", err)
	}
	scscf.setBusy(true)
	if err := p.PushProfile(context.Background(), &cx.PPR{UserName: impi1, UserData: []byte("<x/>")}); err == nil {
		t.Fatal("a PPR every peer refused succeeded")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	scscf.setBusy(false)
	if err := p.PushProfile(ctx, &cx.PPR{UserName: impi1, UserData: []byte("<x/>")}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled push: %v", err)
	}
}
