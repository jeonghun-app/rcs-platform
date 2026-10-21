package proxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// fakeDNS answers from a table and counts the lookups.
type fakeDNS struct {
	mu      sync.Mutex
	answers map[string][]netip.Addr
	err     error
	lookups int
}

func (f *fakeDNS) lookup(_ context.Context, network, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookups++
	if network != "ip" {
		return nil, errors.New("network " + network)
	}
	if f.err != nil {
		return nil, f.err
	}
	a, ok := f.answers[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	return a, nil
}

func TestDNSResolverResolvesNamesAndAddressesToPrivateDestinations(t *testing.T) {
	dns := &fakeDNS{answers: map[string][]netip.Addr{
		"icscf.rcs.internal": {netip.MustParseAddr("10.0.3.7")},
		"v6.rcs.internal":    {netip.MustParseAddr("fd00::7")},
	}}
	r := &DNSResolver{Lookup: dns.lookup, Namespace: "rcs.internal"}
	for _, tt := range []struct {
		uri  string
		want transport.Destination
	}{
		{"sip:icscf.rcs.internal;transport=tcp;lr", transport.Destination{Network: transport.TCP, Addr: netip.MustParseAddrPort("10.0.3.7:5060")}},
		{"sip:ICSCF.rcs.internal:5070;transport=tcp", transport.Destination{Network: transport.TCP, Addr: netip.MustParseAddrPort("10.0.3.7:5070")}},
		{"sip:icscf.rcs.internal.:5070;transport=tcp", transport.Destination{Network: transport.TCP, Addr: netip.MustParseAddrPort("10.0.3.7:5070")}},
		{"sips:icscf.rcs.internal", transport.Destination{Network: transport.TLS, Addr: netip.MustParseAddrPort("10.0.3.7:5061"), ServerName: "icscf.rcs.internal"}},
		{"sip:icscf.rcs.internal;transport=tls", transport.Destination{Network: transport.TLS, Addr: netip.MustParseAddrPort("10.0.3.7:5061"), ServerName: "icscf.rcs.internal"}},
		{"sip:v6.rcs.internal;transport=tcp", transport.Destination{Network: transport.TCP, Addr: netip.MustParseAddrPort("[fd00::7]:5060")}},
		{"sip:10.0.4.8:5070;transport=tcp", transport.Destination{Network: transport.TCP, Addr: netip.MustParseAddrPort("10.0.4.8:5070")}},
		{"sip:[fd00::8];transport=tcp", transport.Destination{Network: transport.TCP, Addr: netip.MustParseAddrPort("[fd00::8]:5060")}},
		{"sip:icscf.rcs.internal", transport.Destination{Network: transport.UDP, Addr: netip.MustParseAddrPort("10.0.3.7:5060")}},
		{"sips:10.0.4.8", transport.Destination{Network: transport.TLS, Addr: netip.MustParseAddrPort("10.0.4.8:5061")}},
	} {
		got, err := r.Resolve(context.Background(), mustURI(tt.uri))
		if err != nil || got != tt.want {
			t.Errorf("Resolve(%s) = %+v, %v; want %+v", tt.uri, got, err, tt.want)
		}
	}
}

// Only private answers are used, whoever wrote the URI: a Route a client
// put in an in-dialog request must not make the proxy reach outside the VPC
// (ADR 0007 §5, #16 question 6).
func TestDNSResolverRefusesPublicAndUnusableAnswers(t *testing.T) {
	dns := &fakeDNS{answers: map[string][]netip.Addr{
		"public.rcs.internal": {netip.MustParseAddr("8.8.8.8")},
		"mixed.rcs.internal":  {netip.MustParseAddr("8.8.4.4"), netip.MustParseAddr("10.0.3.9")},
		"empty.rcs.internal":  nil,
	}}
	r := &DNSResolver{Lookup: dns.lookup, Namespace: "rcs.internal"}
	for _, uri := range []string{
		"sip:public.rcs.internal;transport=tcp",
		"sip:8.8.8.8;transport=tcp",
		"sip:127.0.0.1;transport=tcp",
		"sip:empty.rcs.internal;transport=tcp",
		"sip:missing.rcs.internal;transport=tcp",
		"tel:+15550100001",
		"sip:icscf.rcs.internal;transport=sctp",
	} {
		if d, err := r.Resolve(context.Background(), mustURI(uri)); !errors.Is(err, ErrUnresolvable) {
			t.Errorf("Resolve(%s) = %+v, %v; want ErrUnresolvable", uri, d, err)
		}
	}
	d, err := r.Resolve(context.Background(), mustURI("sip:mixed.rcs.internal;transport=tcp"))
	if err != nil || d.Addr.Addr() != netip.MustParseAddr("10.0.3.9") {
		t.Fatalf("mixed answer gave %+v, %v; want only the private address", d, err)
	}
}

// Answers are kept for TTL, as Cloud Map's records are, and every address
// of one is given, in a new random order each time.
func TestDNSResolverKeepsAnswersForTheTTLAndGivesEveryAddress(t *testing.T) {
	addrs := []netip.Addr{netip.MustParseAddr("10.0.3.1"), netip.MustParseAddr("10.0.3.2"), netip.MustParseAddr("10.0.3.3")}
	dns := &fakeDNS{answers: map[string][]netip.Addr{"scscf.rcs.internal": addrs}}
	now := time.Unix(1_800_000_000, 0)
	rotate := 0
	r := &DNSResolver{Lookup: dns.lookup, TTL: 10 * time.Second, Namespace: "rcs.internal", Now: func() time.Time { return now },
		Shuffle: func(n int, swap func(i, j int)) {
			rotate++
			for range rotate % n {
				for i := range n - 1 {
					swap(i, i+1)
				}
			}
		}}
	u := mustURI("sip:scscf.rcs.internal;transport=tcp")
	firsts := map[netip.Addr]bool{}
	for range 3 {
		all, err := r.ResolveAll(context.Background(), u)
		if err != nil || len(all) != 3 {
			t.Fatalf("%+v, %v", all, err)
		}
		got := map[netip.Addr]bool{}
		for _, d := range all {
			got[d.Addr.Addr()] = true
		}
		if len(got) != 3 {
			t.Fatalf("addresses %v, want all three once", all)
		}
		d, err := r.Resolve(context.Background(), u)
		if err != nil {
			t.Fatal(err)
		}
		firsts[d.Addr.Addr()] = true
	}
	if dns.lookups != 1 || len(firsts) != 3 {
		t.Fatalf("%d lookups, first addresses %v; want one lookup, spread over all three", dns.lookups, firsts)
	}
	if !slices.Equal(dns.answers["scscf.rcs.internal"], addrs) {
		t.Error("the shuffle reordered the kept answer")
	}
	// Past the TTL the answer is still used while it is refreshed.
	now = now.Add(10 * time.Second)
	_, err := r.Resolve(context.Background(), u)
	r.refreshes.Wait()
	if err != nil || dns.lookups != 2 {
		t.Fatalf("after the TTL: %d lookups, %v", dns.lookups, err)
	}
}

// A lookup that fails past the TTL is answered from the last answer for
// Stale, so a short resolver outage fails no request; after that, or with
// nothing kept, the error says what kind of failure it was (review of #198).
func TestDNSResolverUsesAStaleAnswerWhileLookupsFail(t *testing.T) {
	dns := &fakeDNS{answers: map[string][]netip.Addr{"icscf.rcs.internal": {netip.MustParseAddr("10.0.3.1")}}}
	now := time.Unix(1_800_000_000, 0)
	var logs strings.Builder
	r := &DNSResolver{Lookup: dns.lookup, Namespace: "rcs.internal", Now: func() time.Time { return now },
		Logger: slog.New(slog.NewTextHandler(&logs, nil))}
	u := mustURI("sip:icscf.rcs.internal;transport=tcp")
	if _, err := r.Resolve(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	dns.err = &net.DNSError{Err: "i/o timeout", Name: "icscf.rcs.internal", IsTimeout: true}
	for _, after := range []time.Duration{DefaultDNSTTL, time.Minute, DefaultDNSTTL + DefaultDNSStale - time.Second} {
		now = time.Unix(1_800_000_000, 0).Add(after)
		if d, err := r.Resolve(context.Background(), u); err != nil || d.Addr.Addr() != netip.MustParseAddr("10.0.3.1") {
			t.Fatalf("%v after the answer: %+v, %v; want the stale answer", after, d, err)
		}
		r.refreshes.Wait()
	}
	if n := strings.Count(logs.String(), "DNS lookup failed"); n != 2 || !strings.Contains(logs.String(), "failure=timeout") || !strings.Contains(logs.String(), "using_stale_answer=true") {
		t.Errorf("%d failure logs, want the first and one a minute on:\n%s", n, logs.String())
	}
	now = time.Unix(1_800_000_000, 0).Add(DefaultDNSTTL + DefaultDNSStale)
	_, err := r.Resolve(context.Background(), u)
	var de *net.DNSError
	if !errors.Is(err, ErrUnresolvable) || !errors.As(err, &de) || !strings.Contains(err.Error(), "(timeout)") {
		t.Fatalf("past Stale: %v", err)
	}
	// The resolver recovers; the name is looked up again once its backoff
	// has passed.
	dns.err = nil
	now = now.Add(maxLookupBackoff)
	if _, err := r.Resolve(context.Background(), u); err != nil {
		t.Fatalf("a recovered lookup: %v", err)
	}
	dns.err = &net.DNSError{Err: "no such host", Name: "gone.rcs.internal", IsNotFound: true}
	if _, err := r.Resolve(context.Background(), mustURI("sip:gone.rcs.internal;transport=tcp")); !errors.Is(err, ErrUnresolvable) || !strings.Contains(err.Error(), "(not found)") {
		t.Fatalf("a name never found: %v", err)
	}
}

// Only names inside the service namespace are looked up, whole labels
// compared, so a name a client wrote costs no lookup (ADR 0007 §5); without
// a namespace only addresses resolve.
func TestDNSResolverLooksUpOnlyNamesInTheNamespace(t *testing.T) {
	dns := &fakeDNS{answers: map[string][]netip.Addr{}}
	r := &DNSResolver{Lookup: dns.lookup, Namespace: "rcs.internal"}
	for _, host := range []string{"icscf.evil-rcs.internal", "rcs.internal", "icscf.rcs.internal.example.com", "example.com"} {
		if _, err := r.Resolve(context.Background(), mustURI("sip:"+host+";transport=tcp")); !errors.Is(err, ErrUnresolvable) {
			t.Errorf("%s: %v", host, err)
		}
	}
	r = &DNSResolver{Lookup: dns.lookup}
	if _, err := r.Resolve(context.Background(), mustURI("sip:icscf.rcs.internal;transport=tcp")); !errors.Is(err, ErrUnresolvable) {
		t.Errorf("no namespace: %v", err)
	}
	if dns.lookups != 0 {
		t.Fatalf("%d lookups of names outside the namespace", dns.lookups)
	}
}

// The names kept are bounded, since a URI may come from a client.
func TestDNSResolverKeepsABoundedNumberOfNames(t *testing.T) {
	dns := &fakeDNS{answers: map[string][]netip.Addr{}}
	for i := range maxDNSNames + 10 {
		dns.answers[strings.Repeat("a", i%50+1)+"x"+itoa(i)+".rcs.internal"] = []netip.Addr{netip.MustParseAddr("10.0.0.1")}
	}
	r := &DNSResolver{Lookup: dns.lookup, Namespace: "rcs.internal"}
	for host := range dns.answers {
		if _, err := r.Resolve(context.Background(), mustURI("sip:"+host+";transport=tcp")); err != nil {
			t.Fatal(err)
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.names) > maxDNSNames {
		t.Fatalf("%d names kept, want at most %d", len(r.names), maxDNSNames)
	}
}

func TestDNSResolverAllowCanAddLoopback(t *testing.T) {
	r := &DNSResolver{Allow: func(a netip.Addr) bool { return a.IsLoopback() }}
	if _, err := r.Resolve(context.Background(), mustURI("sip:127.0.0.1:5070;transport=tcp")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve(context.Background(), mustURI("sip:10.0.0.1;transport=tcp")); !errors.Is(err, ErrUnresolvable) {
		t.Fatalf("Allow was not used: %v", err)
	}
}

// blockingDNS answers after release, with err, and counts the lookups.
type blockingDNS struct {
	mu      sync.Mutex
	release chan struct{}
	err     error
	addrs   []netip.Addr
	lookups int
}

func (b *blockingDNS) lookup(ctx context.Context, _, _ string) ([]netip.Addr, error) {
	b.mu.Lock()
	b.lookups++
	release, err, addrs := b.release, b.err, b.addrs
	b.mu.Unlock()
	select {
	case <-release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return addrs, err
}

func (b *blockingDNS) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.lookups
}

// While the resolver does not answer, a stale answer is used at once and
// the name is looked up once, not by every caller; after the failure the
// next lookup waits its backoff (review of #198).
func TestDNSResolverServesAStaleAnswerWithoutWaitingOnTheResolver(t *testing.T) {
	dns := &blockingDNS{release: make(chan struct{}), addrs: []netip.Addr{netip.MustParseAddr("10.0.3.1")}}
	close(dns.release)
	now := time.Unix(1_800_000_000, 0)
	var clock sync.Mutex
	r := &DNSResolver{Lookup: dns.lookup, Namespace: "rcs.internal", Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now: func() time.Time { clock.Lock(); defer clock.Unlock(); return now }}
	u := mustURI("sip:icscf.rcs.internal;transport=tcp")
	if _, err := r.Resolve(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	// The outage: lookups hang until released, then time out.
	dns.mu.Lock()
	dns.release = make(chan struct{})
	dns.err = &net.DNSError{Err: "i/o timeout", Name: "icscf.rcs.internal", IsTimeout: true}
	dns.mu.Unlock()
	clock.Lock()
	now = now.Add(DefaultDNSTTL)
	clock.Unlock()
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if d, err := r.Resolve(context.Background(), u); err != nil || d.Addr.Addr() != netip.MustParseAddr("10.0.3.1") {
				t.Errorf("during the outage: %+v, %v", d, err)
			}
		}()
	}
	wg.Wait()
	r.mu.Lock()
	waiting := r.names["icscf.rcs.internal"].inflight != nil
	r.mu.Unlock()
	if !waiting {
		t.Fatal("the Resolves waited for the hanging lookup")
	}
	for range 5 {
		if _, err := r.Resolve(context.Background(), u); err != nil {
			t.Fatal(err)
		}
	}
	// The refresh starts on a goroutine of its own.
	for deadline := time.Now().Add(10 * time.Second); dns.count() < 2 && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
	if n := dns.count(); n != 2 {
		t.Fatalf("%d lookups for 15 Resolves, want the first and one refresh", n)
	}
	close(dns.release)
	r.refreshes.Wait()
	for range 15 {
		if _, err := r.Resolve(context.Background(), u); err != nil {
			t.Fatal(err)
		}
	}
	r.refreshes.Wait()
	if n := dns.count(); n != 2 {
		t.Fatalf("%d lookups within the backoff", n)
	}
	clock.Lock()
	now = now.Add(minLookupBackoff)
	clock.Unlock()
	if _, err := r.Resolve(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	r.refreshes.Wait()
	if n := dns.count(); n != 3 {
		t.Fatalf("%d lookups after the backoff, want one more", n)
	}
}

// Callers with no answer to use share one lookup, and a caller that gives
// up does not end it for the others.
func TestDNSResolverSharesOneLookupOfANewName(t *testing.T) {
	dns := &blockingDNS{release: make(chan struct{}), addrs: []netip.Addr{netip.MustParseAddr("10.0.3.1")}}
	r := &DNSResolver{Lookup: dns.lookup, Namespace: "rcs.internal"}
	u := mustURI("sip:scscf.rcs.internal;transport=tcp")
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Resolve(cancelled, u); !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled caller: %v", err)
	}
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := r.Resolve(context.Background(), u); err != nil {
				t.Errorf("%v", err)
			}
		}()
	}
	for dns.count() == 0 {
		time.Sleep(time.Millisecond)
	}
	close(dns.release)
	wg.Wait()
	if n := dns.count(); n != 1 {
		t.Fatalf("%d lookups", n)
	}
	// A name whose lookup failed gets that error, without a lookup, until
	// its backoff has passed.
	gone := mustURI("sip:gone.rcs.internal;transport=tcp")
	dns.mu.Lock()
	dns.err = &net.DNSError{Err: "no such host", Name: "gone.rcs.internal", IsNotFound: true}
	dns.mu.Unlock()
	for range 5 {
		if _, err := r.Resolve(context.Background(), gone); !errors.Is(err, ErrUnresolvable) || !strings.Contains(err.Error(), "(not found)") {
			t.Fatalf("a name not found: %v", err)
		}
	}
	r.refreshes.Wait()
	if n := dns.count(); n != 2 {
		t.Fatalf("%d lookups, want one for the name not found", n)
	}
}

// A lookup that answers no address is a failure, not an answer kept for
// the TTL. A name with no answer at all is looked up again every 5 s, so a
// service that comes up is found soon after (review of #198); one with a
// stale answer in use backs off, doubling from 5 s to a minute (QA of #198).
func TestDNSResolverBacksOffFailedLookups(t *testing.T) {
	dns := &fakeDNS{answers: map[string][]netip.Addr{"empty.rcs.internal": nil}}
	now := time.Unix(1_800_000_000, 0)
	start := now
	r := &DNSResolver{Lookup: dns.lookup, Namespace: "rcs.internal", Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now: func() time.Time { return now }}
	resolve := func(u sip.URI) error {
		_, err := r.Resolve(context.Background(), u)
		r.refreshes.Wait()
		return err
	}
	// waits are the times between lookups of u over n lookups, resolving
	// every second.
	waits := func(u sip.URI, n int) []time.Duration {
		var out []time.Duration
		for range n {
			from, before := now, dns.lookups
			for dns.lookups == before {
				now = now.Add(time.Second)
				_ = resolve(u)
			}
			out = append(out, now.Sub(from))
		}
		return out
	}
	empty := mustURI("sip:empty.rcs.internal;transport=tcp")
	if err := resolve(empty); !errors.Is(err, ErrUnresolvable) || !strings.Contains(err.Error(), "(not found)") {
		t.Fatalf("an empty answer: %v", err)
	}
	if got, want := waits(empty, 4), []time.Duration{5 * time.Second, 5 * time.Second, 5 * time.Second, 5 * time.Second}; !slices.Equal(got, want) {
		t.Fatalf("a name with no answer: waits %v, want %v", got, want)
	}

	// A service that comes up at 100 s is found by 105 s.
	now = start
	dns.answers["icscf.rcs.internal"] = nil
	icscf := mustURI("sip:icscf.rcs.internal;transport=tcp")
	for err := resolve(icscf); err != nil; err = resolve(icscf) {
		if now.Sub(start) >= 100*time.Second {
			dns.answers["icscf.rcs.internal"] = []netip.Addr{netip.MustParseAddr("10.0.3.7")}
		}
		if now.Sub(start) > 105*time.Second {
			t.Fatal("not found by 105 s")
		}
		now = now.Add(time.Second)
	}

	// With the answer stale and the resolver failing, the waits double.
	now = now.Add(DefaultDNSTTL)
	dns.err = errors.New("timeout")
	if got, want := waits(icscf, 6), []time.Duration{time.Second, 5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second, time.Minute}; !slices.Equal(got, want) {
		t.Fatalf("a stale answer: waits %v, want %v", got, want)
	}
}

// A lookup runs for at most refreshTimeout whatever the resolver does, so a
// name whose resolver hangs is looked up again after that and its backoff.
func TestDNSResolverEndsALookupAfterTenSeconds(t *testing.T) {
	deadline := make(chan time.Duration, 1)
	r := &DNSResolver{Namespace: "rcs.internal", Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Lookup: func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
			dl, ok := ctx.Deadline()
			if !ok {
				deadline <- 0
				return nil, errors.New("no deadline")
			}
			deadline <- time.Until(dl)
			return nil, &net.DNSError{Err: "i/o timeout", IsTimeout: true}
		}}
	_, _ = r.Resolve(context.Background(), mustURI("sip:hung.rcs.internal;transport=tcp"))
	if d := <-deadline; d <= 0 || d > refreshTimeout || refreshTimeout != 10*time.Second {
		t.Fatalf("a lookup may run %v, want at most 10 s", d)
	}
}
