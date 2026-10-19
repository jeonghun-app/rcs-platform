package proxy

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

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
	now = now.Add(10 * time.Second)
	if _, err := r.Resolve(context.Background(), u); err != nil || dns.lookups != 2 {
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
	dns.err = nil
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
