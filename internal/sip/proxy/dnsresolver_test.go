package proxy

import (
	"context"
	"errors"
	"net/netip"
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
	r := &DNSResolver{Lookup: dns.lookup}
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
		"public.example.com": {netip.MustParseAddr("8.8.8.8")},
		"mixed.rcs.internal": {netip.MustParseAddr("8.8.4.4"), netip.MustParseAddr("10.0.3.9")},
		"empty.rcs.internal": nil,
	}}
	r := &DNSResolver{Lookup: dns.lookup}
	for _, uri := range []string{
		"sip:public.example.com;transport=tcp",
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

// Answers are kept for TTL, as Cloud Map's records are, and spread over
// every address of the answer; a failed lookup is not kept.
func TestDNSResolverKeepsAnswersForTheTTLAndSpreadsOverThem(t *testing.T) {
	addrs := []netip.Addr{netip.MustParseAddr("10.0.3.1"), netip.MustParseAddr("10.0.3.2"), netip.MustParseAddr("10.0.3.3")}
	dns := &fakeDNS{answers: map[string][]netip.Addr{"scscf.rcs.internal": addrs}}
	now := time.Unix(1_800_000_000, 0)
	pick := 0
	r := &DNSResolver{Lookup: dns.lookup, TTL: 10 * time.Second, Now: func() time.Time { return now }, Pick: func(n int) int { pick = (pick + 1) % n; return pick }}
	u := mustURI("sip:scscf.rcs.internal;transport=tcp")
	seen := map[netip.Addr]bool{}
	for range 3 {
		d, err := r.Resolve(context.Background(), u)
		if err != nil {
			t.Fatal(err)
		}
		seen[d.Addr.Addr()] = true
	}
	if dns.lookups != 1 || len(seen) != 3 {
		t.Fatalf("%d lookups, addresses %v; want one lookup spread over all three", dns.lookups, seen)
	}
	now = now.Add(10 * time.Second)
	if _, err := r.Resolve(context.Background(), u); err != nil || dns.lookups != 2 {
		t.Fatalf("after the TTL: %d lookups, %v", dns.lookups, err)
	}
	dns.err = errors.New("timeout")
	now = now.Add(time.Minute)
	if _, err := r.Resolve(context.Background(), u); !errors.Is(err, ErrUnresolvable) {
		t.Fatalf("failed lookup gave %v", err)
	}
	dns.err = nil
	if _, err := r.Resolve(context.Background(), u); err != nil || dns.lookups != 4 {
		t.Fatalf("a failure was kept: %d lookups, %v", dns.lookups, err)
	}
}

// The names kept are bounded, since a URI may come from a client.
func TestDNSResolverKeepsABoundedNumberOfNames(t *testing.T) {
	dns := &fakeDNS{answers: map[string][]netip.Addr{}}
	for i := range maxDNSNames + 10 {
		dns.answers[strings.Repeat("a", i%50+1)+"x"+itoa(i)+".rcs.internal"] = []netip.Addr{netip.MustParseAddr("10.0.0.1")}
	}
	r := &DNSResolver{Lookup: dns.lookup}
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
