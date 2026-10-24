package bridge

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/secret"
)

// hssStub is the part of hss's provisioning API the bridge uses
// (docs/api/hss.yaml): subscriptions by IMPI, an IMPU belongs to one
// subscription only (409), and write-only AKA keys.
type hssStub struct {
	t     *testing.T
	mu    sync.Mutex
	subs  map[string]subscription
	owner map[string]string // IMPU to IMPI
	keys  map[string]map[string]string
	posts int
	// status, when set, answers every request.
	status int
	// hideOnce answers the first read of each subscription 404, as a read
	// just before another creation of it does.
	hideOnce map[string]bool
}

func newHSSStub(t *testing.T) (*hssStub, Provisioner) {
	t.Helper()
	s := &hssStub{t: t, subs: map[string]subscription{}, owner: map[string]string{}, keys: map[string]map[string]string{}}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	p, err := NewHSS(HSSConfig{URL: srv.URL + "/", Token: secret.NewString("hss-admin-token"), Domain: testDomain})
	if err != nil {
		t.Fatal(err)
	}
	return s, p
}

func (s *hssStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer hss-admin-token" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if s.status != 0 {
		w.WriteHeader(s.status)
		return
	}
	path := strings.TrimPrefix(r.URL.EscapedPath(), "/v1/subscriptions")
	switch {
	case r.Method == http.MethodPost && path == "":
		var sub subscription
		if json.NewDecoder(r.Body).Decode(&sub) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		s.posts++
		if _, ok := s.subs[sub.IMPI]; ok {
			w.WriteHeader(http.StatusConflict)
			return
		}
		for _, id := range sub.PublicIdentities {
			if _, ok := s.owner[id.IMPU]; ok {
				w.WriteHeader(http.StatusConflict)
				return
			}
		}
		for _, id := range sub.PublicIdentities {
			s.owner[id.IMPU] = sub.IMPI
		}
		s.subs[sub.IMPI] = sub
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(sub)
	case r.Method == http.MethodGet:
		impi, _ := url.PathUnescape(strings.TrimPrefix(path, "/"))
		sub, ok := s.subs[impi]
		if s.hideOnce != nil && !s.hideOnce[impi] {
			s.hideOnce[impi], ok = true, false
		}
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(sub)
	case r.Method == http.MethodPut && strings.HasSuffix(path, "/aka"):
		impi, _ := url.PathUnescape(strings.TrimSuffix(strings.TrimPrefix(path, "/"), "/aka"))
		if _, ok := s.subs[impi]; !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var keys map[string]string
		json.NewDecoder(r.Body).Decode(&keys)
		s.keys[impi] = keys
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// take gives the slot of digits to another subscription, as an earlier
// endpoint or anything else in hss would hold it.
func (s *hssStub) take(digits string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	impi := "someone-else-" + digits + "@" + testDomain
	sub := subscription{IMPI: impi, IMSI: imsiPrefix + digits, PublicIdentities: []identity{{IMPU: "sip:" + msisdnPrefix + digits + "@" + testDomain}, {IMPU: "tel:" + msisdnPrefix + digits}}}
	s.subs[impi] = sub
	for _, id := range sub.PublicIdentities {
		s.owner[id.IMPU] = impi
	}
}

func TestAnEndpointGetsASubscriptionOfTheBridgesRangeWithFreshKeys(t *testing.T) {
	stub, p := newHSSStub(t)
	got, err := p.Provision(context.Background(), "car")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got.IMPI, impiPrefix) || !strings.HasSuffix(got.IMPI, "@"+testDomain) || got.IMPI != impiOf("car", testDomain) {
		t.Fatalf("IMPI %s", got.IMPI)
	}
	sub := stub.subs[got.IMPI]
	n, _ := numberOf(got.Tel)
	digits := strings.TrimPrefix(n, msisdnPrefix)
	if len(digits) != 3 || sub.IMSI != imsiPrefix+digits {
		t.Fatalf("IMSI %s for %s", sub.IMSI, n)
	}
	if got.IMPU.String() != "sip:"+n+"@"+testDomain || got.Tel.String() != "tel:"+n {
		t.Fatalf("identities %s %s", got.IMPU, got.Tel)
	}
	// Both identities in one implicit set, the SIP one first, as
	// stack-seed provisions its subscribers.
	if len(sub.PublicIdentities) != 2 || sub.PublicIdentities[0].IMPU != got.IMPU.String() || sub.PublicIdentities[1].IMPU != got.Tel.String() ||
		sub.PublicIdentities[0].ImplicitSet != sub.PublicIdentities[1].ImplicitSet {
		t.Fatalf("public identities %+v", sub.PublicIdentities)
	}
	keys := stub.keys[got.IMPI]
	k, err1 := hex.DecodeString(keys["k"])
	opc, err2 := hex.DecodeString(keys["opc"])
	if err1 != nil || err2 != nil || len(k) != 16 || len(opc) != 16 || keys["k"] == keys["opc"] || len(keys) != 2 {
		t.Fatalf("AKA keys %d %d bytes", len(k), len(opc))
	}
	if !strings.HasPrefix(got.InstanceID, "urn:uuid:") || got.InstanceID != instanceOf(got.IMPI) {
		t.Fatalf("instance %s", got.InstanceID)
	}
	other, err := p.Provision(context.Background(), "phone")
	if err != nil {
		t.Fatal(err)
	}
	if other.IMPI == got.IMPI || other.Tel.String() == got.Tel.String() || stub.keys[other.IMPI]["k"] == keys["k"] {
		t.Fatal("two endpoints share a subscription or a key")
	}
}

func TestATakenSlotIsSkipped(t *testing.T) {
	_, p := newHSSStub(t)
	// The slot the name picks first, found on an empty hss.
	first, err := p.Provision(context.Background(), "probe")
	if err != nil {
		t.Fatal(err)
	}
	n, _ := numberOf(first.Tel)
	start := strings.TrimPrefix(n, msisdnPrefix)
	stub2, p2 := newHSSStub(t)
	stub2.take(start)
	got, err := p2.Provision(context.Background(), "probe")
	if err != nil {
		t.Fatal(err)
	}
	if gn, _ := numberOf(got.Tel); gn == n {
		t.Fatalf("took the slot someone else holds")
	}
	if stub2.posts != 2 {
		t.Fatalf("%d creations tried, want 2", stub2.posts)
	}
}

func TestAnEndpointFoundAgainKeepsItsIdentitiesAndGetsNewKeys(t *testing.T) {
	stub, p := newHSSStub(t)
	first, err := p.Provision(context.Background(), "car")
	if err != nil {
		t.Fatal(err)
	}
	oldKey := stub.keys[first.IMPI]["k"]
	// A restarted bridge: a Provisioner of its own, the same hss.
	again, err := p.Provision(context.Background(), "car")
	if err != nil {
		t.Fatal(err)
	}
	if again.IMPI != first.IMPI || again.IMPU.String() != first.IMPU.String() || again.Tel.String() != first.Tel.String() {
		t.Fatalf("found again as %s %s, was %s %s", again.IMPU, again.Tel, first.IMPU, first.Tel)
	}
	if stub.posts != 1 {
		t.Fatalf("%d creations, want the first only", stub.posts)
	}
	if stub.keys[first.IMPI]["k"] == oldKey {
		t.Fatal("the keys were not replaced")
	}
}

func TestHSSFailuresNameTheOperationAndStatusOnly(t *testing.T) {
	stub, p := newHSSStub(t)
	stub.status = http.StatusServiceUnavailable
	_, err := p.Provision(context.Background(), "car")
	if err == nil || err.Error() != "hss: read subscription answered 503" {
		t.Fatalf("Provision = %v", err)
	}
}

func TestASubscriptionThatIsNotASlotIsRefused(t *testing.T) {
	stub, p := newHSSStub(t)
	impi := impiOf("car", testDomain)
	stub.subs[impi] = subscription{IMPI: impi, PublicIdentities: []identity{{IMPU: "sip:+15550100001@" + testDomain}, {IMPU: "tel:+15550100001"}}}
	if _, err := p.Provision(context.Background(), "car"); err == nil {
		t.Fatal("took a subscription outside the bridge's range")
	}
}

func TestNewHSSChecksItsSettings(t *testing.T) {
	for _, c := range []HSSConfig{
		{URL: "hss:8081", Token: secret.NewString("t"), Domain: testDomain},
		{URL: "ftp://hss", Token: secret.NewString("t"), Domain: testDomain},
		{URL: "http://hss:8081", Domain: testDomain},
		{URL: "http://hss:8081", Token: secret.NewString("t")},
	} {
		if _, err := NewHSS(c); err == nil {
			t.Errorf("NewHSS(%s) took it", c.URL)
		}
	}
}

func TestIMPIsAndInstancesAreStableAndApart(t *testing.T) {
	if impiOf("car", testDomain) != impiOf("car", testDomain) || impiOf("car", testDomain) == impiOf("Car", testDomain) {
		t.Fatal("impiOf is not a function of the exact name")
	}
	inst := instanceOf(impiOf("car", testDomain))
	// RFC 9562: version 8, variant 10.
	if len(inst) != len("urn:uuid:")+36 || inst[len("urn:uuid:")+14] != '8' || !strings.ContainsRune("89ab", rune(inst[len("urn:uuid:")+19])) {
		t.Fatalf("instance %s", inst)
	}
}

func TestASubscriptionCreatedMeanwhileIsTaken(t *testing.T) {
	stub, p := newHSSStub(t)
	first, err := p.Provision(context.Background(), "car")
	if err != nil {
		t.Fatal(err)
	}
	stub.hideOnce = map[string]bool{}
	again, err := p.Provision(context.Background(), "car")
	if err != nil {
		t.Fatal(err)
	}
	if again.Tel.String() != first.Tel.String() || stub.posts != 2 {
		t.Fatalf("got %s after %d creations, want %s after the one refused", again.Tel, stub.posts, first.Tel)
	}
}

// repeating is a random source whose first two reads give the same bytes,
// and every later one others.
type repeating struct{ n byte }

func (r *repeating) Read(p []byte) (int, error) {
	v := r.n
	if v < 2 {
		v = 7
	}
	for i := range p {
		p[i] = v
	}
	r.n++
	return len(p), nil
}

func TestKAndOPcAlwaysDiffer(t *testing.T) {
	stub, _ := newHSSStub(t)
	srv := httptest.NewServer(stub)
	defer srv.Close()
	p, err := NewHSS(HSSConfig{URL: srv.URL, Token: secret.NewString("hss-admin-token"), Domain: testDomain, Rand: &repeating{}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.Provision(context.Background(), "car")
	if err != nil {
		t.Fatal(err)
	}
	if keys := stub.keys[got.IMPI]; keys["k"] == keys["opc"] {
		t.Fatal("K and OPc are the same")
	}
}
