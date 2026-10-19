package runtime

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"testing"
)

func TestPrivateHostsAreRFC1918ULAAndNamesInTheNamespace(t *testing.T) {
	for host, want := range map[string]bool{
		"10.0.3.7": true, "172.16.0.1": true, "192.168.1.1": true, "fd00::1": true, "fc00::1": true,
		"::ffff:10.0.0.1": true,
		"hss.rcs.local":   true, "HSS.RCS.LOCAL.": true, "rcs-as.prod.rcs.local": true,
		// ADR 0007 §5 refuses these.
		"127.0.0.1": false, "::1": false, "169.254.169.254": false, "169.254.170.2": false,
		"fe80::1": false, "fe80::1%eth0": false, "fd00::1%eth0": false, "2001:db8::1": false,
		"8.8.8.8": false, "172.32.0.1": false, "::ffff:8.8.8.8": false,
		"hss.example.com": false, "rcs.local": false, "evilrcs.local": false, "hss.evil-rcs.local": false,
		".rcs.local": false, "..rcs.local": false, "a..b.rcs.local": false, "*.rcs.local": false, "-a.rcs.local": false,
		"localhost": false, "": false,
	} {
		if got := IsPrivateHost(host, "rcs.local"); got != want {
			t.Errorf("IsPrivateHost(%q) = %t, want %t", host, got, want)
		}
	}
	if IsPrivateHost("hss.rcs.local", "") {
		t.Error("a name is private without a namespace")
	}
	if !InServiceNamespace("rcs-as.rcs.internal", "RCS.Internal.") {
		t.Error("the namespace is compared without regard to case or a trailing dot")
	}
}

func TestPrivateInternalURLsNeedAnHTTPSchemeAndAPrivateHost(t *testing.T) {
	for raw, want := range map[string]bool{
		"http://hss.rcs.local:8081/v1":       true,
		"https://10.0.1.5/":                  true,
		"http://[fd00::5]:8080":              true,
		"http://169.254.169.254/latest/meta": false,
		"http://127.0.0.1:8080":              false,
		"http://hss.example.com":             false,
		"ftp://10.0.1.5/":                    false,
		"http://user@hss.evilrcs.local":      false,
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := IsPrivateInternalURL(u, "rcs.local"); got != want {
			t.Errorf("IsPrivateInternalURL(%q) = %t, want %t", raw, got, want)
		}
	}
	if IsPrivateInternalURL(nil, "rcs.local") {
		t.Error("nil URL is private")
	}
}

func TestInternalClientsDoNotFollowRedirects(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the redirect was followed, carrying %q", r.Header.Get("Authorization"))
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.RedirectHandler(target.URL, http.StatusFound))
	defer redirect.Close()
	client := &http.Client{CheckRedirect: RefuseRedirects}
	req, _ := http.NewRequest(http.MethodGet, redirect.URL, nil)
	req.Header.Set("Authorization", "Bearer token")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want the redirect itself", resp.StatusCode)
	}
}

func TestServiceNamespaceIsAValidatedSharedSetting(t *testing.T) {
	if len(longNamespace) != 253 {
		t.Fatalf("longNamespace has %d characters", len(longNamespace))
	}
	for v, want := range map[string]string{
		"":                "",
		"rcs.local":       "rcs.local",
		"RCS.Prod.Local.": "rcs.prod.local",
		"prod-1.internal": "prod-1.internal",
		"a.b":             "a.b",
		"rcs.local1":      "rcs.local1",
		"x":               "x", // one label is allowed in dev only
		longNamespace:     longNamespace,
	} {
		e := NewEnv("RCS_", envMap{"RCS_ENV": "dev", "RCS_SERVICE_NAMESPACE": v}.lookup)
		loadShared(e)
		if err := e.Err(); err != nil {
			t.Errorf("%q refused: %v", v, err)
		}
		if got := (&Settings{Shared: e}).ServiceNamespace(); got != want {
			t.Errorf("ServiceNamespace() for %q = %q, want %q", v, got, want)
		}
	}
	for _, v := range []string{
		"rcs_local", "-rcs.local", "rcs-.local", "rcs..local", ".", strings.Repeat("a", 64) + ".local", "rcs.local/x", "rcs local",
		// An all-digit last label is an address, not a name.
		"1.2.3.4", "rcs.0", "0",
		longNamespace + "a",
	} {
		e := NewEnv("RCS_", envMap{"RCS_ENV": "dev", "RCS_SERVICE_NAMESPACE": v}.lookup)
		loadShared(e)
		if err := e.Err(); err == nil || !strings.Contains(err.Error(), "RCS_SERVICE_NAMESPACE") {
			t.Errorf("%q accepted: %v", v, err)
		}
		if got := (&Settings{Shared: e}).ServiceNamespace(); got != "" {
			t.Errorf("ServiceNamespace() for invalid %q = %q", v, got)
		}
	}
}

func TestStagingAndProdNeedANamespaceOfTwoOrMoreLabels(t *testing.T) {
	for _, env := range []string{"staging", "prod"} {
		for v, ok := range map[string]bool{"local": false, "com": false, "rcs.local": true, "prod.rcs.internal": true} {
			e := NewEnv("RCS_", envMap{"RCS_ENV": env, "RCS_SERVICE_NAMESPACE": v}.lookup)
			loadShared(e)
			err := e.Err()
			refused := err != nil && strings.Contains(err.Error(), "RCS_SERVICE_NAMESPACE")
			if refused == ok {
				t.Errorf("%s with %q: %v", env, v, err)
			}
		}
	}
}

// longNamespace is a valid namespace of 253 characters, the most a DNS name
// may have.
var longNamespace = strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)

// fakeNet stands in for DNS and the network: lookups answer from a table,
// and dials record the address and fail, as nothing listens there.
type fakeNet struct {
	names  map[string][]netip.Addr
	dialed []string
}

var errNoListener = errors.New("connection refused")

func (f *fakeNet) dialer() InternalDialer {
	return InternalDialer{
		Lookup: func(_ context.Context, _, host string) ([]netip.Addr, error) {
			addrs, ok := f.names[host]
			if !ok {
				return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
			}
			return addrs, nil
		},
		Dial: func(_ context.Context, _, address string) (net.Conn, error) {
			f.dialed = append(f.dialed, address)
			return nil, errNoListener
		},
	}
}

func addrs(ss ...string) []netip.Addr {
	var out []netip.Addr
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

func TestTheInternalDialerConnectsOnlyToPrivateAddresses(t *testing.T) {
	f := &fakeNet{names: map[string][]netip.Addr{
		"metadata.rcs.local": addrs("169.254.170.2"),
		"loop.rcs.local":     addrs("127.0.0.1", "::1"),
		"public.rcs.local":   addrs("203.0.113.9", "2001:db8::9"),
		"zoned.rcs.local":    addrs("fe80::1%eth0", "fd00::1%eth0"),
		"mixed.rcs.local":    addrs("203.0.113.9", "10.0.1.5", "fd00::5"),
		"hss.rcs.local":      addrs("::ffff:10.0.2.7"),
	}}
	d := f.dialer()
	for _, address := range []string{
		"metadata.rcs.local:80", "loop.rcs.local:8081", "public.rcs.local:443", "zoned.rcs.local:80",
		"127.0.0.1:8081", "169.254.169.254:80", "[::1]:443", "8.8.8.8:53",
	} {
		_, err := d.DialContext(context.Background(), "tcp", address)
		if !errors.Is(err, ErrAddressNotPrivate) {
			t.Errorf("%s: %v, want ErrAddressNotPrivate", address, err)
		}
	}
	if len(f.dialed) != 0 {
		t.Fatalf("dialed %q, which are not private", f.dialed)
	}
	// Private addresses are tried in order, the others skipped, and a
	// real failure is reported as itself.
	if _, err := d.DialContext(context.Background(), "tcp", "mixed.rcs.local:8081"); !errors.Is(err, errNoListener) {
		t.Errorf("mixed: %v", err)
	}
	if _, err := d.DialContext(context.Background(), "tcp", "hss.rcs.local:8081"); !errors.Is(err, errNoListener) {
		t.Errorf("mapped: %v", err)
	}
	if _, err := d.DialContext(context.Background(), "tcp", "10.0.3.3:8081"); !errors.Is(err, errNoListener) {
		t.Errorf("literal: %v", err)
	}
	if want := []string{"10.0.1.5:8081", "[fd00::5]:8081", "10.0.2.7:8081", "10.0.3.3:8081"}; !slices.Equal(f.dialed, want) {
		t.Errorf("dialed %q, want %q", f.dialed, want)
	}
	var dnsErr *net.DNSError
	if _, err := d.DialContext(context.Background(), "tcp", "missing.rcs.local:80"); !errors.As(err, &dnsErr) {
		t.Errorf("unknown name: %v", err)
	}
	if _, err := d.DialContext(context.Background(), "tcp", "no-port"); err == nil {
		t.Error("an address without a port was dialed")
	}
}
