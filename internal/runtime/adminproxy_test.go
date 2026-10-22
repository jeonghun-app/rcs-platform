package runtime

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/proxyproto"
)

// serveAdminProxy serves an /readyz that answers 200 behind a
// proxyListener taking headers from networks, and returns its address.
func serveAdminProxy(t *testing.T, networks ...string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var prefixes []netip.Prefix
	for _, n := range networks {
		prefixes = append(prefixes, netip.MustParsePrefix(n))
	}
	srv := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ready") }),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = srv.Serve(proxyListener{Listener: ln, networks: prefixes}) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

// getAfter sends prefix and then a GET /readyz over a new connection, and
// returns the status code, or 0 when the connection closed with no answer.
func getAfter(t *testing.T, addr string, prefix []byte) int {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := c.Write(append(prefix, "GET /readyz HTTP/1.1\r\nHost: admin\r\nConnection: close\r\n\r\n"...)); err != nil {
		return 0
	}
	res, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return 0
	}
	defer res.Body.Close()
	return res.StatusCode
}

// The admin port takes a PROXY protocol v2 header, LOCAL or PROXY, from
// the configured networks, as an NLB health check sends one, and still
// serves a connection without one, as ECS's container health check makes
// (#230).
func TestTheAdminPortTakesAPROXYHeaderFromItsNetworks(t *testing.T) {
	addr := serveAdminProxy(t, "127.0.0.0/8")
	proxy := proxyproto.Header{Command: proxyproto.Proxy,
		Source: netip.MustParseAddrPort("192.0.2.10:40000"), Destination: netip.MustParseAddrPort("192.0.2.20:9090")}
	for name, prefix := range map[string][]byte{
		"no header": nil,
		"LOCAL":     proxyproto.Header{Command: proxyproto.Local}.Marshal(),
		"PROXY":     proxy.Marshal(),
	} {
		if code := getAfter(t, addr, prefix); code != http.StatusOK {
			t.Errorf("%s: %d, want 200", name, code)
		}
	}
}

// A header from a peer outside the networks, or one that does not parse,
// closes the connection before any HTTP is read; so does any header when
// no network is configured.
func TestTheAdminPortRefusesOtherPROXYHeaders(t *testing.T) {
	local := proxyproto.Header{Command: proxyproto.Local}.Marshal()
	t.Run("outside its networks", func(t *testing.T) {
		if code := getAfter(t, serveAdminProxy(t, "192.0.2.0/24"), local); code != 0 {
			t.Errorf("answered %d", code)
		}
	})
	t.Run("no networks", func(t *testing.T) {
		// The listener is only wrapped when networks are set; wrapped
		// with none, it takes no header either.
		if code := getAfter(t, serveAdminProxy(t), local); code != 0 {
			t.Errorf("answered %d", code)
		}
	})
	addr := serveAdminProxy(t, "127.0.0.0/8")
	bad := func(edit func([]byte) []byte) []byte { return edit(append([]byte(nil), local...)) }
	for name, prefix := range map[string][]byte{
		"version 1":       bad(func(b []byte) []byte { b[12] = 0x10; return b }),
		"unknown command": bad(func(b []byte) []byte { b[12] = 0x2f; return b }),
		"too long":        bad(func(b []byte) []byte { b[14], b[15] = 0xff, 0xff; return b }),
		"truncated TLV": func() []byte {
			b := proxyproto.Header{Command: proxyproto.Proxy, Source: netip.MustParseAddrPort("192.0.2.10:40000"),
				Destination: netip.MustParseAddrPort("192.0.2.20:9090")}.Marshal()
			b[15] += 3
			return append(b, 0x04, 0x00, 0xff) // a TLV of 255 bytes that are not there
		}(),
		"signature only": local[:proxyproto.SignatureLen],
		"PROXY over UDP": bad(func(b []byte) []byte { return append(append(append(b[:12], 0x21), 0x12, 0, 12), make([]byte, 12)...) }),
	} {
		if code := getAfter(t, addr, prefix); code != 0 {
			t.Errorf("%s: answered %d, want the connection closed", name, code)
		}
	}
}

// RCS_ADMIN_PROXY_NETWORKS turns the header on for its networks, is off
// when unset, and refuses a /0, which would take a header from anyone.
func TestAdminProxyNetworksAreOptIn(t *testing.T) {
	load := func(v string, set bool) (adminAddr, error) {
		m := envMap{"RCS_ENV": "dev"}
		if set {
			m["RCS_ADMIN_PROXY_NETWORKS"] = v
		}
		e := NewEnv("RCS_", m.lookup)
		s := loadShared(e)
		return s.admin, e.Err()
	}
	if a, err := load("", false); err != nil || a.proxyNetworks != nil {
		t.Errorf("unset: %v, %v", a.proxyNetworks, err)
	}
	if a, err := load("10.0.0.0/16,10.1.0.0/16", true); err != nil || len(a.proxyNetworks) != 2 {
		t.Errorf("two networks: %v, %v", a.proxyNetworks, err)
	}
	for _, v := range []string{"0.0.0.0/0", "10.0.0.0/16,::/0", "10.0.0.1/16", "nowhere"} {
		if a, err := load(v, true); err == nil || a.proxyNetworks != nil {
			t.Errorf("%q accepted: %v", v, a.proxyNetworks)
		} else if !strings.Contains(err.Error(), "ADMIN_PROXY_NETWORKS") {
			t.Errorf("%q: %v", v, err)
		}
	}
}

// Run wraps the admin listener when RCS_ADMIN_PROXY_NETWORKS is set, and
// only then: without it, a header is no HTTP the admin server can serve.
func TestRunTakesAPROXYHeaderOnTheAdminPortOnlyWhenAsked(t *testing.T) {
	local := proxyproto.Header{Command: proxyproto.Local}.Marshal()
	for name, c := range map[string]struct {
		networks string
		want     int
	}{"with RCS_ADMIN_PROXY_NETWORKS": {"127.0.0.0/8", http.StatusOK}, "without": {"", 0}} {
		t.Run(name, func(t *testing.T) {
			env := devEnv()
			if c.networks != "" {
				env["RCS_ADMIN_PROXY_NETWORKS"] = c.networks
			}
			ready := make(chan struct{})
			h := startService(t, env, testService(func(ctx context.Context, rt *Runtime, _ testConfig) error {
				rt.Ready()
				close(ready)
				<-ctx.Done()
				return nil
			}))
			addr := strings.TrimSuffix(strings.TrimPrefix(h.adminURL("/"), "http://"), "/")
			<-ready
			got := getAfter(t, addr, local)
			h.cancel()
			if code := h.wait(); code != ExitOK {
				t.Fatalf("exit %d", code)
			}
			if c.want == http.StatusOK && got != http.StatusOK || c.want == 0 && got == http.StatusOK {
				t.Fatalf("readyz behind a LOCAL header: %d", got)
			}
		})
	}
}
