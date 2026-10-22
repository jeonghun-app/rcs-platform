package msrprelay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/runtime"
)

// devEnv is a minimal valid dev configuration.
var devEnv = map[string]string{
	"RCS_ENV":           "dev",
	"RELAY_PUBLIC_HOST": publicHost,
	"RELAY_CORE_HOST":   "10.0.2.9",
	"RELAY_STORE":       "memory",
	"RELAY_PCSCF_TOKEN": testToken,
}

// prodEnv is as close to a valid production configuration as a test can
// get without AWS: only the memory store is refused, so every other reason
// in the output comes from the setting under test.
var prodEnv = with(devEnv,
	"RCS_ENV", "prod",
	"RCS_PII_HMAC_KEY", strings.Repeat("k", 32),
	"RCS_PROXY_PROTOCOL", "true",
)

func with(base map[string]string, kv ...string) map[string]string {
	m := map[string]string{}
	for k, v := range base {
		m[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "" {
			delete(m, kv[i])
		} else {
			m[kv[i]] = kv[i+1]
		}
	}
	return m
}

// configure runs Configure the way runtime.Run does and returns the
// configuration and every problem.
func configure(env map[string]string) (Config, error) {
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	shared := runtime.NewEnv("RCS_", lookup)
	c := Configure(&runtime.Settings{Env: shared.WithPrefix("RELAY_"), Shared: shared, Environment: runtime.Environment(env["RCS_ENV"])})
	return c, shared.Err()
}

// refusal runs the service with env and returns what it logged; env must be
// refused, so the service never starts.
func refusal(t *testing.T, env map[string]string) string {
	t.Helper()
	var out bytes.Buffer
	status := runtime.Run(context.Background(), Service(), runtime.Process{
		LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok },
		Stdout:    &out,
		Listen:    func(string, string) (net.Listener, error) { return nil, errors.New("must not start") },
	})
	if status != runtime.ExitFailure || !strings.Contains(out.String(), "configuration rejected") {
		t.Fatalf("status %d, want the configuration rejected:\n%s", status, out.String())
	}
	return out.String()
}

func TestDevConfigurationIsReadWithDefaults(t *testing.T) {
	c, err := configure(devEnv)
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenAddr != DefaultListenAddr || c.ControlAddr != DefaultControlAddr || c.Table != DefaultTable ||
		c.StoreTimeout != DefaultStoreTimeout || c.MaxExpiresIn != DefaultMaxExpiresIn || c.KeepAlive != 240*time.Second ||
		c.IdleTimeout != 300*time.Second || c.DrainTimeout != DefaultDrainTimeout || c.PathWait != DefaultPathWait ||
		c.MaxConnections != DefaultMaxConnections || c.MaxConnectionsPerSource != DefaultMaxConnectionsPerSource ||
		c.MaxConcurrentBinds != DefaultMaxConcurrentBinds || c.MaxUnknownSessions != 3 || c.ProxyProtocol {
		t.Fatalf("config = %+v", c)
	}
	if c.Public.String() != "msrps://relay.example.net:2856;tcp" || c.CoreHost != coreHostAddr {
		t.Fatalf("public %s, core host %v", c.Public.String(), c.CoreHost)
	}
	if len(c.CoreNetworks) != len(privateRanges) || len(c.Tokens) != 1 {
		t.Fatalf("networks %v, %d tokens", c.CoreNetworks, len(c.Tokens))
	}
	if len(c.CorePorts) != 1 || c.CorePorts[0] != 2855 || c.FailedLookupsPerSource != DefaultFailedLookupsPerSource || c.UserTimeout != time.Minute {
		t.Fatalf("core ports %v, failed lookups %d", c.CorePorts, c.FailedLookupsPerSource)
	}
}

func TestPlainPublicURIDefaultsToTheNLBsTCPPort(t *testing.T) {
	// A plain msrp: URI must not name the NLB's TLS listener (ADR 0003).
	c, err := configure(with(devEnv, "RELAY_PUBLIC_TLS", "false"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Public.String() != "msrp://relay.example.net:2855;tcp" {
		t.Fatalf("public %s", c.Public.String())
	}
}

func TestEverySettingIsRead(t *testing.T) {
	c, err := configure(with(devEnv,
		"RELAY_LISTEN_ADDR", "127.0.0.1:12855", "RELAY_CONTROL_ADDR", "127.0.0.1:18082",
		"RELAY_PUBLIC_PORT", "2855", "RELAY_PUBLIC_TLS", "false", "RELAY_CORE_NETWORKS", "10.1.0.0/16",
		"RCS_SERVICE_NAMESPACE", "rcs.internal", "RCS_PROXY_PROTOCOL", "true",
		"RELAY_STORE", "dynamodb", "RELAY_DYNAMODB_TABLE", "bindings", "RELAY_DYNAMODB_ENDPOINT", "http://ddb:8000",
		"RELAY_STORE_TIMEOUT", "1s", "RELAY_PCSCF_TOKEN_NEXT", nextToken, "RELAY_MAX_EXPIRES_IN", "1h",
		"RELAY_MAX_CONNECTIONS", "5", "RELAY_MAX_CONNECTIONS_PER_SOURCE", "2", "RELAY_MAX_CONCURRENT_BINDS", "3",
		"RELAY_MAX_UNKNOWN_SESSIONS", "4", "RELAY_PATH_WAIT", "1s", "RELAY_CORE_CONNECT_TIMEOUT", "2s",
		"RELAY_KEEPALIVE_INTERVAL", "100s", "RELAY_IDLE_TIMEOUT", "200s", "RELAY_DRAIN_TIMEOUT", "100s",
		"RCS_SHUTDOWN_TIMEOUT", "115s", "RELAY_METRICS_INTERVAL", "10s",
		"RELAY_CORE_PORTS", "2855, 12855", "RELAY_FAILED_LOOKUPS_PER_SOURCE", "30",
	))
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprint("127.0.0.1:12855 127.0.0.1:18082 msrp://relay.example.net:2855;tcp [10.1.0.0/16] rcs.internal true ",
		"dynamodb bindings http://ddb:8000 1s 2 1h0m0s 5 2 3 4 1s 2s 1m40s 3m20s 1m40s 10s [2855 12855] 30")
	got := fmt.Sprint(c.ListenAddr, " ", c.ControlAddr, " ", c.Public.String(), " ", c.CoreNetworks, " ", c.Namespace, " ", c.ProxyProtocol, " ",
		c.Store, " ", c.Table, " ", c.DynamoDBEndpoint, " ", c.StoreTimeout, " ", len(c.Tokens), " ", c.MaxExpiresIn, " ",
		c.MaxConnections, " ", c.MaxConnectionsPerSource, " ", c.MaxConcurrentBinds, " ", c.MaxUnknownSessions, " ",
		c.PathWait, " ", c.CoreConnectTimeout, " ", c.KeepAlive, " ", c.IdleTimeout, " ", c.DrainTimeout, " ", c.MetricsInterval, " ",
		c.CorePorts, " ", c.FailedLookupsPerSource)
	if got != want {
		t.Fatalf("config\n got %s\nwant %s", got, want)
	}
}

func TestInvalidSettingsAreReported(t *testing.T) {
	for _, tt := range []struct {
		kv   []string
		want string
	}{
		{[]string{"RELAY_LISTEN_ADDR", "2855"}, "RELAY_LISTEN_ADDR: not host:port"},
		{[]string{"RELAY_CONTROL_ADDR", "x"}, "RELAY_CONTROL_ADDR: not host:port"},
		{[]string{"RELAY_PUBLIC_HOST", ""}, "RELAY_PUBLIC_HOST: required"},
		{[]string{"RELAY_PUBLIC_HOST", "bad host"}, "RELAY_PUBLIC_HOST: not a host name"},
		{[]string{"RELAY_PUBLIC_PORT", "0"}, "RELAY_PUBLIC_PORT: must be from 1 to 65535"},
		{[]string{"RELAY_CORE_HOST", "task"}, "RELAY_CORE_HOST: not an IP address"},
		{[]string{"RELAY_CORE_HOST", "fe80::1%eth0"}, "RELAY_CORE_HOST: not an IP address"},
		{[]string{"RELAY_STORE", "redis"}, "RELAY_STORE: not one of dynamodb, memory"},
		{[]string{"RELAY_PCSCF_TOKEN", "", "RELAY_PCSCF_TOKEN_NEXT", nextToken}, "RELAY_PCSCF_TOKEN_NEXT: set without RELAY_PCSCF_TOKEN"},
		{[]string{"RELAY_PCSCF_TOKEN_NEXT", testToken}, "RELAY_PCSCF_TOKEN_NEXT: equal to RELAY_PCSCF_TOKEN"},
		{[]string{"RELAY_PCSCF_TOKEN", testToken + " x"}, "RELAY_PCSCF_TOKEN: not a bearer token"},
		{[]string{"RELAY_STORE_TIMEOUT", "0s"}, "RELAY_STORE_TIMEOUT: must be greater than zero"},
		{[]string{"RELAY_TCP_USER_TIMEOUT", "0s"}, "RELAY_TCP_USER_TIMEOUT: must be greater than zero"},
		{[]string{"RELAY_MAX_EXPIRES_IN", "1500ms"}, "RELAY_MAX_EXPIRES_IN: must be whole seconds"},
		{[]string{"RELAY_KEEPALIVE_INTERVAL", "300s"}, "RELAY_KEEPALIVE_INTERVAL: must be shorter than RELAY_IDLE_TIMEOUT"},
		{[]string{"RELAY_DRAIN_TIMEOUT", "18s"}, "RELAY_DRAIN_TIMEOUT: plus 3s must not exceed RCS_SHUTDOWN_TIMEOUT (20s by default)"},
		{[]string{"RELAY_DRAIN_TIMEOUT", "98s", "RCS_SHUTDOWN_TIMEOUT", "100s"}, "RELAY_DRAIN_TIMEOUT: plus 3s must not exceed RCS_SHUTDOWN_TIMEOUT:"},
		{[]string{"RELAY_CORE_PORTS", "2855, 0"}, "RELAY_CORE_PORTS: item 2 is not a port"},
		{[]string{"RELAY_CORE_PORTS", "02855"}, "RELAY_CORE_PORTS: item 1 is not a port"},
		{[]string{"RELAY_FAILED_LOOKUPS_PER_SOURCE", "0"}, "RELAY_FAILED_LOOKUPS_PER_SOURCE: must be positive"},
		{[]string{"RELAY_MAX_CONNECTIONS", "0"}, "RELAY_MAX_CONNECTIONS: must be positive"},
		{[]string{"RELAY_MAX_CONCURRENT_BINDS", "-1"}, "RELAY_MAX_CONCURRENT_BINDS: must be positive"},
	} {
		t.Run(tt.want, func(t *testing.T) {
			_, err := configure(with(devEnv, tt.kv...))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %v, want %q", err, tt.want)
			}
			// No problem repeats a value: a value in the wrong variable may be
			// a secret.
			if strings.Contains(err.Error(), testToken) || strings.Contains(err.Error(), nextToken) {
				t.Fatalf("a token reached the error: %v", err)
			}
		})
	}
}

func TestMalformedShutdownTimeoutIsLeftToTheRuntime(t *testing.T) {
	// The runtime reports RCS_SHUTDOWN_TIMEOUT itself; Configure must not
	// add a second, misleading problem about the drain.
	if _, err := configure(with(devEnv, "RCS_SHUTDOWN_TIMEOUT", "soon")); err != nil {
		t.Fatalf("error %v", err)
	}
	out := refusal(t, with(devEnv, "RCS_SHUTDOWN_TIMEOUT", "soon"))
	if !strings.Contains(out, "RCS_SHUTDOWN_TIMEOUT") || strings.Contains(out, "RELAY_DRAIN_TIMEOUT") {
		t.Fatalf("output:\n%s", out)
	}
}

func TestConfigNeverPrintsTokens(t *testing.T) {
	c, err := configure(with(devEnv, "RELAY_PCSCF_TOKEN_NEXT", nextToken))
	if err != nil {
		t.Fatal(err)
	}
	// These verbs, valid ones and the invalid %p and %w, which call no
	// method and print the fields (#506, #538).
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%t", "%x", "%o", "%b", "%p", "%w", "%c", "%e"} {
		opts := controlOptions{Namespace: "rcs.local", Tokens: c.Tokens}
		for _, v := range []any{c, &c, c.Tokens, opts, &opts} {
			s := fmt.Sprintf(verb, v)
			for _, secret := range []string{testToken[:12], nextToken[:12], strings.Trim(fmt.Sprint([]byte(testToken[:6])), "[]"), fmt.Sprintf("%x", testToken[:6])} {
				if strings.Contains(s, secret) {
					t.Errorf("%s printed a token: %s", verb, s)
				}
			}
		}
	}
}

func TestCoreHostIsFoundOnTheTasksInterface(t *testing.T) {
	ipnet := func(s string) net.Addr {
		ip, n, _ := net.ParseCIDR(s)
		n.IP = ip
		return n
	}
	for _, tt := range []struct {
		name  string
		addrs []net.Addr
		err   error
		want  string
	}{
		{"one private address among others", []net.Addr{ipnet("127.0.0.1/8"), ipnet("10.0.3.7/24"), ipnet("fd00::7/64"), ipnet("203.0.113.5/24"), &net.IPAddr{IP: net.ParseIP("10.9.9.9")}}, nil, "10.0.3.7"},
		{"two private addresses", []net.Addr{ipnet("10.0.3.7/24"), ipnet("172.17.0.2/16")}, nil, "2 private IPv4 addresses"},
		{"none", []net.Addr{ipnet("127.0.0.1/8")}, nil, "0 private IPv4 addresses"},
		{"no IP in the net", []net.Addr{&net.IPNet{IP: net.IP{1, 2, 3}}}, nil, "0 private IPv4 addresses"},
		{"interfaces unreadable", nil, errors.New("no netlink"), "could not be read"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			old := interfaceAddrs
			t.Cleanup(func() { interfaceAddrs = old })
			interfaceAddrs = func() ([]net.Addr, error) { return tt.addrs, tt.err }
			c, err := configure(with(devEnv, "RELAY_CORE_HOST", ""))
			if want, err2 := netip.ParseAddr(tt.want); err2 == nil {
				if err != nil || c.CoreHost != want {
					t.Fatalf("core host %v, %v", c.CoreHost, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %v, want %q", err, tt.want)
			}
		})
	}
}

func TestProductionRefusesUnsafeSettings(t *testing.T) {
	for _, tt := range []struct {
		kv   []string
		want string
	}{
		{[]string{"RCS_PROXY_PROTOCOL", "false"}, "RCS_PROXY_PROTOCOL is false"},
		{[]string{"RELAY_PUBLIC_TLS", "false"}, "RELAY_PUBLIC_TLS is false"},
		{[]string{"RELAY_PCSCF_TOKEN", ""}, "RELAY_PCSCF_TOKEN is unset"},
		{[]string{"RELAY_PCSCF_TOKEN", strings.Repeat("t", 42)}, "RELAY_PCSCF_TOKEN is shorter than 43 characters"},
		{[]string{"RELAY_PCSCF_TOKEN_NEXT", "short"}, "RELAY_PCSCF_TOKEN_NEXT is shorter than 43 characters"},
		{[]string{"RELAY_CORE_NETWORKS", "10.0.0.0/8, 0.0.0.0/0"}, "RELAY_CORE_NETWORKS includes 0.0.0.0/0"},
		{[]string{"RELAY_CORE_NETWORKS", "127.0.0.0/8"}, "RELAY_CORE_NETWORKS includes 127.0.0.0/8"},
		{[]string{"RELAY_CORE_NETWORKS", "10.0.0.0/7"}, "RELAY_CORE_NETWORKS includes 10.0.0.0/7"},
		{nil, "RELAY_STORE=memory keeps bindings in one task"},
	} {
		t.Run(tt.want, func(t *testing.T) {
			if out := refusal(t, with(prodEnv, tt.kv...)); !strings.Contains(out, tt.want) {
				t.Fatalf("output lacks %q:\n%s", tt.want, out)
			}
		})
	}
	// What production needs is accepted: the only refusal left is the
	// memory store.
	out := refusal(t, with(prodEnv, "RELAY_CORE_NETWORKS", "10.0.0.0/16, fd00::/8"))
	if strings.Count(out, "refused in prod") != 1 {
		t.Fatalf("more than the memory store was refused:\n%s", out)
	}
}
