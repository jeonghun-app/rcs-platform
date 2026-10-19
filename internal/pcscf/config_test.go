package pcscf

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

const publicHost = "pcscf.rcs.example.net"

// devEnv is a minimal valid dev configuration.
var devEnv = map[string]string{
	"RCS_ENV":                "dev",
	"PCSCF_PUBLIC_HOST":      publicHost,
	"PCSCF_CORE_HOST":        "10.0.2.9",
	"PCSCF_CLIENT_TRANSPORT": "tcp",
	"RCS_SERVICE_NAMESPACE":  "rcs.internal",
	"RCS_IMS_DOMAIN":         "ims.mnc001.mcc001.3gppnetwork.org",
}

// prodEnv is a valid production configuration, so every reason a test sees
// comes from the setting under test.
var prodEnv = with(devEnv,
	"RCS_ENV", "prod",
	"RCS_PII_HMAC_KEY", strings.Repeat("k", 32),
	"RCS_PROXY_PROTOCOL", "true",
	"PCSCF_CLIENT_TRANSPORT", "nlb-tls",
	"PCSCF_PUBLIC_ADDRS", "203.0.113.10, 203.0.113.11",
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
	c := Configure(&runtime.Settings{Env: shared.WithPrefix("PCSCF_"), Shared: shared, Environment: runtime.Environment(env["RCS_ENV"])})
	return c, shared.Err()
}

// startup runs the service with env and returns its exit status and what it
// logged; nothing may be listened on.
func startup(t *testing.T, env map[string]string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	status := runtime.Run(context.Background(), Service(), runtime.Process{
		LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok },
		Stdout:    &out,
		Listen:    func(string, string) (net.Listener, error) { return nil, errors.New("must not start") },
	})
	return status, out.String()
}

func TestDevConfigurationIsReadWithDefaults(t *testing.T) {
	c, err := configure(devEnv)
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		PublicHost: publicHost, PublicPort: 5060, ClientTransport: ClientTCP, ClientAddr: "0.0.0.0:5060",
		CoreAddr: DefaultCoreAddr, CoreHost: netip.MustParseAddr("10.0.2.9"),
		MaxFlowsPerIP: DefaultMaxFlowsPerIP, ClientIdleTimeout: DefaultClientIdleTimeout,
		DrainTimeout:   runtime.DefaultShutdownTimeout - stopMargin,
		MaxConnections: DefaultMaxConnections, MaxClientFlows: DefaultMaxClientFlows, CoreConnections: DefaultCoreConnections,
		ICSCF: mustURI(t, "sip:icscf.rcs.internal;transport=tcp;lr"), AllowLoopback: true,
		SCSCFHost: "scscf.rcs.internal", SCSCFPort: DefaultSCSCFPort,
		Namespace: "rcs.internal", HomeDomain: "ims.mnc001.mcc001.3gppnetwork.org", VisitedNetworkID: "ims.mnc001.mcc001.3gppnetwork.org",
		MaxRegistrations: DefaultMaxRegistrations, RegisterRate: DefaultRegisterRate, RegisterBurst: DefaultRegisterBurst,
		InitialRate: DefaultInitialRate, InitialBurst: DefaultInitialBurst,
	}
	if !reflect.DeepEqual(c, want) {
		t.Fatalf("got  %+v\nwant %+v", c, want)
	}
}

func mustURI(t *testing.T, s string) sip.URI {
	t.Helper()
	u, err := sip.ParseURI(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// The visited network is the home domain unless set (TS 24.229 §5.2.2.1).
func TestTheVisitedNetworkIsTheHomeDomainUnlessSet(t *testing.T) {
	for _, v := range []string{"ims.mnc001.mcc002.3gppnetwork.org", `"Visited network number 1";x=1`} {
		c, err := configure(with(devEnv, "PCSCF_VISITED_NETWORK_ID", v))
		if err != nil || c.VisitedNetworkID != v {
			t.Errorf("%q: %q, %v", v, c.VisitedNetworkID, err)
		}
	}
	c, err := configure(with(devEnv, "RCS_IMS_DOMAIN", "IMS.mnc001.mcc001.3gppnetwork.org."))
	if want := "ims.mnc001.mcc001.3gppnetwork.org"; err != nil || c.HomeDomain != want || c.VisitedNetworkID != want {
		t.Errorf("home domain %q, visited network %q, %v", c.HomeDomain, c.VisitedNetworkID, err)
	}
}

// Each problem is reported once (QA of #198).
func TestAProblemIsReportedOnce(t *testing.T) {
	_, err := configure(with(devEnv, "PCSCF_MAX_FLOWS_PER_IP", "0"))
	if err == nil || strings.Count(err.Error(), "PCSCF_MAX_FLOWS_PER_IP") != 1 {
		t.Fatalf("error %v", err)
	}
}

func TestTheICSCFURIAndLoopbackFollowTheSettings(t *testing.T) {
	c, err := configure(with(devEnv, "PCSCF_ICSCF_URI", "sip:10.0.3.7:5070;transport=tcp;lr"))
	if err != nil || c.ICSCF.String() != "sip:10.0.3.7:5070;transport=tcp;lr" {
		t.Fatalf("ICSCF %v, %v", c.ICSCF, err)
	}
	p, err := configure(prodEnv)
	if err != nil || p.AllowLoopback {
		t.Fatalf("production allows loopback core hops: %v", err)
	}
}

func TestThePublicNameAndAddressesAreNormalised(t *testing.T) {
	c, err := configure(with(devEnv, "PCSCF_PUBLIC_HOST", "PCSCF.rcs.example.net.", "PCSCF_PUBLIC_ADDRS", "203.0.113.10,::ffff:203.0.113.11, 2001:db8::10"))
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Addr{netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("203.0.113.11"), netip.MustParseAddr("2001:db8::10")}
	if c.PublicHost != publicHost || !reflect.DeepEqual(c.PublicAddrs, want) {
		t.Fatalf("host %q, addresses %v", c.PublicHost, c.PublicAddrs)
	}
	label := strings.Repeat("a", 63)
	long := strings.Repeat(label+".", 3) + strings.Repeat("b", 61) // 253 characters
	for _, host := range []string{label + ".example.net", long} {
		if _, err := configure(with(devEnv, "PCSCF_PUBLIC_HOST", host)); err != nil {
			t.Errorf("%d-character host refused: %v", len(host), err)
		}
	}
}

func TestTLSTransportsDefaultToPort5061(t *testing.T) {
	for _, tr := range []string{ClientNLBTLS, ClientTLS} {
		c, err := configure(with(devEnv, "PCSCF_CLIENT_TRANSPORT", tr, "PCSCF_TLS_CERT_FILE", "c.pem", "PCSCF_TLS_KEY_FILE", "k.pem"))
		if err != nil || c.PublicPort != 5061 || c.ClientAddr != "0.0.0.0:5061" {
			t.Errorf("%s: %+v, %v", tr, c, err)
		}
	}
}

func TestTheDrainFillsTheShutdownTimeout(t *testing.T) {
	// ADR 0003: a stopping pcscf spreads the closing of its flows over the
	// task's stop timeout, 120 s.
	c, err := configure(with(devEnv, "RCS_SHUTDOWN_TIMEOUT", "120s"))
	if err != nil || c.DrainTimeout != 115*time.Second {
		t.Fatalf("drain %v, %v", c.DrainTimeout, err)
	}
}

func TestInvalidSettingsAreRefused(t *testing.T) {
	for _, tt := range []struct {
		kv   []string
		want string
	}{
		{[]string{"PCSCF_PUBLIC_HOST", ""}, "PCSCF_PUBLIC_HOST"},
		{[]string{"PCSCF_PUBLIC_HOST", "pcscf_1.example.net"}, "PCSCF_PUBLIC_HOST: not a host name"},
		{[]string{"PCSCF_PUBLIC_HOST", "-pcscf.example.net"}, "PCSCF_PUBLIC_HOST: not a host name"},
		{[]string{"PCSCF_PUBLIC_HOST", "pcscf.example.net.."}, "PCSCF_PUBLIC_HOST: not a host name"},
		{[]string{"PCSCF_PUBLIC_HOST", strings.Repeat("a", 64) + ".example.net"}, "PCSCF_PUBLIC_HOST: not a host name"},
		{[]string{"PCSCF_PUBLIC_HOST", strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("b", 62)}, "PCSCF_PUBLIC_HOST: not a host name"},
		{[]string{"PCSCF_PUBLIC_ADDRS", "203.0.113.10, nlb"}, "PCSCF_PUBLIC_ADDRS: item 2 is not an IP address"},
		{[]string{"PCSCF_PUBLIC_ADDRS", "fe80::1%eth0"}, "PCSCF_PUBLIC_ADDRS: item 1 is not an IP address"},
		{[]string{"PCSCF_MAX_CONNECTIONS", "0"}, "PCSCF_MAX_CONNECTIONS: must be positive"},
		{[]string{"PCSCF_MAX_CLIENT_FLOWS", "0"}, "PCSCF_MAX_CLIENT_FLOWS: must be positive"},
		{[]string{"PCSCF_CORE_CONNECTIONS", "0"}, "PCSCF_CORE_CONNECTIONS: must be positive"},
		{[]string{"PCSCF_MAX_CLIENT_FLOWS", "9745"}, "PCSCF_MAX_CLIENT_FLOWS: plus PCSCF_CORE_CONNECTIONS must not exceed PCSCF_MAX_CONNECTIONS"},
		{[]string{"PCSCF_CLIENT_TRANSPORT", "udp"}, "PCSCF_CLIENT_TRANSPORT: not one of tls, nlb-tls, tcp"},
		{[]string{"PCSCF_CLIENT_TRANSPORT", "tls"}, "PCSCF_TLS_CERT_FILE: PCSCF_TLS_CERT_FILE and PCSCF_TLS_KEY_FILE are required"},
		{[]string{"PCSCF_CLIENT_TRANSPORT", "tls", "PCSCF_TLS_CERT_FILE", "c.pem"}, "PCSCF_TLS_CERT_FILE: PCSCF_TLS_CERT_FILE and PCSCF_TLS_KEY_FILE are required"},
		{[]string{"PCSCF_PUBLIC_PORT", "0"}, "PCSCF_PUBLIC_PORT: not a port"},
		{[]string{"PCSCF_PUBLIC_PORT", "65536"}, "PCSCF_PUBLIC_PORT: not a port"},
		{[]string{"PCSCF_CLIENT_ADDR", "5060"}, "PCSCF_CLIENT_ADDR: not host:port"},
		{[]string{"PCSCF_CORE_ADDR", "core"}, "PCSCF_CORE_ADDR: not host:port"},
		{[]string{"PCSCF_CLIENT_UDP_ADDR", "udp"}, "PCSCF_CLIENT_UDP_ADDR: not host:port"},
		{[]string{"PCSCF_CORE_HOST", "task"}, "PCSCF_CORE_HOST: not an IP address"},
		{[]string{"PCSCF_MAX_FLOWS_PER_IP", "0"}, "PCSCF_MAX_FLOWS_PER_IP: must be positive"},
		{[]string{"PCSCF_MAX_REGISTRATIONS", "0"}, "PCSCF_MAX_REGISTRATIONS: must be positive"},
		{[]string{"PCSCF_REGISTER_RATE", "-1"}, "PCSCF_REGISTER_RATE: must be positive"},
		{[]string{"PCSCF_REGISTER_BURST", "0"}, "PCSCF_REGISTER_BURST: must be positive"},
		{[]string{"PCSCF_INITIAL_RATE", "0"}, "PCSCF_INITIAL_RATE: must be positive"},
		{[]string{"PCSCF_INITIAL_BURST", "-1"}, "PCSCF_INITIAL_BURST: must be positive"},
		{[]string{"RCS_SERVICE_NAMESPACE", ""}, "PCSCF_ICSCF_URI: required when RCS_SERVICE_NAMESPACE is unset"},
		{[]string{"PCSCF_ICSCF_URI", "sip:icscf.rcs.internal;transport=tcp"}, "PCSCF_ICSCF_URI: not a sip URI of a host with transport=tcp and lr"},
		{[]string{"PCSCF_ICSCF_URI", "tel:+15550100001"}, "PCSCF_ICSCF_URI: not a sip URI"},
		{[]string{"PCSCF_ICSCF_URI", "sip:icscf@rcs.internal;transport=tcp;lr"}, "PCSCF_ICSCF_URI: not a sip URI"},
		{[]string{"PCSCF_ICSCF_URI", "::"}, "PCSCF_ICSCF_URI: not a sip URI"},
		// It is reached over TCP through the core listener (QA of #198).
		{[]string{"PCSCF_ICSCF_URI", "sip:icscf.rcs.internal;lr"}, "PCSCF_ICSCF_URI: not a sip URI of a host with transport=tcp"},
		{[]string{"PCSCF_ICSCF_URI", "sips:icscf.rcs.internal;transport=tcp;lr"}, "PCSCF_ICSCF_URI: not a sip URI of a host with transport=tcp"},
		{[]string{"PCSCF_ICSCF_URI", "sip:icscf.rcs.internal;transport=tls;lr"}, "PCSCF_ICSCF_URI: not a sip URI of a host with transport=tcp"},
		{[]string{"PCSCF_ICSCF_URI", "sip:icscf.rcs.internal;transport=udp;lr"}, "PCSCF_ICSCF_URI: not a sip URI of a host with transport=tcp"},
		{[]string{"PCSCF_ICSCF_URI", "sip:icscf.example.net;transport=tcp;lr"}, "PCSCF_ICSCF_URI: a host name outside RCS_SERVICE_NAMESPACE"},
		{[]string{"PCSCF_ICSCF_URI", "sip:icscf.evil-rcs.internal;transport=tcp;lr"}, "PCSCF_ICSCF_URI: a host name outside RCS_SERVICE_NAMESPACE"},
		{[]string{"RCS_IMS_DOMAIN", ""}, "RCS_IMS_DOMAIN: required"},
		// The only next hop of a request inside a dialog (review of #208).
		{[]string{"RCS_SERVICE_NAMESPACE", "", "PCSCF_ICSCF_URI", "sip:10.0.3.7;transport=tcp;lr"}, "PCSCF_SCSCF_HOST: required when RCS_SERVICE_NAMESPACE is unset"},
		{[]string{"PCSCF_SCSCF_HOST", "10.0.4.4"}, "PCSCF_SCSCF_HOST: not a name inside RCS_SERVICE_NAMESPACE"},
		{[]string{"PCSCF_SCSCF_HOST", "scscf.example.net"}, "PCSCF_SCSCF_HOST: not a name inside RCS_SERVICE_NAMESPACE"},
		{[]string{"PCSCF_SCSCF_HOST", "pcscf.rcs.internal"}, "PCSCF_SCSCF_HOST: names pcscf itself"},
		{[]string{"PCSCF_SCSCF_HOST", "edge.rcs.internal", "PCSCF_PUBLIC_HOST", "edge.rcs.internal"}, "PCSCF_SCSCF_HOST: names pcscf itself"},
		{[]string{"PCSCF_SCSCF_PORT", "0"}, "PCSCF_SCSCF_PORT: not a port"},
		{[]string{"RCS_IMS_DOMAIN", "ims_1.example.net"}, "RCS_IMS_DOMAIN: not a host name"},
		{[]string{"PCSCF_VISITED_NETWORK_ID", "a, b"}, "PCSCF_VISITED_NETWORK_ID: not one network identifier"},
		{[]string{"PCSCF_VISITED_NETWORK_ID", "\"open"}, "PCSCF_VISITED_NETWORK_ID: not one network identifier"},
		{[]string{"PCSCF_VISITED_NETWORK_ID", "a\r\nRoute: <sip:x>"}, "PCSCF_VISITED_NETWORK_ID: not one network identifier"},
		{[]string{"PCSCF_CLIENT_IDLE_TIMEOUT", "0s"}, "PCSCF_CLIENT_IDLE_TIMEOUT: must be greater than zero"},
		{[]string{"PCSCF_DRAIN_TIMEOUT", "16s"}, "PCSCF_DRAIN_TIMEOUT: plus 5s must not exceed RCS_SHUTDOWN_TIMEOUT (20s)"},
		{[]string{"PCSCF_DRAIN_TIMEOUT", "0s"}, "PCSCF_DRAIN_TIMEOUT: must be greater than zero"},
		{[]string{"RCS_SHUTDOWN_TIMEOUT", "5s"}, "PCSCF_DRAIN_TIMEOUT: must be greater than zero, and RCS_SHUTDOWN_TIMEOUT longer than 5s"},
	} {
		t.Run(tt.want, func(t *testing.T) {
			_, err := configure(with(devEnv, tt.kv...))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %v, want %q", err, tt.want)
			}
		})
	}
}

func TestAMalformedShutdownTimeoutIsLeftToTheRuntime(t *testing.T) {
	c, err := configure(with(devEnv, "RCS_SHUTDOWN_TIMEOUT", "soon"))
	if err != nil || c.DrainTimeout != runtime.DefaultShutdownTimeout-stopMargin {
		t.Fatalf("drain %v, error %v", c.DrainTimeout, err)
	}
	status, out := startup(t, with(devEnv, "RCS_SHUTDOWN_TIMEOUT", "soon"))
	if status != runtime.ExitFailure || !strings.Contains(out, "RCS_SHUTDOWN_TIMEOUT") || strings.Contains(out, "PCSCF_DRAIN_TIMEOUT") {
		t.Fatalf("status %d, output:\n%s", status, out)
	}
}

func TestProductionRefusesWhatLetsClientsPastTheEdge(t *testing.T) {
	if _, err := configure(prodEnv); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		kv   []string
		want string
	}{
		{[]string{"PCSCF_CLIENT_TRANSPORT", "tcp"}, "PCSCF_CLIENT_TRANSPORT=tcp leaves client signalling unencrypted"},
		{[]string{"PCSCF_CLIENT_UDP_ADDR", "0.0.0.0:5060"}, "PCSCF_CLIENT_UDP_ADDR is set"},
		{[]string{"RCS_PROXY_PROTOCOL", "false"}, "RCS_PROXY_PROTOCOL is false"},
		{[]string{"RCS_PROXY_PROTOCOL", ""}, "RCS_PROXY_PROTOCOL is false"},
		{[]string{"PCSCF_PUBLIC_ADDRS", ""}, "PCSCF_PUBLIC_ADDRS is unset"},
	} {
		t.Run(tt.want, func(t *testing.T) {
			status, out := startup(t, with(prodEnv, tt.kv...))
			if status != runtime.ExitFailure || !strings.Contains(out, tt.want) {
				t.Fatalf("status %d, want %q refused:\n%s", status, tt.want, out)
			}
		})
	}
	// The same settings are only warned about in dev.
	if _, err := configure(with(devEnv, "PCSCF_CLIENT_UDP_ADDR", "0.0.0.0:5060")); err != nil {
		t.Fatal(err)
	}
}

func TestTheCoreHostIsFoundOnTheInterfaces(t *testing.T) {
	for _, tt := range []struct {
		name  string
		addrs []net.Addr
		err   error
		want  string
	}{
		{"one private address", []net.Addr{ipNet("127.0.0.1"), ipNet("10.0.3.7"), ipNet("fd00::7")}, nil, "10.0.3.7"},
		{"two private addresses", []net.Addr{ipNet("10.0.3.7"), ipNet("10.0.4.7")}, nil, "PCSCF_CORE_HOST: unset, and this host has 2 private IPv4 addresses rather than one"},
		{"none", []net.Addr{ipNet("127.0.0.1")}, nil, "PCSCF_CORE_HOST: unset, and this host has 0 private IPv4 addresses"},
		{"unreadable", nil, errors.New("no"), "PCSCF_CORE_HOST: unset, and the interface addresses could not be read"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			old := interfaceAddrs
			t.Cleanup(func() { interfaceAddrs = old })
			interfaceAddrs = func() ([]net.Addr, error) { return tt.addrs, tt.err }
			c, err := configure(with(devEnv, "PCSCF_CORE_HOST", ""))
			switch {
			case err == nil && c.CoreHost.String() == tt.want:
			case err != nil && strings.Contains(err.Error(), tt.want):
			default:
				t.Fatalf("host %v, error %v, want %q", c.CoreHost, err, tt.want)
			}
		})
	}
}

func ipNet(s string) net.Addr {
	ip := net.ParseIP(s)
	bits := 32
	if ip.To4() == nil {
		bits = 128
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
}
